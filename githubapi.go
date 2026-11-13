// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"tailscale.com/client/tailscale/apitype"
)

// APIProxy is an HTTP handler that proxies read-only GitHub API
// requests on behalf of unauthenticated tailnet clients. It gives a
// caller the same read access to their granted repos that a read-only
// collaborator would have on the GitHub website: PRs, issues,
// comments, reviews, checks, statuses, and Actions runs and logs.
//
// It lays out its URLs like GitHub Enterprise Server so that the gh
// CLI and other GitHub clients can use it as a GHES host: REST at
// /api/v3/ and GraphQL at /api/graphql.
//
// Safety is layered. Only GET and HEAD under /api/v3/repos/{owner}/{repo}/
// and GraphQL queries (not mutations) are accepted, the caller must
// have a pull grant on the repo, and the upstream request uses an
// installation token downscoped to read-only permissions and the
// caller's granted repos (see multiOrgTransport.scopedToken).
type APIProxy struct {
	// Upstream is the GitHub API base URL. If empty, it defaults to
	// "https://api.github.com".
	Upstream string

	// Token returns a read-only GitHub token for the given lowercase
	// org, restricted to the given bare repo names (or the whole
	// installation if repos is empty).
	Token func(ctx context.Context, org string, repos []string) (string, error)

	// WhoIs, if non-nil, identifies the tailnet peer at remoteAddr.
	WhoIs func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)

	RequireGrants bool         // if true, enforce tailnet grants for repo access
	HTTPClient    *http.Client // optional; defaults to http.DefaultClient's settings
	Logf          Logf         // optional; defaults to log.Printf
}

const (
	apiRESTPrefix  = "/api/v3"
	apiGraphQLPath = "/api/graphql"

	// maxRewriteBody is the largest JSON response body that is
	// buffered to rewrite upstream API URLs. Larger bodies are
	// streamed unmodified.
	maxRewriteBody = 32 << 20

	// maxGraphQLBody is the largest GraphQL request body accepted.
	maxGraphQLBody = 1 << 20
)

// Register registers p's handlers on mux.
func (p *APIProxy) Register(mux *http.ServeMux) {
	mux.HandleFunc(apiRESTPrefix+"/", p.serveREST)
	mux.HandleFunc(apiRESTPrefix+"/meta", p.serveMeta)
	mux.HandleFunc(apiGraphQLPath, p.serveGraphQL)
}

func (p *APIProxy) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (p *APIProxy) upstream() string {
	if p.Upstream != "" {
		return strings.TrimRight(p.Upstream, "/")
	}
	return "https://api.github.com"
}

// httpClient returns the client for upstream requests. It follows
// redirects (Actions logs and artifacts redirect to blob storage that
// clients typically can't reach) but never sends the token to any
// host other than the upstream.
func (p *APIProxy) httpClient() *http.Client {
	var c http.Client
	if p.HTTPClient != nil {
		c = *p.HTTPClient
	}
	up, _ := url.Parse(p.upstream())
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" && req.URL.Scheme != up.Scheme {
			return fmt.Errorf("refusing redirect to %s URL", req.URL.Scheme)
		}
		if req.URL.Host != up.Host {
			req.Header.Del("Authorization")
		}
		return nil
	}
	return &c
}

// identify returns the caller's WhoIs (nil if unavailable) and a
// human-readable description for logs.
func (p *APIProxy) identify(r *http.Request) (*apitype.WhoIsResponse, string) {
	if p.WhoIs == nil {
		return nil, r.RemoteAddr
	}
	who, err := p.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return nil, r.RemoteAddr
	}
	return who, formatWhoIs(r.RemoteAddr, who)
}

func (p *APIProxy) deny(w http.ResponseWriter, r *http.Request, whoStr string, code int, msg string) {
	counterAPIDenied.Add(1)
	p.logf("ghapi: denied %s %s by %s: %s", r.Method, r.URL.Path, whoStr, msg)
	apiError(w, code, msg)
}

// apiError writes a GitHub-style JSON error response.
func apiError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

// serveMeta serves a synthetic GHES /meta response. The gh CLI fetches
// it to learn the GHES version for feature detection; we claim a
// version new enough that gh uses the same features as on github.com.
func (p *APIProxy) serveMeta(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{
		"installed_version":                  "3.99.0",
		"verifiable_password_authentication": false,
	})
}

// serveREST proxies GET and HEAD requests for
// /api/v3/repos/{owner}/{repo}/... to the upstream GitHub REST API.
func (p *APIProxy) serveREST(w http.ResponseWriter, r *http.Request) {
	counterAPIRequests.Add(1)
	who, whoStr := p.identify(r)

	if r.Method != "GET" && r.Method != "HEAD" {
		p.deny(w, r, whoStr, http.StatusMethodNotAllowed, "rogitproxy: only GET and HEAD are allowed")
		return
	}
	// Reject paths with escaped characters that decode differently
	// (e.g. "%2F") so the path we check is exactly the path we forward.
	if r.URL.RawPath != "" {
		p.deny(w, r, whoStr, http.StatusBadRequest, "rogitproxy: escaped characters in path not supported")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, apiRESTPrefix)
	segs := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	if len(segs) < 3 || segs[0] != "repos" {
		p.deny(w, r, whoStr, http.StatusNotFound, "rogitproxy: only /repos/{owner}/{repo}/... is supported")
		return
	}
	for _, s := range segs {
		if s == "." || s == ".." {
			p.deny(w, r, whoStr, http.StatusBadRequest, "rogitproxy: invalid path")
			return
		}
	}
	owner, repo := segs[1], segs[2]
	if !validRepoComponent(owner) || !validRepoComponent(repo) {
		p.deny(w, r, whoStr, http.StatusBadRequest, "rogitproxy: invalid owner or repo")
		return
	}
	if p.RequireGrants {
		if who == nil {
			p.deny(w, r, whoStr, http.StatusForbidden, "rogitproxy: unable to identify peer")
			return
		}
		if !checkGrant(who, owner+"/"+repo, AccessPull) {
			p.deny(w, r, whoStr, http.StatusForbidden, fmt.Sprintf("rogitproxy: no grant for %s/%s", owner, repo))
			return
		}
	}

	tok, err := p.Token(r.Context(), strings.ToLower(owner), []string{repo})
	if err != nil {
		p.logf("ghapi: token for %s/%s: %v", owner, repo, err)
		apiError(w, http.StatusBadGateway, "rogitproxy: failed to get GitHub token")
		return
	}

	target := p.upstream() + (&url.URL{Path: rest}).EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, nil)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	copyHeaders(req.Header, r.Header, forwardRequestHeaders)
	req.Header.Set("Authorization", "Bearer "+tok)
	p.forward(w, r, req, whoStr)
}

// serveGraphQL proxies GraphQL queries (but not mutations or
// subscriptions) to the upstream GitHub GraphQL API.
func (p *APIProxy) serveGraphQL(w http.ResponseWriter, r *http.Request) {
	counterAPIRequests.Add(1)
	who, whoStr := p.identify(r)

	if r.Method != "POST" {
		p.deny(w, r, whoStr, http.StatusMethodNotAllowed, "rogitproxy: only POST is allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxGraphQLBody+1))
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body) > maxGraphQLBody {
		p.deny(w, r, whoStr, http.StatusRequestEntityTooLarge, "rogitproxy: request too large")
		return
	}
	var gq struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(body, &gq); err != nil {
		p.deny(w, r, whoStr, http.StatusBadRequest, "rogitproxy: invalid JSON body")
		return
	}
	if err := checkReadOnlyGraphQL(gq.Query); err != nil {
		p.deny(w, r, whoStr, http.StatusForbidden, "rogitproxy: "+err.Error())
		return
	}

	owner, _ := gq.Variables["owner"].(string)
	org, repos, err := p.graphQLScope(who, strings.ToLower(owner))
	if err != nil {
		p.deny(w, r, whoStr, http.StatusForbidden, "rogitproxy: "+err.Error())
		return
	}
	tok, err := p.Token(r.Context(), org, repos)
	if err != nil {
		p.logf("ghapi: graphql token for %s: %v", org, err)
		apiError(w, http.StatusBadGateway, "rogitproxy: failed to get GitHub token")
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), "POST", p.upstream()+"/graphql", bytes.NewReader(body))
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	copyHeaders(req.Header, r.Header, forwardRequestHeaders)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	p.forward(w, r, req, whoStr)
}

// graphQLScope returns the org and bare repo names that a GraphQL
// request's token should be scoped to. GraphQL requests don't name a
// single repo in their URL, so the token covers all of the caller's
// granted repos in one org: the "owner" variable's org if present
// (gh always sets it for repo queries), else the caller's first
// granted org.
func (p *APIProxy) graphQLScope(who *apitype.WhoIsResponse, owner string) (org string, repos []string, err error) {
	if !p.RequireGrants {
		if owner == "" {
			return "", nil, errors.New(`GraphQL requests require an "owner" variable`)
		}
		return owner, nil, nil
	}
	if who == nil {
		return "", nil, errors.New("unable to identify peer")
	}
	byOrg := map[string][]string{}
	for _, full := range grantedRepos(who, AccessPull) {
		o, r, ok := strings.Cut(strings.ToLower(full), "/")
		if ok && o != "" && r != "" {
			byOrg[o] = append(byOrg[o], r)
		}
	}
	if len(byOrg) == 0 {
		return "", nil, errors.New("no repo grants")
	}
	if owner == "" {
		orgs := make([]string, 0, len(byOrg))
		for o := range byOrg {
			orgs = append(orgs, o)
		}
		slices.Sort(orgs)
		owner = orgs[0]
	}
	if len(byOrg[owner]) == 0 {
		return "", nil, fmt.Errorf("no repo grants in org %q", owner)
	}
	return owner, byOrg[owner], nil
}

// checkReadOnlyGraphQL returns an error if the GraphQL document q
// fails to parse or contains any operation other than a query.
func checkReadOnlyGraphQL(q string) error {
	doc, err := parser.ParseQuery(&ast.Source{Input: q})
	if err != nil {
		return fmt.Errorf("invalid GraphQL query: %v", err)
	}
	if len(doc.Operations) == 0 {
		return errors.New("no GraphQL operations")
	}
	for _, op := range doc.Operations {
		if op.Operation != ast.Query {
			return fmt.Errorf("GraphQL %s operations are not allowed; only queries", op.Operation)
		}
	}
	return nil
}

// validRepoComponent reports whether s is a plausible GitHub owner or
// repo name.
func validRepoComponent(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// forwardRequestHeaders are the client request headers passed upstream.
// Notably, Authorization and Cookie are not.
var forwardRequestHeaders = []string{
	"Accept",
	"If-Modified-Since",
	"If-None-Match",
	"Range",
	"User-Agent",
	"X-GitHub-Api-Version",
}

// forwardResponseHeaders are the upstream response headers passed back
// to the client. Headers starting with "X-Ratelimit-" are also passed.
var forwardResponseHeaders = []string{
	"Cache-Control",
	"Content-Disposition",
	"Content-Range",
	"Content-Type",
	"Etag",
	"Last-Modified",
	"Link",
	"Retry-After",
	"X-Github-Media-Type",
	"X-Github-Request-Id",
}

func copyHeaders(dst, src http.Header, keys []string) {
	for _, k := range keys {
		if vv := src.Values(k); len(vv) > 0 {
			dst[http.CanonicalHeaderKey(k)] = slices.Clone(vv)
		}
	}
}

// forward sends req upstream and writes the response to w, rewriting
// upstream API URLs in the Link header and JSON bodies to point back
// at this proxy.
func (p *APIProxy) forward(w http.ResponseWriter, r *http.Request, req *http.Request, whoStr string) {
	resp, err := p.httpClient().Do(req)
	if err != nil {
		p.logf("ghapi: %s %s by %s: %v", r.Method, r.URL.Path, whoStr, err)
		apiError(w, http.StatusBadGateway, "rogitproxy: upstream error")
		return
	}
	defer resp.Body.Close()
	p.logf("ghapi: %s %s -> %d by %s", r.Method, r.URL.RequestURI(), resp.StatusCode, whoStr)

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	rw := strings.NewReplacer(p.upstream()+"/", scheme+"://"+r.Host+apiRESTPrefix+"/")

	copyHeaders(w.Header(), resp.Header, forwardResponseHeaders)
	for k, vv := range resp.Header {
		if strings.HasPrefix(k, "X-Ratelimit-") {
			w.Header()[k] = slices.Clone(vv)
		}
	}
	if link := w.Header().Get("Link"); link != "" {
		w.Header().Set("Link", rw.Replace(link))
	}

	if !isJSON(resp.Header.Get("Content-Type")) || r.Method == "HEAD" {
		if resp.ContentLength >= 0 {
			w.Header().Set("Content-Length", fmt.Sprint(resp.ContentLength))
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxRewriteBody+1))
	if err != nil {
		apiError(w, http.StatusBadGateway, "rogitproxy: reading upstream response")
		return
	}
	if len(buf) > maxRewriteBody {
		// Too big to rewrite; stream it through unmodified.
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, io.MultiReader(bytes.NewReader(buf), resp.Body))
		return
	}
	out := rw.Replace(string(buf))
	w.Header().Set("Content-Length", fmt.Sprint(len(out)))
	w.WriteHeader(resp.StatusCode)
	io.WriteString(w, out)
}

func isJSON(contentType string) bool {
	ct, _, _ := strings.Cut(contentType, ";")
	ct = strings.TrimSpace(ct)
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}
