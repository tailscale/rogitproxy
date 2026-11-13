// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"tailscale.com/client/tailscale/apitype"
)

// tokenCall records a call to APIProxy.Token.
type tokenCall struct {
	org   string
	repos []string
}

// apiTestEnv is a test APIProxy in front of a fake upstream GitHub API.
type apiTestEnv struct {
	proxy    *httptest.Server
	upstream *httptest.Server
	blob     *httptest.Server // redirect target, like Actions log storage

	mu         sync.Mutex
	tokenCalls []tokenCall
	upReqs     []*http.Request // requests seen by upstream
	blobReqs   []*http.Request // requests seen by blob
}

func newAPITestEnv(t *testing.T, who *apitype.WhoIsResponse) *apiTestEnv {
	t.Helper()
	e := &apiTestEnv{}

	e.blob = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.blobReqs = append(e.blobReqs, r.Clone(context.Background()))
		e.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "log line with "+e.upstream.URL+"/ untouched\n")
	}))
	t.Cleanup(e.blob.Close)

	e.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.upReqs = append(e.upReqs, r.Clone(context.Background()))
		e.mu.Unlock()
		base := "http://" + r.Host
		switch {
		case r.URL.Path == "/graphql":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fmt.Fprintf(w, `{"data":{"echo":%q}}`, body)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			http.Redirect(w, r, e.blob.URL+"/signed?sig=abc", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/tailscale/corp/pulls?page=2>; rel="next"`, base))
			w.Header().Set("X-RateLimit-Remaining", "4999")
			w.Header().Set("Set-Cookie", "secret=1")
			fmt.Fprintf(w, `{"url":"%s/repos/tailscale/corp/pulls/1","html_url":"https://github.com/tailscale/corp/pull/1","path":%q,"query":%q}`,
				base, r.URL.Path, r.URL.RawQuery)
		}
	}))
	t.Cleanup(e.upstream.Close)

	p := &APIProxy{
		Upstream: e.upstream.URL,
		Token: func(ctx context.Context, org string, repos []string) (string, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.tokenCalls = append(e.tokenCalls, tokenCall{org, slices.Clone(repos)})
			return "scoped-token", nil
		},
		Logf: t.Logf,
	}
	if who != nil {
		p.RequireGrants = true
		p.WhoIs = func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			return who, nil
		}
	}
	mux := http.NewServeMux()
	p.Register(mux)
	e.proxy = httptest.NewServer(mux)
	t.Cleanup(e.proxy.Close)
	return e
}

func (e *apiTestEnv) do(t *testing.T, method, path, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, e.proxy.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "token client-token")
	req.Header.Set("Cookie", "client=1")
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(b)
}

func corpWho() *apitype.WhoIsResponse {
	return makeWho(
		grantValue{Repos: []string{"tailscale/corp", "tailscale/tailscale"}, Access: AccessPull},
		grantValue{Repos: []string{"other/thing"}, Access: AccessPull},
	)
}

func TestAPIProxyREST(t *testing.T) {
	e := newAPITestEnv(t, corpWho())

	res, body := e.do(t, "GET", "/api/v3/repos/tailscale/corp/pulls?state=open&per_page=5", "")
	if res.StatusCode != 200 {
		t.Fatalf("status = %d; body: %s", res.StatusCode, body)
	}

	var got struct {
		URL     string `json:"url"`
		HTMLURL string `json:"html_url"`
		Path    string `json:"path"`
		Query   string `json:"query"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}
	if want := e.proxy.URL + "/api/v3/repos/tailscale/corp/pulls/1"; got.URL != want {
		t.Errorf("url = %q; want rewritten %q", got.URL, want)
	}
	if want := "https://github.com/tailscale/corp/pull/1"; got.HTMLURL != want {
		t.Errorf("html_url = %q; want unchanged %q", got.HTMLURL, want)
	}
	if got.Path != "/repos/tailscale/corp/pulls" {
		t.Errorf("upstream path = %q", got.Path)
	}
	if got.Query != "state=open&per_page=5" {
		t.Errorf("upstream query = %q", got.Query)
	}
	if want := fmt.Sprintf(`<%s/api/v3/repos/tailscale/corp/pulls?page=2>; rel="next"`, e.proxy.URL); res.Header.Get("Link") != want {
		t.Errorf("Link = %q; want %q", res.Header.Get("Link"), want)
	}
	if res.Header.Get("X-Ratelimit-Remaining") != "4999" {
		t.Errorf("rate limit header not forwarded")
	}
	if res.Header.Get("Set-Cookie") != "" {
		t.Errorf("Set-Cookie forwarded")
	}

	up := e.upReqs[0]
	if got, want := up.Header.Get("Authorization"), "Bearer scoped-token"; got != want {
		t.Errorf("upstream Authorization = %q; want %q", got, want)
	}
	if up.Header.Get("Cookie") != "" {
		t.Errorf("client Cookie forwarded upstream")
	}
	if up.Header.Get("Accept") != "application/vnd.github+json" {
		t.Errorf("Accept not forwarded")
	}
	if want := []tokenCall{{"tailscale", []string{"corp"}}}; !slices.EqualFunc(e.tokenCalls, want, tokenCallEqual) {
		t.Errorf("token calls = %v; want %v", e.tokenCalls, want)
	}
}

func tokenCallEqual(a, b tokenCall) bool {
	return a.org == b.org && slices.Equal(a.repos, b.repos)
}

func TestAPIProxyRESTDenied(t *testing.T) {
	e := newAPITestEnv(t, corpWho())
	tests := []struct {
		method, path string
		want         int
	}{
		{"POST", "/api/v3/repos/tailscale/corp/issues/1/comments", 405},
		{"PATCH", "/api/v3/repos/tailscale/corp/pulls/1", 405},
		{"PUT", "/api/v3/repos/tailscale/corp/pulls/1/merge", 405},
		{"DELETE", "/api/v3/repos/tailscale/corp", 405},
		{"GET", "/api/v3/repos/tailscale/secret/pulls", 403},
		{"GET", "/api/v3/repos/tailscale", 404},
		{"GET", "/api/v3/user", 404},
		{"GET", "/api/v3/orgs/tailscale/members", 404},
		{"GET", "/api/v3/search/issues?q=foo", 404},
		{"GET", "/api/v3/repos/tailscale/corp%2F..%2Fsecret/pulls", 400},
		{"GET", "/api/v3/repos/tailscale/co%72p/pulls", 400},
	}
	for _, tt := range tests {
		res, body := e.do(t, tt.method, tt.path, "")
		if res.StatusCode != tt.want {
			t.Errorf("%s %s = %d; want %d; body: %s", tt.method, tt.path, res.StatusCode, tt.want, body)
		}
	}
	if len(e.upReqs) != 0 {
		t.Errorf("upstream saw %d requests; want 0", len(e.upReqs))
	}
}

func TestAPIProxyRESTNoWhoIs(t *testing.T) {
	e := newAPITestEnv(t, corpWho())
	// Simulate a WhoIs failure by making the proxy require grants with
	// no WhoIs function configured.
	p := &APIProxy{Upstream: e.upstream.URL, RequireGrants: true, Logf: t.Logf}
	mux := http.NewServeMux()
	p.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/api/v3/repos/tailscale/corp/pulls")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Errorf("status = %d; want 403", res.StatusCode)
	}
}

func TestAPIProxyRedirectDropsToken(t *testing.T) {
	e := newAPITestEnv(t, corpWho())
	res, body := e.do(t, "GET", "/api/v3/repos/tailscale/corp/actions/jobs/123/logs", "")
	if res.StatusCode != 200 {
		t.Fatalf("status = %d; body: %s", res.StatusCode, body)
	}
	// Non-JSON bodies are passed through without URL rewriting.
	if want := "log line with " + e.upstream.URL + "/ untouched\n"; body != want {
		t.Errorf("body = %q; want %q", body, want)
	}
	if len(e.blobReqs) != 1 {
		t.Fatalf("blob saw %d requests; want 1", len(e.blobReqs))
	}
	if got := e.blobReqs[0].Header.Get("Authorization"); got != "" {
		t.Errorf("token leaked to redirect target: Authorization = %q", got)
	}
}

func TestAPIProxyMeta(t *testing.T) {
	e := newAPITestEnv(t, corpWho())
	res, body := e.do(t, "GET", "/api/v3/meta", "")
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var meta struct {
		InstalledVersion string `json:"installed_version"`
	}
	if err := json.Unmarshal([]byte(body), &meta); err != nil || meta.InstalledVersion == "" {
		t.Errorf("bad meta %q: %v", body, err)
	}
}

func graphQLBody(query string, vars map[string]any) string {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	return string(b)
}

func TestAPIProxyGraphQL(t *testing.T) {
	const prQuery = `query PullRequestStatusChecks($owner: String!, $repo: String!, $number: Int!) {
		repository(owner: $owner, name: $repo) { pullRequest(number: $number) { title } }
	}`

	tests := []struct {
		name      string
		body      string
		want      int
		wantToken *tokenCall
	}{
		{
			name:      "query with owner",
			body:      graphQLBody(prQuery, map[string]any{"owner": "Tailscale", "repo": "corp", "number": 1}),
			want:      200,
			wantToken: &tokenCall{"tailscale", []string{"corp", "tailscale"}},
		},
		{
			name:      "query with other owner",
			body:      graphQLBody(prQuery, map[string]any{"owner": "other", "repo": "thing", "number": 1}),
			want:      200,
			wantToken: &tokenCall{"other", []string{"thing"}},
		},
		{
			name:      "query without owner uses first granted org",
			body:      graphQLBody(`query { Issue: __type(name: "Issue") { fields { name } } }`, nil),
			want:      200,
			wantToken: &tokenCall{"other", []string{"thing"}},
		},
		{
			name: "query for ungranted org",
			body: graphQLBody(prQuery, map[string]any{"owner": "evil", "repo": "x", "number": 1}),
			want: 403,
		},
		{
			name: "mutation",
			body: graphQLBody(`mutation { addComment(input: {subjectId: "x", body: "hi"}) { clientMutationId } }`, nil),
			want: 403,
		},
		{
			name: "query then mutation",
			body: graphQLBody(`query A { viewer { login } } mutation B { addStar(input: {starrableId: "x"}) { clientMutationId } }`, nil),
			want: 403,
		},
		{
			name: "subscription",
			body: graphQLBody(`subscription { foo }`, nil),
			want: 403,
		},
		{
			name: "garbage",
			body: graphQLBody(`not graphql {{{`, nil),
			want: 403,
		},
		{
			name: "invalid json",
			body: `{`,
			want: 400,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newAPITestEnv(t, corpWho())
			res, body := e.do(t, "POST", "/api/graphql", tt.body)
			if res.StatusCode != tt.want {
				t.Fatalf("status = %d; want %d; body: %s", res.StatusCode, tt.want, body)
			}
			if tt.wantToken == nil {
				if len(e.upReqs) != 0 || len(e.tokenCalls) != 0 {
					t.Errorf("upstream requests = %d, token calls = %d; want 0", len(e.upReqs), len(e.tokenCalls))
				}
				return
			}
			if !slices.EqualFunc(e.tokenCalls, []tokenCall{*tt.wantToken}, tokenCallEqual) {
				t.Errorf("token calls = %v; want %v", e.tokenCalls, *tt.wantToken)
			}
			if !strings.Contains(body, `"echo"`) {
				t.Errorf("unexpected body %q", body)
			}
			if got := e.upReqs[0].Header.Get("Authorization"); got != "Bearer scoped-token" {
				t.Errorf("upstream Authorization = %q", got)
			}
		})
	}

	t.Run("GET", func(t *testing.T) {
		e := newAPITestEnv(t, corpWho())
		res, _ := e.do(t, "GET", "/api/graphql", "")
		if res.StatusCode != 405 {
			t.Errorf("status = %d; want 405", res.StatusCode)
		}
	})
}

func TestAPIProxyDevMode(t *testing.T) {
	e := newAPITestEnv(t, nil) // no grants enforced

	res, body := e.do(t, "GET", "/api/v3/repos/tailscale/anything/pulls", "")
	if res.StatusCode != 200 {
		t.Fatalf("REST status = %d; body: %s", res.StatusCode, body)
	}
	res, body = e.do(t, "POST", "/api/graphql", graphQLBody(`query { viewer { login } }`, map[string]any{"owner": "tailscale"}))
	if res.StatusCode != 200 {
		t.Fatalf("GraphQL status = %d; body: %s", res.StatusCode, body)
	}
	res, _ = e.do(t, "POST", "/api/graphql", graphQLBody(`query { viewer { login } }`, nil))
	if res.StatusCode != 403 {
		t.Errorf("GraphQL without owner status = %d; want 403", res.StatusCode)
	}
	want := []tokenCall{{"tailscale", []string{"anything"}}, {"tailscale", nil}}
	if !slices.EqualFunc(e.tokenCalls, want, tokenCallEqual) {
		t.Errorf("token calls = %v; want %v", e.tokenCalls, want)
	}
	res, _ = e.do(t, "POST", "/api/v3/repos/tailscale/anything/issues", "{}")
	if res.StatusCode != 405 {
		t.Errorf("POST in dev mode status = %d; want 405", res.StatusCode)
	}
}
