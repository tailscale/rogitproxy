// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/tailscale/setec/client/setec"
)

var (
	gitHubAppID = flag.Int64("github-app-id", 3091475, "GitHub App ID")
	setecSecret = flag.String("setec-secret", "prod/rogitproxy/github-app-key-pem", "setec secret name for the GitHub App private key")
)

// GitHubAppTransport returns an http.RoundTripper that authenticates
// HTTPS requests to GitHub using a GitHub App installation token as
// basic auth (x-access-token:<token>), which is the format GitHub's
// git smart HTTP endpoints require.
//
// It discovers all installations of the GitHub App at startup and
// caches per-org transports. New org installations are discovered
// lazily on first request.
//
// It reads the private key from ~/keys/rogitproxy.pem on disk,
// falling back to setec if setecURL is non-empty.
//
// It returns the transport and the number of org installations
// discovered at startup.
func GitHubAppTransport(ctx context.Context, setecURL string, setecDo func(*http.Request) (*http.Response, error)) (*multiOrgTransport, error) {
	keyPEM, err := getGitHubAppPrivateKey(ctx, setecURL, setecDo)
	if err != nil {
		return nil, err
	}
	appsTr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, *gitHubAppID, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub app transport: %w", err)
	}

	mt := &multiOrgTransport{
		base:   http.DefaultTransport,
		appsTr: appsTr,
		orgTr:  make(map[string]*ghinstallation.Transport),
	}

	return mt, nil
}

// multiOrgTransport is an http.RoundTripper that routes GitHub API
// requests to the correct GitHub App installation based on the org
// in the request URL path. It caches per-org installation transports
// and lazily discovers new ones on cache miss.
type multiOrgTransport struct {
	base   http.RoundTripper
	appsTr *ghinstallation.AppsTransport

	mu    sync.RWMutex
	orgTr map[string]*ghinstallation.Transport // lowercase org -> transport
}

func (t *multiOrgTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	org := orgFromPath(req.URL.Path)
	if org == "" {
		return nil, fmt.Errorf("cannot determine org from request path %q", req.URL.Path)
	}

	itr, err := t.transportForOrg(req.Context(), org)
	if err != nil {
		return nil, fmt.Errorf("getting transport for org %q: %w", org, err)
	}

	tok, err := itr.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("getting GitHub App token for org %q: %w", org, err)
	}
	req = req.Clone(req.Context())
	req.SetBasicAuth("x-access-token", tok)
	return t.base.RoundTrip(req)
}

// orgFromPath extracts the GitHub org from a URL path like
// "/tailscale/corp.git/info/refs". It returns the lowercased org
// name, or "" if the path doesn't contain one.
func orgFromPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	slash := strings.IndexByte(path, '/')
	if slash <= 0 {
		return ""
	}
	return strings.ToLower(path[:slash])
}

// transportForOrg returns a cached ghinstallation.Transport for the
// given org. On cache miss it discovers the installation via the
// GitHub API and caches the result.
func (t *multiOrgTransport) transportForOrg(ctx context.Context, org string) (*ghinstallation.Transport, error) {
	t.mu.RLock()
	itr, ok := t.orgTr[org]
	t.mu.RUnlock()
	if ok {
		return itr, nil
	}

	// Cache miss — discover the installation for this org.
	installID, err := t.findInstallationForOrg(ctx, org)
	if err != nil {
		return nil, err
	}
	itr = ghinstallation.NewFromAppsTransport(t.appsTr, installID)
	t.mu.Lock()
	// Only set if we didn't lose the race
	if existing, ok := t.orgTr[org]; !ok {
		t.orgTr[org] = itr
	} else {
		itr = existing
	}
	t.mu.Unlock()
	return itr, nil
}

// findInstallationForOrg calls GET /orgs/{org}/installation using the
// App JWT to discover the installation ID for the given org.
func (t *multiOrgTransport) findInstallationForOrg(ctx context.Context, org string) (int64, error) {
	url := fmt.Sprintf("https://api.github.com/orgs/%s/installation", org)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := t.appsTr.RoundTrip(req)
	if err != nil {
		return 0, fmt.Errorf("GitHub API request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("GitHub App not installed on org %q (HTTP %d)", org, resp.StatusCode)
	}
	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decoding installation response: %w", err)
	}
	if result.ID == 0 {
		return 0, fmt.Errorf("no installation ID returned for org %q", org)
	}
	return result.ID, nil
}

// discoverAllInstallations calls GET /app/installations to enumerate
// all installations of the GitHub App and pre-populates the org cache.
// It returns the number of installations found.
func (t *multiOrgTransport) discoverAllInstallations(ctx context.Context) (int, error) {
	url := "https://api.github.com/app/installations?per_page=100"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := t.appsTr.RoundTrip(req)
	if err != nil {
		return 0, fmt.Errorf("listing installations: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("listing installations: HTTP %d", resp.StatusCode)
	}

	var installations []struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&installations); err != nil {
		return 0, fmt.Errorf("decoding installations: %w", err)
	}

	var verified bool
	for _, inst := range installations {
		org := strings.ToLower(inst.Account.Login)
		if org == "" {
			continue
		}
		itr := ghinstallation.NewFromAppsTransport(t.appsTr, inst.ID)

		// Verify we can get a token for at least one installation.
		if !verified {
			if _, err := itr.Token(ctx); err != nil {
				return 0, fmt.Errorf("getting initial token for org %q (installation %d): %w", org, inst.ID, err)
			}
			verified = true
		}

		t.mu.Lock()
		t.orgTr[org] = itr
		t.mu.Unlock()
	}
	return len(installations), nil
}

func getGitHubAppPrivateKeyFromDisk() (_ []byte, ok bool) {
	if home, err := os.UserHomeDir(); err == nil {
		if pem, err := os.ReadFile(filepath.Join(home, "keys", "rogitproxy.pem")); err == nil {
			return pem, true
		}
	}
	return nil, false
}

func getGitHubAppPrivateKey(ctx context.Context, setecURL string, setecDo func(*http.Request) (*http.Response, error)) ([]byte, error) {
	if pem, ok := getGitHubAppPrivateKeyFromDisk(); ok {
		return pem, nil
	}

	if setecURL != "" {
		sc := setec.Client{
			Server: setecURL,
			DoHTTP: setecDo,
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		v, err := sc.Get(ctx, *setecSecret)
		if err != nil {
			return nil, fmt.Errorf("setec: %w", err)
		}
		return v.Value, nil
	}

	return nil, fmt.Errorf("no GitHub App private key found (tried ~/keys/rogitproxy.pem; set --setec-url to use setec)")
}
