// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/tailscale/setec/client/setec"
)

var (
	gitHubAppID          = flag.Int64("github-app-id", 3091475, "GitHub App ID")
	gitHubInstallationID = flag.Int64("github-app-install-id", 116358802, "GitHub App installation ID")
	setecSecret          = flag.String("setec-secret", "prod/rogitproxy/github-app-key-pem", "setec secret name for the GitHub App private key")
)

// GitHubAppTransport returns an http.RoundTripper that authenticates
// HTTPS requests to GitHub using a GitHub App installation token as
// basic auth (x-access-token:<token>), which is the format GitHub's
// git smart HTTP endpoints require.
//
// It reads the private key from ~/keys/rogitproxy.pem on disk,
// falling back to setec if setecURL is non-empty.
func GitHubAppTransport(ctx context.Context, setecURL string, setecDo func(*http.Request) (*http.Response, error)) (http.RoundTripper, error) {
	keyPEM, err := getGitHubAppPrivateKey(ctx, setecURL, setecDo)
	if err != nil {
		return nil, err
	}
	appTr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, *gitHubAppID, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub app transport: %w", err)
	}
	itr := ghinstallation.NewFromAppsTransport(appTr, *gitHubInstallationID)

	// Verify we can get a token at startup.
	if _, err := itr.Token(ctx); err != nil {
		return nil, fmt.Errorf("getting initial token: %w", err)
	}

	return &gitBasicAuthTransport{base: http.DefaultTransport, itr: itr}, nil
}

// gitBasicAuthTransport wraps a ghinstallation.Transport and adds
// HTTP basic auth (x-access-token:<token>) to each request.
// This is the format GitHub's git smart HTTP endpoints require,
// as opposed to the "Authorization: token <tok>" header that
// ghinstallation uses by default (which works for the REST API
// but not for git HTTP).
type gitBasicAuthTransport struct {
	base http.RoundTripper
	itr  *ghinstallation.Transport
}

func (t *gitBasicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.itr.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("getting GitHub App token: %w", err)
	}
	req = req.Clone(req.Context())
	req.SetBasicAuth("x-access-token", tok)
	return t.base.RoundTrip(req)
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
