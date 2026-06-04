// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

func TestOrgFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/tailscale/corp.git/info/refs", "tailscale"},
		{"/borderzero/border0-cli.git/git-upload-pack", "borderzero"},
		{"/TAILSCALE/Corp.git/info/refs", "tailscale"},
		{"/Org-Name/repo.git/info/refs", "org-name"},
		{"/", ""},
		{"", ""},
		{"/onlyone", ""},
		{"noslash", ""},
	}
	for _, tt := range tests {
		got := orgFromPath(tt.path)
		if got != tt.want {
			t.Errorf("orgFromPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
