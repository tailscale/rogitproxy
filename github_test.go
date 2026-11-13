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

func TestScopedKey(t *testing.T) {
	a := scopedKey(42, normalizeRepoNames([]string{"Corp", "tailscale", "corp"}))
	b := scopedKey(42, normalizeRepoNames([]string{"tailscale", "corp"}))
	if a != b || a != "42:corp,tailscale" {
		t.Errorf("keys = %q, %q; want both %q", a, b, "42:corp,tailscale")
	}
	if got := scopedKey(42, normalizeRepoNames(nil)); got != "42:" {
		t.Errorf("unscoped key = %q; want %q", got, "42:")
	}
}
