// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// startGitHTTPBackend creates a bare git repo with a few commits and
// serves it over HTTP using git-http-backend. It returns the HTTP
// server's base URL (e.g. "http://127.0.0.1:12345"). The repo is
// accessible at <baseURL>/test/repo.git.
func startGitHTTPBackend(t *testing.T) string {
	t.Helper()

	repoRoot := t.TempDir()
	bareDir := filepath.Join(repoRoot, "test", "repo.git")

	// Create a bare repo.
	run(t, "git", "init", "--bare", bareDir)

	// Populate it by cloning, committing, and pushing from a work tree.
	workDir := t.TempDir()
	run(t, "git", "clone", bareDir, workDir)
	run(t, "git", "-C", workDir, "config", "user.email", "test@test")
	run(t, "git", "-C", workDir, "config", "user.name", "Test")
	writeFile(t, filepath.Join(workDir, "hello.txt"), "hello\n")
	run(t, "git", "-C", workDir, "add", "hello.txt")
	run(t, "git", "-C", workDir, "commit", "-m", "first commit")
	writeFile(t, filepath.Join(workDir, "world.txt"), "world\n")
	run(t, "git", "-C", workDir, "add", "world.txt")
	run(t, "git", "-C", workDir, "commit", "-m", "second commit")
	run(t, "git", "-C", workDir, "push", "origin", "HEAD")

	// Enable smart HTTP serving.
	run(t, "git", "-C", bareDir, "config", "http.receivepack", "false")
	run(t, "git", "-C", bareDir, "update-server-info")

	// Find git-http-backend.
	gitExecPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	httpBackend := filepath.Join(strings.TrimSpace(string(gitExecPath)), "git-http-backend")
	if _, err := os.Stat(httpBackend); err != nil {
		t.Skipf("git-http-backend not found at %s", httpBackend)
	}

	// Wrap cgi.Handler so that the Git-Protocol HTTP header is passed
	// through as GIT_PROTOCOL env var. Go's cgi package sets HTTP_GIT_PROTOCOL
	// but git-http-backend reads GIT_PROTOCOL. We create a fresh handler per
	// request to avoid shared-slice races on Env.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := &cgi.Handler{
			Path: httpBackend,
			Env: []string{
				"GIT_PROJECT_ROOT=" + repoRoot,
				"GIT_HTTP_EXPORT_ALL=1",
			},
		}
		if proto := r.Header.Get("Git-Protocol"); proto != "" {
			h.Env = append(h.Env, "GIT_PROTOCOL="+proto)
		}
		h.ServeHTTP(w, r)
	})

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return "http://" + ln.Addr().String()
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// startLocalTestProxy starts the git proxy backed by a local
// git-http-backend server. No network access to github.com.
func startLocalTestProxy(t *testing.T) string {
	t.Helper()
	backend := startGitHTTPBackend(t)
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &GitProxy{Backend: backend, Logf: t.Logf}
	go proxy.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestLsRemote(t *testing.T) {
	addr := startLocalTestProxy(t)
	cmd := exec.Command("git", "ls-remote", fmt.Sprintf("git://%s/test/repo.git", addr))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git ls-remote failed: %v\n%s", err, out)
	}
	output := string(out)
	if !strings.Contains(output, "refs/heads/") {
		t.Errorf("expected refs/heads/ in output, got:\n%s", output)
	}
	t.Logf("ls-remote output:\n%s", output)
}

func TestClone(t *testing.T) {
	addr := startLocalTestProxy(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "repo")

	cmd := exec.Command("git", "clone", fmt.Sprintf("git://%s/test/repo.git", addr), dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone failed: %v\n%s", err, out)
	}

	// Verify the clone has files.
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("cloned repo is empty")
	}

	// Verify both commits are present.
	cmd = exec.Command("git", "-C", dest, "log", "--oneline")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log failed: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 commits, got %d:\n%s", len(lines), out)
	}
	t.Logf("clone log:\n%s", out)
}

func TestCloneShallow(t *testing.T) {
	addr := startLocalTestProxy(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "repo")

	cmd := exec.Command("git", "clone", "--depth=1",
		fmt.Sprintf("git://%s/test/repo.git", addr), dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone --depth=1 failed: %v\n%s", err, out)
	}

	cmd = exec.Command("git", "-C", dest, "log", "--oneline")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log failed: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 commit for shallow clone, got %d:\n%s", len(lines), out)
	}
	t.Logf("shallow clone log:\n%s", out)
}

func TestRejectNonUploadPack(t *testing.T) {
	addr := startLocalTestProxy(t)

	// Every command that isn't exactly "git-upload-pack" must be rejected.
	rejectCmds := []struct {
		name string
		cmd  string
	}{
		{"receive-pack", "git-receive-pack"},
		{"arbitrary command", "echo"},
		{"shell injection attempt", "git-upload-pack;rm -rf /"},
		{"upload-pack prefix", "git-upload-pack-extended"},
		{"uppercase", "GIT-UPLOAD-PACK"},
		{"extra leading space", " git-upload-pack"},
		{"empty command", ""},
	}
	for _, tc := range rejectCmds {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			req := tc.cmd + " /test/repo.git\x00host=test\x00"
			pkt := fmt.Sprintf("%04x%s", len(req)+4, req)
			if _, err := conn.Write([]byte(pkt)); err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			resp := string(buf[:n])
			if !strings.Contains(resp, "ERR") {
				t.Errorf("expected ERR response for %q, got: %q", tc.cmd, resp)
			}
			if !strings.Contains(resp, "read-only") && !strings.Contains(resp, "invalid") {
				t.Errorf("expected rejection message for %q, got: %q", tc.cmd, resp)
			}
		})
	}
}

func TestRejectPushViaGit(t *testing.T) {
	addr := startLocalTestProxy(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "repo")

	// Set up a local repo with a commit to push.
	for _, args := range [][]string{
		{"init", dest},
		{"-C", dest, "commit", "--allow-empty", "-m", "test"},
		{"-C", dest, "remote", "add", "origin",
			fmt.Sprintf("git://%s/test/repo.git", addr)},
	} {
		cmd := exec.Command("git", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	// Attempt to push — must fail.
	cmd := exec.Command("git", "-C", dest, "push", "origin", "HEAD:refs/heads/test-push")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("git push should have failed, but succeeded")
	}
	output := string(out)
	if !strings.Contains(output, "read-only") {
		t.Logf("push output:\n%s", output)
	}
}

func TestFetch(t *testing.T) {
	addr := startLocalTestProxy(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "repo")

	// First clone.
	cmd := exec.Command("git", "clone",
		fmt.Sprintf("git://%s/test/repo.git", addr), dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone failed: %v\n%s", err, out)
	}

	// Then fetch (incremental, exercises have negotiation).
	cmd = exec.Command("git", "-C", dest, "fetch")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git fetch failed: %v\n%s", err, out)
	}
	t.Logf("fetch output:\n%s", out)
}

// startLocalSSHTestProxy starts a local SSH server backed by a local
// bare git repo (the same one used by startGitHTTPBackend), and a
// git proxy pointed at it. No network access needed.
func startLocalSSHTestProxy(t *testing.T) string {
	t.Helper()

	repoRoot := t.TempDir()
	bareDir := filepath.Join(repoRoot, "test", "repo.git")

	run(t, "git", "init", "--bare", bareDir)

	workDir := t.TempDir()
	run(t, "git", "clone", bareDir, workDir)
	run(t, "git", "-C", workDir, "config", "user.email", "test@test")
	run(t, "git", "-C", workDir, "config", "user.name", "Test")
	writeFile(t, filepath.Join(workDir, "hello.txt"), "hello\n")
	run(t, "git", "-C", workDir, "add", "hello.txt")
	run(t, "git", "-C", workDir, "commit", "-m", "first commit")
	writeFile(t, filepath.Join(workDir, "world.txt"), "world\n")
	run(t, "git", "-C", workDir, "add", "world.txt")
	run(t, "git", "-C", workDir, "commit", "-m", "second commit")
	run(t, "git", "-C", workDir, "push", "origin", "HEAD")

	sshAddr := startTestSSHServer(t, repoRoot)
	host, port, _ := net.SplitHostPort(sshAddr)

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &GitProxy{
		Backend: fmt.Sprintf("ssh://%s:%s", host, port),
		Logf:    t.Logf,
		ExtraSSHArgs: []string{
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
		},
	}
	go proxy.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestSSHLsRemote(t *testing.T) {
	addr := startLocalSSHTestProxy(t)
	cmd := exec.Command("git", "ls-remote", fmt.Sprintf("git://%s/test/repo.git", addr))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git ls-remote (ssh) failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "refs/heads/") {
		t.Errorf("expected refs/heads/ in output, got:\n%s", out)
	}
	t.Logf("ssh ls-remote output:\n%s", out)
}

func TestSSHClone(t *testing.T) {
	addr := startLocalSSHTestProxy(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "repo")

	cmd := exec.Command("git", "clone", fmt.Sprintf("git://%s/test/repo.git", addr), dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone (ssh) failed: %v\n%s", err, out)
	}

	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("cloned repo is empty")
	}

	cmd = exec.Command("git", "-C", dest, "log", "--oneline")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log failed: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 commits, got %d:\n%s", len(lines), out)
	}
	t.Logf("ssh clone log:\n%s", out)
}

func TestSSHCloneShallow(t *testing.T) {
	addr := startLocalSSHTestProxy(t)
	dir := t.TempDir()
	dest := filepath.Join(dir, "repo")

	cmd := exec.Command("git", "clone", "--depth=1",
		fmt.Sprintf("git://%s/test/repo.git", addr), dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone --depth=1 (ssh) failed: %v\n%s", err, out)
	}

	cmd = exec.Command("git", "-C", dest, "log", "--oneline")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log failed: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 commit for shallow clone, got %d:\n%s", len(lines), out)
	}
	t.Logf("ssh shallow clone log:\n%s", out)
}

func TestSSHRejectPush(t *testing.T) {
	addr := startLocalSSHTestProxy(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "git-receive-pack /test/repo.git\x00host=test\x00"
	pkt := fmt.Sprintf("%04x%s", len(req)+4, req)
	if _, err := conn.Write([]byte(pkt)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "ERR") || !strings.Contains(resp, "read-only") {
		t.Errorf("expected read-only ERR, got: %q", resp)
	}
	t.Logf("ssh push rejection: %s", resp)
}

func TestCheckGrant(t *testing.T) {
	makeWho := func(grants ...grantValue) *apitype.WhoIsResponse {
		var raw []tailcfg.RawMessage
		for _, g := range grants {
			b, _ := json.Marshal(g)
			raw = append(raw, tailcfg.RawMessage(b))
		}
		return &apitype.WhoIsResponse{
			Node:        &tailcfg.Node{},
			UserProfile: &tailcfg.UserProfile{},
			CapMap:      tailcfg.PeerCapMap{grantCap: raw},
		}
	}

	tests := []struct {
		name   string
		who    *apitype.WhoIsResponse
		repo   string
		access AccessType
		want   bool
	}{
		{
			name:   "allowed repo",
			who:    makeWho(grantValue{Repos: []string{"tailscale/corp", "tailscale/tailscale"}, Access: AccessPull}),
			repo:   "tailscale/corp",
			access: AccessPull,
			want:   true,
		},
		{
			name:   "denied repo",
			who:    makeWho(grantValue{Repos: []string{"tailscale/corp"}, Access: AccessPull}),
			repo:   "tailscale/secret",
			access: AccessPull,
			want:   false,
		},
		{
			name:   "no grants",
			who:    &apitype.WhoIsResponse{Node: &tailcfg.Node{}, UserProfile: &tailcfg.UserProfile{}},
			repo:   "tailscale/corp",
			access: AccessPull,
			want:   false,
		},
		{
			name: "multiple grant values",
			who: makeWho(
				grantValue{Repos: []string{"tailscale/corp"}, Access: AccessPull},
				grantValue{Repos: []string{"tailscale/tailscale"}, Access: AccessPull},
			),
			repo:   "tailscale/tailscale",
			access: AccessPull,
			want:   true,
		},
		{
			name:   "case insensitive",
			who:    makeWho(grantValue{Repos: []string{"Tailscale/Corp"}, Access: AccessPull}),
			repo:   "tailscale/corp",
			access: AccessPull,
			want:   true,
		},
		{
			name:   "wrong access type ignored",
			who:    makeWho(grantValue{Repos: []string{"tailscale/corp"}, Access: "push"}),
			repo:   "tailscale/corp",
			access: AccessPull,
			want:   false,
		},
		{
			name:   "empty access ignored",
			who:    makeWho(grantValue{Repos: []string{"tailscale/corp"}, Access: ""}),
			repo:   "tailscale/corp",
			access: AccessPull,
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkGrant(tt.who, tt.repo, tt.access)
			if got != tt.want {
				t.Errorf("checkGrant(%q, %q) = %v, want %v", tt.repo, tt.access, got, tt.want)
			}
		})
	}
}

var integration = flag.Bool("integration", false, "run integration tests against real GitHub")

func TestIntegrationGitHub(t *testing.T) {
	if !*integration {
		t.Skip("skipping integration test; use -integration to enable")
	}

	// Start a local proxy backed by public GitHub (no auth needed).
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &GitProxy{Backend: "https://github.com", Logf: t.Logf}
	go proxy.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()

	t.Run("ls-remote", func(t *testing.T) {
		cmd := exec.Command("git", "ls-remote", fmt.Sprintf("git://%s/tailscale/tailscale.git", addr))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git ls-remote failed: %v\n%s", err, out)
		}
		output := string(out)
		if !strings.Contains(output, "HEAD") {
			t.Errorf("expected HEAD in ls-remote output, got:\n%s", output[:min(len(output), 500)])
		}
		if !strings.Contains(output, "refs/heads/") {
			t.Errorf("expected refs/heads/ in ls-remote output")
		}
		if !strings.Contains(output, "refs/tags/") {
			t.Errorf("expected refs/tags/ in ls-remote output")
		}
		t.Logf("ls-remote returned %d bytes", len(out))
	})

	t.Run("clone", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "repo")

		cmd := exec.Command("git", "clone", "--depth=1",
			fmt.Sprintf("git://%s/tailscale/rogitproxy.git", addr), dest)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git clone failed: %v\n%s", err, out)
		}

		entries, err := os.ReadDir(dest)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Fatal("cloned repo is empty")
		}

		cmd = exec.Command("git", "-C", dest, "log", "--oneline")
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git log failed: %v\n%s", err, out)
		}
		t.Logf("clone log:\n%s", out)
	})

	t.Run("fetch-noop", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "repo")

		// Clone first.
		cmd := exec.Command("git", "clone", "--depth=1",
			fmt.Sprintf("git://%s/tailscale/rogitproxy.git", addr), dest)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git clone failed: %v\n%s", err, out)
		}

		// Fetch from same repo — should be a no-op (already up to date).
		cmd = exec.Command("git", "-C", dest, "fetch",
			fmt.Sprintf("git://%s/tailscale/rogitproxy.git", addr), "HEAD")
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git fetch failed: %v\n%s", err, out)
		}
		t.Logf("fetch-noop output:\n%s", out)
	})

	t.Run("clone-gzip", func(t *testing.T) {
		// Use a separate proxy that always gzip-compresses POST bodies,
		// even small ones, to verify GitHub accepts Content-Encoding: gzip.
		gzLn, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		gzProxy := &GitProxy{
			Backend:              "https://github.com",
			Logf:                 t.Logf,
			CompressGzipMinBytes: 1, // always gzip
		}
		go gzProxy.Serve(gzLn)
		t.Cleanup(func() { gzLn.Close() })
		gzAddr := gzLn.Addr().String()

		dir := t.TempDir()
		dest := filepath.Join(dir, "repo")

		cmd := exec.Command("git", "clone", "--depth=1",
			fmt.Sprintf("git://%s/tailscale/rogitproxy.git", gzAddr), dest)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git clone (gzip) failed: %v\n%s", err, out)
		}

		cmd = exec.Command("git", "-C", dest, "log", "--oneline")
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git log failed: %v\n%s", err, out)
		}
		t.Logf("clone-gzip log:\n%s", out)
	})

	t.Run("fetch-cross-repo", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "repo")

		// Clone rogitproxy (small repo).
		cmd := exec.Command("git", "clone", "--depth=1",
			fmt.Sprintf("git://%s/tailscale/rogitproxy.git", addr), dest)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git clone failed: %v\n%s", err, out)
		}

		// Fetch from a different repo — exercises have/want negotiation
		// with no common commits.
		cmd = exec.Command("git", "-C", dest, "fetch",
			fmt.Sprintf("git://%s/octocat/Hello-World.git", addr), "master")
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git fetch cross-repo failed: %v\n%s", err, out)
		}
		t.Logf("fetch-cross-repo output:\n%s", out)
	})
}
