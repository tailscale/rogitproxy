// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// rogitproxy is a git protocol proxy that allows read-only access to git
// repositories over the git:// protocol on a tailnet. It proxies to an HTTPS or
// SSH backend (e.g. GitHub) and enforces access control based on tailnet
// grants.
//
// The main use case is allowing sandboxed VMs access to private repositories
// without exposing HTTPS credentials or SSH keys in the sandbox environment.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

func main() {
	var (
		dev      = flag.Bool("dev", false, "listen on localhost instead of tsnet (for testing)")
		backend  = flag.String("backend", "https://github.com", "backend git server URL (https://... or ssh://[user@]host[:port])")
		hostname = flag.String("hostname", "rogitproxy", "tsnet hostname")
		setecURL = flag.String("setec-url", "", "setec server URL for fetching secrets (e.g. https://secrets.your-tailnet.ts.net)")
	)
	flag.Parse()

	proxy := &GitProxy{Backend: *backend}

	var (
		ln  net.Listener
		srv *tsnet.Server
		err error
	)

	if *dev {
		ln, err = net.Listen("tcp", "localhost:0")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "dev mode: listening on %s\n", ln.Addr())
	} else {
		srv = &tsnet.Server{
			Hostname: *hostname,
		}
		defer srv.Close()
		if err := srv.Start(); err != nil {
			log.Fatalf("tsnet.Start: %v", err)
		}
		lc, err := srv.LocalClient()
		if err != nil {
			log.Fatalf("LocalClient: %v", err)
		}
		proxy.LocalClient = lc
		if err := awaitRunning(lc); err != nil {
			log.Fatalf("awaitRunning: %v", err)
		}
		ln, err = srv.Listen("tcp", ":9418")
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("tsnet: listening as %s:9418", *hostname)
	}

	_, keyOnDisk := getGitHubAppPrivateKeyFromDisk()
	useGitHubTokenToBackend := *backend == "https://github.com" && (keyOnDisk || !*dev)

	if useGitHubTokenToBackend {
		var setecDo func(*http.Request) (*http.Response, error)
		if srv != nil {
			setecDo = srv.HTTPClient().Do
		}
		tr, err := GitHubAppTransport(context.Background(), *setecURL, setecDo)
		if err != nil {
			log.Fatalf("github app auth: %v", err)
		}
		proxy.HTTPClient = &http.Client{Transport: tr}
		if srv != nil {
			proxy.RequireGrants = true
		}
		log.Printf("github app auth enabled (app %d, installation %d)", *gitHubAppID, *gitHubInstallationID)
	}

	// Start HTTP debug/status server.
	mux := http.NewServeMux()
	tsweb.Debugger(mux)
	mux.HandleFunc("/", proxy.serveIndex)

	if *dev {
		httpLn, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "dev mode: http on %s\n", httpLn.Addr())
		go http.Serve(httpLn, mux)
	} else {
		httpLn, err := srv.Listen("tcp", ":80")
		if err != nil {
			log.Fatalf("listen :80: %v", err)
		}
		go http.Serve(httpLn, mux)
	}

	log.Fatal(proxy.Serve(ln))
}

func awaitRunning(lc *local.Client) error {
	w, err := lc.WatchIPNBus(context.Background(), 0)
	if err != nil {
		return fmt.Errorf("WatchIPNBus: %w", err)
	}
	defer w.Close()
	for {
		n, err := w.Next()
		if err != nil {
			return fmt.Errorf("IPNBus.Next: %w", err)
		}
		if n.State != nil {
			log.Printf("state: %v", *n.State)
			if *n.State == ipn.Running {
				return nil
			}
		}
	}
}

const grantCap tailcfg.PeerCapability = "github.com/tailscale/rogitproxy"

// AccessType is the type of access granted to a repository.
type AccessType string

// AccessPull is the grant access type for read-only git operations,
// including clone, fetch, ls-remote, and any other operation that
// only reads from the repository (git-upload-pack).
const AccessPull AccessType = "pull"

// grantValue is the JSON structure of each grant value for the
// rogitproxy capability, as defined in the tailnet ACL policy.
type grantValue struct {
	Repos  []string   `json:"repos"`  // e.g. ["tailscale/corp", "tailscale/tailscale"]
	Access AccessType `json:"access"` // e.g. "pull"
}

// Logf is a printf-style logging function.
type Logf func(format string, args ...any)

// GitProxy proxies git:// protocol connections to an HTTPS or SSH backend.
// It only permits read-only operations (git-upload-pack).
type GitProxy struct {
	Backend              string        // backend URL: "https://github.com" or "ssh://git@github.com"
	HTTPClient           *http.Client  // optional; defaults to http.DefaultClient
	LocalClient          *local.Client // optional; if set, used for WhoIs lookups to log caller identity
	RequireGrants        bool          // if true, enforce tailnet grants for repo access
	Logf                 Logf          // optional; defaults to log.Printf
	ExtraSSHArgs         []string      // optional; extra args passed to ssh before the host (e.g. for tests)
	CompressGzipMinBytes int           // min POST body size to gzip; 0 means always, -1 means never, default 1024
}

func (p *GitProxy) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (p *GitProxy) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

// httpGet performs an HTTP GET with an explicit Accept header set so the
// ghinstallation transport doesn't inject "application/vnd.github.v3+json"
// which confuses GitHub's git smart HTTP endpoints.
func (p *GitProxy) httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Git-Protocol", "version=2")
	return p.httpClient().Do(req)
}

// httpPost performs an HTTP POST with the given content type and body,
// setting an explicit Accept header for the same reason as httpGet.
// The request body is gzip-compressed when larger than 1 KiB (matching
// git's own threshold), since the negotiation payloads (want/have lines)
// are repetitive ASCII hex that compresses very well.
func (p *GitProxy) httpPost(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	// Buffer the body so we can measure its size and compress it.
	// Cap at 32 MiB to bound memory usage — a v2 fetch command with
	// 32768 have lines (the largest negotiation round git sends) is
	// ~1.6 MiB, so 32 MiB is very generous.
	const maxPostBody = 32 << 20
	var raw bytes.Buffer
	if _, err := io.Copy(&raw, io.LimitReader(body, maxPostBody+1)); err != nil {
		return nil, err
	}
	if raw.Len() > maxPostBody {
		return nil, fmt.Errorf("POST body too large (%d bytes, max %d)", raw.Len(), maxPostBody)
	}

	gzipMin := p.CompressGzipMinBytes
	if gzipMin == 0 {
		gzipMin = 1024 // default: match git's own threshold
	}

	var reqBody io.Reader = &raw
	var contentEncoding string
	if gzipMin >= 0 && raw.Len() > gzipMin {
		var compressed bytes.Buffer
		gz, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
		if _, err := gz.Write(raw.Bytes()); err != nil {
			return nil, err
		}
		if err := gz.Close(); err != nil {
			return nil, err
		}
		reqBody = &compressed
		contentEncoding = "gzip"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Git-Protocol", "version=2")
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	return p.httpClient().Do(req)
}

func (p *GitProxy) isSSH() bool {
	return strings.HasPrefix(p.Backend, "ssh://")
}

func (p *GitProxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handleConn(conn)
	}
}

func (p *GitProxy) handleConn(conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	br := bufio.NewReader(conn)

	// Read the initial request pkt-line.
	// Format: "git-upload-pack /repo\0host=hostname\0"
	line, pktType, err := readPktLine(br)
	if err != nil {
		p.logf("gitproxy: reading request: %v", err)
		return
	}
	if pktType != pktData || line == nil {
		return
	}

	// Split on NUL: [command+path, host=..., extras...]
	parts := bytes.SplitN(line, []byte{0}, 3)
	cmdPath := string(parts[0])
	spaceIdx := strings.IndexByte(cmdPath, ' ')
	if spaceIdx < 0 {
		sendError(conn, "invalid request")
		return
	}
	cmd := cmdPath[:spaceIdx]
	repoPath := cmdPath[spaceIdx+1:]

	if cmd != "git-upload-pack" {
		counterNumDenied.Add(1)
		sendError(conn, "permission denied: only read-only (fetch/clone) operations are allowed")
		return
	}

	counterNumRequests.Add(1)

	who := p.whoIs(conn)
	whoStr := formatWhoIs(conn, who)

	if p.RequireGrants {
		if who == nil {
			counterNumDenied.Add(1)
			sendError(conn, "access denied: unable to identify peer")
			p.logf("gitproxy: denied %s to %s: no WhoIs", repoPath, whoStr)
			return
		}
		// Normalize "/tailscale/corp.git" to "tailscale/corp".
		repo := strings.TrimPrefix(repoPath, "/")
		repo = strings.TrimSuffix(repo, ".git")
		if !checkGrant(who, repo, AccessPull) {
			counterNumDenied.Add(1)
			sendError(conn, fmt.Sprintf("access denied: no grant for %s", repoPath))
			p.logf("gitproxy: denied %s to %s: no grant", repoPath, whoStr)
			return
		}
	}

	if p.isSSH() {
		p.logf("gitproxy: connect %s by %s", repoPath, whoStr)
		p.handleSSH(ctx, conn, br, repoPath)
		return
	}

	// Check for git protocol v2. The git:// v2 initial request has extra
	// params after the second NUL: "git-upload-pack /repo\0host=X\0\0version=2\0"
	isV2 := len(parts) >= 3 && strings.Contains(string(parts[2]), "version=2")
	if !isV2 {
		sendError(conn, "this proxy requires git protocol v2; upgrade to git 2.26+")
		return
	}

	p.logf("gitproxy: request %s by %s (v2)", repoPath, whoStr)
	p.handleHTTPSv2(ctx, conn, br, repoPath, whoStr)
}

// whoIs returns the WhoIs response for the remote peer, or nil if
// LocalClient is not configured or the lookup fails.
func (p *GitProxy) whoIs(conn net.Conn) *apitype.WhoIsResponse {
	if p.LocalClient == nil {
		return nil
	}
	who, err := p.LocalClient.WhoIs(context.Background(), conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return who
}

// formatWhoIs returns a human-readable string for the peer.
func formatWhoIs(conn net.Conn, who *apitype.WhoIsResponse) string {
	addr := conn.RemoteAddr().String()
	if who == nil {
		return addr
	}
	user := who.UserProfile.LoginName
	node := strings.TrimSuffix(who.Node.Name, ".")
	if user != "" && node != "" {
		return user + " (" + node + ")"
	}
	if user != "" {
		return user
	}
	if node != "" {
		return node
	}
	return addr
}

// checkGrant checks whether the peer identified by who has a grant
// allowing the given access type (e.g. AccessPull) to the given repo.
// The repo is of the form "org/repo" (e.g. "tailscale/corp").
// Only grants matching the requested access type are considered.
func checkGrant(who *apitype.WhoIsResponse, repo string, access AccessType) bool {
	for _, raw := range who.CapMap[grantCap] {
		var g grantValue
		if err := json.Unmarshal([]byte(raw), &g); err != nil {
			continue
		}
		if g.Access != access {
			continue
		}
		for _, allowed := range g.Repos {
			if strings.EqualFold(allowed, repo) {
				return true
			}
		}
	}
	return false
}

// handleSSH proxies via SSH. Since SSH runs git-upload-pack on the remote,
// the wire protocol is identical to git:// — we just pipe the bidirectional
// stream. No capability stripping or shallow workarounds needed.
func (p *GitProxy) handleSSH(ctx context.Context, conn net.Conn, br *bufio.Reader, repoPath string) {
	u, err := url.Parse(p.Backend)
	if err != nil {
		sendError(conn, fmt.Sprintf("invalid backend URL: %v", err))
		return
	}

	remotePath := strings.TrimRight(u.Path, "/") + repoPath

	var args []string
	args = append(args, p.ExtraSSHArgs...)
	if port := u.Port(); port != "" {
		args = append(args, "-p", port)
	}
	userHost := u.Hostname()
	if user := u.User.Username(); user != "" {
		userHost = user + "@" + userHost
	}
	args = append(args, userHost, "git-upload-pack", remotePath)

	sshCmd := exec.CommandContext(ctx, "ssh", args...)
	sshCmd.Stdin = br
	sshCmd.Stdout = conn
	var stderr bytes.Buffer
	sshCmd.Stderr = &stderr

	if err := sshCmd.Run(); err != nil {
		if stderr.Len() > 0 {
			p.logf("gitproxy: ssh git-upload-pack: %v: %s", err, stderr.Bytes())
		}
		// Don't log exit status 128 — that's normal when the client
		// disconnects after ls-remote (broken pipe on the remote).
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 128 {
			return
		}
		if stderr.Len() == 0 {
			p.logf("gitproxy: ssh git-upload-pack: %v", err)
		}
	}
}

// handleHTTPSv2 proxies git protocol v2 over HTTPS. Each client command
// maps 1:1 to one backend HTTP request, making the proxy a transparent pipe.
func (p *GitProxy) handleHTTPSv2(ctx context.Context, conn net.Conn, br *bufio.Reader, repoPath, whoStr string) {
	backendBase := strings.TrimRight(p.Backend, "/")

	// Phase A: Capability advertisement.
	refsURL := backendBase + repoPath + "/info/refs?service=git-upload-pack"
	resp, err := p.httpGet(ctx, refsURL)
	if err != nil {
		sendError(conn, fmt.Sprintf("backend error: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		p.logf("gitproxy: backend %s returned %d: %s", refsURL, resp.StatusCode, body)
		sendError(conn, fmt.Sprintf("repository not found or unavailable (HTTP %d)", resp.StatusCode))
		return
	}

	refsBuf := bufio.NewReader(resp.Body)

	// The v2 info/refs response may or may not start with
	// "# service=git-upload-pack\n" + flush (GitHub includes it,
	// git-http-backend does not). Read the first pkt-line and check.
	firstLine, pt, err := readPktLine(refsBuf)
	if err != nil || pt != pktData {
		sendError(conn, "backend error reading refs")
		return
	}
	if bytes.HasPrefix(firstLine, []byte("# service=")) {
		// Skip the flush after the service header.
		if _, pt, err := readPktLine(refsBuf); err != nil || pt != pktFlush {
			sendError(conn, "expected flush after service header")
			return
		}
		// Read the actual version line.
		firstLine, pt, err = readPktLine(refsBuf)
		if err != nil || pt != pktData {
			sendError(conn, "backend did not return protocol v2")
			return
		}
	}

	// firstLine should now be "version 2\n".
	if !bytes.HasPrefix(firstLine, []byte("version 2")) {
		sendError(conn, fmt.Sprintf("backend returned unexpected version: %s", firstLine))
		return
	}
	versionLine := firstLine

	// Send version line to client.
	if err := writePktLine(conn, versionLine); err != nil {
		return
	}

	// Read and forward capability lines, filtering out wait-for-done.
	for {
		capLine, pt, err := readPktLine(refsBuf)
		if err != nil {
			p.logf("gitproxy: reading backend caps: %v", err)
			return
		}
		if pt == pktFlush {
			if err := writeFlush(conn); err != nil {
				return
			}
			break
		}
		if pt != pktData {
			continue
		}
		// Strip wait-for-done capability — it forces single-round fetch
		// which requires the server to wait, but we want the standard flow.
		if bytes.HasPrefix(capLine, []byte("wait-for-done")) {
			continue
		}
		if err := writePktLine(conn, capLine); err != nil {
			return
		}
	}

	// Phase B: Command loop.
	for {
		cmdName, rawBody, err := readV2Command(br)
		if err != nil {
			// EOF is normal — client disconnected (e.g. after ls-remote).
			if cmdName == "" {
				p.logf("gitproxy: ls-remote %s by %s", repoPath, whoStr)
			}
			return
		}

		// Count wants/haves for fetch commands.
		var numWants, numHaves int
		if cmdName == "fetch" {
			for _, line := range bytes.Split(rawBody.Bytes(), []byte("\n")) {
				s := string(line)
				if strings.HasPrefix(s, "want ") || strings.Contains(s, "want ") {
					numWants++
				}
				if strings.HasPrefix(s, "have ") || strings.Contains(s, "have ") {
					numHaves++
				}
			}
		}

		uploadURL := backendBase + repoPath + "/git-upload-pack"
		postResp, err := p.httpPost(ctx, uploadURL, "application/x-git-upload-pack-request", &rawBody)
		if err != nil {
			p.logf("gitproxy: backend POST: %v", err)
			return
		}
		if postResp.StatusCode != 200 {
			body, _ := io.ReadAll(io.LimitReader(postResp.Body, 512))
			postResp.Body.Close()
			p.logf("gitproxy: backend POST %s returned %d: %s", uploadURL, postResp.StatusCode, body)
			sendError(conn, fmt.Sprintf("backend upload-pack error (HTTP %d)", postResp.StatusCode))
			return
		}

		respBuf := bufio.NewReader(postResp.Body)
		info, err := forwardV2Response(conn, respBuf)
		if err != nil {
			p.logf("gitproxy: forwarding v2 response: %v", err)
			postResp.Body.Close()
			return
		}
		postResp.Body.Close()

		// Log fetch results after we know whether it was a negotiation
		// round (NAK, no packfile) or the final round (with packfile).
		if cmdName == "fetch" {
			if info.hadPackfile {
				if numHaves == 0 {
					p.logf("gitproxy: clone %s (%d wants, %s) by %s", repoPath, numWants, formatBytes(info.bytes), whoStr)
				} else {
					p.logf("gitproxy: fetch %s (%d wants, %d haves, %s) by %s", repoPath, numWants, numHaves, formatBytes(info.bytes), whoStr)
				}
			} else {
				p.logf("gitproxy: fetch %s negotiating (%d haves) by %s", repoPath, numHaves, whoStr)
			}
		}
	}
}

// readV2Command reads a complete git protocol v2 command from the client.
// It returns the command name, the raw pkt-line encoded body (suitable for
// POSTing to the backend), and any error. EOF means the client disconnected.
func readV2Command(br *bufio.Reader) (cmdName string, rawBody bytes.Buffer, err error) {
	// Read the first pkt-line — should be "command=<name>\n".
	line, pt, err := readPktLine(br)
	if err != nil {
		return "", rawBody, err
	}
	if pt != pktData {
		return "", rawBody, fmt.Errorf("expected command pkt-line, got type %d", pt)
	}

	s := strings.TrimRight(string(line), "\n")
	if !strings.HasPrefix(s, "command=") {
		return "", rawBody, fmt.Errorf("expected command=, got %q", s)
	}
	cmdName = strings.TrimPrefix(s, "command=")

	// Write the first line into the raw body.
	rawBody.Write(encodePktLine(line))

	// Accumulate remaining pkt-lines until flush.
	for {
		line, pt, err := readPktLine(br)
		if err != nil {
			return cmdName, rawBody, err
		}
		switch pt {
		case pktFlush:
			rawBody.WriteString("0000")
			return cmdName, rawBody, nil
		case pktDelimiter:
			rawBody.WriteString("0001")
		case pktResponseEnd:
			rawBody.WriteString("0002")
		case pktData:
			rawBody.Write(encodePktLine(line))
		}
	}
}

// v2ResponseInfo contains information about a forwarded v2 response,
// populated by forwardV2Response.
type v2ResponseInfo struct {
	hadPackfile bool  // whether a "packfile" section was seen
	bytes       int64 // total bytes forwarded (headers + payloads)
}

// forwardV2Response streams a git protocol v2 response from the HTTP backend
// to the git:// client. It reads pkt-line headers, forwards data and special
// packets, and stops at response-end (0002) which is HTTP-only.
func forwardV2Response(dst io.Writer, src *bufio.Reader) (v2ResponseInfo, error) {
	var info v2ResponseInfo
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(src, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return info, nil // clean end of response
			}
			return info, err
		}
		info.bytes += 4

		switch string(hdr[:]) {
		case "0000": // flush
			if _, err := dst.Write(hdr[:]); err != nil {
				return info, err
			}
		case "0001": // delimiter
			if _, err := dst.Write(hdr[:]); err != nil {
				return info, err
			}
		case "0002": // response-end — don't forward, stop
			return info, nil
		default:
			// Data packet: forward header + payload.
			if _, err := dst.Write(hdr[:]); err != nil {
				return info, err
			}
			var lenBytes [2]byte
			if _, err := hex.Decode(lenBytes[:], hdr[:]); err != nil {
				return info, fmt.Errorf("invalid pkt-line header %q: %w", hdr, err)
			}
			length := int(lenBytes[0])<<8 | int(lenBytes[1])
			if length < 4 {
				return info, fmt.Errorf("invalid pkt-line length: %d", length)
			}
			payloadLen := int64(length - 4)

			// Peek at first byte to detect "packfile" section marker.
			if !info.hadPackfile && payloadLen >= 8 {
				if peek, err := src.Peek(8); err == nil && string(peek) == "packfile" {
					info.hadPackfile = true
				}
			}

			info.bytes += payloadLen
			if _, err := io.CopyN(dst, src, payloadLen); err != nil {
				return info, err
			}
		}
	}
}

// formatBytes returns a human-readable byte count (e.g. "1.2 MiB").
func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func sendError(w io.Writer, msg string) {
	writePktLine(w, []byte("ERR "+msg+"\n"))
}

// serveIndex serves the HTTP index page showing what rogitproxy is,
// the caller's granted repos, and git remote add examples.
func (p *GitProxy) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Determine our own hostname for the git remote examples.
	nodeName := "rogitproxy"
	if p.LocalClient != nil {
		if st, err := p.LocalClient.StatusWithoutPeers(r.Context()); err == nil && st.Self != nil {
			nodeName = strings.TrimSuffix(st.Self.DNSName, ".")
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "rogitproxy — read-only git proxy\n")
	fmt.Fprintf(w, "=================================\n\n")
	fmt.Fprintf(w, "This is a read-only git protocol proxy. It allows cloning and fetching\n")
	fmt.Fprintf(w, "repositories over the git:// protocol on your tailnet.\n\n")

	if p.LocalClient == nil {
		fmt.Fprintf(w, "Running in dev mode (no tailnet identity available).\n")
		return
	}

	who, err := p.LocalClient.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		fmt.Fprintf(w, "Could not identify you: %v\n", err)
		return
	}

	fmt.Fprintf(w, "Hello, %s\n\n", who.UserProfile.LoginName)

	// Collect all repos the user has pull access to.
	var repos []string
	for _, raw := range who.CapMap[grantCap] {
		var g grantValue
		if err := json.Unmarshal([]byte(raw), &g); err != nil {
			continue
		}
		if g.Access != AccessPull {
			continue
		}
		repos = append(repos, g.Repos...)
	}

	if len(repos) == 0 {
		fmt.Fprintf(w, "You do not currently have access to any repositories through this proxy.\n")
		fmt.Fprintf(w, "Ask your tailnet admin to grant you the %s capability.\n", grantCap)
		return
	}

	fmt.Fprintf(w, "You have read-only access to the following repositories:\n\n")
	for _, repo := range repos {
		fmt.Fprintf(w, "  %s\n", repo)
	}
	fmt.Fprintf(w, "\nTo add a read-only remote, run:\n\n")
	for _, repo := range repos {
		fmt.Fprintf(w, "  git remote add ro git://%s/%s.git\n", nodeName, repo)
	}
	fmt.Fprintf(w, "\nThen clone or fetch:\n\n")
	if len(repos) > 0 {
		fmt.Fprintf(w, "  git clone git://%s/%s.git\n", nodeName, repos[0])
	}
}

// --- pkt-line encoding/decoding ---

// pktLineType represents the type of a pkt-line packet.
type pktLineType int

const (
	pktData        pktLineType = iota // normal data packet
	pktFlush                          // 0000 — flush packet
	pktDelimiter                      // 0001 — delimiter packet (v2)
	pktResponseEnd                    // 0002 — response-end packet (v2)
)

// readPktLine reads a single git pkt-line from r.
// Returns the payload (nil for special packets) and the packet type.
func readPktLine(r io.Reader) ([]byte, pktLineType, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	var lenBytes [2]byte
	if _, err := hex.Decode(lenBytes[:], hdr[:]); err != nil {
		return nil, 0, fmt.Errorf("invalid pkt-line header %q: %w", hdr, err)
	}
	length := int(lenBytes[0])<<8 | int(lenBytes[1])
	switch length {
	case 0:
		return nil, pktFlush, nil
	case 1:
		return nil, pktDelimiter, nil
	case 2:
		return nil, pktResponseEnd, nil
	}
	if length < 4 {
		return nil, 0, fmt.Errorf("invalid pkt-line length: %d", length)
	}
	data := make([]byte, length-4)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, 0, err
	}
	return data, pktData, nil
}

func writePktLine(w io.Writer, data []byte) error {
	_, err := fmt.Fprintf(w, "%04x%s", len(data)+4, data)
	return err
}

func writeFlush(w io.Writer) error {
	_, err := io.WriteString(w, "0000")
	return err
}

func encodePktLine(data []byte) []byte {
	return fmt.Appendf(nil, "%04x%s", len(data)+4, data)
}
