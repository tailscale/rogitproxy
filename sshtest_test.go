// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer starts an SSH server backed by a local bare git repo.
// It handles "git-upload-pack <path>" exec requests by running git-upload-pack
// locally against repoRoot. It returns the address (host:port) of the server.
func startTestSSHServer(t *testing.T, repoRoot string) string {
	t.Helper()

	// Generate a host key.
	hostKey, err := generateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSSHConn(t, conn, config, repoRoot)
		}
	}()

	return ln.Addr().String()
}

func generateHostKey() (ssh.Signer, error) {
	dir, err := os.MkdirTemp("", "sshtest")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	keyFile := filepath.Join(dir, "key")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyFile, "-N", "", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ssh-keygen: %w: %s", err, out)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(keyPEM)
}

func handleSSHConn(t *testing.T, conn net.Conn, config *ssh.ServerConfig, repoRoot string) {
	defer conn.Close()

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go handleSSHSession(t, ch, reqs, repoRoot)
	}
}

func handleSSHSession(t *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request, repoRoot string) {
	defer ch.Close()

	for req := range reqs {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}

		if len(req.Payload) < 4 {
			req.Reply(false, nil)
			continue
		}
		cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
		if uint32(len(req.Payload)) < 4+cmdLen {
			req.Reply(false, nil)
			continue
		}
		cmdStr := string(req.Payload[4 : 4+cmdLen])

		// Only allow git-upload-pack.
		parts := strings.SplitN(cmdStr, " ", 2)
		if len(parts) != 2 || parts[0] != "git-upload-pack" {
			req.Reply(false, nil)
			ch.Stderr().Write([]byte("only git-upload-pack is supported\n"))
			sendExitStatus(ch, 1)
			return
		}

		// The path may be single-quoted by ssh.
		repoPath := strings.Trim(parts[1], "'")
		fullPath := repoRoot + repoPath

		req.Reply(true, nil)

		cmd := exec.Command("git-upload-pack", fullPath)
		cmd.Stdin = ch
		cmd.Stdout = ch
		cmd.Stderr = ch.Stderr()

		var exitCode int
		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
		sendExitStatus(ch, exitCode)
		return
	}
}

func sendExitStatus(ch ssh.Channel, code int) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(code))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Drain any remaining input so the client doesn't block.
		io.Copy(io.Discard, ch)
	}()
	ch.CloseWrite()
	wg.Wait()
	ch.SendRequest("exit-status", false, buf[:])
}
