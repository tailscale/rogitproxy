# rogitproxy

rogitproxy is a read-only git protocol proxy for a tailnet. It listens on
port 9418 (the git:// protocol port) via tsnet and proxies to an HTTPS or SSH
backend (e.g. GitHub). It enforces access control using tailnet grants.

The main use case is allowing sandboxed VMs access to private repositories
without exposing HTTPS credentials or SSH keys in the sandbox environment.

## Usage

    $ rogitproxy

In dev mode (no tsnet, listens on localhost):

    $ rogitproxy --dev

Then:

    git clone git://rogitproxy.your-tailnet.ts.net/org/repo.git
    git ls-remote git://rogitproxy.your-tailnet.ts.net/org/repo.git

## GitHub App authentication

When the backend is `https://github.com` (the default) and either a
GitHub App private key is available (at `~/keys/rogitproxy.pem`) or in
[setec](https://github.com/tailscale/setec/)), rogitproxy
authenticates to GitHub using a GitHub App installation token.

Flags:

    --github-app-id=N          GitHub App ID
    --github-app-install-id=N  GitHub App installation ID
    --setec-url                setec server URL, for fetching the private key

## Access control

In tsnet mode with GitHub App auth enabled, access is controlled by tailnet
grants using the `github.com/tailscale/rogitproxy` capability. A grant looks
like:

```json
{
    "src": ["group:eng@example.com"],
    "dst": ["tag:rogitproxy"],
    "app": {
        "github.com/tailscale/rogitproxy": [{
            "repos": ["org/repo1", "org/repo2"],
            "access": "pull"
        }]
    }
}
```

The `"access": "pull"` type covers all read-only git operations (clone, fetch,
ls-remote).

## HTTP status page

rogitproxy serves an HTTP status page on port 80 (tsnet) showing the
requesting user's granted repos and usage examples. It also serves
`/debug/` via tsweb.Debugger (metrics, pprof, etc.).

## Only read-only operations

Only `git-upload-pack` (the read-only git protocol command) is permitted.
All other commands, including `git-receive-pack` (push), are rejected.
