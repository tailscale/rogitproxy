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

## Read-only GitHub API proxy

When GitHub App auth is enabled, rogitproxy also proxies read-only GitHub
API requests with no client credentials, so sandboxed tools can read PRs,
issues, comments, reviews, checks, commit statuses, and GitHub Actions runs
and logs for the repos they have `pull` grants on. URLs are laid out like
GitHub Enterprise Server:

    REST:    http://rogitproxy.your-tailnet.ts.net/api/v3/repos/org/repo/...
    GraphQL: http://rogitproxy.your-tailnet.ts.net/api/graphql

Both are served over plain HTTP on port 80 and over HTTPS on port 443 using
the tailnet's TLS certificate (no MITM or custom root certs needed).

Safety is layered:

* Each upstream request uses a GitHub App installation token downscoped to
  read-only permissions (`actions`, `checks`, `contents`, `issues`,
  `metadata`, `pull_requests`, `statuses`) and to the requested repo (REST)
  or the caller's granted repos in one org (GraphQL).
* REST: only `GET` and `HEAD` under `/api/v3/repos/{owner}/{repo}/`, which
  requires a `pull` grant on that repo.
* GraphQL: only `query` operations; mutations and subscriptions are rejected.
  The token's org is taken from the `owner` variable if present.
* Client `Authorization` and `Cookie` headers are dropped. Redirects (e.g.
  Actions log downloads) are followed server-side without the token.
* `https://api.github.com/` URLs in JSON bodies and `Link` headers are
  rewritten to point back at the proxy, so pagination works.

The GitHub App must have been granted the read permissions above, and each
org installation must accept them.

### Clients

The gh CLI only speaks HTTPS to Enterprise hosts. Point it at the proxy
(gh requires a token to be set, but its value is ignored):

    export GH_HOST=rogitproxy.your-tailnet.ts.net GH_ENTERPRISE_TOKEN=unused
    gh pr checks 123
    gh run view 456 --log-failed

Inside a checkout cloned from `git://rogitproxy.your-tailnet.ts.net/...`,
gh detects the repo from the remote. Elsewhere, pass
`-R rogitproxy.your-tailnet.ts.net/org/repo` or set `GH_REPO`.

For go-github, use
`github.NewClient(nil).WithEnterpriseURLs("http://rogitproxy.your-tailnet.ts.net/api/v3/", "")`.
For curl and scripts, swap `https://api.github.com` for
`http://rogitproxy.your-tailnet.ts.net/api/v3`.

## Only read-only operations

Only `git-upload-pack` (the read-only git protocol command) is permitted.
All other commands, including `git-receive-pack` (push), are rejected.
