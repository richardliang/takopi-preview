# takopi-preview

preview command plugin for takopi. starts a dev server (optional), exposes it
via `tailscale serve` or Cloudflare quick tunnels, and tracks preview sessions
by project/worktree context.

published as the `takopi-preview` package. the command id is `preview`.

## features

- `/preview` commands to start, list, stop, and clean up previews
- provider options: tailnet-only URLs (tailscale) or public quick tunnels (cloudflare)
- per-project overrides for ports and dev commands
- optional dev server auto-start with `{port}` substitution
- session registry with ttl expiration
- allowlist support for sensitive commands (like `killall`)

## requirements

- python 3.14+
- takopi >= 0.20
- provider tooling:
  - tailscale installed and authenticated on the host (`tailscale up`)
  - or cloudflared installed for quick tunnels
- dev server binds to 127.0.0.1 (tunnels proxy locally)
- security groups should not expose the dev server port publicly

## install

install into the same environment as takopi.

```sh
uv tool install -U takopi
uv tool install -U takopi --with takopi-transport-slack --with takopi-preview
```

or, with a virtualenv:

```sh
pip install takopi-transport-slack takopi-preview
```

## setup

1. install a provider: tailscale (`tailscale up`) or cloudflared.
2. if using tailscale, enable magicdns so `DEVICE.TAILNET.ts.net` resolves.
3. run takopi with your transport (slack or telegram) as usual.

## configuration

add to `~/.takopi/takopi.toml`:

```toml
[plugins]
enabled = ["takopi-transport-slack", "takopi-preview"]

[plugins.preview]
provider = "cloudflare"
default_port = 3000
dev_command = "pnpm dev -- --host 127.0.0.1 --port {port}"
auto_start = true
ttl_minutes = 120
allowed_user_ids = [123456789]

# optional env injection for the dev server
[plugins.preview.env]
NODE_ENV = "development"

# advanced overrides
local_host = "127.0.0.1"
cloudflared_bin = "cloudflared"
cloudflared_timeout_seconds = 30
cloudflared_args = ["--no-autoupdate"]

# tailscale-specific
tailscale_bin = "tailscale"

# per-project overrides (Takopi project tables are strict, so use plugins.preview.projects)
[plugins.preview.projects.myapp]
port = 5173
dev_command = "npm run dev -- --host 127.0.0.1 --port {port}"
```

notes:

- `provider = "cloudflare"` uses quick tunnels (`*.trycloudflare.com`) and does not require a Cloudflare account.
- `provider = "tailscale"` uses tailnet-only urls from `tailscale serve`.
- `dev_command` may include `{port}`; it will be substituted at runtime.
- `dev_command` is required when `auto_start = true`. set `auto_start = false` to manage the dev server yourself.
- Inline `--dev`/`--` overrides enable auto-start for that run; use `--no-start` to force manual mode.
- To require an explicit command each run, omit `dev_command` and set `auto_start = false`, then pass `--dev` or `--`.
- `ttl_minutes = 0` disables expiration.
- empty `allowed_user_ids` means no allowlist enforcement.

## commands

- `/preview start [port]`: start a preview for the current context
- `/preview start [port] --dev "<command>"`: override the dev command for this run
- `/preview start [port] -- <command>`: shorthand for an inline dev command
- `/preview list`: show active previews (url, port, uptime, context)
- `/preview stop [id|port]`: stop a preview (defaults to current context)
- `/preview killall`: stop all previews (restricted by allowlist)
- `/preview help`: usage help

## workflow

1. choose a context: `/myapp @feat/login` or reply in an existing thread.
   previews only run in worktrees, so include a branch to create/use one.
2. run `/preview start` (or `/preview start 5173`).
3. open the returned url, for example:

```
https://random-words.trycloudflare.com
# tailscale provider example:
https://DEVICE.TAILNET.ts.net/preview/5173
```

4. stop when done: `/preview stop` or `/preview stop 5173`.

## state and ttl

- tailscale: sessions are derived from `tailscale serve status`; no preview state file is written.
- cloudflare: sessions are tracked in-process; list/killall will also scan for
  `cloudflared tunnel --url` processes (external URLs may be unavailable).
- cloudflare: on the first preview command, takopi stops any existing
  `cloudflared tunnel --url` processes to prevent stale sessions.

dev server logs (when auto-started) are written to:

- `~/.takopi/state/preview-logs/<session>.log`

`ttl_minutes` controls automatic expiration for previews started by this takopi
process; expired sessions are cleaned up on the next command invocation.
worktrees that are pruned or deleted are also cleaned up on the next command.
takopi shutdown stops all previews.

## errors

- missing tailscale: follow the install docs and run `tailscale up`.
- missing cloudflared: install cloudflared from the Cloudflare docs or GitHub releases.
- serve disabled: enable serve for your tailnet (Tailscale admin UI) if you see the "Serve is not enabled" error.
- port already in use: when auto-starting, takopi will try to stop listeners on
  that port; if it is still busy, run `/preview list` or pick a new port.
- not in a worktree: include a branch (ex: `/myapp @feat/foo`) to create/use a worktree.
- dev server failures: the error includes log tail + log path.

## spec alignment

this implementation follows the webapp preview workflow spec:

- [x] command surface: start/list/stop/killall/help
- [x] config in `[plugins.preview]` with per-project overrides
- [x] provider support: tailscale serve or cloudflare quick tunnels
- [x] tailnet-only https urls (tailscale) or public https urls (cloudflare)
- [x] tailscale serve registry or in-process tunnel registry
- [x] ttl-based expiration (`ttl_minutes`)
- [x] allowlist enforcement via `allowed_user_ids`

## license

mit
