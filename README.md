# takopi-preview

preview command plugin for takopi. exposes existing local ports via
`tailscale serve`, and tracks preview sessions by project/worktree context.

published as the `takopi-preview` package. the command id is `preview`.

## features

- `/preview` commands to start, list, stop, and clean up previews
- per-project overrides for ports
- session registry with ttl expiration
- allowlist support for sensitive commands (like `killall`)

## requirements

- python 3.14+
- takopi >= 0.20
- provider tooling:
  - tailscale installed and authenticated on the host (`tailscale up`)
- the service you want to share binds to 127.0.0.1 (tunnels proxy locally)
- security groups should not expose the local service port publicly

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

1. install tailscale and authenticate (`tailscale up`).
2. enable magicdns so `DEVICE.TAILNET.ts.net` resolves.
3. run takopi with your transport (slack or telegram) as usual.

## configuration

add to `~/.takopi/takopi.toml`:

```toml
[plugins]
enabled = ["takopi-transport-slack", "takopi-preview"]

[plugins.preview]
provider = "tailscale"
default_port = 3000
ttl_minutes = 120
path_prefix = "/preview"
tailscale_https_port = 443
allowed_user_ids = [123456789]
local_host = "127.0.0.1"
tailscale_bin = "tailscale"

# per-project overrides (Takopi project tables are strict, so use plugins.preview.projects)
[plugins.preview.projects.myapp]
port = 5173
```

notes:

- `provider = "tailscale"` uses tailnet-only urls from `tailscale serve`.
- preview only configures tailscale serve; start your dev server separately.
- `ttl_minutes = 0` disables expiration.
- empty `allowed_user_ids` means no allowlist enforcement.

## commands

- `/preview start [port]`: start a preview for the current context
- `/preview list`: show active previews (url, port, uptime, context)
- `/preview stop [id|port]`: stop a preview (defaults to current context)
- `/preview killall`: stop all previews (restricted by allowlist)
- `/preview help`: usage help

## workflow

1. choose a context: `/myapp @feat/login` or reply in an existing thread.
   previews only run in worktrees, so include a branch to create/use one.
2. start your dev server in that worktree (ex: `pnpm dev -- --port 5173`).
3. run `/preview start` (or `/preview start 5173`).
4. open the returned url, for example:

```
https://DEVICE.TAILNET.ts.net/preview/5173
```

5. stop when done: `/preview stop` or `/preview stop 5173`.

## state and ttl

- tailscale: sessions are derived from `tailscale serve status`; no preview state file is written.
- tailscale: if the requested port is already served, takopi will attempt to
  disable the existing serve entry before starting a new preview.
- tailscale: set `path_prefix = "/"` to serve from the tailnet root. This
  avoids subpath issues with apps that assume `/`, but only one preview can be
  served at a time unless you also set per-preview HTTPS ports.
- tailscale: when `path_prefix = "/"`, the default HTTPS port is the preview
  port (so `5173` maps to `https://host.ts.net:5173`). Set
  `tailscale_https_port = 443` to force the default HTTPS port.

`ttl_minutes` controls automatic expiration for previews started by this takopi
process; expired sessions are cleaned up on the next command invocation.
worktrees that are pruned or deleted are also cleaned up on the next command.
takopi shutdown stops all previews.

## errors

- missing tailscale: follow the install docs and run `tailscale up`.
- serve disabled: enable serve for your tailnet (Tailscale admin UI) if you see the "Serve is not enabled" error.
- preview already active: if a port is already served, takopi will stop the
  existing serve entry before re-enabling it.
- service not reachable: ensure your dev server is running and bound to
  `local_host` (default `127.0.0.1`).
- not in a worktree: include a branch (ex: `/myapp @feat/foo`) to create/use a worktree.

## spec alignment

this implementation follows the webapp preview workflow spec:

- [x] command surface: start/list/stop/killall/help
- [x] config in `[plugins.preview]` with per-project overrides
- [x] tailscale serve for tailnet-only preview urls
- [x] tailscale serve registry
- [x] ttl-based expiration (`ttl_minutes`)
- [x] allowlist enforcement via `allowed_user_ids`

## license

mit
