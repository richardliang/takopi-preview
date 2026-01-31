# takopi-preview

Expose local dev servers over Tailscale Serve with `/preview` commands.

## quickstart

1. install takopi + this plugin (same environment as your transport).

```sh
uv tool install -U takopi --with takopi-transport-slack --with takopi-preview
```

2. make sure tailscale is up and magicdns is enabled (`tailscale up`).
3. add minimal config to `~/.takopi/takopi.toml`:

```toml
[plugins]
enabled = ["takopi-transport-slack", "takopi-preview"]

[plugins.preview]
provider = "tailscale"
```

4. in chat, pick a worktree context and start a preview:

```
/myapp @feat/login
/preview start 5173 use pnpm dev -- --host 127.0.0.1 --port 5173
```

Open the returned URL, then stop when done:

```
/preview stop 5173
```

## commands

- `/preview start [port] [instruction...]`: start a preview for the current context
- `/preview list`: show active previews (url, port, uptime, context)
- `/preview stop [id|port]`: stop a preview (defaults to current context)
- `/preview killall`: stop all previews (restricted by allowlist)
- `/preview help`: usage help

## optional config

```toml
[plugins.preview]
path_prefix = "/preview"
ttl_minutes = 120
tailscale_https_port = 443
allowed_user_ids = [123456789]
local_host = "127.0.0.1"
tailscale_bin = "tailscale"
start_port = 5173
start_instruction = "use pnpm dev -- --host 127.0.0.1 --port 5173"
dev_server_start_timeout_seconds = 600

[plugins.preview.projects.myapp]
path_prefix = "/preview"
start_port = 3000
start_instruction = "start web subrepo dev server only"
```

Notes:

- `provider = "tailscale"` uses tailnet-only URLs from `tailscale serve`.
- `ttl_minutes = 0` disables expiration.
- empty `allowed_user_ids` means no allowlist enforcement.

## dev server prompting

`/preview start` asks Takopi to ensure the dev server is running for the current
worktree before enabling Tailscale Serve.

- if the target port is already listening, Takopi confirms it is the right
  server and leaves it running.
- if the port is closed, Takopi finds the right dev command (README, AGENTS,
  package scripts) and starts it, preferring pnpm > bun > npm > yarn or
  uv > poetry > pip.
- the server should bind to `local_host` (default `127.0.0.1`) and the requested
  port; `/preview start` waits up to `dev_server_start_timeout_seconds` for the
  port to open (default: 90s).

All text after `/preview start` is forwarded to Takopi. If `start_port` is not
configured, the preview port must be the first argument. When `start_port` is
set, `/preview start` uses it by default and any arguments are treated as
instruction text.

You can include flags directly in the instruction:

```
/preview start 5173 use pnpm dev --host 127.0.0.1 --port 5173
```

`/preview stop` and `/preview killall` ask Takopi to stop the dev server if it is
still listening on the preview port.

## common setups

### vite / web apps

Allow tailnet hosts and bind to localhost:

```ts
server: {
  host: "127.0.0.1",
  port: 5173,
  allowedHosts: [".ts.net"],
},
```

Start the dev server (or rely on `/preview start`), then run `/preview start 5173`.

### react native (metro)

Metro expects requests at the root path, so use `path_prefix = "/"` and a
dedicated HTTPS port for the Metro port (example: 8081).

`metro.config.js` example:

```js
const config = getDefaultConfig(__dirname);
const metroPort = Number(process.env.METRO_PORT || 8081);
config.server = {
  ...config.server,
  port: metroPort,
};
module.exports = config;
```

Start Metro bound to localhost:

```sh
METRO_PORT=8081 bun start:dev -- --host localhost --port 8081
```

Expose it over tailnet:

```
/preview start 8081
```

On devices, set the dev server host/port to `HOST.TAILNET.ts.net:8081` in the
React Native dev menu.

If your dev client cannot use HTTPS, skip takopi-preview and connect directly
to the tailnet IP by running Metro with `--host 0.0.0.0`.

## state and ttl

- tailscale: sessions are derived from `tailscale serve status`; no preview state file is written.
- tailscale: if the requested port is already served, takopi will attempt to
  disable the existing serve entry before starting a new preview.
- tailscale: set `path_prefix = "/"` to serve from the tailnet root. This
  avoids subpath issues with apps that assume `/`, but only one preview can be
  served at a time with the built-in config. Use `path_prefix = "/preview"` if
  you need multiple concurrent previews.
- tailscale: the default HTTPS port is `443`, so previews map to
  `https://host.ts.net/preview/<port>` (or `https://host.ts.net/` when
  `path_prefix = "/"`). Set `tailscale_https_port = 0` to use the preview
  port (for `https://host.ts.net:3000/`). When using per-port HTTPS, start the
  dev server on `127.0.0.1` (no `--host 0.0.0.0`) so tailscale can bind the
  public port without conflicts.

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
  `local_host` (default `127.0.0.1`); rerun `/preview start` if needed.
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
