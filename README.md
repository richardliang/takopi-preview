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
2. enable magicdns so `DEVICE.TAILNET.ts.net` resolves. (https://tailscale.com)
3. run takopi with your transport (slack or telegram) as usual.

## configuration

add to `~/.takopi/takopi.toml`:

```toml
[plugins]
enabled = ["takopi-transport-slack", "takopi-preview"]

[plugins.preview]
provider = "tailscale"
ttl_minutes = 120
path_prefix = "/preview"
tailscale_https_port = 443
allowed_user_ids = [123456789]
local_host = "127.0.0.1"
tailscale_bin = "tailscale"

# per-project overrides (Takopi project tables are strict, so use plugins.preview.projects)
[plugins.preview.projects.myapp]
path_prefix = "/preview"
```

notes:

- `provider = "tailscale"` uses tailnet-only urls from `tailscale serve`.
- `/preview start` prompts Takopi to start the dev server if needed and waits
  for the port to open; you can also start it manually.
- takopi-preview is a command backend plugin that registers `/preview` and
  manages `tailscale serve` entries based on takopi context/worktrees.
- `ttl_minutes = 0` disables expiration.
- empty `allowed_user_ids` means no allowlist enforcement.

## commands

- `/preview start <port> [instruction...]`: start a preview for the current context
- `/preview list`: show active previews (url, port, uptime, context)
- `/preview stop [id|port]`: stop a preview (defaults to current context)
- `/preview killall`: stop all previews (restricted by allowlist)
- `/preview help`: usage help

## workflow

1. choose a context: `/myapp @feat/login` or reply in an existing thread.
   previews only run in worktrees, so include a branch to create/use one.
2. start your dev server in that worktree (ex: `pnpm dev -- --host 127.0.0.1 --port 5173`)
   or let `/preview start` prompt Takopi to do it.
3. run `/preview start 5173` and wait for readiness.
4. open the returned url, for example:

```
https://DEVICE.TAILNET.ts.net/preview/5173
```

5. stop when done: `/preview stop` or `/preview stop 5173`.

## dev server prompting

`/preview start` asks Takopi to ensure the dev server is running for the current
worktree before enabling Tailscale Serve.

- if the target port is already listening, Takopi confirms it is the right
  server and leaves it running.
- if the port is closed, Takopi finds the right dev command (README, AGENTS,
  package scripts) and starts it, preferring pnpm > bun > npm > yarn or
  uv > poetry > pip.
- the server should bind to `local_host` (default `127.0.0.1`) and the requested
  port; `/preview start` waits up to ~90s for the port to open.

You can append an instruction to steer which server should run:

```
/preview start 8081 dev server for expo
```

All text after `/preview start` is forwarded to Takopi. The preview port must be
the first argument.

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
