# takopi-tailscale

Lightweight Tailscale preview command plugin for Takopi.

## Install

```sh
uv pip install takopi-tailscale
```

## Configure

```toml
[plugins]
enabled = ["takopi-transport-slack", "takopi-tailscale"]

[plugins.preview]
provider = "tailscale"
default_port = 3000
dev_command = "pnpm dev -- --host 127.0.0.1 --port {port}"
auto_start = true
allowed_user_ids = [123456789]

[projects.zkp2p-mobile.preview]
port = 8081
dev_command = "pnpm react-native start --port {port}"
```

## Commands

- `/preview start [port]`
- `/preview list`
- `/preview stop [port]`
- `/preview killall`
- `/preview help`

## Notes

- Uses `tailscale serve --tcp` to expose `tcp://127.0.0.1:<port>` inside the tailnet.
- URLs are tailnet-only: `http://DEVICE.TAILNET.ts.net:<port>`.
