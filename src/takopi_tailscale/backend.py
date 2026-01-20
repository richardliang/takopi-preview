from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from takopi.api import (
    CommandBackend,
    CommandContext,
    CommandResult,
    ConfigError,
    HOME_CONFIG_PATH,
    get_logger,
    read_config,
)

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class PreviewConfig:
    default_port: int
    dev_command: str | None
    auto_start: bool
    allowed_user_ids: set[int] | None
    env: dict[str, str]
    tailscale_bin: str
    local_host: str


@dataclass(slots=True)
class PreviewSession:
    session_id: str
    port: int
    url: str | None
    started_at: float
    context_line: str | None
    dev_process: subprocess.Popen[str] | None

    @property
    def dev_pid(self) -> int | None:
        return self.dev_process.pid if self.dev_process is not None else None


class PreviewManager:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._sessions: dict[int, PreviewSession] = {}

    async def start(
        self,
        *,
        ctx: CommandContext,
        config: PreviewConfig,
        port: int,
        context_line: str | None,
        cwd: Path | None,
    ) -> PreviewSession:
        async with self._lock:
            if port in self._sessions:
                raise ConfigError(f"Preview already active on port {port}.")

            dev_process = None
            if config.auto_start:
                if not config.dev_command:
                    raise ConfigError("preview.dev_command is required when auto_start=true")
                dev_process = _start_dev_server(
                    command=config.dev_command,
                    port=port,
                    cwd=cwd,
                    env=config.env,
                )

            try:
                _tailscale_tcp_on(config=config, port=port)
            except Exception:
                if dev_process is not None:
                    _stop_process(dev_process)
                raise

            session = PreviewSession(
                session_id=_build_session_id(context_line, port),
                port=port,
                url=_build_url(config=config, port=port),
                started_at=time.time(),
                context_line=context_line,
                dev_process=dev_process,
            )
            self._sessions[port] = session
            return session

    async def stop(self, *, config: PreviewConfig, port: int) -> PreviewSession:
        async with self._lock:
            session = self._sessions.pop(port, None)
            if session is None:
                raise ConfigError(f"No active preview on port {port}.")

            try:
                _tailscale_tcp_off(config=config, port=port)
            finally:
                if session.dev_process is not None:
                    _stop_process(session.dev_process)

            return session

    async def stop_all(self, *, config: PreviewConfig) -> list[PreviewSession]:
        async with self._lock:
            ports = list(self._sessions.keys())

        stopped: list[PreviewSession] = []
        for port in ports:
            try:
                stopped.append(await self.stop(config=config, port=port))
            except ConfigError:
                continue
        return stopped

    async def list_sessions(self) -> list[PreviewSession]:
        async with self._lock:
            return list(self._sessions.values())

    async def resolve_port(self, arg: str | None) -> int | None:
        if arg is None:
            return None
        if arg.isdigit():
            return int(arg)
        if ":" in arg:
            tail = arg.rsplit(":", 1)[-1]
            if tail.isdigit():
                return int(tail)
        return None


MANAGER = PreviewManager()


class PreviewCommand:
    id = "preview"
    description = "Manage tailscale preview sessions"

    async def handle(self, ctx: CommandContext) -> CommandResult | None:
        try:
            return await self._handle(ctx)
        except ConfigError as exc:
            return CommandResult(text=f"preview error: {exc}")

    async def _handle(self, ctx: CommandContext) -> CommandResult:
        if not ctx.args:
            return CommandResult(text=_help_text())

        resolved = ctx.runtime.resolve_message(
            text=ctx.text,
            reply_text=ctx.reply_text,
            chat_id=_coerce_chat_id(ctx.message.channel_id),
        )
        context_line = ctx.runtime.format_context_line(resolved.context)
        cwd = ctx.runtime.resolve_run_cwd(resolved.context)
        config = _load_config(ctx, resolved.context)

        if not _is_user_allowed(ctx, config):
            return CommandResult(text="preview error: user not allowed")

        command = ctx.args[0].lower()
        if command in {"start", "on"}:
            port = await MANAGER.resolve_port(_arg(ctx.args, 1))
            port = port or config.default_port
            session = await MANAGER.start(
                ctx=ctx,
                config=config,
                port=port,
                context_line=context_line,
                cwd=cwd,
            )
            return CommandResult(text=_format_started(session))
        if command == "list":
            sessions = await MANAGER.list_sessions()
            return CommandResult(text=_format_list(sessions))
        if command in {"stop", "off"}:
            port = await MANAGER.resolve_port(_arg(ctx.args, 1))
            if port is None:
                sessions = await MANAGER.list_sessions()
                if len(sessions) == 1:
                    port = sessions[0].port
                else:
                    raise ConfigError("Specify a port to stop.")
            session = await MANAGER.stop(config=config, port=port)
            return CommandResult(text=_format_stopped(session))
        if command in {"killall", "stopall"}:
            sessions = await MANAGER.stop_all(config=config)
            return CommandResult(text=_format_killall(sessions))
        if command in {"help", "--help", "-h"}:
            return CommandResult(text=_help_text())

        raise ConfigError(f"Unknown subcommand {command!r}.")


BACKEND: CommandBackend = PreviewCommand()


def _arg(args: tuple[str, ...], index: int) -> str | None:
    if len(args) > index:
        return args[index]
    return None


def _coerce_chat_id(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    return None


def _load_config(ctx: CommandContext, context) -> PreviewConfig:
    base = dict(ctx.plugin_config or {})
    project_override: dict[str, Any] = {}
    config_path = ctx.config_path or HOME_CONFIG_PATH
    if context is not None and context.project and config_path.exists():
        try:
            raw = read_config(config_path)
        except ConfigError as exc:
            logger.warning("preview.config_read_failed", error=str(exc))
        else:
            projects = raw.get("projects")
            if isinstance(projects, dict):
                project_cfg = projects.get(context.project)
                if isinstance(project_cfg, dict):
                    preview_cfg = project_cfg.get("preview")
                    if isinstance(preview_cfg, dict):
                        project_override = preview_cfg

    merged = {**base, **project_override}

    default_port = _coerce_int(merged.get("port")) or _coerce_int(
        merged.get("default_port")
    )
    if default_port is None:
        default_port = 3000

    dev_command = merged.get("dev_command")
    if dev_command is not None and not isinstance(dev_command, str):
        raise ConfigError("preview.dev_command must be a string")

    auto_start = merged.get("auto_start")
    if auto_start is None:
        auto_start = True
    auto_start = bool(auto_start)

    allowed_user_ids = _coerce_int_set(merged.get("allowed_user_ids"))
    env = _coerce_env(merged.get("env"))
    tailscale_bin = merged.get("tailscale_bin") or "tailscale"
    local_host = merged.get("local_host") or "127.0.0.1"

    return PreviewConfig(
        default_port=default_port,
        dev_command=dev_command,
        auto_start=auto_start,
        allowed_user_ids=allowed_user_ids,
        env=env,
        tailscale_bin=tailscale_bin,
        local_host=local_host,
    )


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _coerce_int_set(value: Any) -> set[int] | None:
    if value is None:
        return None
    if isinstance(value, list):
        items = {_coerce_int(item) for item in value}
        if None in items:
            raise ConfigError("preview.allowed_user_ids must be integers")
        return set(items)  # type: ignore[return-value]
    raise ConfigError("preview.allowed_user_ids must be a list")


def _coerce_env(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError("preview.env must be a table")
    env: dict[str, str] = {}
    for key, raw in value.items():
        if not isinstance(key, str):
            raise ConfigError("preview.env keys must be strings")
        if not isinstance(raw, str):
            raise ConfigError("preview.env values must be strings")
        env[key] = raw
    return env


def _is_user_allowed(ctx: CommandContext, config: PreviewConfig) -> bool:
    if not config.allowed_user_ids:
        return True
    sender_id = ctx.message.sender_id
    if sender_id is None:
        return False
    return sender_id in config.allowed_user_ids


def _start_dev_server(
    *,
    command: str,
    port: int,
    cwd: Path | None,
    env: dict[str, str],
) -> subprocess.Popen[str]:
    command = command.format(port=port)
    process_env = os.environ.copy()
    process_env.update(env)
    logger.info("preview.dev_start", command=command, cwd=str(cwd) if cwd else None)
    return subprocess.Popen(
        command,
        shell=True,
        cwd=str(cwd) if cwd else None,
        env=process_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _tailscale_tcp_on(*, config: PreviewConfig, port: int) -> None:
    _ensure_tailscale(config)
    target = f"tcp://{config.local_host}:{port}"
    cmd = [
        config.tailscale_bin,
        "serve",
        "--bg",
        "--tcp",
        str(port),
        target,
    ]
    _run(cmd, "preview.tailscale_on")


def _tailscale_tcp_off(*, config: PreviewConfig, port: int) -> None:
    _ensure_tailscale(config)
    target = f"tcp://{config.local_host}:{port}"
    cmd = [
        config.tailscale_bin,
        "serve",
        "--tcp",
        str(port),
        target,
        "off",
    ]
    _run(cmd, "preview.tailscale_off")


def _ensure_tailscale(config: PreviewConfig) -> None:
    if subprocess.call(
        [config.tailscale_bin, "status"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) != 0:
        raise ConfigError("tailscale is not available or not authenticated")


def _run(cmd: list[str], log_event: str) -> None:
    logger.info(log_event, cmd=" ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise ConfigError(message or "tailscale command failed")


def _build_url(*, config: PreviewConfig, port: int) -> str | None:
    dns = _get_dns_name(config)
    if dns is None:
        return None
    return f"http://{dns}:{port}"


def _get_dns_name(config: PreviewConfig) -> str | None:
    cmd = [config.tailscale_bin, "status", "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    dns = data.get("Self", {}).get("DNSName")
    if isinstance(dns, str) and dns:
        return dns.rstrip(".")
    host = data.get("Self", {}).get("HostName")
    suffix = data.get("MagicDNSSuffix")
    if isinstance(host, str) and isinstance(suffix, str):
        return f"{host}.{suffix}"
    return None


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _build_session_id(context_line: str | None, port: int) -> str:
    if context_line:
        base = context_line.replace("`", "").replace("ctx:", "").strip()
        if base:
            return f"{base}:{port}"
    return f"default:{port}"


def _format_started(session: PreviewSession) -> str:
    url = session.url or "(url unavailable)"
    context = f"\n{session.context_line}" if session.context_line else ""
    return (
        f"Preview started on port {session.port}.\n"
        f"URL: {url}{context}\n"
        f"ID: {session.session_id}"
    )


def _format_stopped(session: PreviewSession) -> str:
    return f"Preview stopped on port {session.port}."


def _format_killall(sessions: list[PreviewSession]) -> str:
    if not sessions:
        return "No active previews."
    ports = ", ".join(str(session.port) for session in sessions)
    return f"Stopped previews on ports: {ports}."


def _format_list(sessions: list[PreviewSession]) -> str:
    if not sessions:
        return "No active previews."
    lines = ["Active previews:"]
    for session in sessions:
        age = _format_age(session.started_at)
        url = session.url or "(url unavailable)"
        lines.append(
            f"- {session.session_id} -> {url} ({age}, pid={session.dev_pid})"
        )
    return "\n".join(lines)


def _format_age(started_at: float) -> str:
    seconds = int(time.time() - started_at)
    minutes, seconds = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def _help_text() -> str:
    return (
        "preview commands:\n"
        "/preview start [port]\n"
        "/preview list\n"
        "/preview stop [port]\n"
        "/preview killall\n"
        "/preview help"
    )
