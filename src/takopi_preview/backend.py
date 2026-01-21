from __future__ import annotations

import atexit
import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from takopi.api import (
    CommandBackend,
    CommandContext,
    CommandResult,
    ConfigError,
    HOME_CONFIG_PATH,
    get_logger,
)
from takopi.utils.git import git_stdout, resolve_main_worktree_root

logger = get_logger(__name__)

SAFE_PORT_MIN = 1024
SAFE_PORT_MAX = 65535
DEFAULT_TTL_MINUTES = 120
LOGS_DIRNAME = "preview-logs"
PATH_PREFIX = "/preview"
_PREVIEW_PORT_RE = re.compile(r"/preview/(\d+)")
LISTEN_PID_RE = re.compile(r"pid=(\d+)")
LOCAL_PROXY_PORT_RE = re.compile(
    r"http://(?:127\.0\.0\.1|localhost|0\.0\.0\.0):(\d+)"
)


@dataclass(frozen=True, slots=True)
class PreviewConfig:
    default_port: int
    dev_command: str | None
    auto_start: bool
    ttl_minutes: int
    allowed_user_ids: set[int] | None
    env: dict[str, str]
    tailscale_bin: str
    local_host: str
    logs_dir: Path
    path_prefix: str

    @classmethod
    def from_config(cls, config: object, *, config_path: Path) -> "PreviewConfig":
        if isinstance(config, PreviewConfig):
            return config
        if not isinstance(config, dict):
            raise ConfigError(
                f"Invalid `preview` config in {config_path}; expected a table."
            )

        provider = _optional_str(config, "provider", config_path=config_path)
        if provider and provider != "tailscale":
            raise ConfigError(
                f"Invalid `preview.provider` in {config_path}; "
                "cloudflare support has been removed, use 'tailscale'."
            )
        if any(
            key in config
            for key in (
                "cloudflared_bin",
                "cloudflared_args",
                "cloudflared_timeout_seconds",
            )
        ):
            raise ConfigError(
                f"Invalid preview config in {config_path}; "
                "cloudflare options have been removed."
            )

        default_port = _optional_int(config, "port", config_path=config_path)
        if default_port is None:
            default_port = _optional_int(config, "default_port", config_path=config_path)
        if default_port is None:
            default_port = 3000

        dev_command = _optional_str(config, "dev_command", config_path=config_path)
        if dev_command is not None and not dev_command:
            raise ConfigError(
                f"Invalid `preview.dev_command` in {config_path}; "
                "expected a non-empty string."
            )

        auto_start = _optional_bool(config, "auto_start", config_path=config_path)
        if auto_start is None:
            auto_start = True

        ttl_minutes = _optional_int(config, "ttl_minutes", config_path=config_path)
        if ttl_minutes is None:
            ttl_minutes = DEFAULT_TTL_MINUTES
        if ttl_minutes < 0:
            raise ConfigError(
                f"Invalid `preview.ttl_minutes` in {config_path}; "
                "expected a non-negative integer."
            )

        allowed_user_ids = _optional_int_set(
            config, "allowed_user_ids", config_path=config_path
        )
        if allowed_user_ids is not None and not allowed_user_ids:
            allowed_user_ids = None

        env = _optional_env(config, "env", config_path=config_path)
        tailscale_bin = (
            _optional_str(config, "tailscale_bin", config_path=config_path) or "tailscale"
        )
        local_host = (
            _optional_str(config, "local_host", config_path=config_path) or "127.0.0.1"
        )
        path_prefix = _normalize_path_prefix(
            _optional_str(config, "path_prefix", config_path=config_path) or PATH_PREFIX
        )

        state_dir = config_path.parent / "state"
        logs_dir = state_dir / LOGS_DIRNAME

        return cls(
            default_port=default_port,
            dev_command=dev_command,
            auto_start=auto_start,
            ttl_minutes=ttl_minutes,
            allowed_user_ids=allowed_user_ids,
            env=env,
            tailscale_bin=tailscale_bin,
            local_host=local_host,
            logs_dir=logs_dir,
            path_prefix=path_prefix,
        )


@dataclass(slots=True)
class PreviewSession:
    session_id: str
    project: str | None
    branch: str | None
    port: int
    url: str | None
    created_at: float
    last_seen: float
    context_line: str | None
    dev_pid: int | None
    owns_dev_process: bool
    worktree_path: Path | None = None
    repo_root: Path | None = None
    dev_process: subprocess.Popen[str] | None = None
    log_path: Path | None = None

    def touch(self, now: float | None = None) -> None:
        self.last_seen = now or time.time()


class PreviewManager:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._sessions: dict[int, PreviewSession] = {}
        self._last_config: PreviewConfig | None = None
        self._expiry_task: asyncio.Task[None] | None = None

    def record_config(self, config: PreviewConfig) -> None:
        self._last_config = config

    async def expire_stale(self, config: PreviewConfig) -> list[PreviewSession]:
        if config.ttl_minutes <= 0:
            return []
        self._last_config = config
        now = time.time()
        ttl_seconds = config.ttl_minutes * 60

        async with self._lock:
            expired = [
                session
                for session in self._sessions.values()
                if now - session.last_seen >= ttl_seconds
            ]
            for session in expired:
                self._sessions.pop(session.port, None)

        for session in expired:
            await asyncio.to_thread(
                _stop_session,
                config=config,
                session=session,
            )
        return expired

    async def start(
        self,
        *,
        config: PreviewConfig,
        port: int,
        context_line: str | None,
        context: object | None,
        cwd: Path | None,
        worktree_path: Path | None,
        repo_root: Path | None,
    ) -> PreviewSession:
        self._last_config = config

        _validate_port(port)

        active_ports: set[int] = await asyncio.to_thread(
            _tailscale_list_ports, config
        )
        async with self._lock:
            in_sessions = port in self._sessions
        if in_sessions or port in active_ports:
            await self._clear_tailscale_conflict(config=config, port=port)
            active_ports = await asyncio.to_thread(_tailscale_list_ports, config)
            async with self._lock:
                in_sessions = port in self._sessions
            if in_sessions or port in active_ports:
                raise ConfigError(
                    f"Preview already active on port {port}. Try /preview list."
                )

        dev_process = None
        log_path = None
        owns_dev_process = False
        if config.auto_start:
            if not config.dev_command:
                raise ConfigError("preview.dev_command is required when auto_start=true")
            if not _is_port_available(config.local_host, port):
                killed = _kill_port_listeners(port)
                if killed:
                    logger.info(
                        "preview.port_conflict_killed",
                        port=port,
                        pids=sorted(killed),
                    )
                if not _is_port_available(config.local_host, port):
                    raise ConfigError(
                        f"Port {port} is already in use. Try /preview list or another port."
                    )
            dev_process, log_path = _start_dev_server(
                command=config.dev_command,
                port=port,
                cwd=cwd,
                env=config.env,
                logs_dir=config.logs_dir,
                session_id=_build_session_id(context, port),
            )
            owns_dev_process = True
            try:
                await _verify_dev_server(dev_process, log_path)
            except ConfigError:
                _stop_process(dev_process)
                raise

        url = None
        try:
            await asyncio.to_thread(
                _tailscale_http_on,
                config=config,
                port=port,
            )
            url = _build_url(config=config, port=port)
        except Exception:
            if dev_process is not None:
                _stop_process(dev_process)
            raise

        session = PreviewSession(
            session_id=_build_session_id(context, port),
            project=_context_project(context),
            branch=_context_branch(context),
            port=port,
            url=url,
            created_at=time.time(),
            last_seen=time.time(),
            context_line=context_line,
            dev_pid=dev_process.pid if dev_process is not None else None,
            owns_dev_process=owns_dev_process,
            worktree_path=worktree_path,
            repo_root=repo_root,
            dev_process=dev_process,
            log_path=log_path,
        )

        async with self._lock:
            self._sessions[port] = session
        return session

    async def stop(self, *, config: PreviewConfig, session: PreviewSession) -> PreviewSession:
        self._last_config = config

        async with self._lock:
            self._sessions.pop(session.port, None)

        await asyncio.to_thread(
            _stop_session,
            config=config,
            session=session,
        )
        return session

    async def stop_all(self, *, config: PreviewConfig) -> list[PreviewSession]:
        self._last_config = config
        now = time.time()
        ports = await asyncio.to_thread(_tailscale_list_ports, config)
        async with self._lock:
            sessions: list[PreviewSession] = []
            for port in ports:
                session = self._sessions.pop(port, None)
                if session is None:
                    session = _external_session(config=config, port=port, now=now)
                sessions.append(session)
            sessions.extend(self._sessions.values())
            self._sessions.clear()

        for session in sessions:
            await asyncio.to_thread(
                _stop_session,
                config=config,
                session=session,
            )
        return sessions

    async def list_sessions(self, *, config: PreviewConfig) -> list[PreviewSession]:
        self._last_config = config
        now = time.time()
        ports = await asyncio.to_thread(_tailscale_list_ports, config)
        sessions: list[PreviewSession] = []
        async with self._lock:
            for port in ports:
                session = self._sessions.get(port)
                if session is None:
                    session = _external_session(config=config, port=port, now=now)
                else:
                    session.touch(now)
                sessions.append(session)
        return sessions

    async def find_session(
        self,
        *,
        config: PreviewConfig,
        arg: str | None,
        context: object | None,
    ) -> PreviewSession:
        sessions = await self.list_sessions(config=config)

        if not sessions:
            raise ConfigError("No active previews.")

        port = _parse_port(arg)
        if port is not None:
            return _find_by_port(sessions, port)
        if arg:
            return _find_by_id(sessions, arg)
        return _find_by_context(sessions, context)

    async def ensure_expiry_loop(self, config: PreviewConfig) -> None:
        if config.ttl_minutes <= 0:
            return
        if self._expiry_task is not None and not self._expiry_task.done():
            return
        self._expiry_task = asyncio.create_task(self._expiry_loop())

    async def _expiry_loop(self) -> None:
        while True:
            config = self._last_config
            if config is not None and config.ttl_minutes > 0:
                await self.expire_stale(config)
                sleep_for = min(60, config.ttl_minutes * 60)
            else:
                sleep_for = 60
            await asyncio.sleep(sleep_for)

    def shutdown(self) -> None:
        config = self._last_config
        if config is None:
            return
        sessions = list(self._sessions.values())
        self._sessions.clear()
        for session in sessions:
            _stop_session(config=config, session=session)

    async def expire_pruned(self, config: PreviewConfig) -> list[PreviewSession]:
        self._last_config = config

        async with self._lock:
            sessions = list(self._sessions.values())

        if not sessions:
            return []

        pruned = await asyncio.to_thread(_find_pruned_sessions, sessions)
        if not pruned:
            return []

        async with self._lock:
            for session in pruned:
                self._sessions.pop(session.port, None)

        for session in pruned:
            await asyncio.to_thread(
                _stop_session,
                config=config,
                session=session,
            )
        return pruned

    async def _clear_tailscale_conflict(
        self, *, config: PreviewConfig, port: int
    ) -> None:
        now = time.time()
        async with self._lock:
            session = self._sessions.pop(port, None)
        if session is None:
            session = _external_session(config=config, port=port, now=now)
        await asyncio.to_thread(
            _stop_session,
            config=config,
            session=session,
        )


MANAGER = PreviewManager()


class PreviewCommand:
    id = "preview"
    description = "Manage preview sessions"

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
        context = resolved.context
        context_line = ctx.runtime.format_context_line(context)
        cwd = ctx.runtime.resolve_run_cwd(context)
        config = _load_config(ctx, context)

        if not _is_user_allowed(ctx, config):
            return CommandResult(text="preview error: user not allowed")

        MANAGER.record_config(config)
        await MANAGER.ensure_expiry_loop(config)
        await MANAGER.expire_stale(config)
        await MANAGER.expire_pruned(config)

        command = ctx.args[0].lower()
        if command in {"start", "on"}:
            port, dev_command, auto_start = _parse_start_args(ctx.args[1:], config)
            if dev_command is not None or auto_start is not None:
                config = _override_config(
                    config,
                    dev_command=dev_command,
                    auto_start=auto_start,
                )
            worktree_path, repo_root = _require_worktree(cwd)
            session = await MANAGER.start(
                config=config,
                port=port,
                context_line=context_line,
                context=context,
                cwd=cwd,
                worktree_path=worktree_path,
                repo_root=repo_root,
            )
            dev_status = _describe_dev_status(session=session, config=config)
            return CommandResult(text=_format_started(session, dev_status=dev_status))
        if command == "list":
            sessions = await MANAGER.list_sessions(config=config)
            return CommandResult(text=_format_list(sessions))
        if command in {"stop", "off"}:
            session = await MANAGER.find_session(
                config=config,
                arg=_arg(ctx.args, 1),
                context=context,
            )
            session = await MANAGER.stop(config=config, session=session)
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


def _load_config(ctx: CommandContext, context: object | None) -> PreviewConfig:
    base = dict(ctx.plugin_config or {})
    project_override: dict[str, Any] = {}
    config_path = ctx.config_path or HOME_CONFIG_PATH
    if context is not None:
        project = _context_project(context)
        if project:
            project_override = _project_override(base, project, config_path=config_path)

    merged = _merge_preview_config(base, project_override)
    return PreviewConfig.from_config(merged, config_path=config_path)


def _project_override(
    config: dict[str, Any],
    project: str,
    *,
    config_path: Path,
) -> dict[str, Any]:
    overrides = config.get("projects")
    if overrides is None:
        return {}
    if not isinstance(overrides, dict):
        raise ConfigError(
            f"Invalid `plugins.preview.projects` in {config_path}; expected a table."
        )
    raw = overrides.get(project)
    if raw is None:
        raw = overrides.get(project.lower())
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(
            f"Invalid `plugins.preview.projects.{project}` in {config_path}; "
            "expected a table."
        )
    return dict(raw)


def _merge_preview_config(
    base: dict[str, Any], override: dict[str, Any]
) -> dict[str, Any]:
    if not override:
        return base
    merged = dict(base)
    merged.update(override)
    base_env = base.get("env")
    override_env = override.get("env")
    if isinstance(base_env, dict) and isinstance(override_env, dict):
        merged["env"] = {**base_env, **override_env}
    return merged


def _optional_str(config: dict[str, Any], key: str, *, config_path: Path) -> str | None:
    if key not in config:
        return None
    value = config.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(
            f"Invalid `preview.{key}` in {config_path}; expected a string."
        )
    return value.strip()


def _optional_int(config: dict[str, Any], key: str, *, config_path: Path) -> int | None:
    if key not in config:
        return None
    value = config.get(key)
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ConfigError(f"Invalid `preview.{key}` in {config_path}; expected an int.")


def _optional_bool(config: dict[str, Any], key: str, *, config_path: Path) -> bool | None:
    if key not in config:
        return None
    value = config.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ConfigError(f"Invalid `preview.{key}` in {config_path}; expected a bool.")


def _optional_int_set(
    config: dict[str, Any], key: str, *, config_path: Path
) -> set[int] | None:
    if key not in config:
        return None
    value = config.get(key)
    if value is None:
        return None
    if isinstance(value, list):
        items = {_coerce_int(item) for item in value}
        if None in items:
            raise ConfigError(
                f"Invalid `preview.{key}` in {config_path}; expected integers."
            )
        return set(items)  # type: ignore[return-value]
    raise ConfigError(f"Invalid `preview.{key}` in {config_path}; expected a list.")


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _optional_env(
    config: dict[str, Any], key: str, *, config_path: Path
) -> dict[str, str]:
    if key not in config:
        return {}
    value = config.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"Invalid `preview.{key}` in {config_path}; expected a table.")
    env: dict[str, str] = {}
    for env_key, raw in value.items():
        if not isinstance(env_key, str):
            raise ConfigError(
                f"Invalid `preview.{key}` in {config_path}; expected string keys."
            )
        if not isinstance(raw, str):
            raise ConfigError(
                f"Invalid `preview.{key}` in {config_path}; expected string values."
            )
        env[env_key] = raw
    return env


def _is_user_allowed(ctx: CommandContext, config: PreviewConfig) -> bool:
    if not config.allowed_user_ids:
        return True
    sender_id = ctx.message.sender_id
    if sender_id is None:
        return False
    return sender_id in config.allowed_user_ids


def _validate_port(port: int) -> None:
    if not (SAFE_PORT_MIN <= port <= SAFE_PORT_MAX):
        raise ConfigError(
            f"Port {port} is out of range ({SAFE_PORT_MIN}-{SAFE_PORT_MAX})."
        )


def _require_worktree(cwd: Path | None) -> tuple[Path, Path]:
    if cwd is None:
        raise ConfigError("preview start requires a worktree; specify a project/branch.")
    top = git_stdout(
        ["rev-parse", "--path-format=absolute", "--show-toplevel"], cwd=cwd
    )
    if not top:
        raise ConfigError("preview start requires a git worktree.")
    worktree_path = Path(top).resolve(strict=False)
    repo_root = resolve_main_worktree_root(worktree_path)
    if repo_root is None:
        raise ConfigError("preview start requires a git worktree.")
    repo_root = repo_root.resolve(strict=False)
    if worktree_path == repo_root:
        raise ConfigError("preview start requires a worktree (not the main repo).")
    return worktree_path, repo_root


def _parse_port(arg: str | None) -> int | None:
    if arg is None:
        return None
    if arg.isdigit():
        return int(arg)
    if ":" in arg:
        tail = arg.rsplit(":", 1)[-1]
        if tail.isdigit():
            return int(tail)
    return None


def _parse_start_args(
    args: tuple[str, ...],
    config: PreviewConfig,
) -> tuple[int, str | None, bool | None]:
    port: int | None = None
    dev_command: str | None = None
    auto_start: bool | None = None
    idx = 0

    while idx < len(args):
        token = args[idx]
        if token == "--":
            if idx + 1 >= len(args):
                raise ConfigError("preview start requires a command after `--`")
            dev_command = " ".join(args[idx + 1 :]).strip()
            if not dev_command:
                raise ConfigError("preview start requires a non-empty command after `--`")
            auto_start = True
            break
        key, value = _split_flag(token)
        if key in {"--dev", "--dev-command", "--cmd"}:
            if value is None:
                idx += 1
                if idx >= len(args):
                    raise ConfigError("preview start requires a value after --dev-command")
                value = args[idx]
            dev_command = value.strip()
            if not dev_command:
                raise ConfigError("preview start requires a non-empty --dev-command")
            auto_start = True
            idx += 1
            continue
        if key == "--port":
            if value is None:
                idx += 1
                if idx >= len(args):
                    raise ConfigError("preview start requires a value after --port")
                value = args[idx]
            parsed = _parse_port(value)
            if parsed is None:
                raise ConfigError(f"Invalid port {value!r}.")
            port = parsed
            idx += 1
            continue
        if key in {"--no-start", "--manual"}:
            auto_start = False
            idx += 1
            continue
        if key.startswith("--"):
            raise ConfigError(f"Unknown flag {key!r}.")
        if port is None:
            parsed = _parse_port(token)
            if parsed is not None:
                port = parsed
                idx += 1
                continue
        raise ConfigError(f"Unexpected argument {token!r}.")

    if port is None:
        port = config.default_port
    return port, dev_command, auto_start


def _split_flag(token: str) -> tuple[str, str | None]:
    if "=" in token:
        key, value = token.split("=", 1)
        return key, value
    return token, None


def _normalize_path_prefix(prefix: str) -> str:
    trimmed = prefix.strip()
    if not trimmed:
        return PATH_PREFIX
    if not trimmed.startswith("/"):
        trimmed = f"/{trimmed}"
    if trimmed != "/" and trimmed.endswith("/"):
        trimmed = trimmed.rstrip("/")
    return trimmed


def _override_config(
    config: PreviewConfig,
    *,
    dev_command: str | None,
    auto_start: bool | None,
) -> PreviewConfig:
    updates: dict[str, Any] = {}
    if dev_command is not None:
        updates["dev_command"] = dev_command
    if auto_start is not None:
        updates["auto_start"] = auto_start
    if not updates:
        return config
    return replace(config, **updates)


def _is_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        try:
            sock.bind((host, port))
        except OSError:
            return False
        return True


def _listening_pids(port: int) -> set[int]:
    commands = [
        (["lsof", f"-iTCP:{port}", "-sTCP:LISTEN", "-n", "-P"], _parse_lsof_pids),
        (["ss", "-ltnp", f"sport = :{port}"], _parse_ss_pids),
    ]
    for cmd, parser in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            continue
        if result.returncode != 0 or not result.stdout:
            continue
        pids = parser(result.stdout)
        if pids:
            return pids
    return set()


def _parse_lsof_pids(output: str) -> set[int]:
    pids: set[int] = set()
    lines = output.splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[1].isdigit():
            pids.add(int(parts[1]))
    return pids


def _parse_ss_pids(output: str) -> set[int]:
    pids: set[int] = set()
    for line in output.splitlines():
        for match in LISTEN_PID_RE.findall(line):
            pids.add(int(match))
    return pids


def _kill_port_listeners(port: int) -> set[int]:
    pids = _listening_pids(port)
    for pid in pids:
        _stop_pid(pid)
    return pids


def _start_dev_server(
    *,
    command: str,
    port: int,
    cwd: Path | None,
    env: dict[str, str],
    logs_dir: Path,
    session_id: str,
) -> tuple[subprocess.Popen[str], Path]:
    command = command.format(port=port)
    process_env = os.environ.copy()
    process_env.update(env)
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{_slugify(session_id)}.log"
    logger.info("preview.dev_start", command=command, cwd=str(cwd) if cwd else None)
    log_handle = open(log_path, "a", encoding="utf-8")
    process = subprocess.Popen(
        command,
        shell=True,
        cwd=str(cwd) if cwd else None,
        env=process_env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    log_handle.close()
    return process, log_path


async def _verify_dev_server(
    process: subprocess.Popen[str], log_path: Path | None
) -> None:
    await asyncio.sleep(0.6)
    if process.poll() is None:
        return
    tail = _tail_log(log_path) if log_path else None
    message = "dev server failed to start"
    if tail:
        message = f"{message}\nlast output:\n{tail}\nlogs: {log_path}"
    raise ConfigError(message)


def _parse_local_target_port(
    value: str, allowed_hosts: set[str]
) -> int | None:
    if not value:
        return None
    if "://" not in value:
        value = f"http://{value}"
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return None
    host = parsed.hostname
    if host is None or host not in allowed_hosts:
        return None
    if parsed.port is None:
        return None
    return parsed.port


def _tailscale_http_on(*, config: PreviewConfig, port: int) -> None:
    _ensure_tailscale(config)
    target = f"http://{config.local_host}:{port}"
    path = _build_path(config, port)
    cmd = [
        config.tailscale_bin,
        "serve",
        "--bg",
        "--https",
        "443",
        "--set-path",
        path,
        target,
    ]
    legacy = [
        config.tailscale_bin,
        "serve",
        "--bg",
        "--https=443",
        path,
        target,
    ]
    _run_tailscale(cmd, "preview.tailscale_on", fallback=legacy)


def _tailscale_http_off(*, config: PreviewConfig, port: int) -> None:
    _ensure_tailscale(config)
    path = _build_path(config, port)
    cmd = [
        config.tailscale_bin,
        "serve",
        "--https",
        "443",
        "--set-path",
        path,
        "off",
    ]
    legacy = [
        config.tailscale_bin,
        "serve",
        "--https=443",
        path,
        "off",
    ]
    _run_tailscale(cmd, "preview.tailscale_off", fallback=legacy)


def _ensure_tailscale(config: PreviewConfig) -> None:
    result = subprocess.run(
        [config.tailscale_bin, "status", "--json"], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise ConfigError(
            "tailscale is not available or not authenticated; run `tailscale up`."
        )


def _run(cmd: list[str], log_event: str) -> None:
    logger.info(log_event, cmd=" ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise ConfigError(message or "tailscale command failed")


def _run_tailscale(
    cmd: list[str],
    log_event: str,
    *,
    fallback: list[str] | None = None,
) -> None:
    try:
        _run(cmd, log_event)
    except ConfigError as exc:
        if fallback is None:
            raise
        message = str(exc).lower()
        if "invalid argument format" not in message and "unknown flag" not in message:
            raise
        _run(fallback, log_event)


def _extract_preview_ports_from_text(text: str) -> set[int]:
    ports: set[int] = set()
    for match in _PREVIEW_PORT_RE.finditer(text):
        try:
            ports.add(int(match.group(1)))
        except ValueError:
            continue
    for match in LOCAL_PROXY_PORT_RE.finditer(text):
        try:
            ports.add(int(match.group(1)))
        except ValueError:
            continue
    return ports


def _extract_preview_ports(payload: Any) -> set[int]:
    ports: set[int] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str):
                    ports.update(_extract_preview_ports_from_text(key))
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            ports.update(_extract_preview_ports_from_text(value))

    visit(payload)
    return ports


def _extract_tailscale_ports(payload: Any, config: PreviewConfig) -> set[int]:
    ports: set[int] = set()
    prefix = config.path_prefix
    allowed_hosts = {config.local_host, "localhost", "127.0.0.1", "0.0.0.0"}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            handlers = value.get("Handlers")
            if isinstance(handlers, dict):
                for path, handler in handlers.items():
                    if not isinstance(path, str):
                        continue
                    if prefix in {"/", ""}:
                        if path != "/":
                            continue
                    else:
                        if not path.startswith(f"{prefix}/"):
                            continue
                    if not isinstance(handler, dict):
                        continue
                    proxy = handler.get("Proxy")
                    if not isinstance(proxy, str):
                        continue
                    port = _parse_local_target_port(proxy, allowed_hosts)
                    if port is not None:
                        ports.add(port)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    return ports


def _should_fallback_serve_status(message: str) -> bool:
    lowered = message.lower()
    return (
        "unknown flag" in lowered
        or "unknown argument" in lowered
        or "unknown command" in lowered
        or "unknown subcommand" in lowered
        or "invalid argument format" in lowered
    )


def _tailscale_list_ports(config: PreviewConfig) -> set[int]:
    _ensure_tailscale(config)
    cmd = [config.tailscale_bin, "serve", "status", "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return _extract_preview_ports_from_text(result.stdout)
        ports = _extract_tailscale_ports(payload, config)
        if ports:
            return ports
        return _extract_preview_ports(payload)

    message = result.stderr.strip() or result.stdout.strip()
    if _should_fallback_serve_status(message):
        fallback = [config.tailscale_bin, "serve", "status"]
        result = subprocess.run(fallback, capture_output=True, text=True)
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            raise ConfigError(message or "tailscale command failed")
        output = "\n".join([result.stdout, result.stderr]).strip()
        return _extract_preview_ports_from_text(output)

    raise ConfigError(message or "tailscale command failed")


def _build_url(*, config: PreviewConfig, port: int) -> str | None:
    dns = _get_dns_name(config)
    if dns is None:
        return None
    path = _build_path(config, port)
    if path == "/":
        return f"https://{dns}"
    return f"https://{dns}{path}"


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


def _external_session(
    *, config: PreviewConfig, port: int, now: float
) -> PreviewSession:
    return PreviewSession(
        session_id=str(port),
        project=None,
        branch=None,
        port=port,
        url=_build_url(config=config, port=port),
        created_at=0.0,
        last_seen=now,
        context_line=None,
        dev_pid=None,
        owns_dev_process=False,
    )


def _stop_session(*, config: PreviewConfig, session: PreviewSession) -> None:
    try:
        _tailscale_http_off(config=config, port=session.port)
    except ConfigError as exc:
        logger.warning("preview.tailscale_off_failed", error=str(exc))
    if session.owns_dev_process:
        if session.dev_process is not None:
            _stop_process(session.dev_process)
        elif session.dev_pid is not None:
            _stop_pid(session.dev_pid)


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _stop_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        return
    if _pid_is_alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return False
    return True


def _build_session_id(context: object | None, port: int) -> str:
    project = _context_project(context)
    branch = _context_branch(context)
    if project and branch:
        base = f"{project}@{branch}"
    elif project:
        base = project
    else:
        base = "default"
    return f"{base}:{port}"


def _context_project(context: object | None) -> str | None:
    if context is None:
        return None
    value = getattr(context, "project", None)
    if isinstance(value, str) and value:
        return value
    return None


def _context_branch(context: object | None) -> str | None:
    if context is None:
        return None
    value = getattr(context, "branch", None)
    if isinstance(value, str) and value:
        return value
    return None


def _build_path(config: PreviewConfig, port: int) -> str:
    prefix = config.path_prefix
    if prefix in {"", "/"}:
        return "/"
    return f"{prefix}/{port}"


def _slugify(value: str) -> str:
    if not value:
        return "preview"
    safe = []
    for ch in value:
        if ch.isalnum() or ch in {"-", "_", "."}:
            safe.append(ch)
        else:
            safe.append("-")
    slug = "".join(safe).strip("-")
    return slug or "preview"


def _tail_log(log_path: Path | None, *, lines: int = 12) -> str | None:
    if log_path is None or not log_path.exists():
        return None
    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    rows = content.strip().splitlines()
    if not rows:
        return None
    tail = rows[-lines:]
    return "\n".join(tail)


def _find_by_port(sessions: list[PreviewSession], port: int) -> PreviewSession:
    for session in sessions:
        if session.port == port:
            return session
    raise ConfigError(f"No active preview on port {port}.")


def _find_by_id(sessions: list[PreviewSession], session_id: str) -> PreviewSession:
    for session in sessions:
        if session.session_id == session_id:
            return session
    raise ConfigError(f"No active preview with id {session_id!r}.")


def _find_by_context(
    sessions: list[PreviewSession], context: object | None
) -> PreviewSession:
    project = _context_project(context)
    branch = _context_branch(context)
    matches = [
        session
        for session in sessions
        if session.project == project and session.branch == branch
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ConfigError("Multiple previews match this context; specify a port.")
    if len(sessions) == 1:
        return sessions[0]
    raise ConfigError("Specify a port or id to stop.")


def _list_worktree_paths(repo_root: Path) -> set[Path] | None:
    output = git_stdout(["worktree", "list", "--porcelain"], cwd=repo_root)
    if not output:
        return None
    paths: set[Path] = set()
    for line in output.splitlines():
        if line.startswith("worktree "):
            raw = line[len("worktree ") :].strip()
            if raw:
                paths.add(Path(raw).resolve(strict=False))
    return paths


def _find_pruned_sessions(sessions: list[PreviewSession]) -> list[PreviewSession]:
    pruned: list[PreviewSession] = []
    worktree_cache: dict[Path, set[Path] | None] = {}
    for session in sessions:
        worktree_path = session.worktree_path
        if worktree_path is None:
            continue
        if not worktree_path.exists():
            pruned.append(session)
            continue
        repo_root = session.repo_root or resolve_main_worktree_root(worktree_path)
        if repo_root is None:
            continue
        repo_root = repo_root.resolve(strict=False)
        worktree_path_resolved = worktree_path.resolve(strict=False)
        if worktree_path_resolved == repo_root:
            pruned.append(session)
            continue
        if repo_root in worktree_cache:
            worktrees = worktree_cache[repo_root]
        else:
            worktrees = _list_worktree_paths(repo_root)
            worktree_cache[repo_root] = worktrees
        if worktrees is None:
            continue
        if worktree_path_resolved not in worktrees:
            pruned.append(session)
    return pruned


def _format_started(
    session: PreviewSession,
    *,
    dev_status: str | None = None,
) -> str:
    url = session.url or "(url unavailable)"
    context = f"\n{session.context_line}" if session.context_line else ""
    if dev_status is None:
        dev_status = "started by preview" if session.owns_dev_process else "external"
    dev_line = f"Dev server: {dev_status}"
    label = "Tailscale preview enabled"
    return (
        f"{label} on port {session.port}.\n"
        f"{dev_line}\n"
        f"Open: {url}{context}\n"
        f"ID: {session.session_id}"
    )


def _describe_dev_status(*, session: PreviewSession, config: PreviewConfig) -> str:
    if session.owns_dev_process:
        return "started by preview"
    host = config.local_host
    port = session.port
    if _is_port_available(host, port):
        return f"not detected on {host}:{port}"
    return f"port in use on {host}:{port}"


def _format_stopped(session: PreviewSession) -> str:
    url = session.url or "(url unavailable)"
    return f"Preview stopped on port {session.port}.\nURL: {url}"


def _format_killall(sessions: list[PreviewSession]) -> str:
    if not sessions:
        return "No active previews."
    lines = ["Stopped previews:"]
    for session in sorted(sessions, key=lambda item: item.port):
        url = session.url or "(url unavailable)"
        lines.append(f"- port {session.port} | {url}")
    return "\n".join(lines)


def _format_list(sessions: list[PreviewSession]) -> str:
    if not sessions:
        return "No active previews."
    lines = ["Active previews:"]
    for session in sorted(sessions, key=lambda item: item.port):
        age = _format_age(session.created_at)
        url = session.url or "(url unavailable)"
        context = session.context_line or "(no context)"
        lines.append(
            f"- {session.session_id} | port {session.port} | {url} | {age} | {context}"
        )
    return "\n".join(lines)


def _format_age(started_at: float) -> str:
    if started_at <= 0:
        return "unknown"
    seconds = int(time.time() - started_at)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def _help_text() -> str:
    return (
        "preview commands:\n"
        "/preview start [port] [--dev <command> | -- <command>]\n"
        "/preview list\n"
        "/preview stop [id|port]\n"
        "/preview killall\n"
        "/preview help"
    )


atexit.register(MANAGER.shutdown)
