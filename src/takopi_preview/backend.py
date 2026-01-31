from __future__ import annotations

import atexit
import asyncio
import json
import re
import socket
import subprocess
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from takopi.api import (
    CommandBackend,
    CommandContext,
    CommandResult,
    ConfigError,
    HOME_CONFIG_PATH,
    RunContext,
    RunRequest,
    get_logger,
)
from takopi.utils.git import git_stdout, resolve_main_worktree_root

logger = get_logger(__name__)

SAFE_PORT_MIN = 1024
SAFE_PORT_MAX = 65535
DEFAULT_TTL_MINUTES = 120
PATH_PREFIX = "/preview"
DEV_SERVER_START_TIMEOUT_SECONDS = 90
DEV_SERVER_POLL_INTERVAL_SECONDS = 1.0
_PREVIEW_PORT_RE = re.compile(r"/preview/(\d+)")
LOCAL_PROXY_PORT_RE = re.compile(
    r"http://(?:127\.0\.0\.1|localhost|0\.0\.0\.0):(\d+)"
)

DEV_SERVER_START_PROMPT = (
    "You are operating within a Takopi worktree context.\n"
    "\n"
    "Goal: ensure the correct dev server is running for preview.\n"
    "\n"
    "Target:\n"
    "- host: {host}\n"
    "- port: {port}\n"
    "\n"
    "Rules:\n"
    "- If something is already listening on the target port, confirm it is the "
    "correct dev server and leave it running.\n"
    "- If nothing is listening, find the right dev command from README, "
    "AGENTS, or package scripts and start it.\n"
    "- Prefer the repo's primary toolchain (pnpm > bun > npm > yarn; "
    "uv > poetry > pip for Python).\n"
    "- Install dependencies only if required to start the dev server.\n"
    "- Bind to the target host and port; avoid public binds unless required.\n"
    "\n"
    "Edge cases:\n"
    "- Monorepo with multiple apps: pick the app for this context and say which.\n"
    "- If the default port differs, override it to {port} or explain why you "
    "cannot.\n"
    "- If startup fails, report the error and the next step.\n"
    "\n"
    "Context: {context_line}\n"
    "Worktree: {worktree}\n"
)

DEV_SERVER_STOP_PROMPT = (
    "You are operating within a Takopi worktree context.\n"
    "\n"
    "Goal: stop the dev server if it is still listening on port {port}.\n"
    "\n"
    "Rules:\n"
    "- If nothing is listening on the port, do nothing.\n"
    "- Prefer a graceful stop (repo stop command or SIGTERM).\n"
    "- Report what you stopped or why it could not be stopped.\n"
    "\n"
    "Context: {context_line}\n"
    "Worktree: {worktree}\n"
)


@dataclass(frozen=True, slots=True)
class PreviewConfig:
    ttl_minutes: int
    allowed_user_ids: set[int] | None
    tailscale_bin: str
    tailscale_https_port: int | None
    local_host: str
    path_prefix: str
    start_port: int | None
    start_instruction: str | None
    dev_server_start_timeout_seconds: int

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
        if any(key in config for key in ("dev_command", "auto_start", "env")):
            raise ConfigError(
                f"Invalid preview config in {config_path}; "
                "dev server auto-start has been removed. "
                "Use /preview start to ask Takopi to start your server, or start "
                "it manually."
            )

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

        tailscale_bin = (
            _optional_str(config, "tailscale_bin", config_path=config_path) or "tailscale"
        )
        tailscale_https_port = _optional_int(
            config, "tailscale_https_port", config_path=config_path
        )
        if tailscale_https_port is not None and tailscale_https_port != 0 and not (
            1 <= tailscale_https_port <= 65535
        ):
            raise ConfigError(
                f"Invalid `preview.tailscale_https_port` in {config_path}; "
                "expected a valid port or 0 to use the preview port."
            )
        local_host = (
            _optional_str(config, "local_host", config_path=config_path) or "127.0.0.1"
        )
        path_prefix = _normalize_path_prefix(
            _optional_str(config, "path_prefix", config_path=config_path) or PATH_PREFIX
        )
        start_port = _optional_int(config, "start_port", config_path=config_path)
        if start_port is not None:
            _validate_port(start_port)
        start_instruction = _optional_str(
            config, "start_instruction", config_path=config_path
        )
        if start_instruction is not None:
            start_instruction = start_instruction.strip() or None
        dev_server_start_timeout_seconds = _optional_int(
            config, "dev_server_start_timeout_seconds", config_path=config_path
        )
        if dev_server_start_timeout_seconds is None:
            dev_server_start_timeout_seconds = DEV_SERVER_START_TIMEOUT_SECONDS
        if dev_server_start_timeout_seconds <= 0:
            raise ConfigError(
                f"Invalid `preview.dev_server_start_timeout_seconds` in {config_path}; "
                "expected a positive integer."
            )

        return cls(
            ttl_minutes=ttl_minutes,
            allowed_user_ids=allowed_user_ids,
            tailscale_bin=tailscale_bin,
            tailscale_https_port=tailscale_https_port,
            local_host=local_host,
            path_prefix=path_prefix,
            start_port=start_port,
            start_instruction=start_instruction,
            dev_server_start_timeout_seconds=dev_server_start_timeout_seconds,
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
    worktree_path: Path | None = None
    repo_root: Path | None = None

    def touch(self, now: float | None = None) -> None:
        self.last_seen = now or time.time()


@dataclass(frozen=True, slots=True)
class PromptContext:
    context_line: str | None
    cwd: Path | None
    worktree_path: Path | None


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

        url = None
        try:
            await asyncio.to_thread(
                _tailscale_http_on,
                config=config,
                port=port,
            )
            url = _build_url(config=config, port=port)
        except Exception:
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
            worktree_path=worktree_path,
            repo_root=repo_root,
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
        context = _resolve_context(ctx, resolved.context)
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
            port, instruction = _parse_start_args(
                ctx.args[1:],
                default_port=config.start_port,
                default_instruction=config.start_instruction,
            )
            _validate_port(port)
            worktree_path, repo_root = _require_worktree(cwd)
            await _ensure_dev_server_ready(
                ctx=ctx,
                config=config,
                port=port,
                instruction=instruction,
                context=context,
                context_line=context_line,
                cwd=cwd,
                worktree_path=worktree_path,
            )
            session = await MANAGER.start(
                config=config,
                port=port,
                context_line=context_line,
                context=context,
                cwd=cwd,
                worktree_path=worktree_path,
                repo_root=repo_root,
            )
            return CommandResult(text=_format_started(session))
        if command == "list":
            sessions = await MANAGER.list_sessions(config=config)
            return CommandResult(text=_format_list(sessions))
        if command in {"stop", "off"}:
            session = await MANAGER.find_session(
                config=config,
                arg=_arg(ctx.args, 1),
                context=context,
            )
            await _maybe_stop_dev_server(
                ctx=ctx,
                config=config,
                port=session.port,
                context_line=session.context_line or context_line,
                cwd=cwd,
                worktree_path=session.worktree_path,
                run_context=_session_context(session),
            )
            session = await MANAGER.stop(config=config, session=session)
            return CommandResult(text=_format_stopped(session))
        if command in {"killall", "stopall"}:
            sessions = await MANAGER.stop_all(config=config)
            for session in sessions:
                await _maybe_stop_dev_server(
                    ctx=ctx,
                    config=config,
                    port=session.port,
                    context_line=session.context_line or context_line,
                    cwd=cwd,
                    worktree_path=session.worktree_path,
                    run_context=_session_context(session),
                )
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


def _resolve_context(
    ctx: CommandContext,
    resolved_context: object | None,
) -> object | None:
    if resolved_context is not None:
        return resolved_context
    default_context = getattr(ctx.executor, "default_context", None)
    if default_context is not None:
        return default_context
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
    *,
    default_port: int | None,
    default_instruction: str | None,
) -> tuple[int, str | None]:
    if not args:
        if default_port is None:
            raise ConfigError(_usage_preview_start())
        instruction = (default_instruction or "").strip() or None
        return default_port, instruction
    port_token = args[0]
    parsed = _parse_port(port_token)
    if parsed is None:
        if default_port is None:
            raise ConfigError(f"Invalid port {port_token!r}.")
        instruction = " ".join(args).strip()
        if not instruction:
            instruction = (default_instruction or "").strip() or None
        return default_port, instruction or None
    instruction = " ".join(args).strip()
    if len(args) == 1 and default_instruction:
        return parsed, default_instruction.strip() or None
    return parsed, instruction or None


def _usage_preview_start() -> str:
    return "usage: `/preview start [port] [instruction...]`"


def _normalize_path_prefix(prefix: str) -> str:
    trimmed = prefix.strip()
    if not trimmed:
        return PATH_PREFIX
    if not trimmed.startswith("/"):
        trimmed = f"/{trimmed}"
    if trimmed != "/" and trimmed.endswith("/"):
        trimmed = trimmed.rstrip("/")
    return trimmed


def _probe_hosts(config: PreviewConfig) -> tuple[str, ...]:
    host = config.local_host.strip()
    if host in {"0.0.0.0", "localhost"}:
        return ("127.0.0.1", "::1")
    return (host or "127.0.0.1",)


def _format_prompt_context(prompt_context: PromptContext) -> str:
    return prompt_context.context_line or "none"


def _format_prompt_worktree(prompt_context: PromptContext) -> str:
    if prompt_context.worktree_path is not None:
        return str(prompt_context.worktree_path)
    if prompt_context.cwd is not None:
        return str(prompt_context.cwd)
    return "unknown"


def _build_dev_server_start_prompt(
    *,
    host: str,
    port: int,
    prompt_context: PromptContext,
    instruction: str | None,
) -> str:
    prompt = DEV_SERVER_START_PROMPT.format(
        host=host,
        port=port,
        context_line=_format_prompt_context(prompt_context),
        worktree=_format_prompt_worktree(prompt_context),
    )
    if instruction:
        prompt = f"{prompt}\nUser instruction: {instruction}\n"
    return prompt


def _build_dev_server_stop_prompt(
    *,
    port: int,
    prompt_context: PromptContext,
) -> str:
    return DEV_SERVER_STOP_PROMPT.format(
        port=port,
        context_line=_format_prompt_context(prompt_context),
        worktree=_format_prompt_worktree(prompt_context),
    )


def _as_run_context(context: object | None) -> RunContext | None:
    if isinstance(context, RunContext):
        return context
    project = _context_project(context)
    branch = _context_branch(context)
    if project is None and branch is None:
        return None
    return RunContext(project=project, branch=branch)


def _session_context(session: PreviewSession) -> RunContext | None:
    if session.project is None and session.branch is None:
        return None
    return RunContext(project=session.project, branch=session.branch)


def _is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.25):
            return True
    except OSError:
        return False


async def _wait_for_port_open(
    hosts: tuple[str, ...],
    port: int,
    *,
    timeout_seconds: float,
    interval_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        for host in hosts:
            if await asyncio.to_thread(_is_port_open, host, port):
                return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(interval_seconds)


def _log_background_task_exception(task: asyncio.Task[object]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        return
    except Exception:
        logger.exception("preview.dev_server_start_failed")


async def _ensure_dev_server_ready(
    *,
    ctx: CommandContext,
    config: PreviewConfig,
    port: int,
    instruction: str | None,
    context: object | None,
    context_line: str | None,
    cwd: Path | None,
    worktree_path: Path | None,
) -> None:
    hosts = _probe_hosts(config)
    prompt_context = PromptContext(
        context_line=context_line,
        cwd=cwd,
        worktree_path=worktree_path,
    )
    prompt = _build_dev_server_start_prompt(
        host=hosts[0],
        port=port,
        prompt_context=prompt_context,
        instruction=instruction,
    )
    request = RunRequest(prompt=prompt, context=_as_run_context(context))
    background_runner = getattr(ctx.executor, "run_background", None)
    run_task: asyncio.Task[object] | None = None
    if callable(background_runner):
        result = background_runner(request)
        if asyncio.iscoroutine(result):
            result = await result
        if isinstance(result, asyncio.Task):
            run_task = result
    if run_task is None:
        run_task = asyncio.create_task(ctx.executor.run_one(request))
    run_task.add_done_callback(_log_background_task_exception)
    ready = await _wait_for_port_open(
        hosts,
        port,
        timeout_seconds=config.dev_server_start_timeout_seconds,
        interval_seconds=DEV_SERVER_POLL_INTERVAL_SECONDS,
    )
    if not ready:
        if not run_task.done():
            run_task.cancel()
        host_label = ", ".join(hosts)
        raise ConfigError(
            f"Dev server did not start on {host_label}:{port} within "
            f"{config.dev_server_start_timeout_seconds:.0f}s."
        )


async def _maybe_stop_dev_server(
    *,
    ctx: CommandContext,
    config: PreviewConfig,
    port: int,
    context_line: str | None,
    cwd: Path | None,
    worktree_path: Path | None,
    run_context: RunContext | None,
) -> None:
    hosts = _probe_hosts(config)
    open_found = False
    for host in hosts:
        if await asyncio.to_thread(_is_port_open, host, port):
            open_found = True
            break
    if not open_found:
        return
    prompt_context = PromptContext(
        context_line=context_line,
        cwd=cwd,
        worktree_path=worktree_path,
    )
    prompt = _build_dev_server_stop_prompt(
        port=port,
        prompt_context=prompt_context,
    )
    await ctx.executor.run_one(RunRequest(prompt=prompt, context=run_context))


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


def _tailscale_https_port(config: PreviewConfig, port: int) -> int:
    if config.tailscale_https_port is not None:
        if config.tailscale_https_port == 0:
            return port
        return config.tailscale_https_port
    return 443


def _tailscale_http_on(*, config: PreviewConfig, port: int) -> None:
    _ensure_tailscale(config)
    target = f"http://{config.local_host}:{port}"
    path = _build_path(config, port)
    https_port = _tailscale_https_port(config, port)
    cmd = [
        config.tailscale_bin,
        "serve",
        "--bg",
        "--https",
        str(https_port),
        "--set-path",
        path,
        target,
    ]
    legacy = [
        config.tailscale_bin,
        "serve",
        "--bg",
        f"--https={https_port}",
        path,
        target,
    ]
    _run_tailscale(cmd, "preview.tailscale_on", fallback=legacy)


def _tailscale_http_off(*, config: PreviewConfig, port: int) -> None:
    _ensure_tailscale(config)
    path = _build_path(config, port)
    https_port = _tailscale_https_port(config, port)
    cmd = [
        config.tailscale_bin,
        "serve",
        "--https",
        str(https_port),
        "--set-path",
        path,
        "off",
    ]
    legacy = [
        config.tailscale_bin,
        "serve",
        f"--https={https_port}",
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
    https_port = _tailscale_https_port(config, port)
    host = dns if https_port == 443 else f"{dns}:{https_port}"
    if path == "/":
        return f"https://{host}"
    return f"https://{host}{path}"


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
    )


def _stop_session(*, config: PreviewConfig, session: PreviewSession) -> None:
    try:
        _tailscale_http_off(config=config, port=session.port)
    except ConfigError as exc:
        logger.warning("preview.tailscale_off_failed", error=str(exc))


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


def _format_started(session: PreviewSession) -> str:
    url = session.url or "(url unavailable)"
    context = f"\n{session.context_line}" if session.context_line else ""
    label = "Tailscale preview enabled"
    return (
        f"{label} on port {session.port}.\n"
        f"Open: {url}{context}\n"
        f"ID: {session.session_id}"
    )


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
        "/preview start [port] [instruction...]\n"
        "/preview list\n"
        "/preview stop [id|port]\n"
        "/preview killall\n"
        "/preview help"
    )


atexit.register(MANAGER.shutdown)
