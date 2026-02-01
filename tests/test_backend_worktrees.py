import asyncio
import subprocess
import sys
import time
import types
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists():
    sys.path.insert(0, str(SRC))


def _ensure_takopi_stubs() -> None:
    if "takopi" in sys.modules:
        return
    takopi_mod = types.ModuleType("takopi")
    api_mod = types.ModuleType("takopi.api")
    utils_mod = types.ModuleType("takopi.utils")
    git_mod = types.ModuleType("takopi.utils.git")
    json_mod = types.ModuleType("takopi.utils.json_state")

    class ConfigError(RuntimeError):
        pass

    class CommandBackend:
        pass

    class CommandContext:
        pass

    class CommandResult:
        def __init__(self, text: str, notify: bool = True, reply_to=None) -> None:
            self.text = text
            self.notify = notify
            self.reply_to = reply_to

    class RunContext:
        def __init__(self, project: str | None = None, branch: str | None = None) -> None:
            self.project = project
            self.branch = branch

    class RunRequest:
        def __init__(
            self,
            prompt: str,
            engine: str | None = None,
            context: RunContext | None = None,
        ) -> None:
            self.prompt = prompt
            self.engine = engine
            self.context = context

    class _Logger:
        def info(self, *_args, **_kwargs) -> None:
            return None

        def warning(self, *_args, **_kwargs) -> None:
            return None

    def get_logger(_name: str) -> _Logger:
        return _Logger()

    def git_stdout(args: list[str], *, cwd: Path) -> str | None:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        output = result.stdout.strip()
        return output or None

    def resolve_main_worktree_root(cwd: Path) -> Path | None:
        common_dir = git_stdout(
            ["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=cwd
        )
        if not common_dir:
            return None
        if git_stdout(["rev-parse", "--is-bare-repository"], cwd=cwd) == "true":
            return cwd
        common_path = Path(common_dir)
        if not common_path.is_absolute():
            common_path = (cwd / common_path).resolve()
        return common_path.parent

    def atomic_write_json(_path: Path, _payload) -> None:
        return None

    api_mod.CommandBackend = CommandBackend
    api_mod.CommandContext = CommandContext
    api_mod.CommandResult = CommandResult
    api_mod.ConfigError = ConfigError
    api_mod.HOME_CONFIG_PATH = Path.home() / ".takopi" / "takopi.toml"
    api_mod.RunContext = RunContext
    api_mod.RunRequest = RunRequest
    api_mod.get_logger = get_logger

    git_mod.git_stdout = git_stdout
    git_mod.resolve_main_worktree_root = resolve_main_worktree_root
    json_mod.atomic_write_json = atomic_write_json

    takopi_mod.api = api_mod
    takopi_mod.utils = utils_mod
    utils_mod.git = git_mod
    utils_mod.json_state = json_mod

    sys.modules["takopi"] = takopi_mod
    sys.modules["takopi.api"] = api_mod
    sys.modules["takopi.utils"] = utils_mod
    sys.modules["takopi.utils.git"] = git_mod
    sys.modules["takopi.utils.json_state"] = json_mod


_ensure_takopi_stubs()

from takopi.api import ConfigError
from takopi_preview import backend


def _run_git(args: list[str], cwd: Path) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(["init", "-b", "main"], repo)
    _run_git(["config", "user.email", "test@example.com"], repo)
    _run_git(["config", "user.name", "Test"], repo)
    (repo / "README.md").write_text("test\n", encoding="utf-8")
    _run_git(["add", "README.md"], repo)
    _run_git(["commit", "-m", "init"], repo)
    return repo


def _add_worktree(repo: Path, name: str) -> Path:
    worktrees_root = repo / ".worktrees"
    worktrees_root.mkdir(exist_ok=True)
    worktree_path = worktrees_root / name
    _run_git(["worktree", "add", "-b", name, str(worktree_path)], repo)
    return worktree_path


def test_require_worktree_rejects_main_repo(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    with pytest.raises(ConfigError):
        backend._require_worktree(repo)


def test_require_worktree_accepts_worktree(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    worktree = _add_worktree(repo, "feat-accepts")
    worktree_path, repo_root = backend._require_worktree(worktree)
    assert worktree_path == worktree.resolve(strict=False)
    assert repo_root == repo.resolve(strict=False)


def test_pruned_worktree_sessions_are_removed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    worktree = _add_worktree(repo, "feat-pruned")
    session = backend.PreviewSession(
        session_id="sess-1",
        project="proj",
        branch="feat-pruned",
        port=5173,
        url="https://example/preview/5173",
        created_at=time.time(),
        last_seen=time.time(),
        context_line=None,
        worktree_path=worktree,
        repo_root=repo,
    )
    _run_git(["worktree", "remove", "--force", str(worktree)], repo)
    pruned = backend._find_pruned_sessions([session])
    assert pruned == [session]


def test_active_worktree_sessions_are_retained(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    worktree = _add_worktree(repo, "feat-live")
    session = backend.PreviewSession(
        session_id="sess-2",
        project="proj",
        branch="feat-live",
        port=5174,
        url="https://example/preview/5174",
        created_at=time.time(),
        last_seen=time.time(),
        context_line=None,
        worktree_path=worktree,
        repo_root=repo,
    )
    pruned = backend._find_pruned_sessions([session])
    assert pruned == []


def test_killall_includes_urls() -> None:
    session = backend.PreviewSession(
        session_id="sess-3",
        project="proj",
        branch="feat-url",
        port=5175,
        url="https://example/preview/5175",
        created_at=time.time(),
        last_seen=time.time(),
        context_line=None,
    )
    output = backend._format_killall([session])
    assert "https://example/preview/5175" in output


def test_rejects_cloudflare_provider() -> None:
    with pytest.raises(ConfigError):
        backend.PreviewConfig.from_config(
            {"provider": "cloudflare"},
            config_path=Path("takopi.toml"),
        )


def test_rejects_cloudflared_options() -> None:
    with pytest.raises(ConfigError):
        backend.PreviewConfig.from_config(
            {"cloudflared_bin": "/usr/bin/cloudflared"},
            config_path=Path("takopi.toml"),
        )


def test_preview_server_config_defaults() -> None:
    config = backend.PreviewServerConfig.from_config(
        {},
        config_path=Path("takopi.toml"),
    )
    assert config.host == "localhost"
    assert config.start_port is None


def test_preview_server_config_rejects_invalid_port() -> None:
    with pytest.raises(ConfigError):
        backend.PreviewServerConfig.from_config(
            {"start_port": 80},
            config_path=Path("takopi.toml"),
        )


def test_preview_server_config_trims_instructions() -> None:
    config = backend.PreviewServerConfig.from_config(
        {"start_instruction": "  start  ", "stop_instruction": "   "},
        config_path=Path("takopi.toml"),
    )
    assert config.start_instruction == "start"
    assert config.stop_instruction is None


def test_allows_preview_port_https() -> None:
    config = backend.PreviewConfig.from_config(
        {"tailscale_https_port": 0},
        config_path=Path("takopi.toml"),
    )
    assert config.tailscale_https_port == 0


def test_rejects_invalid_https_port() -> None:
    with pytest.raises(ConfigError):
        backend.PreviewConfig.from_config(
            {"tailscale_https_port": 70000},
            config_path=Path("takopi.toml"),
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"dev_command": "pnpm dev"},
        {"auto_start": True},
        {"env": {"NODE_ENV": "development"}},
        {"start_instruction": "use pnpm dev"},
        {"dev_server_start_timeout_seconds": 120},
        {"start_wait_for_port": True},
    ],
)
def test_rejects_removed_dev_server_settings(payload: dict) -> None:
    with pytest.raises(ConfigError):
        backend.PreviewConfig.from_config(
            payload,
            config_path=Path("takopi.toml"),
        )


def test_parse_start_args_requires_port() -> None:
    with pytest.raises(ConfigError):
        backend._parse_start_args((), default_port=None)


def test_parse_start_args_port_only() -> None:
    port = backend._parse_start_args(("5173",), default_port=None)
    assert port == 5173


def test_parse_start_args_rejects_invalid_port() -> None:
    with pytest.raises(ConfigError):
        backend._parse_start_args(("dev",), default_port=None)


def test_parse_start_args_uses_default_port() -> None:
    port = backend._parse_start_args((), default_port=5173)
    assert port == 5173


def test_parse_start_args_rejects_extra_args() -> None:
    with pytest.raises(ConfigError):
        backend._parse_start_args(("5173", "extra"), default_port=None)


def test_start_requires_valid_port() -> None:
    with pytest.raises(ConfigError):
        backend._validate_port(0)




def test_extract_ports_from_text() -> None:
    text = "active /preview/3000 and https://host/preview/5173/test"
    ports = backend._extract_preview_ports_from_text(text)
    assert ports == {3000, 5173}


def test_extract_ports_from_json() -> None:
    payload = {
        "Web": {"Handlers": {"/preview/4444": {"Proxy": "http://127.0.0.1:4444"}}},
        "Extra": ["/preview/5555", {"path": "/preview/6666/"}],
    }
    ports = backend._extract_preview_ports(payload)
    assert ports == {4444, 5555, 6666}


def test_extract_tailscale_ports_root_path() -> None:
    config = backend.PreviewConfig.from_config(
        {"provider": "tailscale", "path_prefix": "/"},
        config_path=Path("takopi.toml"),
    )
    payload = {
        "Web": {
            "host.ts.net:443": {
                "Handlers": {
                    "/": {"Proxy": "http://127.0.0.1:5173"},
                    "/preview/9999": {"Proxy": "http://127.0.0.1:9999"},
                }
            }
        }
    }
    ports = backend._extract_tailscale_ports(payload, config)
    assert ports == {5173}


def test_build_url_uses_port_for_root_path() -> None:
    config = backend.PreviewConfig.from_config(
        {"path_prefix": "/"},
        config_path=Path("takopi.toml"),
    )
    original = backend._get_dns_name
    backend._get_dns_name = lambda _config: "host.ts.net"
    try:
        assert backend._build_url(config=config, port=5173) == "https://host.ts.net"
        override = replace(config, tailscale_https_port=0)
        assert (
            backend._build_url(config=override, port=5173)
            == "https://host.ts.net:5173"
        )
    finally:
        backend._get_dns_name = original


def test_start_clears_tailscale_conflict() -> None:
    manager = backend.PreviewManager()
    config = backend.PreviewConfig.from_config(
        {"provider": "tailscale"},
        config_path=Path("takopi.toml"),
    )
    calls = {"off": 0, "on": 0}
    list_calls = {"count": 0}

    def _list_ports(_config):
        list_calls["count"] += 1
        if list_calls["count"] == 1:
            return {5173}
        return set()

    original_list = backend._tailscale_list_ports
    original_on = backend._tailscale_http_on
    original_off = backend._tailscale_http_off
    original_build_url = backend._build_url
    backend._tailscale_list_ports = _list_ports
    backend._tailscale_http_on = lambda **_kwargs: calls.__setitem__(
        "on", calls["on"] + 1
    )
    backend._tailscale_http_off = lambda **_kwargs: calls.__setitem__(
        "off", calls["off"] + 1
    )
    backend._build_url = (
        lambda *, config, port: f"https://example.ts.net/preview/{port}"
    )
    try:
        session = asyncio.run(
            manager.start(
                config=config,
                port=5173,
                context_line=None,
                context=None,
                cwd=None,
                worktree_path=None,
                repo_root=None,
            )
        )
    finally:
        backend._tailscale_list_ports = original_list
        backend._tailscale_http_on = original_on
        backend._tailscale_http_off = original_off
        backend._build_url = original_build_url
    assert calls["off"] == 1
    assert calls["on"] == 1
    assert session.port == 5173
