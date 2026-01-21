import asyncio
import types
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

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
        if (
            git_stdout(["rev-parse", "--is-bare-repository"], cwd=cwd)
            == "true"
        ):
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


class WorktreePolicyTests(unittest.TestCase):
    def test_require_worktree_rejects_main_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            with self.assertRaises(ConfigError):
                backend._require_worktree(repo)

    def test_require_worktree_accepts_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            worktree = _add_worktree(repo, "feat-accepts")
            worktree_path, repo_root = backend._require_worktree(worktree)
            self.assertEqual(worktree_path, worktree.resolve(strict=False))
            self.assertEqual(repo_root, repo.resolve(strict=False))

    def test_pruned_worktree_sessions_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            worktree = _add_worktree(repo, "feat-pruned")
            session = backend.PreviewSession(
                session_id="sess-1",
                project="proj",
                branch="feat-pruned",
                port=5173,
                url="https://example/preview/5173",
                provider="tailscale",
                created_at=time.time(),
                last_seen=time.time(),
                context_line=None,
                dev_pid=None,
                tunnel_pid=None,
                owns_dev_process=False,
                worktree_path=worktree,
                repo_root=repo,
            )
            _run_git(["worktree", "remove", "--force", str(worktree)], repo)
            pruned = backend._find_pruned_sessions([session])
            self.assertEqual(pruned, [session])

    def test_active_worktree_sessions_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_repo(Path(tmp))
            worktree = _add_worktree(repo, "feat-live")
            session = backend.PreviewSession(
                session_id="sess-2",
                project="proj",
                branch="feat-live",
                port=5174,
                url="https://example/preview/5174",
                provider="tailscale",
                created_at=time.time(),
                last_seen=time.time(),
                context_line=None,
                dev_pid=None,
                tunnel_pid=None,
                owns_dev_process=False,
                worktree_path=worktree,
                repo_root=repo,
            )
            pruned = backend._find_pruned_sessions([session])
            self.assertEqual(pruned, [])

    def test_killall_includes_urls(self) -> None:
        session = backend.PreviewSession(
            session_id="sess-3",
            project="proj",
            branch="feat-url",
            port=5175,
            url="https://example/preview/5175",
            provider="tailscale",
            created_at=time.time(),
            last_seen=time.time(),
            context_line=None,
            dev_pid=None,
            tunnel_pid=None,
            owns_dev_process=False,
        )
        output = backend._format_killall([session])
        self.assertIn("https://example/preview/5175", output)


class CloudflareConfigTests(unittest.TestCase):
    def test_cloudflare_defaults(self) -> None:
        config = backend.PreviewConfig.from_config(
            {"provider": "cloudflare"},
            config_path=Path("takopi.toml"),
        )
        self.assertEqual(config.provider, "cloudflare")
        self.assertEqual(config.cloudflared_bin, "cloudflared")
        self.assertEqual(config.cloudflared_args, ("--no-autoupdate",))
        self.assertEqual(
            config.cloudflared_timeout_seconds,
            backend.DEFAULT_CLOUDFLARED_TIMEOUT_SECONDS,
        )

    def test_cloudflare_args_override(self) -> None:
        config = backend.PreviewConfig.from_config(
            {
                "provider": "cloudflare",
                "cloudflared_args": ["--protocol", "http2"],
                "cloudflared_timeout_seconds": 45,
            },
            config_path=Path("takopi.toml"),
        )
        self.assertEqual(config.cloudflared_args, ("--protocol", "http2"))
        self.assertEqual(config.cloudflared_timeout_seconds, 45)

    def test_cloudflare_invalid_timeout(self) -> None:
        with self.assertRaises(ConfigError):
            backend.PreviewConfig.from_config(
                {"provider": "cloudflare", "cloudflared_timeout_seconds": 0},
                config_path=Path("takopi.toml"),
            )

    def test_cloudflare_args_validation(self) -> None:
        with self.assertRaises(ConfigError):
            backend.PreviewConfig.from_config(
                {"provider": "cloudflare", "cloudflared_args": ["", "ok"]},
                config_path=Path("takopi.toml"),
            )


class CloudflareSessionTests(unittest.TestCase):
    def test_list_sessions_prunes_dead_tunnels(self) -> None:
        class _Proc:
            def __init__(self, alive: bool) -> None:
                self._alive = alive

            def poll(self) -> int | None:
                return None if self._alive else 1

        manager = backend.PreviewManager()
        config = backend.PreviewConfig.from_config(
            {"provider": "cloudflare"},
            config_path=Path("takopi.toml"),
        )
        alive = backend.PreviewSession(
            session_id="sess-live",
            project="proj",
            branch="feat-live",
            port=5173,
            url="https://example.trycloudflare.com",
            provider="cloudflare",
            created_at=time.time(),
            last_seen=time.time(),
            context_line=None,
            dev_pid=None,
            tunnel_pid=None,
            owns_dev_process=False,
            tunnel_process=_Proc(True),
        )
        dead = backend.PreviewSession(
            session_id="sess-dead",
            project="proj",
            branch="feat-dead",
            port=5174,
            url="https://example.trycloudflare.com",
            provider="cloudflare",
            created_at=time.time(),
            last_seen=time.time(),
            context_line=None,
            dev_pid=None,
            tunnel_pid=None,
            owns_dev_process=False,
            tunnel_process=_Proc(False),
        )
        manager._sessions = {5173: alive, 5174: dead}

        sessions = asyncio.run(manager.list_sessions(config=config))
        self.assertEqual([session.session_id for session in sessions], ["sess-live"])

    def test_extract_ports_from_text(self) -> None:
        text = "active /preview/3000 and https://host/preview/5173/test"
        ports = backend._extract_preview_ports_from_text(text)
        self.assertEqual(ports, {3000, 5173})

    def test_extract_ports_from_json(self) -> None:
        payload = {
            "Web": {"Handlers": {"/preview/4444": {"Proxy": "http://127.0.0.1:4444"}}},
            "Extra": ["/preview/5555", {"path": "/preview/6666/"}],
        }
        ports = backend._extract_preview_ports(payload)
        self.assertEqual(ports, {4444, 5555, 6666})


if __name__ == "__main__":
    unittest.main()
