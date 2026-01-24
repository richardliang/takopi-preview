# Repository Guidelines

## Project Structure & Module Organization
- `src/takopi_preview/`: Python package for the Takopi preview backend; entrypoint is `backend.py`.
- `tests/`: unittest suite (for example, `tests/test_backend_worktrees.py`).
- `dist/`: build artifacts from `uv build` (generated; do not edit).
- `README.md`: user-facing setup, configuration, and workflow.

## Build, Test, and Development Commands
- `python -m unittest discover -s tests -v`: run the full test suite.
- `uv build`: build sdist/wheel outputs into `dist/`.
- `pip install -e .` (or `pip install .`): install the package locally for manual testing with Takopi.

## Coding Style & Naming Conventions
- Python 3.14+ with type hints; use 4-space indentation.
- `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants.
- Keep configuration defaults and validation centralized in `PreviewConfig`; update `README.md` when config keys change.

## Testing Guidelines
- Use stdlib `unittest`; prefer deterministic tests that do not require a live Tailscale daemon.
- Name tests `tests/test_*.py` and keep fixtures small and focused.
- Add coverage for config validation and preview session behavior when touching backend logic.

## Commit & Pull Request Guidelines
- Use short, imperative commit messages (for example, "Fix tailscale preview port binding").
- PRs should include a brief behavior summary, tests run, and README updates for any command or config changes.
- Call out any required environment changes (Python version, Tailscale settings) in the PR description.

## Security & Configuration Tips
- Previews are tailnet-only; keep services bound to `127.0.0.1` and avoid exposing ports publicly.
- If using root-path previews (`path_prefix = "/"`), document the limitation to one concurrent preview.
