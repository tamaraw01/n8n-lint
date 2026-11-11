#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 (>= 3.10) is required." >&2
  exit 1
fi

if command -v pipx >/dev/null 2>&1; then
  pipx install --force "$ROOT_DIR"
  echo "Installed n8n-lint via pipx. Run: n8n-lint scan examples/clean_workflow.json"
  exit 0
fi

if command -v uv >/dev/null 2>&1; then
  uv tool install --force "$ROOT_DIR"
  echo "Installed n8n-lint via uv. Run: n8n-lint scan examples/clean_workflow.json"
  exit 0
fi

VENV_DIR="$ROOT_DIR/.venv"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --no-build-isolation "$ROOT_DIR" 2>/dev/null || true

if [ -x "$VENV_DIR/bin/n8n-lint" ]; then
  echo "Installed into $VENV_DIR/bin/n8n-lint"
  "$VENV_DIR/bin/n8n-lint" --version
else
  echo "Running zero-install fallback via PYTHONPATH=$ROOT_DIR/src"
  PYTHONPATH="$ROOT_DIR/src" python3 -m n8n_lint --version
fi
