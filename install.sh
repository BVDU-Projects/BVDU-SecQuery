#!/usr/bin/env sh
set -eu
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 -m venv "$PROJECT_ROOT/.venv"
"$PROJECT_ROOT/.venv/bin/python" -m pip install --upgrade pip
"$PROJECT_ROOT/.venv/bin/python" -m pip install "$PROJECT_ROOT"
if ! "$PROJECT_ROOT/.venv/bin/python" -m pip install 'yara-python>=4.5'; then
  printf 'Optional YARA install failed; built-in checks and other engines remain available.\n' >&2
fi
printf 'Installed. Run %s/.venv/bin/secquery --help\n' "$PROJECT_ROOT"
