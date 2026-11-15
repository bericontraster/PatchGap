#!/usr/bin/env sh
# Compatibility entry point. The inventory implementation is in Python 3.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$SCRIPT_DIR/linux-outdated-enum.py" "$@"
