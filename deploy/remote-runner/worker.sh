#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
exec python3 -I "$(dirname "$0")/worker.py" "$@"
