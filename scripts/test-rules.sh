#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"
exec python3 "$SCRIPT_DIR/verify-logtest.py" --container "${WAZUH_CONTAINER:-wazuh-server}" "$@"
