#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MODE="${1:---check}"
if [[ $# -gt 1 || "$MODE" != "--check" && "$MODE" != "--start" ]]; then
    echo "Usage: bash scripts/setup.sh [--check|--start]" >&2
    exit 2
fi
cd "$PROJECT_DIR"

command -v python3 >/dev/null || { echo "Python 3.10+ is required." >&2; exit 1; }
python3 -S -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required.")'
python3 -S -m anlan validate -o output/validation.json
command -v docker >/dev/null || { echo "Docker Compose v2 is required for lab checks." >&2; exit 1; }
docker compose version
docker compose config --quiet
echo "Static configuration checks passed; no service has been started."
echo "This is an incomplete LAB TEMPLATE. Configure official Wazuh TLS,"
echo "indexer security, credentials and Filebeat before deployment."

if [[ "$MODE" == "--check" ]]; then
    exit 0
fi

# Derive host ports from Compose rather than assume defaults after user edits.
command -v ss >/dev/null || { echo "ss is required to check host listeners." >&2; exit 1; }
COMPOSE_JSON="$(docker compose config --format json)"
PORTS="$(printf '%s' "$COMPOSE_JSON" | python3 -S -c '
import json, sys
ports = set()
for service in json.load(sys.stdin)["services"].values():
    for port in service.get("ports", []):
        number = int(port["published"])
        if not 9000 <= number <= 65535 or number in {57321, 11432, 11433}:
            raise SystemExit(f"Refusing reserved or out-of-range host port {number}.")
        if port.get("host_ip") != "127.0.0.1":
            raise SystemExit("Only loopback host publishing is allowed.")
        ports.add(number)
print("\n".join(map(str, sorted(ports))))
')"
check_ports() {
    local port listeners
    while IFS= read -r port; do
        [[ -n "$port" ]] || continue
        listeners="$(ss -H -ltnu "sport = :$port")" || {
            echo "Cannot inspect port $port; startup refused." >&2
            exit 1
        }
        if [[ -n "$listeners" ]]; then
            echo "Port $port is already occupied; no service was changed." >&2
            exit 1
        fi
    done <<< "$PORTS"
}
check_ports
echo "Requested host ports:"
printf '%s\n' "$PORTS"
read -r -p "Confirm the lab prerequisites and service startup by typing START: " confirmation
if [[ "$confirmation" != "START" ]]; then
    echo "Cancelled; no service was changed."
    exit 1
fi
check_ports
docker compose up -d
echo "Startup requested. Check component health; this does not prove successful deployment."
echo "Default Dashboard endpoint: https://127.0.0.1:9443 (verify your resolved Compose ports)."
