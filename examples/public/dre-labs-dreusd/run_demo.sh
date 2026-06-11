#!/usr/bin/env bash
# ProtocolGate demo: deterministic gate + advisory institutional memory.
#
# Everything this script prints is real output:
#   - ProtocolGate's builtin rule engine evaluates the manifest (CG001-CG038).
#   - If a local Vestige server is running, --with-memory attaches advisory
#     evidence (audit findings, contest facts, ops decisions) to each finding.
#
# The deterministic verdict is authoritative. Memory never gates.
#
# Usage:
#   ./run_demo.sh                 # table output, memory if available
#   ./run_demo.sh --no-memory     # deterministic gate only
#   MEMORY_URL=http://localhost:3937 ./run_demo.sh   # dedicated demo instance

set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../../.. && pwd)"
MANIFEST="examples/public/dre-labs-dreusd/protocolgate.dreusd.yaml"
MEMORY_URL="${MEMORY_URL:-http://localhost:3927}"

MEMORY_FLAGS=(--with-memory --memory-url "$MEMORY_URL")
if [[ "${1:-}" == "--no-memory" ]]; then
  MEMORY_FLAGS=()
fi

echo "== ProtocolGate x Vestige: dreUSD control-plane demo =="
echo "manifest: $MANIFEST"
echo "memory:   ${MEMORY_FLAGS[*]:-disabled}"
echo

cd "$REPO_ROOT"
# Exit code 1 (findings) is the expected demo outcome; don't let set -e kill us.
uv run protocolgate validate "$MANIFEST" "${MEMORY_FLAGS[@]}" || status=$?

echo
echo "Deterministic verdict above is authoritative (exit ${status:-0})."
echo "Institutional evidence, when shown, is advisory context only."
exit 0
