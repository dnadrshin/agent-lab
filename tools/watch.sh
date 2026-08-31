#!/bin/bash
# Live timeline of the agent's actions and its network.
cd "$(dirname "$0")/.." || exit 1
exec python3 tools/correlate.py -f "$@"
