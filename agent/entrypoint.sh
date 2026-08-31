#!/bin/bash
# Agent container setup:
#   1) trust the proxy CA
#   2) default route to the proxy container (the only way out)
#   3) verify interception actually works — otherwise refuse to start (fail closed)
#   4) hook config + filesystem watcher
#   5) drop to the unprivileged `agent` user: it can no longer restore the route
set -e

CERT=/certs/mitmproxy-ca-cert.pem
CFG="${CLAUDE_CONFIG_DIR:-/home/agent/.claude}"

echo "[agent] waiting for the proxy CA ($CERT)…"
for _ in $(seq 1 60); do [ -f "$CERT" ] && break; sleep 1; done
if [ -f "$CERT" ]; then
  cp "$CERT" /usr/local/share/ca-certificates/mitmproxy.crt
  update-ca-certificates 2>/dev/null | tail -1
  echo "[agent] proxy CA installed into the system trust store"
else
  echo "[agent] ABORT: the proxy CA did not appear within 60s" >&2
  exit 1
fi

if [ "${AGENT_ROUTE:-proxy}" = "proxy" ]; then
  PROXY_IP=$(getent hosts proxy | awk '{print $1; exit}')
  if [ -z "$PROXY_IP" ]; then
    echo "[agent] ABORT: hostname 'proxy' does not resolve" >&2
    exit 1
  fi
  ip route del default 2>/dev/null || true
  if ip route add default via "$PROXY_IP"; then
    echo "[agent] default route → proxy ($PROXY_IP)"
  else
    echo "[agent] ABORT: could not route through the proxy (missing NET_ADMIN?)" >&2
    exit 1
  fi
fi

# Fail closed: make sure a request that goes around the env proxy still shows up
# in the log as transparent. If it does not, the agent has an unsupervised way
# out — the worst possible outcome: it works, and you cannot see it.
if [ "${AGENT_VERIFY:-1}" = "1" ] && [ "${AGENT_ROUTE:-proxy}" = "proxy" ]; then
  BEFORE=$(wc -l < /logs/traffic.jsonl 2>/dev/null || echo 0)
  curl -s --noproxy '*' --max-time 10 -o /dev/null http://example.com/ || true
  sleep 1
  if tail -n "+$((BEFORE + 1))" /logs/traffic.jsonl 2>/dev/null \
       | grep -q '"mode": "transparent"'; then
    echo "[agent] interception verified: env-proxy bypass shows up in the log"
  else
    echo "[agent] ABORT: the canary request around the env proxy never reached the log." >&2
    echo "        The agent would have an unsupervised way out. Check the proxy:" >&2
    echo "        docker compose logs proxy; docker compose exec proxy iptables -t nat -L -n -v" >&2
    exit 1
  fi
fi

mkdir -p "$CFG"
[ -f "$CFG/settings.json" ] || cp /opt/agent-lab/settings.json "$CFG/settings.json"
chown -R agent:agent /home/agent
touch /logs/actions.jsonl 2>/dev/null || true
chmod 666 /logs/actions.jsonl 2>/dev/null || true

if [ "${AGENT_FSWATCH:-1}" = "1" ]; then
  gosu agent python3 /opt/agent-lab/hooks/fswatch.py &
  echo "[agent] filesystem watcher running over ${FSWATCH_ROOT:-/work}"
fi

echo "[agent] ready. Proxy: ${HTTPS_PROXY}. Logs: /logs/{traffic,actions}.jsonl"
exec gosu agent "$@"
