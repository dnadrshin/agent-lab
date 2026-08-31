#!/bin/sh
# The lab gateway: the agent's only way out.
#   :8080 — ordinary HTTP(S) proxy (via HTTP_PROXY/HTTPS_PROXY)
#   :8081 — transparent (for traffic that ignores the proxy env vars)
#   :8082 — mitmweb UI, when MITM_UI=web
set -e

AGENT_SUBNET="${AGENT_SUBNET:-172.31.66.0/24}"
FORWARD_OTHER="${FORWARD_OTHER:-drop}"   # drop | masq

echo "[proxy] agent subnet: $AGENT_SUBNET, forward-other: $FORWARD_OTHER"

# ip_forward is set through compose sysctls; belt and braces.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Redirect all 80/443 coming from the agent subnet to the transparent listener.
iptables -t nat -A PREROUTING -s "$AGENT_SUBNET" -p tcp --dport 80  -j REDIRECT --to-ports 8081
iptables -t nat -A PREROUTING -s "$AGENT_SUBNET" -p tcp --dport 443 -j REDIRECT --to-ports 8081

# Everything else the agent tries to forward out (SSH, arbitrary ports,
# DNS-over-TCP to a foreign resolver) is cut by default: mitm cannot see it,
# so it has no business existing inside the lab.
if [ "$FORWARD_OTHER" = "masq" ]; then
  iptables -t nat -A POSTROUTING -s "$AGENT_SUBNET" ! -d "$AGENT_SUBNET" -j MASQUERADE
  echo "[proxy] WARNING: non-HTTP egress is allowed and NOT logged (FORWARD_OTHER=masq)"
else
  iptables -A FORWARD -s "$AGENT_SUBNET" ! -d "$AGENT_SUBNET" -j REJECT --reject-with icmp-admin-prohibited
fi

mkdir -p /certs /logs
chmod 755 /certs

COMMON="--set confdir=/certs \
  -s /addons/mitm_logger.py \
  --set connection_strategy=lazy \
  --set stream_large_bodies=10m \
  --showhost"

if [ "${MITM_UI:-dump}" = "web" ]; then
  echo "[proxy] mitmweb UI: http://localhost:8082 (token appears below in this log)"
  exec mitmweb --mode regular@8080 --mode transparent@8081 \
       --web-host 0.0.0.0 --web-port 8082 --no-web-open-browser $COMMON
else
  exec mitmdump --mode regular@8080 --mode transparent@8081 \
       --set flow_detail=1 $COMMON
fi
