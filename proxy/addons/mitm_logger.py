"""
mitmproxy addon: structured JSONL log of the agent's outbound traffic.

Writes /logs/traffic.jsonl. Besides the requests themselves it detects:
  - leaks (emails / keys / host paths / ~/.ssh, ~/.aws references) in bodies and headers
  - request floods against a single domain (the "accidental DDoS" incident class)
  - requests outside the allowlist (blocked with 403 when MITM_ALLOW_HOSTS is set)

Environment:
  MITM_ALLOW_HOSTS   csv of allowed hosts (suffix match). Empty = allow everything.
  MITM_QUIET_HOSTS   csv of hosts treated as the agent's own infrastructure: their
                     bodies are not stored and their headers are not scanned for
                     secrets (LLM endpoints by default). Bodies are still scanned.
  MITM_BODY_PREVIEW  how many body bytes to keep in the log (default 2048).
  MITM_FLOOD_N       request threshold per domain within the window (default 30).
  MITM_FLOOD_WINDOW  window in seconds (default 10).
  MITM_SECRET_PATTERNS_FILE  extra file with one regex per line.
"""

import json
import logging
import os
import re
import time
from collections import defaultdict, deque

from mitmproxy import http

LOG_PATH = os.environ.get("MITM_LOG", "/logs/traffic.jsonl")
BODY_PREVIEW = int(os.environ.get("MITM_BODY_PREVIEW", "2048"))
FLOOD_N = int(os.environ.get("MITM_FLOOD_N", "30"))
FLOOD_WINDOW = float(os.environ.get("MITM_FLOOD_WINDOW", "10"))


def _csv(name: str, default: str = "") -> list:
    raw = os.environ.get(name, default)
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


ALLOW_HOSTS = _csv("MITM_ALLOW_HOSTS")
QUIET_HOSTS = _csv(
    "MITM_QUIET_HOSTS",
    "api.anthropic.com,statsig.anthropic.com,mcp-proxy.anthropic.com,"
    "platform.claude.com,downloads.claude.ai,sentry.io",
)

# What counts as a leak signal. Deliberately broad: the goal is to see, not to filter.
SECRET_PATTERNS = [
    ("email", re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("aws_access_key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}")),
    ("github_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("anthropic_key", re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai_key", re.compile(rb"\bsk-[A-Za-z0-9]{32,}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("bearer_header", re.compile(rb"(?i)authorization:\s*bearer\s+\S{20,}")),
    ("host_path", re.compile(rb"/Users/[A-Za-z0-9._-]+/")),
    ("ssh_dir", re.compile(rb"\.ssh/(?:id_[a-z0-9]+|authorized_keys|config)")),
    ("aws_dir", re.compile(rb"\.aws/(?:credentials|config)")),
    ("env_dump", re.compile(rb"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\s*[=:]\s*[^\s\"',}]{8,}")),
]

_extra = os.environ.get("MITM_SECRET_PATTERNS_FILE")
if _extra and os.path.exists(_extra):
    with open(_extra, "rb") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if line and not line.startswith(b"#"):
                try:
                    SECRET_PATTERNS.append((f"custom_{i}", re.compile(line)))
                except re.error:
                    pass


def _match_host(host: str, patterns: list) -> bool:
    host = (host or "").lower()
    return any(host == p or host.endswith("." + p) for p in patterns)


def _scan(blob: bytes) -> list:
    """Returns findings as [{kind, sample}], deduplicated by kind."""
    out = []
    if not blob:
        return out
    for kind, rx in SECRET_PATTERNS:
        m = rx.search(blob)
        if m:
            sample = m.group(0)[:80].decode("utf-8", "replace")
            if kind in ("private_key", "aws_secret", "github_token", "anthropic_key",
                        "openai_key", "slack_token", "jwt", "bearer_header", "env_dump"):
                sample = sample[:12] + "…<redacted>"
            out.append({"kind": kind, "sample": sample})
    return out


# Which way the agent got out:
#   proxy       — the sanctioned path, via HTTP(S)_PROXY
#   transparent — around the env proxy, caught by the iptables redirect on the gateway
# The second almost always means a bypass attempt and deserves separate attention.
_MODE_NAMES = {"regular": "proxy", "upstream": "proxy", "transparent": "transparent"}


def _mode(flow) -> str:
    pm = getattr(flow.client_conn, "proxy_mode", None)
    name = getattr(pm, "type_name", None) if pm is not None else None
    if name:
        return _MODE_NAMES.get(name, name)
    sock = getattr(flow.client_conn, "sockname", None)
    if sock and len(sock) >= 2:
        return {8080: "proxy", 8081: "transparent"}.get(sock[1], "unknown")
    return "unknown"


def _write(rec: dict) -> None:
    rec.setdefault("ts", time.time())
    rec.setdefault("ts_iso", time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(rec["ts"]))
                   + f".{int(rec['ts'] % 1 * 1000):03d}")
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as exc:  # logging must never take the proxy down
        logging.warning("traffic log write failed: %s", exc)


class AgentTrafficLogger:
    def __init__(self):
        self.hits = defaultdict(deque)   # host -> request timestamps, for flood detection
        self.flood_announced = set()

    # ---------- lifecycle ----------

    def load(self, loader):
        _write({
            "event": "proxy_start",
            "allow_hosts": ALLOW_HOSTS or None,
            "quiet_hosts": QUIET_HOSTS,
            "flood": {"n": FLOOD_N, "window_s": FLOOD_WINDOW},
        })

    # ---------- request ----------

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = req.pretty_host
        now = time.time()

        # sliding rate window per domain
        dq = self.hits[host]
        dq.append(now)
        while dq and now - dq[0] > FLOOD_WINDOW:
            dq.popleft()
        flood = len(dq) >= FLOOD_N
        if flood and host not in self.flood_announced:
            self.flood_announced.add(host)
            _write({
                "event": "alert",
                "kind": "request_flood",
                "host": host,
                "count_in_window": len(dq),
                "window_s": FLOOD_WINDOW,
                "detail": f"{len(dq)} requests to {host} in {FLOOD_WINDOW:g}s",
            })
        if not flood:
            self.flood_announced.discard(host)

        quiet = _match_host(host, QUIET_HOSTS)
        body = req.raw_content or b""

        # A quiet host is the agent's own infrastructure. Its Authorization header
        # carries the agent's own credentials by design — scanning it buries every
        # real finding under one anthropic_key/bearer_header/jwt hit per request.
        # The body is still scanned: a secret pasted into a prompt is precisely
        # the kind of leak worth catching, it just never gets stored verbatim.
        groups = [_scan(body), _scan(req.pretty_url.encode())]
        if not quiet:
            headers_blob = "\n".join(f"{k}: {v}" for k, v in req.headers.items()).encode()
            groups.append(_scan(headers_blob))
        findings = [f for group in groups for f in group]
        # collapse duplicates by kind
        seen, uniq = set(), []
        for f in findings:
            if f["kind"] not in seen:
                seen.add(f["kind"])
                uniq.append(f)

        blocked = bool(ALLOW_HOSTS) and not _match_host(host, ALLOW_HOSTS)

        rec = {
            "event": "request",
            "flow_id": flow.id,
            "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            "mode": _mode(flow),
            "method": req.method,
            "scheme": req.scheme,
            "host": host,
            "port": req.port,
            "path": req.path,
            "url": req.pretty_url,
            "req_body_len": len(req.raw_content or b""),
            "req_body_preview": (
                None if quiet else (body[:BODY_PREVIEW].decode("utf-8", "replace") or None)
            ),
            "user_agent": req.headers.get("user-agent"),
            "findings": uniq or None,
            "flood": flood or None,
            "blocked": blocked or None,
        }
        _write(rec)

        if blocked:
            flow.response = http.Response.make(
                403,
                json.dumps({"error": "egress blocked by agent-lab allowlist", "host": host}).encode(),
                {"Content-Type": "application/json"},
            )

    # ---------- response ----------

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        host = flow.request.pretty_host
        quiet = _match_host(host, QUIET_HOSTS)
        body = b"" if quiet else (flow.response.raw_content or b"")
        _write({
            "event": "response",
            "flow_id": flow.id,
            "host": host,
            "method": flow.request.method,
            "path": flow.request.path,
            "status": flow.response.status_code,
            "content_type": flow.response.headers.get("content-type"),
            "resp_body_len": len(flow.response.raw_content or b""),
            "resp_body_preview": (
                None if quiet else (body[:BODY_PREVIEW].decode("utf-8", "replace") or None)
            ),
        })

    def error(self, flow: http.HTTPFlow) -> None:
        _write({
            "event": "error",
            "flow_id": getattr(flow, "id", None),
            "host": getattr(getattr(flow, "request", None), "pretty_host", None),
            "detail": str(flow.error) if flow.error else None,
        })


addons = [AgentTrafficLogger()]
