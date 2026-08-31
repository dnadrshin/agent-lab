#!/usr/bin/env python3
"""
Stitches the agent's actions and its outbound traffic into a single timeline.

    python3 tools/correlate.py              # whole run
    python3 tools/correlate.py -f           # live
    python3 tools/correlate.py --summary    # per-domain aggregate
    python3 tools/correlate.py --alerts     # findings only: leaks, floods, blocks
    python3 tools/correlate.py --since 15m  # last 15 minutes

The idea: a network request on its own says very little. It gets meaning once
you can see WHICH AGENT STEP it followed.
"""
import argparse
import json
import os
import re
import signal
import sys
import time
from collections import Counter, defaultdict

# Let `./lab alerts | head` end quietly instead of dumping a BrokenPipeError.
try:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
except (AttributeError, ValueError):
    pass

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(HERE, "logs")

C = {
    "dim": "\033[2m", "red": "\033[31m", "grn": "\033[32m", "ylw": "\033[33m",
    "blu": "\033[34m", "mag": "\033[35m", "cyn": "\033[36m", "bld": "\033[1m", "off": "\033[0m",
}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def parse_since(s):
    if not s:
        return 0.0
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        return 0.0
    n, unit = int(m.group(1)), m.group(2)
    return time.time() - n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def hhmmss(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


def fmt_action(r):
    ev, tool = r.get("event"), r.get("tool")
    d = r.get("detail") or {}
    if ev == "UserPromptSubmit":
        return f"{C['bld']}{C['mag']}▸ TASK{C['off']} {(r.get('prompt') or '')[:160]}"
    if ev == "SessionStart":
        return f"{C['dim']}▸ session {str(r.get('session_id'))[:8]} started{C['off']}"
    if ev == "Stop":
        return f"{C['dim']}▸ agent stopped{C['off']}"
    if ev == "fs_change":
        col = {"created": C["grn"], "modified": C["ylw"], "deleted": C["red"]}.get(r.get("change"), "")
        delta = r.get("size_delta")
        tail = f" ({delta:+d} B)" if isinstance(delta, int) and delta else ""
        return f"{col}✎ FILE {r.get('change')}{C['off']} {r.get('path')}{tail}"
    if ev != "PreToolUse":
        return None  # PostToolUse is kept for results but stays out of the timeline
    if tool == "Bash":
        cmd = (d.get("command") or "").replace("\n", " ⏎ ")[:200]
        # highlight git commands as a whole instead of tacking a label onto them
        body = f"{C['cyn']}{cmd}{C['off']}" if d.get("is_git") else cmd
        blocked = f" {C['red']}[BLOCKED: {r['blocked']}]{C['off']}" if r.get("blocked") else ""
        return f"{C['blu']}$ {C['off']}{body}{blocked}"
    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        return f"{C['ylw']}✎ {tool}{C['off']} {d.get('file_path')}"
    if tool in ("WebFetch", "WebSearch"):
        return f"{C['mag']}⌕ {tool}{C['off']} {d.get('url') or d.get('query')}"
    if tool == "Read":
        return f"{C['dim']}· Read {d.get('file_path')}{C['off']}"
    if tool in ("Grep", "Glob"):
        return f"{C['dim']}· {tool} {d.get('pattern')}{C['off']}"
    return f"· {tool}"


def fmt_request(r, verbose=False):
    flags = []
    if r.get("findings"):
        kinds = ", ".join(f["kind"] for f in r["findings"])
        flags.append(f"{C['red']}{C['bld']}LEAK?{C['off']} {C['red']}{kinds}{C['off']}")
    if r.get("flood"):
        flags.append(f"{C['red']}FLOOD{C['off']}")
    if r.get("blocked"):
        flags.append(f"{C['ylw']}BLOCKED by allowlist{C['off']}")
    if r.get("mode") == "transparent":
        flags.append(f"{C['ylw']}bypassed env proxy{C['off']}")
    body = ""
    if r.get("req_body_len"):
        body = f" {C['dim']}[{r['req_body_len']} B body]{C['off']}"
    line = (f"    {C['dim']}{hhmmss(r['ts'])}{C['off']} "
            f"{C['grn']}→{C['off']} {r.get('method')} {r.get('host')}{r.get('path', '')[:110]}{body}")
    if flags:
        line += "  " + "  ".join(flags)
    if verbose and r.get("req_body_preview"):
        preview = r["req_body_preview"][:400].replace("\n", "\\n")
        line += f"\n      {C['dim']}{preview}{C['off']}"
    return line


def fmt_alert(r):
    return (f"    {C['dim']}{hhmmss(r['ts'])}{C['off']} {C['red']}{C['bld']}⚑ {r.get('kind')}{C['off']} "
            f"{r.get('detail', '')}")


def build(since=0.0):
    actions = [r for r in read_jsonl(os.path.join(LOGS, "actions.jsonl")) if r.get("ts", 0) >= since]
    traffic = [r for r in read_jsonl(os.path.join(LOGS, "traffic.jsonl")) if r.get("ts", 0) >= since]
    events = []
    for r in actions:
        if r.get("event") in ("PostToolUse",):
            continue
        events.append(("action", r))
    for r in traffic:
        if r.get("event") == "request":
            events.append(("request", r))
        elif r.get("event") == "alert":
            events.append(("alert", r))
    events.sort(key=lambda e: e[1].get("ts", 0))
    return events


def render(events, verbose=False, alerts_only=False):
    out = []
    for kind, r in events:
        if alerts_only:
            if kind == "alert":
                out.append(fmt_alert(r))
            elif kind == "request" and (r.get("findings") or r.get("flood") or r.get("blocked")):
                out.append(fmt_request(r, verbose))
            continue
        if kind == "action":
            line = fmt_action(r)
            if line:
                out.append(f"{C['dim']}{hhmmss(r['ts'])}{C['off']} {line}")
        elif kind == "request":
            out.append(fmt_request(r, verbose))
        else:
            out.append(fmt_alert(r))
    return out


def summary(since=0.0):
    traffic = [r for r in read_jsonl(os.path.join(LOGS, "traffic.jsonl"))
               if r.get("ts", 0) >= since and r.get("event") == "request"]
    if not traffic:
        print("No traffic in the log.")
        return
    per_host = Counter(r.get("host") for r in traffic)
    bytes_out = defaultdict(int)
    findings = defaultdict(Counter)
    for r in traffic:
        bytes_out[r.get("host")] += r.get("req_body_len") or 0
        for f in r.get("findings") or []:
            findings[r.get("host")][f["kind"]] += 1

    print(f"\n{C['bld']}Agent outbound traffic by domain{C['off']}")
    print(f"{'requests':>9}  {'sent':>11}  domain")
    print("-" * 72)
    for host, n in per_host.most_common():
        b = bytes_out[host]
        size = f"{b/1024:.1f} KB" if b >= 1024 else f"{b} B"
        mark = ""
        if findings[host]:
            mark = f"   {C['red']}⚑ {', '.join(f'{k}×{v}' for k, v in findings[host].items())}{C['off']}"
        print(f"{n:>9}  {size:>11}  {host}{mark}")
    print("-" * 72)
    print(f"{sum(per_host.values()):>9}  {sum(bytes_out.values())/1024:>8.1f} KB  total "
          f"across {len(per_host)} domains\n")


def follow(verbose, alerts_only):
    seen = 0
    print(f"{C['dim']}live timeline (Ctrl-C to exit)…{C['off']}")
    while True:
        events = build()
        lines = render(events, verbose, alerts_only)
        for line in lines[seen:]:
            print(line, flush=True)
        seen = len(lines)
        time.sleep(1.0)


def main():
    ap = argparse.ArgumentParser(description="Timeline: agent steps × its outbound network")
    ap.add_argument("-f", "--follow", action="store_true", help="live mode")
    ap.add_argument("-v", "--verbose", action="store_true", help="show request body previews")
    ap.add_argument("--summary", action="store_true", help="per-domain aggregate")
    ap.add_argument("--alerts", action="store_true", help="leaks/floods/blocks only")
    ap.add_argument("--since", default=None, help="window: 30s, 15m, 2h, 1d")
    args = ap.parse_args()

    since = parse_since(args.since)
    if args.summary:
        summary(since)
        return
    if args.follow:
        try:
            follow(args.verbose, args.alerts)
        except KeyboardInterrupt:
            print()
        return
    lines = render(build(since), args.verbose, args.alerts)
    if not lines:
        print("Empty. Logs appear after the first agent run (./lab claude).")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
