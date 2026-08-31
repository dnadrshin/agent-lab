#!/usr/bin/env python3
"""
Claude Code hook → /logs/actions.jsonl.

Records every agent action (user prompt, tool call, result) with a timestamp so
it can later be stitched together with network traffic in tools/correlate.py.

Additionally (AGENT_GIT_GUARD=1) blocks dangerous git operations: remote
tampering, force-push, history rewriting. Blocking = exit code 2.
"""
import json
import os
import re
import shlex
import sys
import time

LOG = os.environ.get("ACTIONS_LOG", "/logs/actions.jsonl")
GIT_GUARD = os.environ.get("AGENT_GIT_GUARD", "0") == "1"
PREVIEW = int(os.environ.get("ACTIONS_PREVIEW", "1200"))

# (regex over the normalized command, reason)
GIT_DANGER = [
    (re.compile(r"\bgit\s+remote\s+(add|set-url|rename)\b"), "git remote tampering"),
    (re.compile(r"\bgit\s+push\b[^|;&]*(--force\b|--force-with-lease\b|\s-f\b)"), "force-push"),
    (re.compile(r"\bgit\s+push\b[^|;&]*--mirror\b"), "push --mirror (pushes the whole repository)"),
    (re.compile(r"\bgit\s+(filter-branch|filter-repo)\b"), "history rewrite"),
    (re.compile(r"\bgit\s+config\s+(--global|--system)\b"), "global git config change"),
    (re.compile(r"\bgit\s+(update-ref|reflog\s+delete)\b"), "direct ref manipulation"),
]
GIT_ANY = re.compile(r"\bgit\b")


def summarize(tool: str, ti: dict) -> dict:
    """Compact gist of the call — what you actually want to see in the timeline."""
    if not isinstance(ti, dict):
        return {}
    if tool == "Bash":
        cmd = ti.get("command", "")
        out = {"command": cmd[:PREVIEW]}
        if GIT_ANY.search(cmd):
            out["is_git"] = True
            try:
                out["git_argv"] = shlex.split(cmd)[:8]
            except ValueError:
                pass
        return out
    if tool in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
        out = {"file_path": ti.get("file_path") or ti.get("notebook_path")}
        for k in ("old_string", "new_string", "content"):
            if isinstance(ti.get(k), str):
                out[k + "_len"] = len(ti[k])
        out["mutating"] = True
        return out
    if tool == "Read":
        return {"file_path": ti.get("file_path"), "offset": ti.get("offset")}
    if tool in ("WebFetch", "WebSearch"):
        return {"url": ti.get("url"), "query": ti.get("query"), "prompt": (ti.get("prompt") or "")[:200]}
    if tool in ("Grep", "Glob"):
        return {"pattern": ti.get("pattern"), "path": ti.get("path")}
    if tool.startswith("mcp__"):
        return {"mcp_args_preview": json.dumps(ti, ensure_ascii=False)[:PREVIEW]}
    return {"args_preview": json.dumps(ti, ensure_ascii=False)[:PREVIEW]}


def write(rec: dict) -> None:
    ts = rec.setdefault("ts", time.time())
    rec.setdefault("ts_iso", time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
                   + f".{int(ts % 1 * 1000):03d}")
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"agent-lab: could not write {LOG}: {exc}", file=sys.stderr)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # a hook must never break the agent

    event = payload.get("hook_event_name", "unknown")
    tool = payload.get("tool_name")
    ti = payload.get("tool_input") or {}

    rec = {
        "event": event,
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
        "tool": tool,
    }
    if event == "UserPromptSubmit":
        rec["prompt"] = (payload.get("prompt") or "")[:PREVIEW]
    if tool:
        rec["detail"] = summarize(tool, ti)
    if event == "PostToolUse":
        resp = payload.get("tool_response")
        if isinstance(resp, dict):
            rec["result"] = {k: resp[k] for k in ("filePath", "type", "success") if k in resp}
            for k in ("stdout", "stderr"):
                if isinstance(resp.get(k), str) and resp[k]:
                    rec.setdefault("result", {})[k + "_preview"] = resp[k][:400]
        elif isinstance(resp, str):
            rec["result"] = {"preview": resp[:400]}

    # git guard
    if event == "PreToolUse" and tool == "Bash" and GIT_GUARD:
        cmd = ti.get("command", "")
        for rx, reason in GIT_DANGER:
            if rx.search(cmd):
                rec["blocked"] = reason
                write(rec)
                print(f"agent-lab git-guard: blocked — {reason}.\n"
                      f"Command: {cmd[:300]}\n"
                      f"If this is intentional, run it by hand outside the agent "
                      f"or unset AGENT_GIT_GUARD.", file=sys.stderr)
                return 2  # exit 2 = block the call, stderr text goes to the model
        rec["git_guard"] = "pass"

    write(rec)
    return 0


if __name__ == "__main__":
    sys.exit(main())
