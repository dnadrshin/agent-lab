#!/usr/bin/env python3
"""
Filesystem watcher over the agent's working directory → /logs/actions.jsonl.

Catches changes the tool hooks never see: edits via `sed -i`, scripts, archive
extraction, `npm install`, build output. Plain mtime/size polling — enough for a
working tree and it pulls in no dependencies.

ENV: FSWATCH_ROOT (default /work), FSWATCH_INTERVAL (2s),
     FSWATCH_MAX_FILES (20000), FSWATCH_IGNORE (csv of path substrings).
"""
import json
import os
import time

ROOT = os.environ.get("FSWATCH_ROOT", "/work")
LOG = os.environ.get("ACTIONS_LOG", "/logs/actions.jsonl")
INTERVAL = float(os.environ.get("FSWATCH_INTERVAL", "2"))
MAX_FILES = int(os.environ.get("FSWATCH_MAX_FILES", "20000"))
IGNORE = [s for s in os.environ.get(
    "FSWATCH_IGNORE",
    ".git/,node_modules/,__pycache__/,.venv/,dist/,build/,.next/,.cache/"
).split(",") if s]


def skip(path: str) -> bool:
    return any(frag in path for frag in IGNORE)


def snapshot() -> dict:
    state, n = {}, 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if not skip(os.path.join(dirpath, d) + "/")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if skip(p):
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            state[p] = (st.st_mtime, st.st_size)
            n += 1
            if n >= MAX_FILES:
                return state
    return state


def emit(change: str, path: str, extra: dict | None = None) -> None:
    ts = time.time()
    rec = {
        "ts": ts,
        "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) + f".{int(ts % 1 * 1000):03d}",
        "event": "fs_change",
        "change": change,
        "path": path,
    }
    if extra:
        rec.update(extra)
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main() -> None:
    prev = snapshot()
    while True:
        time.sleep(INTERVAL)
        try:
            cur = snapshot()
        except Exception:
            continue
        for p, meta in cur.items():
            if p not in prev:
                emit("created", p, {"size": meta[1]})
            elif prev[p] != meta:
                emit("modified", p, {"size": meta[1], "size_delta": meta[1] - prev[p][1]})
        for p in prev:
            if p not in cur:
                emit("deleted", p)
        prev = cur


if __name__ == "__main__":
    main()
