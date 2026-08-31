#!/usr/bin/env python3
"""
Local viewer for the lab logs: serves tools/viewer/index.html and streams new
records from logs/*.jsonl to it.

    ./lab viewer            # http://127.0.0.1:8083

Binds to the loopback interface only, and deliberately so: traffic.jsonl holds
decrypted request bodies and live credentials. Nothing here should ever be
reachable from another machine.

Reads the logs, never writes them.
"""
import argparse
import json
import mimetypes
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOGS = os.path.join(ROOT, "logs")
STATIC = os.path.join(HERE, "viewer")

MAX_RECORDS = 20000     # ring cap, so a long-running lab cannot exhaust memory


class Tail:
    """Incremental JSONL reader: keeps a file position and parses only new lines."""

    def __init__(self, path):
        self.path = path
        self.pos = 0
        self.buf = ""
        self.records = []

    def poll(self, seq_start):
        """Parse whatever was appended since the last call. Returns the next seq."""
        seq = seq_start
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return seq
        if size < self.pos:          # file truncated or rotated — start over
            self.pos, self.buf, self.records = 0, "", []
        if size == self.pos:
            return seq
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self.pos)
            self.buf += fh.read()
            self.pos = fh.tell()
        *lines, self.buf = self.buf.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec["seq"] = seq
            seq += 1
            self.records.append(rec)
        if len(self.records) > MAX_RECORDS:
            del self.records[:len(self.records) - MAX_RECORDS]
        return seq


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.seq = 0
        self.actions = Tail(os.path.join(LOGS, "actions.jsonl"))
        self.traffic = Tail(os.path.join(LOGS, "traffic.jsonl"))

    def snapshot(self, after=-1, since=0.0):
        with self.lock:
            self.seq = self.actions.poll(self.seq)
            self.seq = self.traffic.poll(self.seq)
            out = []
            for tail, kind in ((self.actions, "action"), (self.traffic, "traffic")):
                for r in tail.records:
                    if r["seq"] > after and r.get("ts", 0) >= since:
                        out.append({"src": kind, **r})
            out.sort(key=lambda r: (r.get("ts", 0), r["seq"]))
            return {"events": out, "cursor": self.seq - 1}


STORE = Store()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass  # the viewer polls once a second; keep the console usable

    def _send(self, body: bytes, ctype: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/api/events":
            q = parse_qs(url.query)
            after = int(q.get("after", ["-1"])[0])
            since = float(q.get("since", ["0"])[0])
            body = json.dumps(STORE.snapshot(after, since)).encode()
            return self._send(body, "application/json")

        rel = "index.html" if url.path in ("/", "") else url.path.lstrip("/")
        path = os.path.normpath(os.path.join(STATIC, rel))
        if not path.startswith(STATIC) or not os.path.isfile(path):
            return self._send(b"not found", "text/plain", 404)
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as fh:
            return self._send(fh.read(), ctype)


def main():
    ap = argparse.ArgumentParser(description="Local viewer for agent-lab logs")
    ap.add_argument("--port", type=int, default=8083)
    ap.add_argument("--host", default="127.0.0.1",
                    help="loopback by default; the logs contain decrypted secrets")
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"agent-lab viewer: http://{args.host}:{args.port}  (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
