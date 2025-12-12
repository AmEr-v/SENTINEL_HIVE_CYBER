#!/usr/bin/env python3
import os
import json
import time
from pathlib import Path
from collections import deque
from flask import Flask, Response, jsonify, request, abort

app = Flask(__name__)

COWRIE_LOG = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.log")
COWRIE_JSON = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")

API_TOKEN = os.environ.get("API_TOKEN")
HOST = "0.0.0.0"
PORT = 8088
MAX_JSON_LINES = 20000


def auth():
    token = request.headers.get("X-API-Token") or request.args.get("token")
    if token != API_TOKEN:
        abort(401)


def follow(path):
    """Tail a file and yield new lines."""
    with path.open("r", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")


@app.get("/stream/cowrie-log")
def stream_log():
    auth()

    def events():
        for line in follow(COWRIE_LOG):
            yield f"data: {line}\n\n"

    return Response(events(), mimetype="text/event-stream")


@app.get("/stream/cowrie-json")
def stream_json():
    auth()

    def events():
        for line in follow(COWRIE_JSON):
            # Lines in cowrie.json are already JSON; emit as-is for SSE consumers
            yield f"data: {line}\n\n"

    return Response(events(), mimetype="text/event-stream")


@app.get("/stats/cowrie")
def stats():
    auth()

    ips = set()
    attempts = 0
    lines = deque(maxlen=MAX_JSON_LINES)

    with COWRIE_JSON.open("r", errors="replace") as f:
        for l in f:
            lines.append(l)

    for l in lines:
        try:
            j = json.loads(l)
        except Exception:
            continue

        ip = j.get("src_ip")
        if ip:
            ips.add(ip)

        if j.get("eventid", "").startswith("cowrie.login."):
            attempts += 1

    return jsonify({
        "unique_ips": len(ips),
        "login_attempts": attempts,
        "scanned_lines": len(lines)
    })


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    if not API_TOKEN:
        raise SystemExit("API_TOKEN not set")
    app.run(host=HOST, port=PORT, threaded=True)
