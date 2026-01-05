#!/usr/bin/env python3
"""
VM Log Shipper for Sentinel Hive Dashboard

This script runs on the VM and ships log events to the dashboard.

Usage:
    python shipper.py --dashboard-url http://dashboard-host:5000 --http-log /path/to/http.log --ssh-log /path/to/cowrie.json

It tails the logs and POSTs new events to /api/ingest.
"""

import argparse
import json
import time
from pathlib import Path
from typing import Dict, Any, List
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LogShipper:
    def __init__(self, dashboard_url: str, http_log: Path, ssh_log: Path):
        self.dashboard_url = dashboard_url.rstrip('/')
        self.http_log = http_log
        self.ssh_log = ssh_log
        self.http_offset = 0
        self.ssh_offset = 0

    def read_new_lines(self, path: Path, offset: int) -> tuple[List[str], int]:
        if not path.exists():
            return [], 0
        try:
            size = path.stat().st_size
        except OSError:
            return [], offset
        if size < offset:
            logger.info(f"Log rotated or truncated, resetting offset: {path}")
            offset = 0
        with open(path, 'rb') as f:
            f.seek(offset)
            data = f.read()
            new_offset = f.tell()
        lines = data.decode('utf-8', errors='ignore').splitlines()
        return lines, new_offset

    def parse_http_line(self, line: str) -> Dict[str, Any]:
        try:
            data = json.loads(line)
            return {
                "source": "HTTP",
                "event": "http_request",
                "ip": data.get("remote_addr") or data.get("src_ip"),
                "timestamp": data.get("time") or data.get("timestamp"),
                "method": data.get("method"),
                "path": data.get("path"),
                "username": data.get("username"),
                "password": data.get("password"),
                "user_agent": data.get("headers", {}).get("User-Agent"),
            }
        except:
            return None

    def parse_ssh_line(self, line: str) -> Dict[str, Any]:
        try:
            data = json.loads(line)
            eventid = data.get("eventid", "")
            if not eventid.startswith("cowrie.login."):
                return None
            return {
                "source": "SSH",
                "event": eventid,
                "ip": data.get("src_ip"),
                "timestamp": data.get("timestamp"),
                "username": data.get("username"),
                "password": data.get("password"),
                "message": data.get("message"),
            }
        except:
            return None

    def ship_events(self, events: List[Dict[str, Any]]):
        if not events:
            return
        try:
            resp = requests.post(f"{self.dashboard_url}/api/ingest", json=events, timeout=10)
            if resp.status_code == 200:
                logger.info(f"Shipped {len(events)} events")
            else:
                logger.error(f"Failed to ship: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"Error shipping events: {e}")

    def run(self):
        logger.info(f"Starting shipper: HTTP={self.http_log}, SSH={self.ssh_log}, Dashboard={self.dashboard_url}")
        while True:
            events = []

            # HTTP
            lines, self.http_offset = self.read_new_lines(self.http_log, self.http_offset)
            for line in lines:
                event = self.parse_http_line(line)
                if event:
                    events.append(event)

            # SSH
            lines, self.ssh_offset = self.read_new_lines(self.ssh_log, self.ssh_offset)
            for line in lines:
                event = self.parse_ssh_line(line)
                if event:
                    events.append(event)

            self.ship_events(events)
            time.sleep(5)  # poll every 5 seconds

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VM Log Shipper")
    parser.add_argument("--dashboard-url", required=True, help="Dashboard URL, e.g. http://localhost:5000")
    parser.add_argument("--http-log", required=True, help="Path to HTTP honeypot log")
    parser.add_argument("--ssh-log", required=True, help="Path to Cowrie JSON log")
    args = parser.parse_args()

    shipper = LogShipper(args.dashboard_url, Path(args.http_log), Path(args.ssh_log))
    shipper.run()