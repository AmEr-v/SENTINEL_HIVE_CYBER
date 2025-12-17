#!/usr/bin/env python3
"""
VM Log Shipper for Sentinel Hive Dashboard

This script runs on the VM and ships log events to the dashboard.

Usage:
    python vm_shipper.py --dashboard-url http://dashboard-host:5000 --http-log /path/to/http.log --ssh-log /path/to/cowrie.json

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
    def __init__(self, dashboard_url: str, http_log: Path, ssh_log: Path, offset_file: Path = Path("offsets.json")):
        self.dashboard_url = dashboard_url.rstrip('/')
        self.http_log = http_log
        self.ssh_log = ssh_log
        self.offset_file = offset_file
        self.offsets = self._load_offsets()

    def _load_offsets(self) -> Dict[str, int]:
        if self.offset_file.exists():
            try:
                with open(self.offset_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {str(self.http_log): 0, str(self.ssh_log): 0}

    def _save_offsets(self):
        try:
            with open(self.offset_file, 'w') as f:
                json.dump(self.offsets, f)
        except Exception as e:
            logger.error(f"Failed to save offsets: {e}")

    def read_new_lines(self, path: Path) -> List[str]:
        offset = self.offsets.get(str(path), 0)
        if not path.exists():
            return []
        with open(path, 'rb') as f:
            f.seek(offset)
            data = f.read()
            self.offsets[str(path)] = f.tell()
        lines = data.decode('utf-8', errors='ignore').splitlines()
        return lines

    def parse_http_line(self, line: str) -> Dict[str, Any]:
        try:
            data = json.loads(line)
            return {
                "source": "HTTP",
                "timestamp": data.get("time") or data.get("timestamp"),
                "ip": data.get("remote_addr") or data.get("src_ip"),
                "event_type": "http_request",
                "username": data.get("username"),
                "password": data.get("password"),
                "path": data.get("path"),
                "raw": data
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
                "timestamp": data.get("timestamp"),
                "ip": data.get("src_ip"),
                "event_type": eventid,
                "username": data.get("username"),
                "password": data.get("password"),
                "raw": data
            }
        except:
            return None

    def ship_events(self, events: List[Dict[str, Any]]):
        if not events:
            return
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = requests.post(f"{self.dashboard_url}/api/ingest", json=events, timeout=10)
                if resp.status_code == 200:
                    logger.info(f"Shipped {len(events)} events")
                    return
                else:
                    logger.error(f"Failed to ship (attempt {attempt+1}): {resp.status_code} {resp.text}")
            except Exception as e:
                logger.error(f"Error shipping events (attempt {attempt+1}): {e}")
            if attempt < max_retries - 1:
                sleep_time = 2 ** attempt  # exponential backoff
                logger.info(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
        logger.error("Failed to ship events after all retries")

    def run(self):
        logger.info(f"Starting shipper: HTTP={self.http_log}, SSH={self.ssh_log}, Dashboard={self.dashboard_url}")
        while True:
            events = []

            # HTTP
            lines = self.read_new_lines(self.http_log)
            for line in lines:
                event = self.parse_http_line(line)
                if event:
                    events.append(event)

            # SSH
            lines = self.read_new_lines(self.ssh_log)
            for line in lines:
                event = self.parse_ssh_line(line)
                if event:
                    events.append(event)

            self.ship_events(events)
            self._save_offsets()
            time.sleep(5)  # poll every 5 seconds

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VM Log Shipper")
    parser.add_argument("--dashboard-url", required=True, help="Dashboard URL, e.g. http://localhost:5000")
    parser.add_argument("--http-log", required=True, help="Path to HTTP honeypot log")
    parser.add_argument("--ssh-log", required=True, help="Path to Cowrie JSON log")
    parser.add_argument("--offset-file", default="offsets.json", help="File to store offsets")
    args = parser.parse_args()

    shipper = LogShipper(args.dashboard_url, Path(args.http_log), Path(args.ssh_log), Path(args.offset_file))
    shipper.run()