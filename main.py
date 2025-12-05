#!/usr/bin/env python3
"""
SENTINEL HIVE - Main Entry Point
Starts all honeypot services and the Flask dashboard.
"""

import json
import os
import sys
import threading
import argparse

from honeypot import AttackLogger, SSHHoneyPot, HTTPHoneyPot, FTPHoneyPot
from dashboard.app import run_dashboard


def load_config(config_path="config/config.json"):
    """Load configuration from JSON file."""
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return {
        "honeypot": {
            "ssh_port": 2222,
            "http_port": 8080,
            "ftp_port": 2121
        },
        "dashboard": {
            "host": "0.0.0.0",
            "port": 5000,
            "debug": False
        },
        "logging": {
            "log_dir": "logs"
        }
    }


def main():
    parser = argparse.ArgumentParser(description='SENTINEL HIVE HoneyPot System')
    parser.add_argument('--ssh', action='store_true', help='Start SSH honeypot')
    parser.add_argument('--http', action='store_true', help='Start HTTP honeypot')
    parser.add_argument('--ftp', action='store_true', help='Start FTP honeypot')
    parser.add_argument('--dashboard', action='store_true', help='Start dashboard only')
    parser.add_argument('--all', action='store_true', help='Start all services')
    parser.add_argument('--config', default='config/config.json', help='Config file path')
    
    args = parser.parse_args()
    
    # If no specific service is selected, start all
    if not any([args.ssh, args.http, args.ftp, args.dashboard]):
        args.all = True
    
    config = load_config(args.config)
    
    # Initialize logger
    log_dir = config.get('logging', {}).get('log_dir', 'logs')
    logger = AttackLogger(log_dir=log_dir)
    
    honeypots = []
    threads = []
    
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║          🐝 SENTINEL HIVE CYBER 🐝               ║
    ║          HoneyPot Security System                 ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    try:
        # Start SSH HoneyPot
        if args.ssh or args.all:
            ssh_port = config.get('honeypot', {}).get('ssh_port', 2222)
            ssh_honeypot = SSHHoneyPot(logger, port=ssh_port)
            honeypots.append(ssh_honeypot)
            ssh_thread = threading.Thread(target=ssh_honeypot.start, daemon=True)
            ssh_thread.start()
            threads.append(ssh_thread)
        
        # Start HTTP HoneyPot
        if args.http or args.all:
            http_port = config.get('honeypot', {}).get('http_port', 8080)
            http_honeypot = HTTPHoneyPot(logger, port=http_port)
            honeypots.append(http_honeypot)
            http_thread = threading.Thread(target=http_honeypot.start, daemon=True)
            http_thread.start()
            threads.append(http_thread)
        
        # Start FTP HoneyPot
        if args.ftp or args.all:
            ftp_port = config.get('honeypot', {}).get('ftp_port', 2121)
            ftp_honeypot = FTPHoneyPot(logger, port=ftp_port)
            honeypots.append(ftp_honeypot)
            ftp_thread = threading.Thread(target=ftp_honeypot.start, daemon=True)
            ftp_thread.start()
            threads.append(ftp_thread)
        
        # Start Dashboard
        if args.dashboard or args.all:
            dashboard_config = config.get('dashboard', {})
            host = dashboard_config.get('host', '0.0.0.0')
            port = dashboard_config.get('port', 5000)
            debug = dashboard_config.get('debug', False)
            
            print(f"[*] Starting Dashboard on http://{host}:{port}")
            run_dashboard(host=host, port=port, debug=debug)
        else:
            # Keep main thread alive if only running honeypots
            print("\n[*] HoneyPots are running. Press Ctrl+C to stop.")
            # Use cross-platform wait instead of signal.pause() which is Unix-only
            import time
            while True:
                time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        for honeypot in honeypots:
            honeypot.stop()
        sys.exit(0)


if __name__ == '__main__':
    main()
