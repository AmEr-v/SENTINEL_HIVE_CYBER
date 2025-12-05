"""
Attack Logger Module
Handles logging of all honeypot attacks and events to JSON files.
"""

import json
import os
from datetime import datetime
from threading import Lock


class AttackLogger:
    """Thread-safe logger for recording honeypot attacks."""
    
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.lock = Lock()
        self._ensure_log_dir()
    
    def _ensure_log_dir(self):
        """Ensure the log directory exists."""
        os.makedirs(self.log_dir, exist_ok=True)
    
    def _get_log_file(self, attack_type):
        """Get the log file path for a specific attack type."""
        filename = f"{attack_type}_attacks.json"
        return os.path.join(self.log_dir, filename)
    
    def log_attack(self, attack_type, source_ip, source_port, details=None):
        """
        Log an attack event.
        
        Args:
            attack_type: Type of attack (ssh, http, ftp, etc.)
            source_ip: Source IP address of the attacker
            source_port: Source port of the attacker
            details: Additional details about the attack
        """
        attack_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "attack_type": attack_type,
            "source_ip": source_ip,
            "source_port": source_port,
            "details": details or {}
        }
        
        with self.lock:
            log_file = self._get_log_file(attack_type)
            attacks = self._load_attacks(log_file)
            attacks.append(attack_record)
            self._save_attacks(log_file, attacks)
        
        return attack_record
    
    def _load_attacks(self, log_file):
        """Load existing attacks from file."""
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []
    
    def _save_attacks(self, log_file, attacks):
        """Save attacks to file."""
        with open(log_file, 'w') as f:
            json.dump(attacks, f, indent=2)
    
    def get_all_attacks(self):
        """Get all logged attacks."""
        all_attacks = []
        if os.path.exists(self.log_dir):
            for filename in os.listdir(self.log_dir):
                if filename.endswith('_attacks.json'):
                    log_file = os.path.join(self.log_dir, filename)
                    attacks = self._load_attacks(log_file)
                    all_attacks.extend(attacks)
        return sorted(all_attacks, key=lambda x: x['timestamp'], reverse=True)
    
    def get_attacks_by_type(self, attack_type):
        """Get attacks of a specific type."""
        log_file = self._get_log_file(attack_type)
        return self._load_attacks(log_file)
    
    def get_attack_statistics(self):
        """Get attack statistics for the dashboard."""
        all_attacks = self.get_all_attacks()
        
        stats = {
            "total_attacks": len(all_attacks),
            "attacks_by_type": {},
            "attacks_by_ip": {},
            "recent_attacks": all_attacks[:10],
            "hourly_distribution": {}
        }
        
        for attack in all_attacks:
            # Count by type
            attack_type = attack.get("attack_type", "unknown")
            stats["attacks_by_type"][attack_type] = stats["attacks_by_type"].get(attack_type, 0) + 1
            
            # Count by IP
            source_ip = attack.get("source_ip", "unknown")
            stats["attacks_by_ip"][source_ip] = stats["attacks_by_ip"].get(source_ip, 0) + 1
            
            # Hourly distribution
            try:
                timestamp = datetime.fromisoformat(attack.get("timestamp", ""))
                hour = timestamp.strftime("%H:00")
                stats["hourly_distribution"][hour] = stats["hourly_distribution"].get(hour, 0) + 1
            except (ValueError, TypeError):
                pass
        
        # Get top attackers
        sorted_ips = sorted(stats["attacks_by_ip"].items(), key=lambda x: x[1], reverse=True)
        stats["top_attackers"] = sorted_ips[:10]
        
        return stats
