"""
SSH HoneyPot Service
Simulates a vulnerable SSH server to capture attack attempts.
"""

import socket
import threading
import paramiko
from datetime import datetime


class SSHHoneyPot:
    """SSH HoneyPot that captures login attempts."""
    
    def __init__(self, logger, host="0.0.0.0", port=2222):
        self.logger = logger
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.host_key = paramiko.RSAKey.generate(2048)
    
    def start(self):
        """Start the SSH honeypot server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True
        
        print(f"[*] SSH HoneyPot listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"[!] Error accepting connection: {e}")
    
    def stop(self):
        """Stop the SSH honeypot server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _handle_client(self, client_socket, client_addr):
        """Handle a client connection."""
        source_ip, source_port = client_addr
        print(f"[+] SSH connection from {source_ip}:{source_port}")
        
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            server = SSHServer(self.logger, source_ip, source_port)
            
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                print(f"[!] SSH negotiation failed from {source_ip}")
                self.logger.log_attack(
                    "ssh",
                    source_ip,
                    source_port,
                    {"action": "negotiation_failed"}
                )
                return
            
            # Wait for authentication attempt
            channel = transport.accept(20)
            if channel is not None:
                channel.close()
            
        except Exception as e:
            print(f"[!] Error handling SSH client {source_ip}: {e}")
            self.logger.log_attack(
                "ssh",
                source_ip,
                source_port,
                {"action": "error", "error": str(e)}
            )
        finally:
            client_socket.close()


class SSHServer(paramiko.ServerInterface):
    """Paramiko SSH server implementation for honeypot."""
    
    def __init__(self, logger, source_ip, source_port):
        self.logger = logger
        self.source_ip = source_ip
        self.source_port = source_port
        self.event = threading.Event()
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        """Log password authentication attempts."""
        print(f"[+] SSH login attempt: {username}:{password} from {self.source_ip}")
        
        self.logger.log_attack(
            "ssh",
            self.source_ip,
            self.source_port,
            {
                "action": "password_auth",
                "username": username,
                "password": password
            }
        )
        
        # Always reject - this is a honeypot
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Log public key authentication attempts."""
        print(f"[+] SSH public key attempt: {username} from {self.source_ip}")
        
        self.logger.log_attack(
            "ssh",
            self.source_ip,
            self.source_port,
            {
                "action": "pubkey_auth",
                "username": username,
                "key_type": key.get_name()
            }
        )
        
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return 'password,publickey'
