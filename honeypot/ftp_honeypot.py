"""
FTP HoneyPot Service
Simulates a vulnerable FTP server to capture attack attempts.
"""

import socket
import threading


class FTPHoneyPot:
    """FTP HoneyPot that captures login attempts."""
    
    def __init__(self, logger, host="0.0.0.0", port=2121):
        self.logger = logger
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
    
    def start(self):
        """Start the FTP honeypot server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True
        
        print(f"[*] FTP HoneyPot listening on {self.host}:{self.port}")
        
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
        """Stop the FTP honeypot server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _handle_client(self, client_socket, client_addr):
        """Handle a client connection."""
        source_ip, source_port = client_addr
        print(f"[+] FTP connection from {source_ip}:{source_port}")
        
        username = None
        commands = []
        
        try:
            # Send FTP banner
            client_socket.send(b"220 FTP Server Ready\r\n")
            
            while True:
                # Receive command
                data = client_socket.recv(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                commands.append(command)
                
                # Parse command
                parts = command.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                
                print(f"[+] FTP command from {source_ip}: {command}")
                
                if cmd == "USER":
                    username = arg
                    client_socket.send(b"331 Password required\r\n")
                
                elif cmd == "PASS":
                    password = arg
                    
                    # Log the login attempt
                    self.logger.log_attack(
                        "ftp",
                        source_ip,
                        source_port,
                        {
                            "action": "login_attempt",
                            "username": username or "anonymous",
                            "password": password,
                            "commands": commands
                        }
                    )
                    
                    # Always fail authentication
                    client_socket.send(b"530 Login incorrect\r\n")
                
                elif cmd == "QUIT":
                    client_socket.send(b"221 Goodbye\r\n")
                    break
                
                elif cmd == "SYST":
                    client_socket.send(b"215 UNIX Type: L8\r\n")
                
                elif cmd == "PWD":
                    client_socket.send(b"257 \"/\" is current directory\r\n")
                
                elif cmd == "TYPE":
                    client_socket.send(b"200 Type set\r\n")
                
                elif cmd == "PASV":
                    client_socket.send(b"227 Entering Passive Mode (127,0,0,1,0,20)\r\n")
                
                elif cmd == "LIST" or cmd == "NLST":
                    client_socket.send(b"150 Opening data connection\r\n")
                    client_socket.send(b"226 Transfer complete\r\n")
                
                elif cmd == "CWD":
                    client_socket.send(b"250 Directory changed\r\n")
                
                elif cmd == "FEAT":
                    client_socket.send(b"211-Features:\r\n UTF8\r\n211 End\r\n")
                
                else:
                    # Log unknown command
                    self.logger.log_attack(
                        "ftp",
                        source_ip,
                        source_port,
                        {
                            "action": "unknown_command",
                            "command": command,
                            "username": username
                        }
                    )
                    client_socket.send(b"502 Command not implemented\r\n")
        
        except Exception as e:
            print(f"[!] Error handling FTP client {source_ip}: {e}")
            self.logger.log_attack(
                "ftp",
                source_ip,
                source_port,
                {
                    "action": "error",
                    "error": str(e),
                    "commands": commands
                }
            )
        finally:
            client_socket.close()
