"""
HTTP HoneyPot Service
Simulates a vulnerable HTTP server to capture attack attempts.
"""

import socket
import threading
from datetime import datetime
from urllib.parse import unquote

# Constants for size limits
MAX_BODY_LOG_SIZE = 1000
MAX_RAW_REQUEST_LOG_SIZE = 2000


class HTTPHoneyPot:
    """HTTP HoneyPot that captures web attack attempts."""
    
    def __init__(self, logger, host="0.0.0.0", port=8080):
        self.logger = logger
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
    
    def start(self):
        """Start the HTTP honeypot server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True
        
        print(f"[*] HTTP HoneyPot listening on {self.host}:{self.port}")
        
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
        """Stop the HTTP honeypot server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def _handle_client(self, client_socket, client_addr):
        """Handle a client connection."""
        source_ip, source_port = client_addr
        
        try:
            # Receive request
            request_data = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if request_data:
                # Parse request
                request_info = self._parse_request(request_data)
                
                print(f"[+] HTTP {request_info['method']} {request_info['path']} from {source_ip}")
                
                # Detect attack patterns
                attack_patterns = self._detect_attack_patterns(request_data)
                
                # Log the attack
                self.logger.log_attack(
                    "http",
                    source_ip,
                    source_port,
                    {
                        "method": request_info.get("method"),
                        "path": request_info.get("path"),
                        "headers": request_info.get("headers"),
                        "body": request_info.get("body", "")[:MAX_BODY_LOG_SIZE],
                        "user_agent": request_info.get("headers", {}).get("User-Agent", ""),
                        "attack_patterns": attack_patterns,
                        "raw_request": request_data[:MAX_RAW_REQUEST_LOG_SIZE]
                    }
                )
                
                # Send fake response
                response = self._generate_response(request_info)
                client_socket.send(response.encode('utf-8'))
        
        except Exception as e:
            print(f"[!] Error handling HTTP client {source_ip}: {e}")
        finally:
            client_socket.close()
    
    def _parse_request(self, request_data):
        """Parse HTTP request."""
        lines = request_data.split('\r\n')
        request_info = {
            "method": "",
            "path": "",
            "version": "",
            "headers": {},
            "body": ""
        }
        
        if lines:
            # Parse request line
            request_line = lines[0].split(' ')
            if len(request_line) >= 2:
                request_info["method"] = request_line[0]
                request_info["path"] = unquote(request_line[1])
                if len(request_line) >= 3:
                    request_info["version"] = request_line[2]
            
            # Parse headers
            body_start = False
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = True
                    continue
                if body_start:
                    request_info["body"] = '\r\n'.join(lines[i:])
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    request_info["headers"][key.strip()] = value.strip()
        
        return request_info
    
    def _detect_attack_patterns(self, request_data):
        """Detect common attack patterns in the request."""
        patterns = []
        request_lower = request_data.lower()
        
        # SQL Injection patterns
        sql_patterns = ["'", "\"", "union", "select", "insert", "delete", 
                       "drop", "update", "--", "/*", "*/", "or 1=1", "' or '"]
        for pattern in sql_patterns:
            if pattern in request_lower:
                patterns.append(f"SQL_INJECTION:{pattern}")
        
        # XSS patterns
        xss_patterns = ["<script", "javascript:", "onerror=", "onload=", 
                       "onclick=", "alert(", "document.cookie"]
        for pattern in xss_patterns:
            if pattern in request_lower:
                patterns.append(f"XSS:{pattern}")
        
        # Path traversal
        if "../" in request_data or "..%2f" in request_lower:
            patterns.append("PATH_TRAVERSAL")
        
        # Command injection
        cmd_patterns = ["|", ";", "`", "$(",  "&&", "||"]
        for pattern in cmd_patterns:
            if pattern in request_data:
                patterns.append(f"CMD_INJECTION:{pattern}")
        
        # Scanner detection
        scanner_agents = ["nikto", "nmap", "sqlmap", "burp", "dirbuster", 
                        "gobuster", "wfuzz", "hydra", "masscan"]
        for scanner in scanner_agents:
            if scanner in request_lower:
                patterns.append(f"SCANNER:{scanner}")
        
        return patterns
    
    def _generate_response(self, request_info):
        """Generate a fake HTTP response."""
        path = request_info.get("path", "/")
        
        # Return different responses based on path
        if path == "/" or path == "/index.html":
            body = """<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome to our server</h1>
<p>This server is under maintenance.</p>
</body>
</html>"""
        elif "/admin" in path or "/login" in path:
            body = """<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
<h1>Admin Panel</h1>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form>
</body>
</html>"""
        elif ".php" in path:
            body = """<!DOCTYPE html>
<html>
<head><title>PHP Page</title></head>
<body>
<h1>PHP Application</h1>
<p>Processing your request...</p>
</body>
</html>"""
        else:
            body = """<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 - Page Not Found</h1>
</body>
</html>"""
        
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Server: Apache/2.4.41 (Ubuntu)\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        
        return response
