# SENTINEL HIVE CYBER 🐝

A comprehensive HoneyPot security system designed to detect and log cyber attacks. The system simulates vulnerable services (SSH, HTTP, FTP) to attract attackers and captures their attack patterns, which are then displayed on a real-time Flask dashboard.

## Features

- **Multi-Protocol HoneyPots**: Simulates SSH, HTTP, and FTP services
- **Attack Logging**: Captures detailed information about attack attempts
- **Pattern Detection**: Identifies common attack patterns (SQL injection, XSS, path traversal, etc.)
- **Real-time Dashboard**: Flask-based web interface for monitoring attacks
- **Statistics & Analytics**: Visual charts and statistics about attack patterns
- **Top Attackers Tracking**: Monitors and ranks attacking IP addresses

## Project Structure

```
SENTINEL_HIVE_CYBER/
├── honeypot/                    # HoneyPot services
│   ├── __init__.py
│   ├── logger.py               # Attack logging module
│   ├── ssh_honeypot.py         # SSH HoneyPot service
│   ├── http_honeypot.py        # HTTP HoneyPot service
│   └── ftp_honeypot.py         # FTP HoneyPot service
├── dashboard/                   # Flask dashboard
│   ├── app.py                  # Main Flask application
│   ├── templates/              # HTML templates
│   │   ├── index.html         # Main dashboard
│   │   ├── attacks.html       # Attacks detail page
│   │   └── attackers.html     # Top attackers page
│   └── static/
│       └── css/
│           └── style.css      # Dashboard styles
├── config/
│   └── config.json            # Configuration file
├── logs/                       # Attack logs directory
├── main.py                     # Main entry point
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/AmEr-v/SENTINEL_HIVE_CYBER.git
   cd SENTINEL_HIVE_CYBER
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Edit `config/config.json` to customize the honeypot settings:

```json
{
    "honeypot": {
        "ssh_port": 2222,
        "http_port": 8080,
        "ftp_port": 2121
    },
    "dashboard": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": false
    },
    "logging": {
        "log_dir": "logs"
    }
}
```

## Usage

### Start All Services

```bash
python main.py --all
```

### Start Specific Services

```bash
# SSH HoneyPot only
python main.py --ssh

# HTTP HoneyPot only
python main.py --http

# FTP HoneyPot only
python main.py --ftp

# Dashboard only
python main.py --dashboard
```

### Access the Dashboard

Open your web browser and navigate to:
```
http://localhost:5000
```

## Dashboard Features

### Main Dashboard
- Total attack count
- Attacks breakdown by type (SSH, HTTP, FTP)
- Attack type distribution chart
- Hourly attack distribution chart
- Recent attacks table
- Top attackers list

### Attacks Page
- Detailed list of all attacks
- Filter by attack type
- Search functionality
- Detailed attack information including credentials and patterns

### Attackers Page
- Top attackers by attack count
- Threat level classification
- Visual chart of attack distribution

## HoneyPot Services

### SSH HoneyPot (Port 2222)
- Captures login credentials
- Logs authentication attempts (password and public key)
- Records attacker IP and connection details

### HTTP HoneyPot (Port 8080)
- Simulates vulnerable web server
- Detects attack patterns:
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - Path Traversal
  - Command Injection
  - Scanner detection (Nikto, Nmap, SQLMap, etc.)
- Logs request details, headers, and payloads

### FTP HoneyPot (Port 2121)
- Captures FTP login attempts
- Logs commands and credentials
- Simulates basic FTP responses

## Security Considerations

⚠️ **Warning**: This system is designed to be intentionally vulnerable for research and educational purposes.

- Run the honeypot on an isolated network or VM
- Do not expose to production environments
- Monitor the system for any unusual activity
- Regularly review and analyze the captured logs

## API Endpoints

The dashboard provides REST API endpoints:

- `GET /api/stats` - Get attack statistics
- `GET /api/attacks` - Get all attacks
- `GET /api/attacks/<type>` - Get attacks by type (ssh, http, ftp)

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This tool is intended for educational and research purposes only. Use responsibly and only on systems you own or have permission to test. The authors are not responsible for any misuse or damage caused by this tool.