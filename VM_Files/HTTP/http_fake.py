from flask import Flask, request, make_response, redirect
import datetime
import json
import os

app = Flask(__name__)

LOGFILE = os.path.expanduser("~/http-honeypot.log")


def log_request():
    """Log every HTTP request as JSON to a file."""
    data = {
        "event": "http_request",
        "time": datetime.datetime.utcnow().isoformat() + "Z",
        "remote_addr": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode("utf8", "ignore"),
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True),
    }
    try:
        with open(LOGFILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception:
        # Honeypot should never crash because logging failed
        pass


def log_login(username: str, password: str):
    """Log fake login credentials."""
    data = {
        "event": "fake_login",
        "time": datetime.datetime.utcnow().isoformat() + "Z",
        "remote_addr": request.remote_addr,
        "username": username,
        "password": password,
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "path": request.path,
    }
    try:
        with open(LOGFILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception:
        pass


@app.before_request
def before_request():
    log_request()


LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>USCYBERCOM ACCESS GATEWAY</title>
  <style>
    html, body {{
      margin: 0;
      padding: 0;
      background: #020617;
      color: #e5e7eb;
      font-family: "Courier New", monospace;
    }}
    body {{
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .frame {{
      border: 1px solid #22d3ee;
      box-shadow: 0 0 30px #22d3ee55;
      padding: 24px 28px;
      max-width: 480px;
      width: 100%;
      background: #020617eb;
    }}
    .title {{
      font-size: 20px;
      letter-spacing: 3px;
      text-transform: uppercase;
      color: #22d3ee;
      margin-bottom: 4px;
    }}
    .subtitle {{
      font-size: 11px;
      letter-spacing: 2px;
      color: #9ca3af;
      margin-bottom: 14px;
    }}
    .badge {{
      display: inline-block;
      font-size: 10px;
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid #f97316;
      color: #fed7aa;
      text-transform: uppercase;
      margin-bottom: 10px;
    }}
    .warning {{
      font-size: 11px;
      color: #fecaca;
      margin-bottom: 16px;
      text-transform: uppercase;
    }}
    label {{
      display: block;
      font-size: 11px;
      margin-top: 8px;
      margin-bottom: 2px;
      color: #9ca3af;
    }}
    input[type="text"],
    input[type="password"] {{
      width: 100%;
      border: 1px solid #334155;
      background: #020617;
      color: #e5e7eb;
      padding: 6px 7px;
      font-family: inherit;
      font-size: 12px;
    }}
    input[type="text"]:focus,
    input[type="password"]:focus {{
      outline: 1px solid #22d3ee;
    }}
    .meta {{
      font-size: 11px;
      color: #6b7280;
      margin-top: 10px;
    }}
    .btn-row {{
      margin-top: 14px;
      display: flex;
      justify-content: flex-end;
    }}
    button {{
      border: 1px solid #22d3ee;
      background: #0f172a;
      color: #e5f3ff;
      font-size: 11px;
      padding: 6px 14px;
      text-transform: uppercase;
      letter-spacing: 1px;
      cursor: pointer;
    }}
    button:hover {{
      background: #22d3ee33;
    }}
    .ip-line {{
      margin-top: 4px;
      font-size: 11px;
      color: #94a3b8;
    }}
  </style>
</head>
<body>
  <div class="frame">
    <div class="title">USCYBERCOM GATEWAY</div>
    <div class="subtitle">SENTINEL HIVE CYBER - PENTA-DB EDGE NODE</div>

    <div class="badge">TOP SECRET // SI // NOFORN</div>
    <div class="warning">
      Unauthorized access is strictly prohibited. All credentials and activity are recorded.
    </div>

    <form method="post" action="/">
      <label for="username">USER ID</label>
      <input type="text" id="username" name="username" autocomplete="off" required>

      <label for="password">ACCESS KEY</label>
      <input type="password" id="password" name="password" autocomplete="off" required>

      <div class="btn-row">
        <button type="submit">INITIATE SESSION</button>
      </div>
    </form>

    <div class="meta">
      Session source: {ip}<br>
      Gateway profile: HONEYPOT_HTTP_EDGE
    </div>
    <div class="ip-line">
      Notice: Login attempts are mirrored to central audit infrastructure.
    </div>
  </div>
</body>
</html>
"""


CONSOLE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PENTAGON DATA CORE</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <style>
    html, body {{
      margin: 0;
      padding: 0;
      background: #020409;
      color: #e5f3ff;
      font-family: "Courier New", monospace;
    }}
    body {{ min-height: 100vh; }}
    .scan-bg {{
      position: fixed;
      inset: 0;
      background: radial-gradient(circle at top, #122338 0, #020409 55%);
      opacity: 0.9;
      pointer-events: none;
      z-index: 0;
    }}
    .wrapper {{
      position: relative;
      z-index: 1;
      max-width: 1200px;
      margin: 24px auto 40px auto;
      padding: 0 16px 40px 16px;
    }}
    .card {{
      border: 1px solid #26d1ff33;
      box-shadow: 0 0 32px #26d1ff33;
      background: #050812f2;
      padding: 24px 26px;
    }}
    .header-line {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #26d1ff55;
      padding-bottom: 10px;
      margin-bottom: 16px;
    }}
    .sys-title {{
      font-size: 26px;
      letter-spacing: 4px;
      text-transform: uppercase;
      color: #26d1ff;
    }}
    .sys-sub {{
      font-size: 13px;
      letter-spacing: 2px;
      color: #94a3b8;
      margin-top: 4px;
    }}
    .badge {{
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid #ff3860;
      color: #ffced6;
      text-transform: uppercase;
      background: #3b0b15;
    }}
    .warning {{
      color: #ff6b6b;
      font-size: 13px;
      margin-bottom: 14px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}
    .section-title {{
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 2px;
      color: #7dd3fc;
      margin-top: 22px;
      margin-bottom: 6px;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1.3fr 1fr;
      gap: 18px;
      margin-top: 10px;
    }}
    .panel {{
      border: 1px solid #26d1ff33;
      padding: 12px 14px;
      background: #020617;
      font-size: 12px;
      min-height: 140px;
      overflow: hidden;
    }}
    .panel-header {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      color: #9ca3af;
      font-size: 11px;
    }}
    .status-ok {{ color: #22c55e; }}
    .status-warn {{ color: #f97316; }}
    .console {{
      font-size: 12px;
      line-height: 1.4;
      white-space: pre-wrap;
      color: #c4f1ff;
    }}
    .footer {{
      margin-top: 18px;
      border-top: 1px solid #26d1ff33;
      padding-top: 8px;
      font-size: 11px;
      color: #6b7280;
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      row-gap: 4px;
    }}
    .blink {{ animation: blink 1.2s steps(2, start) infinite; }}
    @keyframes blink {{ to {{ visibility: hidden; }} }}
    .input-row {{
      margin-top: 10px;
      font-size: 12px;
      color: #a5b4fc;
    }}
    .fake-input {{
      border: 1px solid #26d1ff55;
      background: #020617;
      color: #e5e7eb;
      padding: 6px 7px;
      width: 100%;
      font-family: inherit;
      font-size: 12px;
    }}
    .table-wrap {{
      border: 1px solid #26d1ff33;
      background: #020617;
      padding: 10px 12px;
      overflow-x: auto;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      font-size: 12px;
    }}
    th, td {{
      border-bottom: 1px solid #1f2933;
      padding: 4px 6px;
      text-align: left;
      white-space: nowrap;
    }}
    th {{
      color: #7dd3fc;
      font-weight: normal;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-size: 11px;
    }}
    tr:nth-child(even) td {{ background: #020814; }}
    tr.danger td {{
      color: #fecaca;
      background: #450a0a;
    }}
    .tag {{
      font-size: 10px;
      text-transform: uppercase;
      border-radius: 3px;
      padding: 1px 5px;
      border: 1px solid #4b5563;
      color: #9ca3af;
    }}
    .tag-red {{
      border-color: #f97316;
      color: #fed7aa;
    }}
    .tag-green {{
      border-color: #22c55e;
      color: #bbf7d0;
    }}
    .log-block {{
      border: 1px solid #26d1ff33;
      background: #020617;
      padding: 10px 12px;
      font-size: 11px;
      color: #c4f1ff;
      white-space: pre-wrap;
      line-height: 1.35;
      max-height: 260px;
      overflow-y: auto;
    }}
  </style>
</head>
<body>
<div class="scan-bg"></div>
<div class="wrapper">
  <div class="card">
    <div class="header-line">
      <div>
        <div class="sys-title">USCYBERCOM DATA CORE</div>
        <div class="sys-sub">
          NODE: PENTA-DB-{node_id}   CLUSTER: SENTINEL-HIVE   CLASS: TIER-0 STORAGE
        </div>
      </div>
      <div class="badge">TOP SECRET // SI // NOFORN</div>
    </div>

    <div class="warning">
      UNAUTHORIZED ACCESS TO THIS SYSTEM CONSTITUTES A FEDERAL OFFENSE. ALL ACTIVITY IS LOGGED AND ACTIVELY MONITORED.
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-header">
          <span>AUTH SESSION TRACE</span>
          <span class="status-ok">SECURE CHANNEL ESTABLISHED</span>
        </div>
        <div class="console">
authd: binding user context &lt;external-session&gt;
authd: federated token accepted
authd: mapping source {ip} to virtual clearance profile
vault: mounting classified dataset views for sector EAST-CORE
vault: granting read only cursor to segment PENTA_CORE_7
audit: enabling deep packet inspection on session
audit: correlating source {ip} with live threat matrix
[READY] enter query at prompt below<span class="blink">_</span>
        </div>

        <div class="input-row">
          db@PENTA_CORE_7:~$ <input class="fake-input"
            value="SELECT * FROM threat_matrix WHERE src_ip='{ip}' ORDER BY last_seen DESC LIMIT 50;" />
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <span>LIVE SYSTEM STATUS</span>
          <span class="status-warn">DECEPTION LAYER: ARMED</span>
        </div>
        <div class="console">
CLUSTER HEALTH       [ OK ]
REPL SET PING        [ 1.2 ms ]
ACTIVE NODES         [ 12 ]
INGEST RATE          [ 84,129 events / min ]
ANOMALY SCORE        [ 0.93 ]
COUNTERINTRUSION     [ ENGAGED ]
HONEYPOT SURFACES    [ SSH, HTTP, API, DB ]
LOG SINK             [ /blacksite-7/funnel/core.log ]
OPERATOR ON DUTY     [ RED CELL / DELTA ]
        </div>
      </div>
    </div>

    <div class="section-title">REQUEST METADATA SNAPSHOT</div>
    <div class="table-wrap">
      <table>
        <tbody>
          <tr><th>FIELD</th><th>VALUE</th></tr>
          <tr><td>remote_addr</td><td>{ip}</td></tr>
          <tr><td>method</td><td>{method}</td></tr>
          <tr><td>path</td><td>{path}</td></tr>
          <tr><td>user_agent</td><td>{user_agent}</td></tr>
          <tr><td>request_id</td><td>{req_id}</td></tr>
          <tr><td>time_utc</td><td>{time}</td></tr>
          <tr><td>route_profile</td><td>HONEYPOT_HTTP_EDGE</td></tr>
          <tr><td>threat_level</td><td><span class="tag tag-red">ELEVATED</span></td></tr>
        </tbody>
      </table>
    </div>

    <div class="section-title">VIRTUAL USER DIRECTORY INDEX</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>UID</th>
            <th>ACCOUNT</th>
            <th>CLEARANCE</th>
            <th>LAST LOGIN</th>
            <th>ORIGIN</th>
            <th>STATUS</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>0001</td>
            <td>root_core</td>
            <td>TIER-0 / ROOT</td>
            <td>2025-11-28T00:00:00Z</td>
            <td>INTNET-0</td>
            <td><span class="tag tag-green">LOCKED</span></td>
          </tr>
          <tr>
            <td>0413</td>
            <td>sec_ops</td>
            <td>TIER-2 / OPS</td>
            <td>2025-11-27T18:22:11Z</td>
            <td>USCYBER-OPS</td>
            <td><span class="tag tag-green">ACTIVE</span></td>
          </tr>
          <tr>
            <td>0927</td>
            <td>threat_intel</td>
            <td>TIER-3 / ANALYST</td>
            <td>2025-11-27T22:09:43Z</td>
            <td>INTNET-3</td>
            <td><span class="tag">RESTRICTED</span></td>
          </tr>
          <tr class="danger">
            <td>6666</td>
            <td>external_{ip}</td>
            <td>UNCLASSIFIED / OBSERVED</td>
            <td>{time}</td>
            <td>{ip}</td>
            <td><span class="tag tag-red">FLAGGED</span></td>
          </tr>
          <tr>
            <td>7777</td>
            <td>honey_daemon</td>
            <td>DECOY CONTROLLER</td>
            <td>n/a</td>
            <td>INTERNAL</td>
            <td><span class="tag">SYSTEM</span></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="section-title">ACCESS AUDIT TRAIL (SCROLLBACK)</div>
    <div class="log-block">
{time}   [AUTH]  new http session from {ip} mapped to profile &lt;external-observer&gt;
{time}   [ROUTE] request {req_id} routed to HONEYPOT_HTTP_EDGE
{time}   [INTEL] user agent fingerprint: {user_agent}
{time}   [INTEL] heuristic score: 0.76  tags: [WEB-SCAN] [RECON]
{time}   [STORE] event archived to segment PENTA_CORE_7
{time}   [ALERT] mirrored traffic exported to red team sandbox
{time}   [TRACE] preparing synthetic dataset responses
{time}   [TRACE] injecting decoy delay into response stream
{time}   [NOTE ] operator hint: watch source {ip} for follow up activity

2025-11-27T21:58:12Z   [HIST] external session 198.x.x.x probed /admin, /login, /config, /shell
2025-11-27T22:03:41Z   [HIST] external session 198.x.x.x attempted credential spray
2025-11-27T22:05:02Z   [HIST] signatures matched: webshell generic, phpmyadmin brute
2025-11-27T22:10:29Z   [HIST] automatic blacklist trial period started

2025-11-26T13:11:55Z   [HIST] internal QA job replayed attack corpus against honeypot surface
2025-11-25T09:43:07Z   [HIST] baselining normal traffic profiles for PENTA_CORE_7
    </div>

    <div class="footer">
      <span>USCYBERCOM PENTA-DB GATEWAY v7.4.9</span>
      <span>ALL COMMANDS ARE RECORDED FOR NATIONAL SECURITY REVIEW</span>
    </div>
  </div>
</div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def login():
    """Fake login gateway. Any credentials are accepted and logged."""
    ip = request.remote_addr or "0.0.0.0"

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        log_login(username, password)

        # Simple fake session token, not secure and not needed to be
        token = hex(abs(hash(f"{username}-{password}-{ip}-{datetime.datetime.utcnow()}")))[2:18]
        resp = redirect("/console")
        resp.set_cookie("auth_token", token, httponly=True)
        return resp

    html = LOGIN_TEMPLATE.format(ip=ip)
    return make_response(html, 200)


@app.route("/console", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/console/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def console(path):
    """Main fake Pentagon console after login."""
    ip = request.remote_addr or "0.0.0.0"
    method = request.method
    ua = request.headers.get("User-Agent", "unknown")
    now = datetime.datetime.utcnow().isoformat() + "Z"
    req_id = hex(abs(hash(f"{ip}-{now}-{path}-{method}")))[2:10].upper()
    node_id = req_id[:4]

    html = CONSOLE_TEMPLATE.format(
        ip=ip,
        method=method,
        path="/" + path,
        user_agent=ua,
        time=now,
        req_id=req_id,
        node_id=node_id,
    )
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
