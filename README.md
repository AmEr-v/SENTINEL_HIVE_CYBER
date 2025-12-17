# SENTINEL_HIVE_CYBER

## Log Ingestion from VM

The dashboard displays real attack attempts from the VM's honeypots.

### Log Locations on VM

- **HTTP Honeypot Log**: Configured path (e.g., `/var/log/http-honeypot.log`)
- **Cowrie SSH Log**: `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`

### Ingestion Architecture

VM pushes events to dashboard.

- **Shipper Script**: `vm_shipper.py` runs on the VM.
- **Endpoint**: Dashboard exposes `POST /api/ingest` to receive events.
- **Incremental**: Shipper tracks file offsets in `offsets.json` to send only new events.
- **Retries**: On failure, retries with exponential backoff.

### Running the Shipper

On the VM, install dependencies:

```bash
pip install requests
```

Run the shipper:

```bash
python vm_shipper.py --dashboard-url http://<WINDOWS_DASHBOARD_IP>:<PORT> --http-log <HTTP_LOG_PATH> --ssh-log /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

The shipper tails the logs and POSTs new events every 5 seconds.

### Dashboard Metrics

- **HTTP Attempts**: Count of `http_request` events.
- **SSH Attempts**: Count of `cowrie.login.failed` and `cowrie.login.success` events.
- **Real-Time**: Metrics update as events are ingested from DB.

### Proof Test

1. Delete `telemetry.db` on Windows
2. Start dashboard: `python app.py`
3. Start `vm_shipper.py` on VM
4. Generate 5 SSH login failures + 5 HTTP requests against honeypots
5. Dashboard shows increases immediately
6. Console logs on VM prove events posted and inserted