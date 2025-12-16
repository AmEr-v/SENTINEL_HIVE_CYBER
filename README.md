# SENTINEL_HIVE_CYBER

## Log Ingestion from VM

The dashboard displays real attack attempts from the VM's honeypots.

### Log Locations on VM

- **HTTP Honeypot Log**: `/home/<user>/http-honeypot.log` (JSONL format)
- **Cowrie SSH Log**: `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` (JSONL format)

### Ingestion Architecture

Uses **Option A: VM pushes events to dashboard**.

- **Shipper Script**: `shipper.py` runs on the VM.
- **Endpoint**: Dashboard exposes `POST /api/ingest` to receive events.
- **Incremental**: Shipper tracks file offsets to send only new events.

### Running the Shipper

On the VM, install dependencies:

```bash
pip install requests
```

Run the shipper:

```bash
python shipper.py --dashboard-url http://dashboard-host:5000 --http-log /home/user/http-honeypot.log --ssh-log /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

The shipper tails the logs and POSTs new events every 5 seconds.

### Dashboard Metrics

- **HTTP Attempts**: Count of `http_request` events.
- **SSH Attempts**: Count of `cowrie.login.failed` and `cowrie.login.success` events.
- **Real-Time**: Metrics update as events are ingested.

### Proof Test

1. Delete `telemetry.db`
2. Restart dashboard (shows 0)
3. Generate traffic: 5 HTTP requests + 5 SSH attempts
4. Metrics increase by 5 each
5. Logs show ingested counts