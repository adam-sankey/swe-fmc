# Cisco Secure Analytics → Firepower Management Center (FMC) Webhook Integration

A lightweight Flask-based webhook listener that automatically blocks malicious IPs detected by Cisco Secure Analytics (formerly Stealthwatch Enterprise) by adding them to a blocked network group in Cisco Firepower Management Center (FMC).

---

## How It Works

1. Cisco Secure Analytics detects a suspicious or malicious IP and fires a webhook event to this service.
2. The service parses the target IP (and hostname, if available) from the event payload.
3. A new **Host object** is created in FMC via the FMC REST API.
4. The new host is appended to an existing **Network Group** (`malicious_ips` by default).
5. Any firewall policy referencing that group will immediately begin blocking traffic to/from that IP.

```
Cisco Secure Analytics
        │
        │  POST /blockdns  (webhook)
        ▼
  Flask Webhook Listener
        │
        ├─ 1. Parse target IP + hostname
        ├─ 2. Authenticate → FMC (generate token)
        ├─ 3. Create Host object in FMC
        ├─ 4. Fetch current members of block group
        └─ 5. Update block group with new host
```

---

## Prerequisites

- Python 3.x
- A running **Cisco FMC** instance with API access enabled
- A **Cisco Secure Analytics** (Stealthwatch) deployment configured to send webhooks
- A pre-existing **Network Group** in FMC that is referenced by a blocking access control policy

### Python Dependencies

```bash
pip install flask requests urllib3
```

---

## Configuration

Edit the environment-specific variables at the top of the script before deploying:

| Variable | Description | Example |
|---|---|---|
| `fmcHostName` | Hostname or IP of your FMC instance | `fmc.yourdomain.net` |
| `fmcAuthString` | Base64-encoded `username:password` for FMC API auth | `YXBpOkMhc2NvMTIzNDU2Nw==` |
| `fmcDomain` | UUID of the FMC domain to operate in | `e276abec-e0f2-11e3-8169-6d9ed49b625f` |
| `fmcBlockGroupId` | UUID of the Network Group to add blocked IPs to | `000D3A3A-EE99-0ed3-0000-004294968227` |
| `fmcBlockGroupName` | Name of the Network Group (must match FMC) | `malicious_ips` |

### Generating the Base64 Auth String

```bash
echo -n "apiuser:YourPassword123" | base64
```

### Finding Your FMC Domain UUID

The domain UUID can be retrieved from the FMC API:

```
GET https://<fmcHostName>/api/fmc_platform/v1/info/domain
```

---

## Running the Service

### Directly

```bash
python3 webhook_listener.py
```

The Flask app will listen on `0.0.0.0:5000` by default.

### With a WSGI Server (Recommended for Production)

A WSGI entry point (`wsgi.py`) is included to serve the app via a production-grade server such as **gunicorn** or **mod_wsgi**. It expects the application to be installed at `/var/www/flaskapps/` with the main script named `ddc.py`.

**Directory structure expected:**
```
/var/www/flaskapps/
└── ddc/
    ├── ddc.py          ← main webhook script (rename if needed)
    ├── wsgi.py         ← WSGI entry point
    └── webapp.log      ← created automatically at runtime
```

**Running with gunicorn:**
```bash
pip install gunicorn
gunicorn --bind 0.0.0.0:5000 wsgi:application
```

If your main script is named differently than `ddc.py`, update the import in `wsgi.py` to match:
```python
from your_script_name import app as application
```

### As a systemd Service (Recommended for Production)

Create `/etc/systemd/system/fmc-webhook.service`:

```ini
[Unit]
Description=Cisco Secure Analytics FMC Webhook Listener
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/flaskapps/ddc
ExecStart=/usr/bin/gunicorn --bind 0.0.0.0:5000 wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable fmc-webhook
sudo systemctl start fmc-webhook
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Health check — returns a status string |
| `POST` | `/blockdns` | Webhook receiver — processes incoming Secure Analytics events |

### Expected Webhook Payload

```json
{
  "event": {
    "target_ip": "192.168.1.100",
    "target_hostname": "malicious-host.example.com"
  }
}
```

`target_hostname` is optional — if absent, the host object will be named `unknown-<ip>`.

---

## Logging

All activity is logged to `/var/www/flaskapps/ddc/webapp.log` with timestamps.

```
2024-03-06 14:32:01  Webhook received: 192.168.1.100
2024-03-06 14:32:02  Group successfully updated with new host
```

Ensure the process has write access to this path, or update the `writeLog()` function to point to a different location.

---

## Security Considerations

- **SSL verification is disabled** (`verify=False`) for FMC API calls. It is strongly recommended to install a valid certificate on your FMC and re-enable verification in production.
- The `fmcAuthString` is a static Base64-encoded credential. Consider rotating this regularly or using environment variables instead of hardcoding:
  ```python
  import os
  fmcAuthString = os.environ.get("FMC_AUTH_STRING")
  ```
- Restrict access to the `/blockdns` endpoint to only the IP(s) of your Secure Analytics instance using a reverse proxy (e.g., nginx) or firewall rules.
- Run the Flask app behind a production WSGI server (e.g., **gunicorn**) rather than the built-in development server in production environments.

---

## Troubleshooting

| Symptom | Likely Cause |
|---|---|
| `401` on token request | Incorrect or expired `fmcAuthString` |
| `404` on host creation | Wrong `fmcDomain` UUID |
| `404` on group fetch/update | Wrong `fmcBlockGroupId` UUID |
| `409` on host creation | Host object with that name already exists in FMC |
| No log entries | Check write permissions on the log file path |
