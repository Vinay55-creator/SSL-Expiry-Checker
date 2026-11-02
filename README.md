# SSL Expiry Scanner

Enter a website address. The app finds its subdomains in public certificate logs (crt.sh, with Cert Spotter as a
fallback), connects to each hostname on port 443, reads the live certificate and lists everything by expiry date,
soonest first. Results can be filtered, searched, sorted, and downloaded as **Excel** or **PDF**.

## Option A: run with Docker (recommended)

1. Install Docker Desktop (Windows/macOS) or Docker Engine (Linux) and check it works: `docker --version`
2. Unzip the project and open a terminal inside the folder (the one containing `Dockerfile`).
3. Build and start:
   ```bash
   docker compose up --build -d
   ```
4. Open http://localhost:8000
5. Useful commands:
   ```bash
   docker compose logs -f      # watch logs
   docker compose down         # stop and remove the container
   ```

Without Compose:
```bash
docker build -t ssl-expiry-checker .
docker run -d --name ssl-scanner -p 8000:8000 --restart unless-stopped ssl-expiry-checker
```

## Option B: run without Docker

1. Install Python 3.10 or newer.
2. In the project folder create a virtual environment and install packages:
   ```bash
   python -m venv .venv
   source .venv/bin/activate          # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Start the app: `python app.py`
4. Open http://127.0.0.1:8000

## Run the tests
```bash
python -m unittest discover -s tests -v
```
The tests run offline: a local TLS server stands in for a real website.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RATE_LIMIT_PER_HOUR` | 20 | Scans allowed per visitor per hour |
| `MAX_RUNNING_SCANS` | 3 | Scans running at the same time |
| `MAX_HOSTS` | 500 | Hostnames checked per scan |
| `LOOKBACK_DAYS` | 90 | Also check certificates that expired this many days ago |
| `SCAN_WORKERS` | 20 | Parallel certificate checks per scan |
| `CONNECT_TIMEOUT` | 6 | Seconds to wait for each host |
| `TRUST_PROXY` | 0 | Set to 1 behind nginx/Traefik so visitor IPs are read from `X-Forwarded-For` |

Set them under `environment:` in `docker-compose.yml`, or with `-e NAME=value` on `docker run`.

## Putting it on a server
- Put a reverse proxy (nginx, Caddy, Traefik) with HTTPS in front of port 8000 and set `TRUST_PROXY=1`.
- Keep a single gunicorn worker (already set in the Dockerfile). Scan results are held in memory for one hour,
  so all requests must reach the same process. Restarting the container clears them.

## Good to know
- Subdomains come from public certificate logs. A host that never received a public certificate will not appear,
  and the "common subdomain names" option only adds a small list of guesses (mail, api, vpn and so on).
- Only port 443 is checked.
- Hostnames that resolve to private or reserved addresses are skipped, so the tool cannot be used to probe
  internal networks. Do not change this on a public server (`ALLOW_PRIVATE_TARGETS` is for tests only).
- Only scan domains you own or are allowed to monitor.
