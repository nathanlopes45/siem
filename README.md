# SIEM — A Hands-On Security Information & Event Management Lab

A custom-built SIEM backend that ingests logs, correlates events, and raises alerts on suspicious activity — built from scratch to understand how detection engineering actually works under the hood, rather than just operating someone else's tool.

## Why this project exists

Most SIEM experience on a resume comes from clicking around Splunk or Sentinel dashboards. This project goes one layer deeper: designing the log schema, writing the correlation logic, and reasoning about detection tradeoffs (false positives, alert fatigue, time-window sizing) myself.

## Architecture

```
                 ┌─────────────┐
   raw logs ───► │   FastAPI   │
                 │  (ingest +  │
                 │  detection) │
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │  PostgreSQL │
                 │ hosts/logs/ │
                 │   alerts    │
                 └─────────────┘
```

- **API layer**: FastAPI, handles log ingestion and exposes query endpoints for hosts, logs, and alerts
- **Storage**: PostgreSQL via SQLAlchemy ORM
- **Detection engine**: runs correlation rules against ingested logs on each write (roadmap: move to an async background worker — see below)
- **Deployment**: fully containerized with Docker Compose (API + Postgres)

## Detections implemented

| Detection | Logic | MITRE ATT&CK |
|---|---|---|
| Brute Force Attempt | ≥5 failed password attempts from one IP against a host | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Rapid Brute Force | ≥5 failed attempts from one IP within a 2-minute window | T1110 (time-boxed variant) |
| Successful Brute Force | A successful login from an IP that had ≥5 prior failed attempts | T1110 → T1078 (Valid Accounts, post-compromise) |
| Threat Intel Match | Log contains a source IP found on a known-malicious IP list | [T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) (C2 infrastructure reuse) |

## Tech stack

- **Backend**: Python, FastAPI, SQLAlchemy
- **Database**: PostgreSQL
- **Containerization**: Docker, Docker Compose
- **Detection engineering**: custom correlation rules (regex-based log parsing, IP extraction, time-windowed aggregation)

## Getting started

### Prerequisites
- Docker and Docker Compose installed

### Setup

```bash
git clone https://github.com/nathanlopes45/siem.git
cd siem
cp .env.example .env
# edit .env and set a real password for POSTGRES_PASSWORD
docker compose up --build
```

The API will be available at `http://localhost:8000`.

### Verify it's running

```bash
curl http://localhost:8000/
# {"status":"SIEM backend running with database connected"}
```

## API usage

### Register a host
```bash
curl -X POST "http://localhost:8000/hosts?hostname=web-server-01&ip_address=10.0.0.5&os_type=linux"
```

### Ingest a log
```bash
curl -X POST "http://localhost:8000/logs" \
  -d "host_id=<HOST_UUID>" \
  -d "log_source=sshd" \
  -d "raw_log=Failed password for root from 185.220.101.1 port 4444 ssh2"
```

### List hosts
```bash
curl http://localhost:8000/hosts
```

### Query logs (optionally filter by host or source)
```bash
curl "http://localhost:8000/logs?host_id=<HOST_UUID>&log_source=sshd"
```

### View triggered alerts
```bash
curl http://localhost:8000/alerts
```

## Security practices in this repo

- No secrets committed — credentials are loaded from a gitignored `.env`, with `.env.example` as the template
- `detect-secrets` baseline scan integrated to catch accidental credential leaks before they're pushed
- Database connection retry/healthcheck logic to avoid race conditions on container startup

## Roadmap

- [ ] Real log parsers for syslog/auth.log formats (structured fields instead of single regex IP extraction)
- [ ] Move detection engine to an async background worker, decoupled from the ingestion request path
- [ ] Cross-host correlation (e.g., same attacker IP hitting multiple hosts — lateral movement / credential stuffing signal)
- [ ] API authentication
- [ ] Alerting integrations (Slack/webhook notifications on new alerts)
- [ ] LLM-assisted alert triage: natural-language incident summaries and severity suggestions generated from raw log context
- [ ] Dashboard for visualizing alerts and log volume over time
- [ ] Automated test suite for detection logic

## License

MIT
