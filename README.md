# SIEM — A Hands-On Security Information & Event Management Lab

A custom-built SIEM backend that ingests logs, correlates events, and raises alerts on suspicious activity — built from scratch to understand how detection engineering actually works under the hood, rather than just operating someone else's tool.

## Why this project exists

Most SIEM experience on a resume comes from clicking around Splunk or Sentinel dashboards. This project goes one layer deeper: designing the log schema, writing the correlation logic, and reasoning about detection tradeoffs (false positives, alert fatigue, time-window sizing, ingestion vs. detection latency) myself.

## Architecture

```
                 ┌─────────────┐
   raw logs ───► │   FastAPI   │──── fast path: parse + store only
                 │  (ingest)   │
                 └──────┬──────┘
                        │
                        ▼
                ┌───────────────┐        ┌────────────────────┐
                │   PostgreSQL  │◄──────►│  Detection Worker  │
                │ hosts/logs/   │  polls │  (separate proc.,  │
                │   alerts      │  every │   runs on a timer) │
                └───────────────┘   10s  └────────────────────┘
```

- **API layer**: FastAPI. Ingestion is deliberately "dumb and fast" — parse structured fields from the raw log, store it, return. No detection logic runs on the request path.
- **Detection worker**: a separate process/container that polls the database on a fixed interval and runs every detection rule against each host. Decoupled so a slow, expensive, or failing detector (e.g. an ML model, an external threat-intel API call) can never add latency to log ingestion, and detection can be scaled independently of the API.
- **Log parsing**: structured field extraction (event type, username, source IP, source port) at ingest time, rather than one generic regex grabbing an IP out of an opaque string.
- **Storage**: PostgreSQL via SQLAlchemy ORM, with indexes on the columns every detector actually filters/groups by.
- **Deployment**: fully containerized with Docker Compose (API + worker + Postgres, three independent services sharing one database).

## Detections implemented

| Detection | Logic | MITRE ATT&CK |
|---|---|---|
| Brute Force Attempt | ≥5 `failed_password` events from one IP against a host | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Rapid Brute Force | ≥5 `failed_password` events from one IP within a 2-minute window | T1110 (time-boxed variant) |
| Successful Brute Force | An `accepted_password` event from an IP that had ≥5 prior `failed_password` events | T1110 → T1078 (Valid Accounts, post-compromise) |
| Threat Intel Match | Log's source IP matches a known-malicious IP list | [T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) (C2 infrastructure reuse) |

All detections run against structured, parsed fields (`event_type`, `attacker_ip`) rather than raw-text pattern matching, and use aggregated `GROUP BY`/`HAVING` queries rather than pulling every row into Python.

## Tech stack

- **Backend**: Python, FastAPI, SQLAlchemy
- **Database**: PostgreSQL
- **Containerization**: Docker, Docker Compose (API, worker, and DB as independent services)
- **Detection engineering**: custom correlation rules, structured log parsing, aggregated queries, decoupled background detection worker

## Getting started

### Prerequisites
- Docker and Docker Compose installed

### Setup

```bash
git clone https://github.com/nathanlopes45/siem.git
cd siem
cp .env.example .env
# edit .env: set a real POSTGRES_PASSWORD and a long random API_KEY
docker compose up --build
```

This starts three containers: `siem_postgres`, `siem_api`, and `siem_worker`. The API is available at `http://localhost:8000`. The worker runs silently in the background, polling every 10 seconds.

Every endpoint except the root health check (`GET /`) requires an `X-API-Key` header matching the `API_KEY` value in your `.env`.

### Verify it's running

```bash
curl http://localhost:8000/
# {"status":"SIEM backend running with database connected"}
```

## API usage

All requests below require your API key. Export it once per terminal session so you don't have to repeat it:
```bash
API_KEY="your-api-key-from-.env"
```

### Register a host
```bash
curl -X POST "http://localhost:8000/hosts?hostname=web-server-01&ip_address=10.0.0.5&os_type=linux" \
  -H "X-API-Key: $API_KEY"
```

### Ingest a log
```bash
curl -X POST "http://localhost:8000/logs" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host_id": "<HOST_UUID>", "log_source": "sshd", "raw_log": "Failed password for root from 185.220.101.1 port 4444 ssh2"}'
```

The response includes structured fields extracted by the parser: `event_type`, `username`, `attacker_ip`, `src_port`.

### List hosts
```bash
curl http://localhost:8000/hosts -H "X-API-Key: $API_KEY"
```

### Query logs (optionally filter by host, source, or event type)
```bash
curl "http://localhost:8000/logs?host_id=<HOST_UUID>&event_type=failed_password" \
  -H "X-API-Key: $API_KEY"
```

### View triggered alerts
```bash
curl http://localhost:8000/alerts -H "X-API-Key: $API_KEY"
```

### Manually trigger detection for a host (useful for demos — the worker also does this automatically every 10s)
```bash
curl -X POST "http://localhost:8000/detect/<HOST_UUID>" -H "X-API-Key: $API_KEY"
```

## Security practices in this repo

- No secrets committed — credentials are loaded from a gitignored `.env`, with `.env.example` as the template
- `detect-secrets` baseline scan integrated to catch accidental credential leaks before they're pushed
- Database connection retry/healthcheck logic to avoid race conditions on container startup

## Roadmap

- [x] Real log parsing (structured `event_type`/`username`/`src_port` fields instead of a single regex-extracted IP)
- [x] Decoupled background detection worker (moved off the ingestion request path)
- [x] API authentication (API key required on every endpoint except health check)
- [ ] Cross-host correlation (e.g., same attacker IP hitting multiple hosts — lateral movement / credential stuffing signal)
- [ ] Alerting integrations (Slack/webhook notifications on new alerts)
- [ ] LLM-assisted alert triage: natural-language incident summaries and severity suggestions generated from raw log context
- [ ] Dashboard for visualizing alerts and log volume over time
- [ ] Automated test suite for detection logic
- [ ] Support additional log source formats beyond SSH (e.g. web server access logs)

## License

MIT