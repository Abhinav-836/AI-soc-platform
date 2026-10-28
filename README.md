# AI SOC Platform 🛡️

A working Security Operations Center platform. It ingests security logs in real time, detects threats with rules, Sigma, threat intelligence, a learned behavioural baseline (ML) and multi-stage attack-chain correlation, then helps an analyst triage and respond, with approval-gated, injection-safe actions.

It runs as a **website** (API + dashboard on one URL), a **Windows desktop app** (installer, own window, works offline) or in **Docker**.

```
 files / syslog / Kafka / REST ──► normalize ──► enrich ──► threat intel ──► rules + Sigma ──► ML baseline ──► attack chains
                                                                                                      │
                     dashboard ◄── WebSocket ◄── alerts (dedup, score, MITRE) ── SQLite (+ Elasticsearch)
                                                     │
                              playbooks ──► approval queue ──► dry-run / enforce (firewall, EDR, notify)
```

## What it does

| Layer | Details |
|---|---|
| **Host monitor** | Real telemetry from the PC it runs on (psutil, Windows/Linux/macOS): new network connections with the owning process, new listening ports, newly started processes. Remote IPs are checked against threat intel and processes against rules/Sigma. Command lines are off by default (they can hold secrets). |
| **Ingestion** | Tails files (globs, rotation, resume after restart), syslog UDP/TCP, Kafka, REST (`POST /api/v1/ingest`). Parses JSON, CEF, sshd, sudo, useradd, iptables/UFW and Apache/Nginx logs, and keeps each event's real timestamp. |
| **Rules** | YAML rules with field modifiers (`contains`, `re`, `cidr`, `private`, `gte`…) and stateful thresholds: count, **distinct** (port scans, password spraying) and **sum** (data exfiltration) per entity within a time window. 11 rules are bundled, each mapped to MITRE ATT&CK. |
| **Sigma** | Loads Sigma rules (selections, modifiers, `and/or/not`, `1 of`/`all of`, Sigma field names). Aggregation rules are rejected with a clear error instead of silently mis-running. |
| **Threat intel** | IOC matching on IPs, CIDRs, domains (including sub-domains), hashes and URLs. Sources: bundled list, analyst-added (saved), optional abuse.ch feeds, and AbuseIPDB / VirusTotal lookups when API keys are set. |
| **ML** | Unsupervised behavioural baseline learned separately for internal and external sources (event volume, failures, distinct ports/destinations/users/DNS names, bytes). It explains every anomaly ("distinct ports from this source: 3.4, normal max 1.6"), monitors drift (PSI), and retrains from the UI. |
| **Correlation** | Attack chains across alerts and events: brute force → successful login, recon → attack, malware → C2/exfiltration, credential theft → persistence. |
| **Alerts** | One attack = one alert. Repeat hits update the same alert within its cooldown. Each alert has a 0–100 risk score, priority P1–P4, MITRE links, evidence and sample events. It moves through new → investigating → contained / resolved / false positive, with notes and an assignee, all saved. |
| **Response** | Playbooks (block IP, isolate host, disable user, notify). Risky actions wait for an analyst's approval. **Dry-run by default.** Enforce mode uses the Windows firewall or iptables via argument lists (never a shell), refuses internal or protected IPs, and auto-unblocks when a block expires. Slack / Teams / webhook / e-mail notifications. Everything goes to an audit log. |
| **Simulation** | A built-in network simulator streams realistic normal traffic and injects 7 attack scenarios, with a live scorecard: detected or missed, time to detect, alerts on normal traffic. |
| **Ops** | `/health`, Prometheus `/metrics`, optional API key, CORS locked to the dashboard, everything runs on localhost by default. |

### Measured on the built-in simulator

- **Live dashboard run:** every injected attack (7/7 and 8/8 in two runs) was detected. Mean time to detect was 1–3 s, with 0–1 alerts on normal traffic.
- **ML baseline (held-out simulated data):** brute force 5/5, port scan 8/8, DNS tunneling 7/7, data exfiltration 3/3, with 0 false-positive sources in 6,000 events. Malware and privilege escalation are signature-type attacks; rules and threat intel catch those.
- **Throughput:** about 6,000 events/s through the full pipeline on one core, at about 0.3 ms per event (p95).

These numbers describe the simulator, not your network. After deploying, retrain the baseline on your own traffic (**Detection → Retrain on recent stored events**).

## Run it

### Website (from source)

```bash
git clone https://github.com/Abhinav-836/ai-soc-platform.git
cd ai-soc-platform
python -m venv venv
venv\Scripts\activate              # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

python run.py --simulate           # http://127.0.0.1:8080  (drop --simulate for real data only)
```

On the first start the ML baseline trains itself in a few seconds. Open the dashboard and click **Inject attack** to watch an attack get detected live.

**Feeding real data:**
- **Log files:** drop them into `data/raw/` (`*.log`, `*.jsonl`), or add paths such as `/var/log/auth.log` in `config/ingestion.yaml`.
- **Syslog:** enable it in `config/ingestion.yaml` and forward with `*.* @127.0.0.1:5514`.
- **Any tool:** `POST /api/v1/ingest` with a JSON event, a list of events, or `{"raw_message": "<log line>"}`.
- **Offline:** `python run.py analyze /path/to/auth.log` prints the alerts.

### Desktop app (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File desktop\build_desktop.ps1
```

This needs Python 3.10–3.12 (64-bit). [Inno Setup 6](https://jrsoftware.org/isdl.php) is optional and produces the setup `.exe`.

The build creates:
- `dist\AISOCPlatform-Setup-2.0.0.exe` (installer, no admin rights needed)
- `dist\AISOCPlatform\AISOCPlatform.exe` (portable app)
- a portable zip

The app opens in its own window (Edge WebView2) and works offline. Its data lives in `%LOCALAPPDATA%\AISOCPlatform`: drop logs into its `raw` folder, and put your own config overrides in its `config` folder. To run it from source instead: `pip install pywebview` and then `python desktop/launcher.py --simulate`.

### Docker

```bash
docker compose -f docker/docker-compose.yml up --build                      # http://localhost:8080
docker compose -f docker/docker-compose.yml --profile elastic up --build    # + Elasticsearch/Kibana mirror
```

## Dashboard

A plain, light/dark security console (follows your system theme; switch in the sidebar or Settings). Every number comes from the API - nothing is decorative.

- **Overview:** open alerts, critical/high, events per hour, approvals waiting, blocked IPs, detection latency; alerts per minute by severity; event volume per data source; categories; latest alerts; top alerting sources.
- **Alerts:** filter, search, paging. The detail panel shows description, MITRE links, why the ML flagged it, threat-intel matches, evidence and sample events; change status, assign, add notes, run a playbook.
- **Investigate:** type any IP, host name or user (or click one anywhere in the console) to see its events, alerts, threat-intel verdict, block status, peers and full activity timeline, with *Block IP* and *Add to threat intel* buttons.
- **Events:** live stream with source filter (this computer / log files / imported / API / simulation) and a search over stored events.
- **Threat intel**, **Response** (approval queue, blocked IPs, history) and **Detection** (rules on/off, attack chains, ML status and retraining).
- **Data sources:** collector status and counts, **import a log file from your computer** (auth/syslog, Apache/Nginx, UFW/iptables, CEF, JSON - analysed with every rule using the file's own timestamps), how to send logs continuously, and the optional attack simulator with its scorecard. Simulated data is labelled everywhere and a banner shows while it runs.
- **Settings:** API key, analyst name (written to the audit log), theme, system health, clear data.

## Configuration

| File | Controls |
|---|---|
| `config/app.yaml` | host/port, API key, CORS, simulation defaults |
| `config/ingestion.yaml` | file paths, syslog, Kafka, parsers |
| `config/detection.yaml` | rule paths, Sigma, attack chains, threat-intel sources and keys, scoring, critical assets |
| `config/rules/*.yaml`, `config/rules/sigma/*.yml` | detection rules |
| `config/ml.yaml` | baseline quantile/margin |
| `config/response.yaml` | `mode: dry_run \| enforce`, auto-response, approvals, firewall, EDR webhook, notifications |
| `config/playbooks/*.yaml` | response playbooks |
| `config/intel/*.csv` | local indicators |

Any file can be overridden without editing the originals, by placing a file with the same name in `<data dir>/config/`. Extra rules, Sigma rules, playbooks and IOC lists can go in `<data dir>/rules/`, `rules/sigma/`, `playbooks/` and `intel/`. Environment variables are listed in `.env.example`.

## API

Interactive docs are at `/api/docs`. The main endpoints:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/ingest` | events (JSON, list, or raw log lines) → returns alert ids |
| GET / PATCH | `/api/v1/alerts`, `/api/v1/alerts/{id}` | list/filter; status, assignee, notes |
| GET | `/api/v1/events` | stored events (search, ip, type, flagged) |
| GET / PATCH | `/api/v1/rules`, `/api/v1/rules/{id}` | rules and chains; enable/disable |
| GET / POST / DELETE | `/api/v1/intel/iocs`, `/api/v1/intel/lookup` | indicators and reputation |
| POST | `/api/v1/responses`, `/responses/{id}/approve`, `/reject` | playbook requests and approvals |
| GET / DELETE | `/api/v1/blocked` | blocked IPs |
| GET / POST | `/api/v1/ml`, `/api/v1/ml/retrain` | model status / retrain |
| POST | `/api/v1/simulation/start`, `/stop`, `/inject` | simulator |
| WS | `/ws` | live events, alerts, responses, stats |
| GET | `/health`, `/metrics` | health, Prometheus |

When `SOC_API_KEY` is set, the API requires the `X-API-Key` header and the WebSocket requires `?api_key=`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q          # 30 tests: parsing, collectors, rules, Sigma, intel, chains, ML, response safety, API, WebSocket
```

## Docs

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Playbooks](docs/SOC_PLAYBOOKS.md) · [Roadmap](docs/ROADMAP.md)

## License

MIT. See `LICENSE.txt`.
