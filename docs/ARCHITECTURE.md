# Architecture

```
src/
  main.py                 SOCPlatform: builds and wires every component; CLI (serve / analyze / train)
  api/app.py              FastAPI app: REST, WebSocket, dashboard (src/ui), auth, CORS
  api/websocket_manager   per-client queues, rate-limited event stream
  ingestion/              collectors (file, syslog, kafka) -> queue -> normalizer -> detection
  detection/detector.py   per event: enrich -> intel -> rules/Sigma -> ML -> chains -> alerts
  detection/rules/        matcher (field modifiers), YAML rule engine (thresholds), Sigma loader
  detection/correlator    attack chains across alerts and events
  detection/scoring       0-100 risk score, P1-P4 priority
  intel/                  IOC matcher, feeds/lookups, enrichment (scope, direction, assets)
  ml/                     features (5-min per-source behaviour), baseline model, training, drift
  response/               playbooks, approvals, firewall (no shell), notifications
  storage/                SQLite store (events, alerts, responses, blocks, IOCs), Elasticsearch mirror
  simulation/             traffic + attack generator, live simulator with scorecard
  monitoring/             health, Prometheus metrics
  ui/                     dashboard (vanilla JS, Chart.js bundled locally)
```

## Event flow

1. A collector (or the API / simulator) produces a raw event.
2. `LogNormalizer` parses it (JSON, CEF, syslog formats, access logs) into one flat
   schema (`src_ip`, `dst_ip`, `user`, `hostname`, `event_type`, ...) and keeps the
   original timestamp.
3. `DetectionEngine.add_event` enriches it (internal/external, direction, asset
   criticality) and runs threat intel, every rule (YAML + Sigma), the ML baseline
   and event-triggered attack chains.
4. Each hit is upserted into an alert keyed by `rule + entity`. Within the rule's
   cooldown, repeat hits update the same alert. New alerts feed alert-triggered chains.
5. Listeners fire: WebSocket broadcast, the simulator scorecard, notifications, and
   auto-response (which creates approval requests).
6. Events are written to SQLite in 0.5 s batches (and to Elasticsearch, if enabled).

## Design decisions

- **SQLite as the source of truth.** It works the same in the desktop app, Docker
  and tests, with no server to run. Elasticsearch is an optional mirror for Kibana.
- **Event time, not arrival time.** Threshold windows use each event's own timestamp,
  so replayed or late logs land in the right windows.
- **Behavioural baseline instead of Isolation Forest.** IF cannot score values beyond
  the range it saw in training, and attacks are exactly "more than ever seen". See
  `src/ml/anomaly/baseline.py` for the measurements.
- **Dry-run by default; approvals enforced on the server.** The API cannot skip
  approval, and no response action ever goes through a shell.
