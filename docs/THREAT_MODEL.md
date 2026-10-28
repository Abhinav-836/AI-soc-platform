# Threat model (of the platform itself)

| Asset | Threat | Mitigation |
|---|---|---|
| Response actions (firewall, EDR) | Command injection via event or API data | IPs parsed with `ipaddress`; hostnames and users validated by regex; commands are argument lists (`shell=False`); tests cover injection strings |
| Response actions | Unapproved or automated misuse | Approval required (from config, not the request); dry-run default; audit log of every request, approval, rejection and action |
| Firewall | Blocking yourself or the internal network | Internal (RFC1918/loopback/link-local) and `protected` ranges are refused; blocks expire |
| API | Unauthenticated access | Binds to 127.0.0.1 by default; optional `SOC_API_KEY` (constant-time compare) for REST and WebSocket |
| API | Cross-site requests from other origins | CORS limited to the dashboard's origin |
| Dashboard | Stored XSS through log content (attacker-controlled) | Every value is HTML-escaped before rendering |
| Ingestion | Flooding | Bounded queues (drop + count); WebSocket stream rate-limited per client; batch API limit of 1,000 events |
| Detection | Forged ground truth / evaluation | `_`-prefixed fields are stripped from API input |
| Secrets | Keys in the repo | Keys only via environment / `.env` (git-ignored); config uses `${VAR}` substitution |

Not covered: multi-user RBAC (single shared API key), TLS termination (put a reverse
proxy in front when exposing the platform), or tamper-proof audit storage.
