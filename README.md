# AI SOC Platform 🚨

An **AI-powered Security Operations Center (SOC) platform** built to automate
**log ingestion, threat detection, correlation, intelligence enrichment, and
response orchestration**.

This project is a **working, terminal-based SOC prototype** that focuses on
**core detection and response intelligence**, following real-world
**SIEM + SOAR architecture principles**.

---

## 🎯 Project Highlights

- End-to-end SOC pipeline (Ingestion → Detection → Correlation → Response)
- Rule-based + ML-based threat detection
- Threat intelligence enrichment
- SOAR-style automated response playbooks
- Modular, config-driven, production-inspired design
- Docker-ready and extensible for APIs and dashboards

---

## 🔍 Core Capabilities

### 🔹 Log Ingestion
- Multi-source ingestion:
  - File-based logs
  - Syslog
  - Kafka-ready collectors
- Structured parsing and normalization (JSON, CEF, custom formats)
- Centralized ingestion orchestration

### 🔹 Threat Detection
- Signature and rule-based detections (Sigma, YARA-style rules)
- Detection scoring and prioritization
- Extensible detection engine

### 🔹 Machine Learning Detection
- Anomaly detection models:
  - Isolation Forest
  - Autoencoder-based detection
- Training and inference pipelines
- Concept drift monitoring for model reliability

### 🔹 Correlation Engine
- Cross-source event correlation
- Multi-stage attack detection
- Temporal pattern analysis

### 🔹 Threat Intelligence
- IOC ingestion and matching
- External feed enrichment (e.g., IP/domain reputation)
- Contextual risk scoring

### 🔹 Automated Response (SOAR)
- Playbook-driven response workflows
- Actions such as:
  - IP blocking
  - Brute-force mitigation
  - Malware containment
- Alert notification and escalation hooks

### 🔹 Storage & Persistence
- Local storage abstraction (prototype)
- Elasticsearch-compatible storage layer
- Caching support for performance optimization

### 🔹 Monitoring & Health
- Pipeline health checks
- Metrics and system status reporting
- Audit and alert logging

---

## 🧪 Project Status

**Status:** 🧪 **Working Prototype**

- Core SOC pipeline is functional and executable
- Designed with real SOC workflows and architecture
- UI and external APIs are intentionally optional and extensible

⚠️ This project prioritizes **backend SOC intelligence**, not a web UI.

---

## 🏗 High-Level Architecture

ai-soc-platform/
│
├── README.md
├── LICENSE
├── Makefile
├── pyproject.toml              # Modern Python config
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── .gitignore
│
├── config/                     # All configuration (YAML-based)
│   ├── app.yaml                # App settings
│   ├── ingestion.yaml          # Log sources
│   ├── detection.yaml          # Rules & thresholds
│   ├── ml.yaml                 # ML model configs
│   ├── response.yaml           # SOAR actions
│   └── logging.yaml
│
├── data/
│   ├── raw/                    # Raw logs / PCAPs
│   ├── processed/              # Feature-engineered data
│   ├── models/                 # Trained ML models
│   └── intel/                  # Threat intel feeds
│
├── logs/
│   ├── app.log
│   ├── alerts.log
│   └── audit.log
│
├── src/
│   ├── main.py                 # ENTRY POINT (headless)
│   │
│   ├── ingestion/              # Data ingestion layer
│   │   ├── __init__.py
│   │   ├── collectors/
│   │   │   ├── file_collector.py
│   │   │   ├── syslog_collector.py
│   │   │   └── kafka_collector.py
│   │   ├── parsers/
│   │   │   ├── json_parser.py
│   │   │   ├── cef_parser.py
│   │   │   └── normalizer.py
│   │   └── pipeline.py         # Ingestion orchestration
│   │
│   ├── detection/              # Core detection engine
│   │   ├── __init__.py
│   │   ├── rules/
│   │   │   ├── sigma/
│   │   │   ├── yara/
│   │   │   └── custom_rules.py
│   │   ├── correlator.py
│   │   ├── scoring.py
│   │   └── detector.py
│   │
│   ├── ml/                     # ML threat detection
│   │   ├── __init__.py
│   │   ├── anomaly/
│   │   │   ├── isolation_forest.py
│   │   │   └── autoencoder.py
│   │   ├── training.py
│   │   ├── inference.py
│   │   └── drift_monitor.py
│   │
│   ├── response/               # SOAR / automated response
│   │   ├── __init__.py
│   │   ├── playbooks/
│   │   │   ├── block_ip.yaml
│   │   │   ├── brute_force.yaml
│   │   │   └── malware.yaml
│   │   ├── executor.py
│   │   ├── firewall.py
│   │   └── notifier.py
│   │
│   ├── intel/                  # Threat intelligence
│   │   ├── __init__.py
│   │   ├── feeds.py
│   │   ├── ioc_matcher.py
│   │   └── enrich.py
│   │
│   ├── storage/                # Storage abstraction
│   │   ├── __init__.py
│   │   ├── elastic.py
│   │   ├── local_store.py
│   │   └── cache.py
│   │
│   ├── api/                    # OPTIONAL (add later)
│   │   ├── __init__.py
│   │   ├── app.py
│   │   └── routes.py
│   │
│   ├── ui/                     # OPTIONAL (add later)
│   │   └── README.md
│   │
│   ├── monitoring/             # Platform health
│   │   ├── __init__.py
│   │   ├── metrics.py
│   │   └── health.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       ├── config_loader.py
│       └── time_utils.py
│
├── tests/
│   ├── unit/
│   │   ├── test_ingestion.py
│   │   ├── test_detection.py
│   │   └── test_ml.py
│   ├── integration/
│   │   └── test_pipeline.py
│   └── fixtures/
│
├── scripts/
│   ├── generate_logs.py
│   ├── replay_attacks.py
│   └── train_models.py
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
│
└── docs/
    ├── ARCHITECTURE.md
    ├── THREAT_MODEL.md
    ├── SOC_PLAYBOOKS.md
    └── ROADMAP.md

---

## ▶️ How to Run
# Create required directories (idempotent)
mkdir config, data\raw, data\processed, data\models, data\intel, logs -Force | Out-Null

# Write app.yaml (FULL schema, flat, safe)
@"
name: Test SOC
version: 0.1.0
environment: development
debug: true
workers: 4
timezone: UTC
"@ | Out-File config\app.yaml -Encoding UTF8 -Force

# Write ingestion.yaml (minimal but valid)
@"
sources:
  file:
    enabled: true
    paths:
      - data/raw/test.jsonl
parsers: {}
normalization: {}
"@ | Out-File config\ingestion.yaml -Encoding UTF8 -Force

# Generate test logs
python scripts/generate_logs.py --count 50 --output data/raw/test.jsonl

# Run SOC pipeline and backend -
python run.py
**FOR UI**- http://127.0.0.1:8080/ui/index.html


### 1️⃣ Install dependencies
```bash
pip install -r requirements.txt
