<p align="center">
  <img src="https://img.shields.io/badge/SecureWatch-v1.0.0-00D1FF?style=for-the-badge&logo=shield&logoColor=white" alt="Version"/>
  <img src="https://img.shields.io/badge/License-GPLv2-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React"/>
  <img src="https://img.shields.io/badge/Elasticsearch-8.13-005571?style=for-the-badge&logo=elasticsearch&logoColor=white" alt="ES"/>
</p>

<h1 align="center">🛡️ SecureWatch</h1>
<h3 align="center">Open-Source Security Information & Event Management Platform</h3>
<p align="center">Unified threat detection, correlation, and active response for local network environments.</p>

---

SecureWatch is a free and open-source SIEM platform purpose-built for SOC (Security Operations Center) teams and cybersecurity students. It provides **real-time threat detection**, **MITRE ATT&CK-mapped correlation rules**, **automated incident response**, and a **premium dark-themed SOC dashboard** — all deployed as a single Docker Compose stack.

Built from scratch with zero dependencies on legacy SIEM codebases. Designed for local network monitoring (`192.168.x.x`) and scalable to organizational deployments.

---

## 🚀 Key Capabilities

**Intrusion Detection**

SecureWatch monitors network endpoints and log sources for indicators of compromise. The correlation engine evaluates events against YAML-based detection rules mapped to the MITRE ATT&CK framework, identifying brute force attacks, lateral movement, privilege escalation, and data exfiltration in real time.

**Log Data Analysis**

Logstash pipelines ingest and normalize logs from Linux syslog, Windows Event Logs, firewall appliances, and network packet captures. Events are enriched with GeoIP data, risk scores, and MITRE technique classifications before storage in Elasticsearch.

**Threat Intelligence**

Integrated with VirusTotal and AbuseIPDB APIs for live IOC lookups. Suspicious IPs and file hashes are automatically checked against global threat databases, with results enriching alert context and risk scoring.

**Correlation Engine**

A custom Python-based detection engine polls Elasticsearch every 30 seconds, evaluating events against configurable YAML rules. Supports threshold-based detection (e.g., 5 failed logins in 2 minutes), sliding-window state tracking via Redis, and automated alert suppression to reduce noise.

**Active Response**

Automated playbooks execute countermeasures when specific conditions are met — including IP blocking, network isolation, credential revocation, and covert insider threat monitoring. All actions are auditable and reversible through the SOC dashboard.

**MITRE ATT&CK Mapping**

Every detection rule maps directly to MITRE ATT&CK tactics and techniques. The platform currently covers 6 core detection scenarios across Initial Access, Execution, Persistence, Privilege Escalation, Exfiltration, and Command & Control.

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MONITORED ENDPOINTS                       │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐  │
│  │ Filebeat  │ │Winlogbeat│ │ Packetbeat│ │  Auditbeat   │  │
│  └─────┬────┘ └─────┬────┘ └─────┬─────┘ └──────┬───────┘  │
└────────┼────────────┼────────────┼───────────────┼──────────┘
         │            │            │               │
         ▼            ▼            ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│                     LOGSTASH PIPELINES                       │
│  ┌───────────┐ ┌───────────┐ ┌────────────┐ ┌───────────┐  │
│  │  Windows  │ │   Linux   │ │  Network   │ │  Firewall  │  │
│  │  Events   │ │   Syslog  │ │  Traffic   │ │   Logs     │  │
│  └─────┬─────┘ └─────┬─────┘ └─────┬──────┘ └─────┬─────┘  │
│        │ MITRE Tagging│  GeoIP     │ Risk Score   │         │
└────────┼──────────────┼────────────┼──────────────┼─────────┘
         │              │            │              │
         ▼              ▼            ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│              ELASTICSEARCH 8.13 CLUSTER                      │
│              siem-logs-* indices                             │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              CORRELATION ENGINE (Python)                      │
│  ┌────────────┐ ┌──────────┐ ┌───────────┐ ┌────────────┐  │
│  │Rule Loader │ │  State   │ │  Threat   │ │   Risk     │  │
│  │  (YAML)    │ │ Manager  │ │   Intel   │ │  Scorer    │  │
│  │  6 Rules   │ │ (Redis)  │ │ (VT/Abuse)│ │            │  │
│  └────────────┘ └──────────┘ └───────────┘ └────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                       SERVER DOMAIN                          │
│                                                             │
│  ┌───────────────────┐               ┌───────────────────┐  │
│  │   Python/FastAPI  │               │   Node.js Relay   │  │
│  │   Core Backend    │               │   Sandbox API     │  │
│  │ ┌───────────────┐ │               │ ┌───────────────┐ │  │
│  │ │ Alerts/Assets │ │               │ │ Log Streaming │ │  │
│  │ └───────────────┘ │               │ └───────────────┘ │  │
│  └─────────┬─────────┘               └─────────┬─────────┘  │
└────────────┼───────────────────────────────────┼────────────┘
             │                                   │
             ▼                                   ▼
┌────────────┴───────────────────────────────────┴────────────┐
│                       CLIENT DOMAIN                          │
│                                                             │
│  ┌───────────────────┐               ┌───────────────────┐  │
│  │ React Dashboard   │               │ React Sandbox     │  │
│  │ SOC Command Center│               │ Attack Simulator  │  │
│  │ ┌───────────────┐ │               │ ┌───────────────┐ │  │
│  │ │ UI Components │ │               │ │ Interactive UI│ │  │
│  │ └───────────────┘ │               │ └───────────────┘ │  │
│  └───────────────────┘               └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Detection Rules (MITRE ATT&CK Mapped)

| Rule ID | Name | Tactic | Technique | Severity |
|---------|------|--------|-----------|----------|
| SIEM-001 | Brute Force Login | Initial Access | T1110 | Critical |
| SIEM-006 | PowerShell Encoded Command | Execution | T1059.001 | High |
| SIEM-012 | New Service Installed | Persistence | T1543.003 | High |
| SIEM-018 | Sudo Abuse Detection | Privilege Escalation | T1548.003 | High |
| SIEM-025 | Large Outbound Data Transfer | Exfiltration | T1041 | Critical |
| SIEM-026 | DNS Tunneling Detection | Command & Control | T1071.004 | Critical |

Rules are defined in YAML format under `correlation_engine/rules/`. Adding custom rules is as simple as dropping a new `.yml` file — no code changes required.

---

## ⚡ Quick Start

### Prerequisites
- **Docker Desktop** (v4.0+) with at least **8GB RAM** allocated
- **Git**

### Installation

```bash
# Clone the repository
git clone https://github.com/JesalShah27/SecureWatch.git
cd SecureWatch/securewatch

# Configure environment (edit API keys and credentials)
cp .env.example .env
nano .env

# Deploy the entire stack
chmod +x start.sh
./start.sh
```

### Access the Services

| Service | URL | Description |
|---------|-----|-------------|
| **SOC Dashboard** | http://localhost:3000 | React-based analyst console |
| **API Docs** | http://localhost:8000/docs | FastAPI Swagger UI |
| **Kibana** | http://localhost:5601 | Elasticsearch visualization |
| **Elasticsearch** | http://localhost:9200 | Direct cluster access |

### Run the Attack Simulator

```bash
# In a separate terminal, simulate a multi-stage attack
cd attack_simulator/
python3 simulator.py
```

This fires SSH brute force and privilege escalation events into the SIEM pipeline. Watch the SOC Dashboard update in real time.

---

## 📁 Project Structure

```
securewatch/
├── client/                     # Frontend Applications (React)
│   ├── dashboard/              # Main SOC Command Center (Vite + Tailwind)
│   └── sandbox/                # Interactive Simulation Environment
├── server/                     # Backend Services
│   ├── api/                    # Core Python/FastAPI Backend
│   │   ├── main.py             # Application entrypoint
│   │   ├── models/             # Pydantic & SQLAlchemy schemas
│   │   ├── routes/             # API route handlers (Alerts, Assets, etc.)
│   │   └── services/           # Business logic & WebSocket manager
│   └── relay/                  # Node.js Sandbox Relay Server (MVC)
│       ├── controllers/        # Request handling and streaming
│       ├── models/             # In-memory log store
│       ├── routes/             # Express API routing
│       └── services/           # Event processing and MITRE mapping
├── correlation_engine/         # Python detection engine
│   ├── engine.py               # Core polling & evaluation loop
│   └── rules/                  # YAML detection rule definitions
├── logstash/                   # Log ingestion & enrichment
│   └── pipeline/               # Parsing & MITRE tagging pipelines
├── attack_simulator/           # Security testing tools
├── beats/                      # Elastic Beats configurations
├── agent/                      # Endpoint agent installers
├── elasticsearch/              # Elasticsearch configuration
├── response/                   # Automated response framework
├── package.json                # Root NPM Workspace configuration
├── docker-compose.yml          # Full stack orchestration
├── start.sh                    # One-command deployment
├── stop.sh                     # Graceful shutdown
├── DEPLOY.md                   # Deployment guide
├── CHANGELOG.md                # Version history
├── CONTRIBUTING.md             # Contribution guidelines
├── SECURITY.md                 # Security policy
└── LICENSE                     # GPLv2 License
```

---

## 🔧 Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Search & Storage | Elasticsearch | 8.13.4 |
| Log Ingestion | Logstash | 8.13.4 |
| Visualization | Kibana | 8.13.4 |
| State Management | Redis | 7 (Alpine) |
| Database | PostgreSQL | 15 (Alpine) |
| Backend API | FastAPI (Python) | 0.110.0 |
| Correlation Engine | Python | 3.11 |
| Frontend | React + Vite | 18.2 / 5.2 |
| Styling | TailwindCSS | 3.4 |
| Containerization | Docker Compose | 3.8 |

### Python Dependencies

| Package | Purpose |
|---------|---------|
| `httpx` | Async HTTP client for ES & API calls |
| `redis` | State management & alert suppression |
| `pyyaml` | Detection rule parsing |
| `pydantic` | Data validation & serialization |
| `python-jose` | JWT token handling |
| `passlib` | Password hashing (bcrypt) |
| `slowapi` | Rate limiting |

---

## 📖 Documentation

- [Deployment Guide](DEPLOY.md) — Step-by-step setup instructions
- [API Documentation](http://localhost:8000/docs) — Interactive Swagger UI (after deployment)

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🔒 Security Policy

See [SECURITY.md](SECURITY.md) for our security policy and responsible disclosure process.

---

## 📄 License

SecureWatch is distributed under the **GNU General Public License v2.0**. See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Jesal Shah** — [GitHub](https://github.com/JesalShah27)

Built as a production-grade cybersecurity project demonstrating enterprise SIEM architecture, MITRE ATT&CK integration, and real-time SOC operations.

---

<p align="center">
  <sub>⭐ Star this repository if you find it useful!</sub>
</p>
