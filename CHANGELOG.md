# Changelog

All notable changes to SecureWatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-09

### Added
- **Infrastructure**: Complete Docker Compose stack with 8 containerized services (Elasticsearch, Logstash, Kibana, Redis, PostgreSQL, FastAPI, Correlation Engine, React Frontend)
- **Log Ingestion**: 4 Logstash pipelines (Windows Events, Linux Syslog, Network Traffic, Firewall Logs) with MITRE ATT&CK tagging and GeoIP enrichment
- **Detection Engine**: Python-based correlation engine with YAML rule framework, Redis sliding-window state management, and 15-minute alert suppression
- **Detection Rules**: 6 core rules mapped to MITRE ATT&CK:
  - SIEM-001: Brute Force Login (T1110)
  - SIEM-006: PowerShell Encoded Command (T1059.001)
  - SIEM-012: New Service Installed (T1543.003)
  - SIEM-018: Sudo Abuse Detection (T1548.003)
  - SIEM-025: Large Outbound Data Transfer (T1041)
  - SIEM-026: DNS Tunneling Detection (T1071.004)
- **Backend API**: FastAPI with REST endpoints for Alerts, Assets, Active Response, and Threat Intelligence
- **Real-time WebSocket**: Live alert streaming from backend to all connected SOC dashboards
- **Threat Intelligence**: Integration with VirusTotal (file hash lookups) and AbuseIPDB (IP reputation) APIs
- **SOC Dashboard**: React + Vite + TailwindCSS dark-themed dashboard with 6 pages (Overview, Alert Console, Active Response, Threat Intel, Asset Inventory, Settings)
- **Active Response**: 4 automated playbooks (Brute Force, Malware Containment, Exfiltration Block, Insider Threat)
- **Agent Installers**: Bash (Linux) and PowerShell (Windows) scripts for endpoint agent deployment
- **Attack Simulator**: Python-based multi-stage attack simulation tool for testing detection coverage
- **Beats Configurations**: Filebeat, Winlogbeat, Packetbeat, Auditbeat, and Metricbeat configs

### Security
- Rate limiting via SlowAPI on all FastAPI endpoints
- CORS middleware configured
- Redis password authentication
- PostgreSQL credential management via environment variables
