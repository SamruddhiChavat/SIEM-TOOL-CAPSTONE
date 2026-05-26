# SecureWatch SIEM Architecture

SecureWatch is an open-source, scalable Security Information and Event Management (SIEM) solution designed with a modern Dockerized architecture inspired by Wazuh and Elastic Security.

## High-Level Architecture

The platform operates across 5 key architectural tiers:

1.  **Endpoint Agents (`/agent`)**
    *   Python-based autonomous daemons running on Windows/Linux.
    *   Features internal collectors: FIM (File Integrity), Compliance Checking, Process Monitoring, Vulnerability Scanning.
    *   Uses secure mutual TLS (`mTLS`) for secure connection to the manager.

2.  **Manager Configuration Array (`/manager`)**
    *   Handles asynchronous endpoint registration using `asyncio` and `uvloop`.
    *   Normalizes and securely stores hardware assets and agent metadata into PostgreSQL.
    *   Routes normalized data buffers to Logstash/Elasticsearch for long-term indexing.

3.  **Correlation Engine & Machine Learning (`/correlation_engine`)**
    *   A high-performance thread loop analyzing the live Elasticsearch buffers.
    *   **Rule Engine**: Uses YAML-defined complex threat rules supporting composite sequences and thresholds.
    *   **ML Baseline**: Employs an Isolation Forest implementation to map standard baseline deviations locally.
    *   **Response Dispatcher**: Binds `Rule IDs` to precise Active Response playbooks.

4.  **Active Response Daemon (`/response`)**
    *   Containerized daemon reading from a Redis Task Queue populated by the Dispatcher.
    *   Executes dynamically loaded Python Playbooks against target hosts natively over the Management API.
    *   Supports 9 full responses: Ransomware Isolation, Brute Force Quarantining, Crypto Mining Blocking, etc.

5.  **Analytics Layer (`/frontend` & `Elastic Stack`)**
    *   **React Dashboard**: A `Vite/React` single-page application utilizing Tailwind CSS glassmorphism, Recharts, and `lucide-react` icons. Secured by JWT with Axios interceptors.
    *   **Elasticsearch + Logstash**: 6 highly tuned Grok pipelines formatting network, syslog, api, and firewall traffic.

## Network Topology

| Service | Protocol/Port | Description |
| :--- | :--- | :--- |
| **Manager Node** | TCP/1514 | Raw Agent Telemetry and Heartbeats |
| **Logstash (Syslog)** | TCP/5140 | Secure syslog endpoint for firewalls/routers |
| **Logstash (Auth)** | TCP/5055 | Linux sshd/sudo authentication monitoring |
| **Logstash (API)** | TCP/5060 | Application microservice JSON audit logs |
| **FastAPI Backend** | TCP/8000 | Core SQL ORM, JWT issuance, and Manager logic bridge |
| **Dashboard** | TCP/3000 | Primary User Interface (React) |

## Authentication Security

All external communications to the Backend require a Bearer token issued by `/api/auth/login`. Agents provision their keys strictly against the PostgreSQL agent table over trusted Manager sockets.
