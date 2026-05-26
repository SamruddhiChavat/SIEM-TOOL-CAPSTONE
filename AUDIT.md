# SecureWatch SIEM - Full Codebase Audit

## 1. Docker & Infrastructure
- **docker-compose.yml**:
  - Missing `restart: unless-stopped` on multiple containers (`elasticsearch`, `logstash`, `kibana`, `postgres`, `redis`, `backend`, `frontend`, `correlation_engine`).
  - Missing proper `healthcheck` on `backend`, `frontend`, and `correlation_engine` containers.
  - Dependencies lack robust `condition: service_healthy` across the board, especially for the backend relying on Postgres.
  - Port configurations need tightening: `postgres` and `redis` should strictly bind to localhost or not expose ports globally if not necessary (internal network is sufficient).
  - Memory and CPU limits are absent per container, which is critical for heavy services like Elasticsearch and Logstash to prevent OOM kills.
- **Start/Stop Scripts**: 
  - `start.sh` lacks preflight checks (e.g., verifying Docker memory allocation) and a robust migration pipeline.
  - `stop.sh` is barebones and needs graceful termination handling.

## 2. Environment & Secrets
- **.env.example**:
  - Missing crucial variables such as JWT expiration config, specific Logstash tuning vars, and CORS configurations.
  - Secrets like `JWT_SECRET`, `ELASTIC_PASSWORD`, and `POSTGRES_PASSWORD` are hardcoded or rely on weak default fallbacks in `docker-compose.yml` and Python code.
  - Backend does not perform a startup validation of critical env vars, leading to late failures if keys are missing.

## 3. Elasticsearch & Logstash
- **Elasticsearch**:
  - Index templates and mappings for `siem-logs-*` are missing or poorly defined, leading to dynamic mapping errors.
  - Index Lifecycle Management (ILM) is entirely absent, meaning logs will grow indefinitely until the disk is full.
  - Basic security (`xpack.security.enabled=false`) needs to be addressed for production readiness.
- **Logstash**:
  - Grok parsing errors are not properly handled.
  - Lack of Dead Letter Queue (DLQ) for malformed events.
  - Enrichment layers (GeoIP, MITRE tagging) are incomplete or missing in the pipelines.

## 4. Backend (FastAPI)
- **Hardcoded Values**: `CORS_ORIGINS` has hardcoded fallbacks in `main.py` that should strictly come from `.env`.
- **WebSocket Manager**: `services/socket_manager.py` catches all exceptions (`except: pass`) without disconnecting dead sockets, leading to memory leaks and broadcast failures. No reconnection handling.
- **Error Handling**: Missing a global exception handler. Errors result in unformatted 500s instead of consistent JSON API error structures.
- **Auth**: JWT implementation lacks token expiration validation, refresh tokens, and robust password hashing handling (e.g., proper bcrypt setup).
- **Rate Limiting**: Public endpoints lack rate limiting.
- **Testing**: End-to-end tests exist but are minimal. Unit tests and full endpoint coverage (90%+) using `httpx.AsyncClient` are missing.

## 5. Correlation Engine
- **Polling Loop**: The `now-15s` sliding window in `engine.py` is brittle. If Elasticsearch goes down temporarily, the polling loop throws errors but doesn't track the last successful query timestamp correctly, leading to missed events.
- **State Manager (Redis)**: Sliding window logic for thresholds is rudimentary. TTLs are not strictly enforced, potentially leading to Redis memory bloat.
- **Alert Suppression**: Deduplication logic is inconsistent. Identical events can generate duplicate alerts if processed quickly.
- **Threat Intel Lookups**: APIs lack timeout enforcement and rate limit handling, which can block the main correlation thread.
- **Health Endpoint**: The engine lacks an HTTP health endpoint for Docker to probe.
- **Rules**: Many YAML rules are missing correct MITRE mapping keys and are not comprehensive. Need additions like Port Scan, Suspicious Process Execution, and Privilege Escalation.

## 6. Attack Simulator (Sandbox)
- **Sandbox UI / Simulator**: The current node.js relay server and UI integration works functionally but lacks multi-stage attack chains (e.g., Brute Force -> Lateral Movement -> Exfiltration).
- **Data Schema**: Generated events don't perfectly align with Logstash's expected schema, causing some parsing fields to be dropped.
- **Demo Mode**: Needs a continuous firing mode (`--continuous`) or UI toggle for live demos.

## 7. Frontend (React)
- **Design & UI/UX**: The current UI is functional but lacks the dense, data-rich "Splunk-like" aesthetic required for a professional SOC.
- **Components**: Lacks responsive, reusable components (SeverityBadges, DataTables with pagination/sorting, GeoMaps, Timeline Charts).
- **Architecture**: Kibana is meant to be fully replaced by the custom UI, but remnants or reliance on it might exist.
- **Features Missing**: Robust Threat Intel search, detailed Response Engine dashboard, Live Log Stream with filtering, and MITRE ATT&CK heatmap.

## 8. Agent Installers
- **Scripts (`install_agent.sh` / `install_agent.ps1`)**: Lack strict version pinning to match the stack version (8.13.4). Path verification and service registration checks are brittle.

## Conclusion
The stack demonstrates a solid proof-of-concept for a full SIEM. However, to achieve production readiness, it requires stringent infrastructure hardening (health checks, DLQs, ILM), backend refactoring (WebSockets, global error handling), correlation engine robustness (Redis sliding windows, error handling), and a complete visual overhaul of the React frontend into a world-class, dark-themed SOC dashboard.
