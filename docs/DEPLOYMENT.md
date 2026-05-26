# Deployment Guide

Deploying SecureWatch involves spinning up our core container matrix, initializing the database schema, and verifying logs.

## 1. Environment Startup

Execute the provided Docker Compose manifest. This will bootstrap exactly 7 services (Elasticsearch, Logstash, Postgres, Redis, Core Backend, Active Response Daemon, and the React Frontend).

```bash
cd realsiem/
docker compose up -d --build
```

Monitor the startup of all components:
```bash
docker compose logs -f
```

## 2. Admin Creation & Database Provisioning

On a fresh start, Alembic migrations need to run so the PostgreSQL tables map to the ORM logic, followed by an admin user seed.

```bash
# Attach to the backend container
docker exec -it securewatch-backend bash

# Run Migrations
alembic upgrade head

# Seed Administrative Access
python create_admin.py admin SecureWatch123!
```

## 3. Running the Attack Simulator

We provide a bundled synthetic IOC (Indicator of Compromise) engine to immediately demonstrate the Correlation Engine's power. It fires raw syslog/CEF events via TCP ports exposed by Logstash.

```bash
# In your host terminal:
cd realsiem/simulator
python attack_simulator.py
```
This will randomly loop highly aggressive scenarios:
- Web Shell Access matching (SIEM-060)
- Brute Force sequences (SIEM-001)
- Data Destruction logic (SIEM-070)
- Privilege Escalation paths (SIEM-066)

If deployed correctly, you will see alerts populate the **Live Alert Feed** dynamically via WebSockets, and Active Response actions trigger in the `active_response` docker container logs!

## 4. Frontend Access

- **Location**: `http://localhost:3000`
- **Username**: `admin`
- **Password**: *Provided during step 2*
