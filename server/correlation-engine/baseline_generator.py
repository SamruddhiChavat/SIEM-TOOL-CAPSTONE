"""
Generates 30 days of synthetic "normal" behavioral baseline data into Elasticsearch
and computes summary statistics into the PostgreSQL `behavioral_baselines` table.
"""

import os
import uuid
import random
import logging
from datetime import datetime, timedelta
import json
import httpx
import psycopg2
from psycopg2.extras import execute_values
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ES_HOST = os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")
ES_USER = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ES_PASS = os.getenv("ELASTICSEARCH_PASSWORD", "")
ES_INDEX = "securewatch-baseline-2026"

POSTGRES_DSN = "postgresql://siemuser:siempass123!@postgres:5432/siemdb"

USERS = ["j.smith", "m.doe", "a.lincoln", "s.connor", "svc_backup"]
HOSTS = ["192.168.1.101", "192.168.1.103", "192.168.1.104", "10.0.0.10", "10.0.0.11"]
SERVICES = ["SSH", "RDP", "File Server", "Finance DB", "Web App"]
DOMAINS = ["google.com", "microsoft.com", "amazon.com", "github.com", "slack.com"]

def generate_es_events(days=30):
    events = []
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    logger.info(f"Generating {days} days of baseline events from {start_date.date()} to {end_date.date()}")

    for host in HOSTS:
        for user in USERS:
            # Randomize base stats per user/host
            base_data_vol = random.uniform(100, 200) # MB
            base_dns_queries = random.randint(300, 600)
            
            for i in range(days):
                current_date = start_date + timedelta(days=i)
                is_weekend = current_date.weekday() >= 5
                
                # 1. Working Hours Pattern & Auth Success
                if is_weekend:
                    auth_count = random.randint(0, 5)
                else:
                    auth_count = random.randint(50, 120)
                
                for _ in range(auth_count):
                    # Distribute within 08:00 - 19:00 mostly
                    hour = int(np.random.normal(13.5, 2.5))
                    hour = max(8, min(18, hour))
                    minute = random.randint(0, 59)
                    ts = current_date.replace(hour=hour, minute=minute)
                    
                    events.append({
                        "@timestamp": ts.isoformat() + "Z",
                        "event": {"category": ["authentication"], "type": ["info"]},
                        "user": {"name": user},
                        "source": {"ip": host},
                        "message": f"Successful login by {user} from {host}",
                        "dimension": "auth_success"
                    })

                # 2. Data Transfer Volume (daily sum event for simplicity)
                vol = np.random.normal(base_data_vol, 40)
                if is_weekend: vol *= 0.1
                vol = max(0, vol)
                
                ts = current_date.replace(hour=23, minute=59)
                events.append({
                    "@timestamp": ts.isoformat() + "Z",
                    "event": {"category": ["network"]},
                    "user": {"name": user},
                    "source": {"ip": host},
                    "network": {"bytes": int(vol * 1024 * 1024)},
                    "message": f"Daily transfer volume: {vol:.2f} MB",
                    "dimension": "data_transfer"
                })

                # 3. DNS Query Rate
                dns_rate = int(np.random.normal(base_dns_queries, 100))
                if is_weekend: dns_rate = int(dns_rate * 0.2)
                dns_rate = max(0, dns_rate)
                
                events.append({
                    "@timestamp": ts.isoformat() + "Z",
                    "event": {"category": ["network", "dns"]},
                    "user": {"name": user},
                    "source": {"ip": host},
                    "dns": {"queries_per_day": dns_rate},
                    "message": f"Daily DNS queries: {dns_rate}",
                    "dimension": "dns_query_rate"
                })

                # 4. Auth Failures (0-3 per day)
                failures = random.randint(0, 3)
                for _ in range(failures):
                    hour = random.randint(0, 23)
                    minute = random.randint(0, 59)
                    ts = current_date.replace(hour=hour, minute=minute)
                    events.append({
                        "@timestamp": ts.isoformat() + "Z",
                        "event": {"category": ["authentication"], "type": ["error"]},
                        "user": {"name": user},
                        "source": {"ip": host},
                        "message": f"Failed login by {user}",
                        "dimension": "auth_failure"
                    })

    return events

def bulk_index_es(events):
    logger.info(f"Indexing {len(events)} events to Elasticsearch into {ES_INDEX}...")
    
    # Create index if not exists
    httpx.put(f"{ES_HOST}/{ES_INDEX}", auth=(ES_USER, ES_PASS))
    
    # Bulk index
    chunk_size = 5000
    for i in range(0, len(events), chunk_size):
        chunk = events[i:i+chunk_size]
        payload = ""
        for ev in chunk:
            payload += json.dumps({"index": {"_index": ES_INDEX}}) + "\n"
            payload += json.dumps(ev) + "\n"
            
        resp = httpx.post(
            f"{ES_HOST}/_bulk",
            auth=(ES_USER, ES_PASS),
            headers={"Content-Type": "application/x-ndjson"},
            content=payload,
            timeout=30.0
        )
        if resp.status_code not in [200, 201]:
            logger.error(f"Failed to bulk index: {resp.text[:200]}")
    logger.info("ES indexing complete.")

def compute_and_store_pg(events):
    logger.info("Computing baselines and storing in PostgreSQL...")
    
    # We will compute baselines per host for Data Transfer and DNS
    # And per user for Auth
    
    baselines = []
    
    # Data Transfer
    for host in HOSTS:
        vols = [e["network"]["bytes"] for e in events if e.get("dimension") == "data_transfer" and e["source"]["ip"] == host]
        if vols:
            vols = np.array(vols) / (1024*1024) # to MB
            baselines.append({
                "host": host, "user": None, "dimension": "DATA_TRANSFER_MB",
                "mean": int(np.mean(vols)), "std_dev": int(np.std(vols)),
                "p95": int(np.percentile(vols, 95)), "p99": int(np.percentile(vols, 99)),
                "max_normal": int(np.max(vols))
            })

    # DNS Queries
    for host in HOSTS:
        rates = [e["dns"]["queries_per_day"] for e in events if e.get("dimension") == "dns_query_rate" and e["source"]["ip"] == host]
        if rates:
            baselines.append({
                "host": host, "user": None, "dimension": "DNS_QUERY_RATE",
                "mean": int(np.mean(rates)), "std_dev": int(np.std(rates)),
                "p95": int(np.percentile(rates, 95)), "p99": int(np.percentile(rates, 99)),
                "max_normal": int(np.max(rates))
            })

    # Auth Failures
    for user in USERS:
        # daily count of auth failures per user
        baselines.append({
            "host": None, "user": user, "dimension": "AUTH_FAILURE_RATE",
            "mean": 1, "std_dev": 1,
            "p95": 2, "p99": 3,
            "max_normal": 3
        })

    # Port Scan / Lateral Movement
    for host in HOSTS:
        baselines.append({
            "host": host, "user": None, "dimension": "LATERAL_MOVEMENT_SCAN",
            "mean": 0, "std_dev": 0, "p95": 0, "p99": 0, "max_normal": 0
        })

    # Global Hours
    baselines.append({
        "host": "global", "user": "global", "dimension": "WORKING_HOURS_START",
        "mean": 8, "std_dev": 0, "p95": 8, "p99": 8, "max_normal": 8
    })
    baselines.append({
        "host": "global", "user": "global", "dimension": "WORKING_HOURS_END",
        "mean": 19, "std_dev": 0, "p95": 19, "p99": 19, "max_normal": 19
    })

    # Insert to PG
    conn = psycopg2.connect(POSTGRES_DSN)
    cursor = conn.cursor()
    
    # Create table if not exists (should be handled by alembic/models usually, but just in case)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_baselines (
            id VARCHAR(36) PRIMARY KEY,
            host VARCHAR(128),
            "user" VARCHAR(128),
            dimension VARCHAR(128) NOT NULL,
            mean INTEGER NOT NULL,
            std_dev INTEGER NOT NULL,
            p95 INTEGER NOT NULL,
            p99 INTEGER NOT NULL,
            max_normal INTEGER NOT NULL,
            computed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Clear existing
    cursor.execute("TRUNCATE TABLE behavioral_baselines")
    
    insert_query = """
        INSERT INTO behavioral_baselines 
        (id, host, "user", dimension, mean, std_dev, p95, p99, max_normal) 
        VALUES %s
    """
    
    values = []
    for b in baselines:
        values.append((
            str(uuid.uuid4()), b["host"], b["user"], b["dimension"],
            b["mean"], b["std_dev"], b["p95"], b["p99"], b["max_normal"]
        ))
        
    execute_values(cursor, insert_query, values)
    conn.commit()
    cursor.close()
    conn.close()
    logger.info(f"Inserted {len(baselines)} baselines into PostgreSQL.")

if __name__ == "__main__":
    events = generate_es_events(days=30)
    bulk_index_es(events)
    compute_and_store_pg(events)
    logger.info("Baseline generation complete.")
