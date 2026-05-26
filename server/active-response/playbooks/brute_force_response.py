import logging
import httpx
import os

logger = logging.getLogger(__name__)

def run(target_ip, dry_run=False):
    """
    PLAYBOOK-001: Brute Force Response
    1. Validate IP
    2. Notify (slack/email)
    3. Push iptables block to local infrastructure / firewalls via API
    """
    logger.info(f"Initiating Brute Force Playbook against {target_ip}")
    
    if target_ip.startswith("192.168.1.1") or target_ip.startswith("10.0.0.1"):
        logger.error(f"ABORT: Cannot block critical infrastructure gateway IP: {target_ip}")
        return False
        
    if dry_run:
        logger.info(f"[DRY-RUN] Would have blocked IP {target_ip} globally.")
        logger.info(f"[DRY-RUN] Would have notified SOC channel.")
        return True

    # Real execution
    fastapi_url = os.getenv("FASTAPI_URL", "http://localhost:8000")
    try:
        # Authenticate first
        auth_res = httpx.post(f"{fastapi_url}/api/auth/login", data={"username": "admin", "password": "SecureWatch123!"}, timeout=5.0)
        token = ""
        if auth_res.status_code == 200:
            token = auth_res.json().get("access_token", "")
            
        headers = {"Authorization": f"Bearer {token}"} if token else {}
            
        # Push block request to our central FastAPI state
        res = httpx.post(
            f"{fastapi_url}/api/response/block-ip",
            json={"ip_address": target_ip, "reason": "Automated Brute Force Playbook Trigger"},
            headers=headers,
            timeout=5.0
        )
        if res.status_code == 200:
            logger.info(f"Successfully deployed block rule for {target_ip}")
            return True
        else:
            logger.error(f"Failed to deploy block rule: {res.text}")
            return False
    except Exception as e:
        logger.error(f"Block action failed: {e}")
        return False
