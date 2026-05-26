import logging
import httpx
import os

logger = logging.getLogger(__name__)

def run(destination_ip, dry_run=False):
    """
    PLAYBOOK-003: Exfiltration
    Blocks the destination IP entirely from the network.
    """
    logger.info(f"Initiating Exfiltration Playbook against Dest IP {destination_ip}")
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would have blocked outbound traffic to {destination_ip}.")
        return True

    fastapi_url = os.getenv("FASTAPI_URL", "http://localhost:8000")
    try:
        res = httpx.post(
            f"{fastapi_url}/api/response/block-ip",
            json={"ip_address": destination_ip, "reason": "Automated Exfiltration Playbook - Block Outbound"},
            timeout=5.0
        )
        if res.status_code == 200:
            logger.info("Destination IP blocked successfully.")
            return True
    except Exception as e:
        logger.error(f"Action failed: {e}")
        
    return False
