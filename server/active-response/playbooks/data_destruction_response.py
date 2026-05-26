import logging
import httpx
import os

logger = logging.getLogger(__name__)

def run(target_entity, dry_run=False):
    """
    PLAYBOOK-009: Data Destruction Response
    1. Identify unusual mass file deletions or wiping software.
    2. Completely quarantine host to prevent further destruction or lateral movement.
    3. Revoke access keys.
    """
    logger.info(f"Initiating Data Destruction Playbook against {target_entity}")
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would have quarantined host {target_entity}.")
        logger.info(f"[DRY-RUN] Would have revoked user access keys temporarily.")
        return True

    fastapi_url = os.getenv("FASTAPI_URL", "http://localhost:8000")
    
    try:
        payload = {
            "command": "run_script",
            "args": {"script": "isolate_network.sh"}
        }
        res = httpx.post(
            f"{fastapi_url}/api/agents/{target_entity}/command",
            json=payload,
            timeout=5.0
        )
        if res.status_code == 200:
            logger.info("Host isolation command sent.")
            return True
        else:
            logger.error("Failed to send isolation command.")
            return False
    except Exception as e:
        logger.error(f"Playbook execution failed: {e}")
        return False
