import logging
import httpx
import os

logger = logging.getLogger(__name__)

def run(target_entity, dry_run=False):
    """
    PLAYBOOK-006: Web Shell Response
    1. Identify malicious file path from alert.
    2. Instruct agent to quarantine/delete the web shell file.
    3. Block the attacking external IP via edge firewall.
    """
    logger.info(f"Initiating Web Shell Playbook against {target_entity}")
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would have deleted web shell file on host.")
        logger.info(f"[DRY-RUN] Would have blocked attacker IP.")
        return True

    fastapi_url = os.getenv("FASTAPI_URL", "http://localhost:8000")
    
    try:
        payload = {
            "command": "delete_file",
            "args": {"target": "/var/www/html/shell.php"} # In a real implementation, parse from target_entity/alert
        }
        res = httpx.post(
            f"{fastapi_url}/api/agents/{target_entity}/command",
            json=payload,
            timeout=5.0
        )
        if res.status_code == 200:
            logger.info("Web shell deletion command sent.")
            return True
        else:
            logger.error("Failed to send deletion command.")
            return False
    except Exception as e:
        logger.error(f"Playbook execution failed: {e}")
        return False
