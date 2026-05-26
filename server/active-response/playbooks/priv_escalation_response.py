import logging
import httpx
import os

logger = logging.getLogger(__name__)

def run(target_entity, dry_run=False):
    """
    PLAYBOOK-007: Privilege Escalation Response
    1. Identify compromised user account.
    2. Revoke user sessions and disable account in directory/OS.
    """
    logger.info(f"Initiating Privilege Escalation Playbook against {target_entity}")
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would have disabled compromised user account.")
        logger.info(f"[DRY-RUN] Would have killed active shell sessions.")
        return True

    fastapi_url = os.getenv("FASTAPI_URL", "http://localhost:8000")
    
    try:
        # Pushing a backend command to lock the user
        payload = {
            "command": "run_script",
            "args": {"script": "lock_user.sh", "user": "target_user"}
        }
        res = httpx.post(
            f"{fastapi_url}/api/agents/{target_entity}/command",
            json=payload,
            timeout=5.0
        )
        if res.status_code == 200:
            logger.info("Account lock command sent.")
            return True
        else:
            logger.error("Failed to send account lock command.")
            return False
    except Exception as e:
        logger.error(f"Playbook execution failed: {e}")
        return False
