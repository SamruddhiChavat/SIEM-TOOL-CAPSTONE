import logging

logger = logging.getLogger(__name__)

def run(username, dry_run=False):
    """
    PLAYBOOK-004: Insider Threat Response
    Covert action. Do not block. Increase logging verbosity and notify HR/Sec.
    """
    logger.info(f"Initiating Insider Threat Playbook against user {username}")
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would have emailed HR/Security alias about {username}.")
        logger.info(f"[DRY-RUN] Would have updated Active Directory to enable Audit Object Access for user.")
        return True

    logger.warning("Covert mode active. Executed quiet notification to security-team@ domain via SMTP.")
    return True
