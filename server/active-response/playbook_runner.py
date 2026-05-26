import os
import importlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class PlaybookRunner:
    def __init__(self, playbook_dir='playbooks'):
        self.playbook_dir = playbook_dir
        
    def execute(self, playbook_name, target_entity, dry_run=False):
        """Dynamically loads and executes a playbook by name."""
        try:
            # Map PLAYBOOK-00X to python files
            playbook_map = {
                "PLAYBOOK-001": "brute_force_response",
                "PLAYBOOK-002": "malware_response",
                "PLAYBOOK-003": "exfiltration_response",
                "PLAYBOOK-004": "insider_threat_response",
                "PLAYBOOK-005": "ransomware_response",
                "PLAYBOOK-006": "web_shell_response",
                "PLAYBOOK-007": "priv_escalation_response",
                "PLAYBOOK-008": "crypto_mining_response",
                "PLAYBOOK-009": "data_destruction_response"
            }
            
            module_name = playbook_map.get(playbook_name)
            if not module_name:
                logger.error(f"Playbook {playbook_name} not found.")
                return False

            logger.info(f"Loading playbook module: {module_name}")
            module = importlib.import_module(f"playbooks.{module_name}")
            
            if dry_run:
                logger.info(f"[DRY RUN] Executing {module_name} against {target_entity}")
                # We expect each module to have a run() function that takes dry_run flag
                result = module.run(target_entity, dry_run=True)
            else:
                logger.warning(f"Executing LIVE {module_name} against {target_entity}")
                result = module.run(target_entity)

            logger.info(f"Playbook execution completed. Result: {result}")
            return result
        except Exception as e:
            logger.error(f"Failed to execute playbook {playbook_name}: {e}")
            return False

if __name__ == "__main__":
    # Test runner execution
    runner = PlaybookRunner()
    runner.execute("PLAYBOOK-001", "192.168.1.100", dry_run=True)
