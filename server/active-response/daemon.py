import redis
import json
import logging
import time
import os
from playbook_runner import PlaybookRunner

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def main():
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis.from_url(redis_url, decode_responses=True)
    runner = PlaybookRunner()
    
    logger.info("Active Response Daemon started. Listening for tasks on Redis queue 'playbook_tasks'...")
    
    while True:
        try:
            # BLPOP blocks until an item is available
            result = redis_client.blpop("playbook_tasks", timeout=10)
            if result:
                _, task_data = result
                task = json.loads(task_data)
                
                playbook_id = task.get("playbook_id")
                target = task.get("target")
                
                logger.info(f"Received active response task: {playbook_id} -> {target}")
                runner.execute(playbook_id, target, dry_run=False) # In production we would probably have a setting for dry-run globally
        except Exception as e:
            logger.error(f"Error in Active Response Daemon loop: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
