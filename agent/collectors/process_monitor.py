import psutil
import time
import logging

class ProcessMonitor:
    def __init__(self, config):
        self.config = config
        self.interval = config.get("interval", 10)
        self.logger = logging.getLogger("ProcessMonitor")
        self.seen_pids = set()

    def start(self, event_queue):
        self.event_queue = event_queue
        # Initial snapshot
        for proc in psutil.process_iter(['pid']):
            self.seen_pids.add(proc.info['pid'])

    def poll(self):
        try:
            current_pids = set()
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                pid = proc.info.get('pid')
                current_pids.add(pid)
                
                if pid and pid not in self.seen_pids:
                    # New process detected
                    self.event_queue.append({
                        "module": "process_monitor",
                        "event_type": "process_started",
                        "pid": pid,
                        "name": proc.info.get('name'),
                        "cmdline": proc.info.get('cmdline'),
                        "username": proc.info.get('username')
                    })
            
            # Update seen pids
            self.seen_pids = current_pids
        except Exception as e:
            self.logger.error(f"Error monitoring processes: {e}")
