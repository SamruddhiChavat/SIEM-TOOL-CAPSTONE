import os
import time
import socket
import logging

class LogCollector:
    def __init__(self, config):
        self.config = config
        self.paths = config.get("paths", [])
        self.file_pointers = {}
        self.logger = logging.getLogger("LogCollector")

    def start(self, event_queue):
        self.event_queue = event_queue
        for path in self.paths:
            if os.path.exists(path):
                try:
                    f = open(path, 'r')
                    f.seek(0, 2) # Seek to end
                    self.file_pointers[path] = f
                    self.logger.info(f"Started monitoring {path}")
                except Exception as e:
                    self.logger.error(f"Failed to open {path}: {e}")

    def poll(self):
        for path, f in self.file_pointers.items():
            try:
                line = f.readline()
                while line:
                    if line.strip():
                        self.event_queue.append({
                            "module": "log_collector",
                            "file": path,
                            "raw": line.strip()
                        })
                    line = f.readline()
            except Exception as e:
                self.logger.error(f"Error reading {path}: {e}")
