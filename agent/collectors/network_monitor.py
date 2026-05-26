import psutil
import time
import logging

class NetworkMonitor:
    def __init__(self, config):
        self.config = config
        self.interval = config.get("interval", 15)
        self.logger = logging.getLogger("NetworkMonitor")
        self.seen_connections = set()

    def start(self, event_queue):
        self.event_queue = event_queue
        # Initial snapshot
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    conn_id = f"{conn.laddr}-{conn.raddr}"
                    self.seen_connections.add(conn_id)
        except psutil.AccessDenied:
            self.logger.warning("Access denied gathering initial network connections.")

    def poll(self):
        try:
            current_connections = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    conn_id = f"{conn.laddr}-{conn.raddr}"
                    current_connections.add(conn_id)
                    
                    if conn_id not in self.seen_connections:
                        # New connection
                        self.event_queue.append({
                            "module": "network_monitor",
                            "event_type": "new_connection",
                            "local_ip": conn.laddr.ip if conn.laddr else None,
                            "local_port": conn.laddr.port if conn.laddr else None,
                            "remote_ip": conn.raddr.ip if conn.raddr else None,
                            "remote_port": conn.raddr.port if conn.raddr else None,
                            "pid": conn.pid
                        })
            
            self.seen_connections = current_connections
        except psutil.AccessDenied:
            pass # Requires root/admin for some connections
        except Exception as e:
            self.logger.error(f"Error monitoring network: {e}")
