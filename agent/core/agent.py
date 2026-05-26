"""
SecureWatch Agent — Core Daemon

Production-grade endpoint agent that connects to the SecureWatch Manager
via TCP, handles registration, heartbeats, event collection, and
bidirectional command execution. Designed to run as a systemd service
(Linux) or Windows Service.
"""

import asyncio
import json
import os
import platform
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml
from loguru import logger

# ─── Dynamic module imports ─────────────────────────────────────

COLLECTORS_DIR = Path(__file__).parent.parent / "collectors"
sys.path.insert(0, str(COLLECTORS_DIR))


class AgentConfig:
    """Loads and manages agent YAML configuration."""

    def __init__(self, config_path: str = None):
        default_paths = [
            os.getenv("SECUREWATCH_AGENT_CONFIG", ""),
            str(Path(__file__).parent.parent / "config" / "agent.conf"),
            "/etc/securewatch/agent.conf",
        ]

        self.config_path = config_path
        if not self.config_path:
            for p in default_paths:
                if p and os.path.exists(p):
                    self.config_path = p
                    break

        if not self.config_path or not os.path.exists(self.config_path):
            logger.error("Agent configuration file not found! Searched: {}", default_paths)
            sys.exit(1)

        self.data = self._load()

    def _load(self) -> dict:
        with open(self.config_path, "r") as f:
            return yaml.safe_load(f) or {}

    def save(self) -> None:
        with open(self.config_path, "w") as f:
            yaml.dump(self.data, f, default_flow_style=False)

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        val = self.data
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k, default)
            else:
                return default
        return val


class SecureWatchAgent:
    """
    Core agent daemon. Connects to the SecureWatch Manager via TCP,
    registers, sends heartbeats with collected events, and executes
    commands received from the manager.
    """

    VERSION = "2.0.0"

    def __init__(self, config_path: str = None):
        self.config = AgentConfig(config_path)
        self.agent_id: Optional[str] = self.config.get("agent.id")
        self.token: Optional[str] = self.config.get("agent.token")
        self.event_queue: List[Dict[str, Any]] = []
        self.collectors: list = []
        self._running = True

        # Manager connection
        self.manager_host = self.config.get("server.host", "localhost")
        self.manager_port = int(self.config.get("server.port", 1514))

        # Timing
        self.heartbeat_interval = int(self.config.get("agent.heartbeat_interval", 30))
        self.poll_interval = int(self.config.get("agent.poll_interval", 5))

    # ─── Connection ──────────────────

    async def _connect(self) -> tuple:
        """Establish TCP connection to the manager."""
        try:
            reader, writer = await asyncio.open_connection(
                self.manager_host, self.manager_port
            )
            return reader, writer
        except Exception as e:
            logger.error(f"Cannot connect to manager {self.manager_host}:{self.manager_port}: {e}")
            raise

    async def _send_message(self, writer: asyncio.StreamWriter,
                             reader: asyncio.StreamReader,
                             message: dict) -> dict:
        """Send a JSON message and read the response."""
        data = json.dumps(message) + "\n"
        writer.write(data.encode("utf-8"))
        await writer.drain()

        response_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        return json.loads(response_line.decode("utf-8").strip())

    # ─── Registration ────────────────

    async def register(self) -> bool:
        """Register with the SecureWatch Manager."""
        if self.agent_id and self.token:
            logger.info(f"Agent already registered: {self.agent_id}")
            return True

        logger.info(f"Registering with manager at {self.manager_host}:{self.manager_port}...")

        try:
            reader, writer = await self._connect()
        except Exception:
            return False

        try:
            hostname = socket.gethostname()
            response = await self._send_message(writer, reader, {
                "type": "register",
                "data": {
                    "hostname": hostname,
                    "ip_address": self._get_local_ip(),
                    "os_type": platform.system().lower(),
                    "os_version": platform.version(),
                    "agent_version": self.VERSION,
                    "group": self.config.get("agent.group", "default"),
                }
            })

            if response.get("status") == "ok":
                self.agent_id = response["agent_id"]
                self.token = response["token"]

                # Persist to config
                self.config.data.setdefault("agent", {})["id"] = self.agent_id
                self.config.data["agent"]["token"] = self.token
                self.config.save()

                logger.info(f"✅ Registered successfully — Agent ID: {self.agent_id}")
                return True
            else:
                logger.error(f"Registration rejected: {response.get('message', 'unknown')}")
                return False
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False
        finally:
            writer.close()

    # ─── Heartbeat ───────────────────

    async def heartbeat(self) -> None:
        """Send heartbeat to manager with queued events."""
        if not self.agent_id or not self.token:
            return

        try:
            reader, writer = await self._connect()
        except Exception:
            logger.warning("Heartbeat failed — cannot connect to manager")
            return

        try:
            # Drain event queue
            events_to_send = self.event_queue[:1000]  # max 1000 per heartbeat
            self.event_queue = self.event_queue[1000:]

            response = await self._send_message(writer, reader, {
                "type": "heartbeat",
                "agent_id": self.agent_id,
                "token": self.token,
                "events": events_to_send,
            })

            if response.get("status") == "ok":
                processed = response.get("events_processed", 0)
                if processed > 0:
                    logger.debug(f"Heartbeat OK — {processed} events delivered")

                # Execute any pending commands
                for cmd in response.get("commands", []):
                    await self._execute_command(cmd)
            else:
                logger.warning(f"Heartbeat rejected: {response.get('message', '')}")
                # Re-queue events on failure
                self.event_queue = events_to_send + self.event_queue

        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
        finally:
            writer.close()

    # ─── Collectors ──────────────────

    def init_collectors(self) -> None:
        """Initialize enabled collector modules."""
        modules_config = self.config.get("modules", {})

        collector_map = {
            "syslog_collector": "syslog_collector",
            "process_monitor": "process_monitor",
            "network_monitor": "network_monitor",
            "file_integrity_monitor": "file_integrity_monitor",
            "vulnerability_scanner": "vulnerability_scanner",
            "rootkit_detector": "rootkit_detector",
            "compliance_checker": "compliance_checker",
            # Legacy module names for backward compatibility
            "log_collector": "syslog_collector",
            "fim": "file_integrity_monitor",
            "vuln_scanner": "vulnerability_scanner",
            "sca": "compliance_checker",
        }

        for module_name, collector_name in collector_map.items():
            mod_cfg = modules_config.get(module_name, {})
            if not mod_cfg.get("enabled", False):
                continue

            try:
                mod = __import__(collector_name)
                # Look for collector class
                cls_name = self._to_class_name(collector_name)
                cls = getattr(mod, cls_name, None)

                if cls:
                    instance = cls(mod_cfg)
                    instance.start(self.event_queue)
                    self.collectors.append(instance)
                    logger.info(f"Collector loaded: {collector_name}")
                else:
                    logger.warning(f"No class {cls_name} found in {collector_name}")
            except ImportError as e:
                logger.warning(f"Cannot load collector {collector_name}: {e}")
            except Exception as e:
                logger.error(f"Error initializing {collector_name}: {e}")

        logger.info(f"Initialized {len(self.collectors)} collectors")

    def _to_class_name(self, module_name: str) -> str:
        """Convert module_name to ClassName. e.g. syslog_collector -> SyslogCollector"""
        return "".join(word.capitalize() for word in module_name.split("_"))

    # ─── Command Execution ──────────

    async def _execute_command(self, cmd: dict) -> None:
        """Execute a command received from the manager."""
        action = cmd.get("action", "")
        logger.info(f"Executing command: {action}")

        handlers = {
            "restart": self._cmd_restart,
            "update_config": self._cmd_update_config,
            "run_scan": self._cmd_run_scan,
            "kill_process": self._cmd_kill_process,
            "collect_info": self._cmd_collect_info,
        }

        handler = handlers.get(action)
        if handler:
            try:
                await handler(cmd.get("args", {}))
            except Exception as e:
                logger.error(f"Command '{action}' failed: {e}")
        else:
            logger.warning(f"Unknown command: {action}")

    async def _cmd_restart(self, args: dict) -> None:
        logger.info("Restart command received — restarting agent...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

    async def _cmd_update_config(self, args: dict) -> None:
        for key, value in args.items():
            keys = key.split(".")
            d = self.config.data
            for k in keys[:-1]:
                d = d.setdefault(k, {})
            d[keys[-1]] = value
        self.config.save()
        logger.info(f"Config updated: {list(args.keys())}")

    async def _cmd_run_scan(self, args: dict) -> None:
        scan_type = args.get("type", "full")
        logger.info(f"On-demand {scan_type} scan triggered")
        for collector in self.collectors:
            if hasattr(collector, "run_scan"):
                collector.run_scan()

    async def _cmd_kill_process(self, args: dict) -> None:
        import signal as sig
        pid = args.get("pid")
        if pid:
            try:
                os.kill(int(pid), sig.SIGTERM)
                logger.info(f"Process {pid} terminated")
                self.event_queue.append({
                    "module": "active_response",
                    "event_type": "process_killed",
                    "pid": pid,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            except ProcessLookupError:
                logger.warning(f"Process {pid} not found")

    async def _cmd_collect_info(self, args: dict) -> None:
        import psutil
        info = {
            "module": "system_info",
            "event_type": "info_collection",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_version": platform.version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_total_gb": round(psutil.disk_usage("/").total / (1024**3), 2),
            "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
            "active_connections": len(psutil.net_connections()),
            "running_processes": len(psutil.pids()),
        }
        self.event_queue.append(info)
        logger.info("System info collected and queued")

    # ─── Helper ──────────────────────

    def _get_local_ip(self) -> str:
        """Get the primary local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ─── Main Loop ───────────────────

    async def run(self) -> None:
        """Main agent event loop."""
        logger.info("=" * 50)
        logger.info(f"  SecureWatch Agent v{self.VERSION}")
        logger.info(f"  Host: {socket.gethostname()}")
        logger.info(f"  OS: {platform.system()} {platform.release()}")
        logger.info(f"  Manager: {self.manager_host}:{self.manager_port}")
        logger.info("=" * 50)

        # Registration loop
        while self._running:
            if await self.register():
                break
            logger.info("Retrying registration in 10s...")
            await asyncio.sleep(10)

        self.init_collectors()

        last_heartbeat = 0
        poll_count = 0

        while self._running:
            try:
                # Poll collectors
                for collector in self.collectors:
                    try:
                        collector.poll()
                    except Exception as e:
                        logger.error(f"Collector poll error: {e}")

                poll_count += 1

                # Heartbeat
                now = time.time()
                if now - last_heartbeat >= self.heartbeat_interval:
                    await self.heartbeat()
                    last_heartbeat = now

                await asyncio.sleep(self.poll_interval)

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                await asyncio.sleep(5)

        logger.info("Agent shutting down gracefully...")


# ─── Entry Point ─────────────────────────────────────────────────

def main():
    """Entry point for the SecureWatch Agent."""
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>Agent</cyan> | <level>{message}</level>",
        level=os.getenv("LOG_LEVEL", "INFO"),
    )

    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    agent = SecureWatchAgent(config_path)

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")


if __name__ == "__main__":
    main()
