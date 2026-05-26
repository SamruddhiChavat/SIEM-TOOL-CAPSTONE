"""
SecureWatch Manager — Core Server

Async TCP server that accepts agent connections on port 1514.
Handles agent registration, heartbeats, event ingestion,
and command dispatch. This is the central nervous system of the
SecureWatch SIEM platform.
"""

import asyncio
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Optional

import yaml
from loguru import logger

from agent_registry import AgentRegistry, AgentRecord
from event_processor import EventProcessor

# ─── Configuration ──────────────────────────────────────────────

def load_config(path: str = "config/manager.conf") -> dict:
    """Load manager configuration from YAML file with env var substitution."""
    if not os.path.exists(path):
        logger.warning(f"Config file {path} not found, using defaults")
        return {}

    with open(path, "r") as f:
        raw = f.read()

    # Simple env var substitution: ${VAR_NAME}
    import re
    def replace_env(match):
        var_name = match.group(1)
        return os.getenv(var_name, match.group(0))

    raw = re.sub(r'\$\{(\w+)\}', replace_env, raw)
    return yaml.safe_load(raw) or {}


# ─── Protocol Handler ──────────────────────────────────────────

class AgentProtocol:
    """
    Simple line-delimited JSON protocol for agent communication.

    Messages are newline-terminated JSON objects:
      {"type": "register", "data": {...}}
      {"type": "heartbeat", "agent_id": "...", "token": "...", "events": [...]}
      {"type": "event_batch", "agent_id": "...", "token": "...", "events": [...]}
    """

    def __init__(self, registry: AgentRegistry, processor: EventProcessor,
                 command_queue: Dict[str, list]):
        self.registry = registry
        self.processor = processor
        self.command_queue = command_queue

    async def handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        """Handle a single agent TCP connection."""
        peer = writer.get_extra_info("peername")
        logger.info(f"Agent connected from {peer}")

        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=120.0)
                if not line:
                    break

                try:
                    message = json.loads(line.decode("utf-8").strip())
                except json.JSONDecodeError:
                    await self._send(writer, {"status": "error", "message": "Invalid JSON"})
                    continue

                msg_type = message.get("type", "")
                response = await self._dispatch(msg_type, message, peer)
                await self._send(writer, response)

        except asyncio.TimeoutError:
            logger.debug(f"Connection timeout from {peer}")
        except ConnectionResetError:
            logger.debug(f"Connection reset by {peer}")
        except Exception as e:
            logger.error(f"Connection error from {peer}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug(f"Agent disconnected: {peer}")

    async def _dispatch(self, msg_type: str, message: dict, peer: tuple) -> dict:
        """Route message to appropriate handler."""
        handlers = {
            "register": self._handle_register,
            "heartbeat": self._handle_heartbeat,
            "event_batch": self._handle_event_batch,
        }

        handler = handlers.get(msg_type)
        if not handler:
            return {"status": "error", "message": f"Unknown message type: {msg_type}"}

        return await handler(message, peer)

    async def _handle_register(self, message: dict, peer: tuple) -> dict:
        """Process agent registration request."""
        data = message.get("data", {})

        agent = AgentRecord(
            hostname=data.get("hostname", "unknown"),
            ip_address=data.get("ip_address", peer[0] if peer else "unknown"),
            os_type=data.get("os_type", "unknown"),
            os_version=data.get("os_version", ""),
            agent_version=data.get("agent_version", "1.0.0"),
            group_name=data.get("group", "default"),
        )

        registered = await self.registry.register(agent)
        logger.info(f"Agent registered: {registered.hostname} → ID={registered.agent_id}")

        return {
            "status": "ok",
            "agent_id": registered.agent_id,
            "token": registered.token,
            "message": "Registration successful"
        }

    async def _handle_heartbeat(self, message: dict, peer: tuple) -> dict:
        """Process agent heartbeat with optional event batch."""
        agent_id = message.get("agent_id", "")
        token = message.get("token", "")

        if not agent_id or not token:
            return {"status": "error", "message": "Missing agent_id or token"}

        # Validate token
        valid = await self.registry.validate_token(agent_id, token)
        if not valid:
            return {"status": "error", "message": "Invalid agent_id or token"}

        # Update heartbeat
        await self.registry.heartbeat(agent_id)

        # Process any events included in the heartbeat
        events = message.get("events", [])
        processed = 0
        if events:
            agent_data = await self.registry.get(agent_id)
            hostname = agent_data.get("hostname", "unknown") if agent_data else "unknown"
            processed = await self.processor.process_batch(events, agent_id, hostname)

        # Return any pending commands for this agent
        commands = self.command_queue.pop(agent_id, [])

        return {
            "status": "ok",
            "events_processed": processed,
            "commands": commands,
        }

    async def _handle_event_batch(self, message: dict, peer: tuple) -> dict:
        """Process a standalone event batch (outside of heartbeat)."""
        agent_id = message.get("agent_id", "")
        token = message.get("token", "")

        if not await self.registry.validate_token(agent_id, token):
            return {"status": "error", "message": "Authentication failed"}

        events = message.get("events", [])
        agent_data = await self.registry.get(agent_id)
        hostname = agent_data.get("hostname", "unknown") if agent_data else "unknown"
        processed = await self.processor.process_batch(events, agent_id, hostname)

        return {"status": "ok", "events_processed": processed}

    async def _send(self, writer: asyncio.StreamWriter, data: dict) -> None:
        """Send a JSON response to the agent."""
        try:
            msg = json.dumps(data) + "\n"
            writer.write(msg.encode("utf-8"))
            await writer.drain()
        except Exception as e:
            logger.error(f"Failed to send response: {e}")


# ─── Manager Server ────────────────────────────────────────────

class ManagerServer:
    """
    SecureWatch Manager Server.

    Manages agent connections, registration, event ingestion,
    and periodic housekeeping (disconnect detection).
    """

    def __init__(self, config: dict):
        self.config = config
        server_cfg = config.get("server", {})
        db_cfg = config.get("database", {})
        es_cfg = config.get("elasticsearch", {})

        self.host = server_cfg.get("listen_host", "0.0.0.0")
        self.port = server_cfg.get("listen_port", 1514)

        # Database URL — parse manually to handle passwords with special chars
        db_url = os.getenv(
            "POSTGRES_URL",
            db_cfg.get("url", "postgresql://siemuser:siempass123!@postgres:5432/siemdb")
        )
        self.db_params = self._parse_db_url(db_url)

        self.registry = AgentRegistry(self.db_params)
        self.processor = EventProcessor(
            es_hosts=es_cfg.get("hosts", os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")),
            index_prefix=es_cfg.get("index_prefix", "securewatch"),
        )

        # Pending commands for agents: agent_id -> [command_dicts]
        self.command_queue: Dict[str, list] = {}
        self.protocol = AgentProtocol(self.registry, self.processor, self.command_queue)
        self._server = None
        self._running = True

    @staticmethod
    def _parse_db_url(url: str) -> dict:
        """Parse a PostgreSQL URL into components, handling passwords with special chars."""
        # postgresql://user:pass@host:port/db
        url = url.replace("postgresql://", "").replace("postgres://", "")
        # Split at the LAST @ to handle @ in passwords
        at_idx = url.rfind("@")
        if at_idx == -1:
            return {"host": "postgres", "port": 5432, "user": "siemuser",
                    "password": "siempass123!", "database": "siemdb"}

        creds = url[:at_idx]
        rest = url[at_idx + 1:]

        # Parse user:password
        colon_idx = creds.find(":")
        user = creds[:colon_idx] if colon_idx != -1 else creds
        password = creds[colon_idx + 1:] if colon_idx != -1 else ""

        # Parse host:port/database
        slash_idx = rest.find("/")
        host_port = rest[:slash_idx] if slash_idx != -1 else rest
        database = rest[slash_idx + 1:] if slash_idx != -1 else "siemdb"

        colon_idx = host_port.find(":")
        host = host_port[:colon_idx] if colon_idx != -1 else host_port
        port = int(host_port[colon_idx + 1:]) if colon_idx != -1 else 5432

        return {"host": host, "port": port, "user": user,
                "password": password, "database": database}

    async def start(self) -> None:
        """Start the manager server and background tasks."""
        logger.info("=" * 60)
        logger.info("  SecureWatch Manager Server v1.0.0")
        logger.info(f"  Listening on {self.host}:{self.port}")
        logger.info("=" * 60)

        # Initialize database
        await self.registry.init()

        # Start TCP server
        self._server = await asyncio.start_server(
            self.protocol.handle_connection,
            self.host,
            self.port
        )
        logger.info(f"TCP server started on {self.host}:{self.port}")

        # Start background housekeeping
        asyncio.create_task(self._housekeeping_loop())
        asyncio.create_task(self._stats_loop())

        async with self._server:
            await self._server.serve_forever()

    async def _housekeeping_loop(self) -> None:
        """Periodically mark unresponsive agents as disconnected."""
        agent_cfg = self.config.get("agent_defaults", {})
        timeout = agent_cfg.get("heartbeat_timeout", 90)

        while self._running:
            try:
                count = await self.registry.mark_disconnected(timeout)
                if count > 0:
                    logger.warning(f"Housekeeping: {count} agents marked disconnected")
            except Exception as e:
                logger.error(f"Housekeeping error: {e}")

            await asyncio.sleep(30)

    async def _stats_loop(self) -> None:
        """Log server statistics periodically."""
        while self._running:
            try:
                summary = await self.registry.get_summary()
                total_events = self.processor.total_processed
                logger.info(
                    f"[STATS] Agents: {summary.get('active', 0)} active, "
                    f"{summary.get('disconnected', 0)} disconnected, "
                    f"{summary.get('total', 0)} total | "
                    f"Events processed: {total_events}"
                )
            except Exception as e:
                logger.debug(f"Stats error: {e}")

            await asyncio.sleep(60)

    def queue_command(self, agent_id: str, command: dict) -> None:
        """Queue a command to be sent to an agent on next heartbeat."""
        if agent_id not in self.command_queue:
            self.command_queue[agent_id] = []
        self.command_queue[agent_id].append(command)
        logger.info(f"Command queued for agent {agent_id}: {command.get('action', 'unknown')}")

    async def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("Shutting down manager server...")
        self._running = False
        if self._server:
            self._server.close()
        await self.processor.close()
        await self.registry.close()
        logger.info("Manager server stopped.")


# ─── Entry Point ────────────────────────────────────────────────

async def main():
    """Main entry point for the SecureWatch Manager."""
    # Configure loguru
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{module}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
        level="INFO"
    )

    config = load_config()
    server = ManagerServer(config)

    # Graceful shutdown handler
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(server.shutdown()))

    # Wait for dependencies (postgres, elasticsearch)
    logger.info("Waiting 10s for dependent services to initialize...")
    await asyncio.sleep(10)

    try:
        await server.start()
    except asyncio.CancelledError:
        await server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
