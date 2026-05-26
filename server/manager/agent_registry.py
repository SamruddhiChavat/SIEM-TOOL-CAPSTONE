"""
SecureWatch Manager — Agent Registry Module

Handles CRUD operations for agent records in PostgreSQL.
Tracks agent lifecycle: registration, heartbeat, status transitions.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import json
import asyncpg
from loguru import logger
from pydantic import BaseModel, Field


class AgentRecord(BaseModel):
    """Pydantic model for a registered SecureWatch agent."""
    agent_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str
    ip_address: str
    os_type: str  # linux, windows, darwin
    os_version: str = ""
    agent_version: str = "1.0.0"
    status: str = "never_connected"  # active, disconnected, never_connected
    group_name: str = "default"
    last_seen: Optional[datetime] = None
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    labels: Dict[str, str] = Field(default_factory=dict)
    token: str = Field(default_factory=lambda: str(uuid.uuid4()))


# ─── SQL Schema ─────────────────────────────────────────────────

AGENT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id        VARCHAR(64) PRIMARY KEY,
    hostname        VARCHAR(256) NOT NULL,
    ip_address      VARCHAR(64) NOT NULL,
    os_type         VARCHAR(32) NOT NULL,
    os_version      VARCHAR(128) DEFAULT '',
    agent_version   VARCHAR(32) DEFAULT '1.0.0',
    status          VARCHAR(32) DEFAULT 'never_connected',
    group_name      VARCHAR(128) DEFAULT 'default',
    last_seen       TIMESTAMPTZ,
    registered_at   TIMESTAMPTZ DEFAULT NOW(),
    labels          JSONB DEFAULT '{}',
    token           VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_group ON agents(group_name);
"""


class AgentRegistry:
    """Manages agent lifecycle in PostgreSQL."""

    def __init__(self, db_params: dict):
        self.db_params = db_params  # {host, port, user, password, database}
        self.pool: Optional[asyncpg.Pool] = None

    async def init(self) -> None:
        """Initialize database connection pool and create schema."""
        logger.info("Initializing agent registry database connection...")
        self.pool = await asyncpg.create_pool(
            host=self.db_params.get("host", "postgres"),
            port=self.db_params.get("port", 5432),
            user=self.db_params.get("user", "siemuser"),
            password=self.db_params.get("password", "siempass123!"),
            database=self.db_params.get("database", "siemdb"),
            min_size=2,
            max_size=10,
            command_timeout=30
        )
        async with self.pool.acquire() as conn:
            await conn.execute(AGENT_TABLE_SQL)
        logger.info("Agent registry initialized — table 'agents' ready.")

    async def close(self) -> None:
        if self.pool:
            await self.pool.close()

    # ─── CRUD ────────────────────────────────────────────

    async def register(self, agent: AgentRecord) -> AgentRecord:
        """Register a new agent. Returns the agent with assigned ID and token."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agents (agent_id, hostname, ip_address, os_type, os_version,
                                    agent_version, status, group_name, registered_at, labels, token)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (agent_id) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    ip_address = EXCLUDED.ip_address,
                    os_type = EXCLUDED.os_type,
                    os_version = EXCLUDED.os_version,
                    agent_version = EXCLUDED.agent_version,
                    status = 'active',
                    last_seen = NOW()
                """,
                agent.agent_id, agent.hostname, agent.ip_address, agent.os_type,
                agent.os_version, agent.agent_version, "active", agent.group_name,
                agent.registered_at, json.dumps(agent.labels), agent.token
            )
        logger.info(f"Agent registered: {agent.hostname} ({agent.agent_id})")
        return agent

    async def heartbeat(self, agent_id: str) -> bool:
        """Update agent last_seen timestamp and set status to active."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE agents SET last_seen = NOW(), status = 'active'
                WHERE agent_id = $1
                """,
                agent_id
            )
            return result == "UPDATE 1"

    async def get(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get a single agent by ID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM agents WHERE agent_id = $1", agent_id)
            return dict(row) if row else None

    async def list_all(self, status: Optional[str] = None, group: Optional[str] = None) -> List[Dict[str, Any]]:
        """List agents with optional filters."""
        query = "SELECT * FROM agents WHERE 1=1"
        params = []
        idx = 1

        if status:
            query += f" AND status = ${idx}"
            params.append(status)
            idx += 1

        if group:
            query += f" AND group_name = ${idx}"
            params.append(group)
            idx += 1

        query += " ORDER BY last_seen DESC NULLS LAST"

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows]

    async def delete(self, agent_id: str) -> bool:
        """Remove an agent from the registry."""
        async with self.pool.acquire() as conn:
            result = await conn.execute("DELETE FROM agents WHERE agent_id = $1", agent_id)
            deleted = result == "DELETE 1"
            if deleted:
                logger.warning(f"Agent deleted: {agent_id}")
            return deleted

    async def update_status(self, agent_id: str, status: str) -> bool:
        """Update agent status (active/disconnected)."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE agents SET status = $1 WHERE agent_id = $2",
                status, agent_id
            )
            return result == "UPDATE 1"

    async def get_summary(self) -> Dict[str, int]:
        """Get count summary of agents by status."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT status, COUNT(*) as count FROM agents GROUP BY status"
            )
            summary = {"total": 0, "active": 0, "disconnected": 0, "never_connected": 0}
            for row in rows:
                summary[row["status"]] = row["count"]
                summary["total"] += row["count"]
            return summary

    async def mark_disconnected(self, timeout_seconds: int = 90) -> int:
        """Mark agents as disconnected if no heartbeat within timeout."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE agents SET status = 'disconnected'
                WHERE status = 'active'
                  AND last_seen < NOW() - INTERVAL '1 second' * $1
                """,
                timeout_seconds
            )
            count = int(result.split()[-1]) if result else 0
            if count > 0:
                logger.warning(f"Marked {count} agents as disconnected (timeout={timeout_seconds}s)")
            return count

    async def validate_token(self, agent_id: str, token: str) -> bool:
        """Validate an agent's authentication token."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT token FROM agents WHERE agent_id = $1",
                agent_id
            )
            return row is not None and row["token"] == token
