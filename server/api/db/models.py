from sqlalchemy import Column, String, Integer, DateTime, Boolean, JSON, ForeignKey, Text
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True)
    username = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(32), default="viewer") # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True)
    username = Column(String(128), index=True)
    action = Column(String(128), nullable=False)
    resource = Column(String(128), nullable=False)
    target_id = Column(String(128), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(64), nullable=True)
    details = Column(JSON, default=dict)

class Agent(Base):
    __tablename__ = "agents"

    agent_id = Column(String(64), primary_key=True)
    hostname = Column(String(256), nullable=False)
    ip_address = Column(String(64), nullable=False)
    os_type = Column(String(32), nullable=False)
    os_version = Column(String(128), default="")
    agent_version = Column(String(32), default="1.0.0")
    status = Column(String(32), default="never_connected", index=True)
    group_name = Column(String(128), default="default", index=True)
    last_seen = Column(DateTime(timezone=True))
    registered_at = Column(DateTime(timezone=True), server_default=func.now())
    labels = Column(JSON, default=dict)
    token = Column(String(64), nullable=False)

class Rule(Base):
    """Detection Rules modeled in DB for UI management. 
    (Can be synced from/to YAML for the engine)."""
    __tablename__ = "rules"

    id = Column(String(36), primary_key=True)
    rule_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(256), nullable=False)
    severity = Column(String(32), default="low")
    description = Column(Text, nullable=True)
    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique_id = Column(String(64), nullable=True)
    mitre_technique_name = Column(String(128), nullable=True)
    logic = Column(JSON, default=dict)
    suppression = Column(Integer, default=0)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String(36), primary_key=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    trigger_condition = Column(String(256), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ResponseHistory(Base):
    __tablename__ = "response_history"

    id = Column(String(36), primary_key=True)
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=True)
    playbook_name = Column(String(256), nullable=False)
    target = Column(String(256), nullable=False)
    action_taken = Column(String(256), nullable=False)
    outcome = Column(String(32), default="Success") # Success/Failed
    initiated_by = Column(String(128), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class BehavioralBaseline(Base):
    __tablename__ = "behavioral_baselines"

    id = Column(String(36), primary_key=True)
    host = Column(String(128), index=True, nullable=True)
    user = Column(String(128), index=True, nullable=True)
    dimension = Column(String(128), index=True, nullable=False)
    mean = Column(Integer, nullable=False)
    std_dev = Column(Integer, nullable=False)
    p95 = Column(Integer, nullable=False)
    p99 = Column(Integer, nullable=False)
    max_normal = Column(Integer, nullable=False)
    computed_at = Column(DateTime(timezone=True), server_default=func.now())
