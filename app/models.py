from sqlalchemy import Column, String, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
import uuid
from datetime import datetime

Base = declarative_base()

class EvidenceEvent(Base):
    __tablename__ = "evidence_events"

    event_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)

    system = Column(String)
    system_type = Column(String)
    source_ip = Column(String)

    actor = Column(String)
    action_category = Column(String)
    action_operation = Column(String)

    target = Column(String)
    raw_log = Column(Text)
    severity = Column(String)

    prev_hash = Column(String)
    current_hash = Column(String)
    
    session_id = Column(String)
    incident_id = Column(String)
    
    wazuh_id = Column(String, unique=True, index=True)
    wazuh_index = Column(String)
    wazuh_timestamp = Column(String)

    rule_id = Column(String)
    mitre = Column(String)
    agent_id = Column(String)

    stage = Column(String)


