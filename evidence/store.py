from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.models.evidence import Base, EvidenceEvent

DATABASE_URL = "sqlite:///./knighteye.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)


class EvidenceStore:
    """
    Single authority for evidence persistence.
    """
    def __init__(self):
        self.session = SessionLocal()

    def exists(self, wazuh_id: str) -> bool:
        return self.session.query(EvidenceEvent)\
            .filter(EvidenceEvent.wazuh_id == wazuh_id)\
            .first() is not None

    def get_last_event(self):
        return self.session.query(EvidenceEvent)\
            .order_by(EvidenceEvent.timestamp.desc())\
            .first()

    def add(self, event: EvidenceEvent):
        self.session.add(event)
        self.session.commit()

    def fetch_all_ordered(self):
        return self.session.query(EvidenceEvent)\
            .order_by(EvidenceEvent.timestamp)\
            .all()

    def close(self):
        self.session.close()
