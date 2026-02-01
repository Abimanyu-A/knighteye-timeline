from datetime import datetime
import uuid
import os

from dotenv import load_dotenv
load_dotenv()

from collectors.wazuh import WazuhClient
from normalization.wazuh import normalize
from evidence.chain import compute_hash
from evidence.verify import verify_incident
from evidence.store import SessionLocal
from core.models.evidence import EvidenceEvent
from incidents.builder import build_incidents, infer_stage_from_dict
from timelines.compression import compress_events
from correlation.storylines import build_storylines
from synthesis.narrative import generate_narrative


class InvestigationResult:
    def __init__(self):
        self.run_id = str(uuid.uuid4())
        self.started_at = datetime.utcnow()

        self.evidence_count = 0
        self.incidents = []
        self.timelines = []
        self.storylines = []
        self.narratives = []
        self.verification = None


def run_investigation():

    result = InvestigationResult()
    session = SessionLocal()

    wazuh = WazuhClient(
        base_url=os.getenv("WAZUH_URL"),
        username=os.getenv("WAZUH_USER"),
        password=os.getenv("WAZUH_PASS"),
        verify_ssl=False
    )

    last_event = session.query(EvidenceEvent)\
        .order_by(EvidenceEvent.timestamp.desc())\
        .first()

    prev_hash = last_event.current_hash if last_event else "GENESIS"
    last_ts = last_event.wazuh_timestamp if last_event else "1970-01-01T00:00:00Z"
    last_id = last_event.wazuh_id if last_event else None

    stored = 0

    while True:
        alerts = wazuh.get_recent_events(
            since_ts=last_ts,
            since_id=last_id,
            size=500
        )

        if not alerts:
            break

        for hit in alerts:
            alert = hit["_source"]
            alert["_id"] = hit["_id"]
            alert["_index"] = hit["_index"]

            ev = normalize(alert)
            ev["stage"] = infer_stage_from_dict(ev)

            exists = session.query(EvidenceEvent)\
                .filter(EvidenceEvent.wazuh_id == ev["wazuh_id"])\
                .first()
            if exists:
                continue

            current_hash = compute_hash(prev_hash, ev)

            record = EvidenceEvent(
                **ev,
                prev_hash=prev_hash,
                current_hash=current_hash,
                session_id=result.run_id
            )

            session.add(record)
            session.commit()

            prev_hash = current_hash
            stored += 1

        last_ts = alerts[-1]["_source"]["@timestamp"]
        last_id = alerts[-1]["_id"]

    result.evidence_count = stored

    events = session.query(EvidenceEvent)\
        .order_by(EvidenceEvent.timestamp)\
        .all()

    incidents = build_incidents(events)

    timelines = []
    storylines = []
    narratives = []

    for inc in incidents:
        timeline = compress_events(inc["events"])
        timelines.append(timeline)
        storylines.extend(build_storylines(timeline))
        narratives.append(generate_narrative(timeline, storylines))

    verification = verify_incident(events)

    session.close()

    result.incidents = incidents
    result.timelines = timelines
    result.storylines = storylines
    result.narratives = narratives
    result.verification = verification

    return result