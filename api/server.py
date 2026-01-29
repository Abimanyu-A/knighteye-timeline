from fastapi import FastAPI
from evidence.store import init_db, SessionLocal
from collectors.wazuh import WazuhClient
from normalization.wazuh import normalize
from evidence.chain import compute_hash
from core.models.evidence import EvidenceEvent
from incidents.builder import build_incidents, infer_stage_from_dict
from timelines.compression import compress_events
from evidence.verify import verify_incident
from correlation.storylines import build_storylines
from synthesis.narrative import generate_narrative
import uuid
import os

from dotenv import load_dotenv
load_dotenv()

app = FastAPI()
init_db()

wazuh = WazuhClient(
    base_url=os.getenv("WAZUH_URL"),
    username=os.getenv("WAZUH_USER"),
    password=os.getenv("WAZUH_PASS"),
    verify_ssl=False
)

def get_last_cursor(session):
    ev = session.query(EvidenceEvent)\
        .order_by(EvidenceEvent.wazuh_timestamp.desc(),
                  EvidenceEvent.wazuh_id.desc())\
        .first()

    if not ev:
        return "1970-01-01T00:00:00Z", None

    return ev.wazuh_timestamp, ev.wazuh_id

@app.get("/collect/wazuh")
def collect():
    session = SessionLocal()
    session_id = str(uuid.uuid4())

    last_ts, last_id = get_last_cursor(session)

    last_event = session.query(EvidenceEvent)\
        .order_by(EvidenceEvent.timestamp.desc())\
        .first()

    prev_hash = last_event.current_hash if last_event else "GENESIS"
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
                system=ev["system"],
                system_type=ev["system_type"],
                source_ip=ev["source_ip"],

                actor=ev["actor"],
                action_category=ev["action_category"],
                action_operation=ev["action_operation"],

                target=ev["target"],
                raw_log=ev["raw_log"],
                severity=ev["severity"],

                prev_hash=prev_hash,
                current_hash=current_hash,

                session_id=session_id,
                incident_id=None,

                # forensic linkage
                wazuh_id=ev["wazuh_id"],
                wazuh_index=ev["wazuh_index"],
                wazuh_timestamp=ev["wazuh_timestamp"],
                rule_id=ev["rule_id"],
                mitre=ev["mitre"],
                agent_id=ev["agent_id"],
                stage=ev["stage"]
            )

            session.add(record)
            session.commit()

            prev_hash = current_hash
            stored += 1

        last_ts = alerts[-1]["_source"]["@timestamp"]
        last_id = alerts[-1]["_id"]

    session.close()
    return {"status": "ok", "stored": stored}

@app.get("/timeline")
def timeline():
    session = SessionLocal()
    events = session.query(EvidenceEvent).order_by(EvidenceEvent.timestamp).all()

    incidents = build_incidents(events)

    for inc in incidents:
        for ev in inc["events"]:
            ev.incident_id = inc["incident_id"]
            session.add(ev)
    session.commit()

    response = []

    for inc in incidents:
        compressed = compress_events(inc["events"])
        storylines = build_storylines(compressed)
        narrative = generate_narrative(compressed, storylines)

        response.append({
            "incident_id": inc["incident_id"],
            "start_time": inc["start_time"],
            "end_time": inc["end_time"],
            "systems": inc["systems"],

            "storylines": storylines, 
            "timeline": compressed,
            "narrative": narrative
        })

    return response

@app.get("/evidence/verify/{incident_id}")
def verify_evidence(incident_id: str):
    session = SessionLocal()

    events = session.query(EvidenceEvent)\
    .order_by(EvidenceEvent.timestamp, EvidenceEvent.event_id)\
    .all()

    result = verify_incident(events)

    return {
        "incident_id": incident_id,
        "event_count": len(events),
        "verification": result
    }
