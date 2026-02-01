from datetime import datetime
import uuid

from collectors.wazuh_collector import WazuhCollector
from normalization.wazuh import normalize
from evidence.chain import compute_hash
from evidence.verify import verify_incident
from evidence.store import EvidenceStore
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

def reconstruct_from_evidence(events):
    
    incidents = build_incidents(events)

    timelines = []
    storylines = []
    narratives = []

    for inc in incidents:
        timeline = compress_events(inc["events"])
        timelines.append(timeline)

        sl = build_storylines(timeline)
        storylines.extend(sl)

        narratives.append(
            generate_narrative(timeline, sl)
        )

    verification = verify_incident(events)

    return {
        "incidents": incidents,
        "timelines": timelines,
        "storylines": storylines,
        "narratives": narratives,
        "verification": verification
    }

def run_investigation():

    result = InvestigationResult()
    store = EvidenceStore()
    collector = WazuhCollector()

    last_event = store.get_last_event()

    prev_hash = last_event.current_hash if last_event else "GENESIS"
    since_ts = last_event.wazuh_timestamp if last_event else "1970-01-01T00:00:00Z"
    since_id = last_event.wazuh_id if last_event else None

    raw_events, _, _ = collector.fetch_since(since_ts, since_id)

    stored = 0

    for hit in raw_events:
        alert = hit["_source"]
        alert["_id"] = hit["_id"]
        alert["_index"] = hit["_index"]

        ev = normalize(alert)
        ev["stage"] = infer_stage_from_dict(ev)

        if store.exists(ev["wazuh_id"]):
            continue

        current_hash = compute_hash(prev_hash, ev)

        record = EvidenceEvent(
            **ev,
            prev_hash=prev_hash,
            current_hash=current_hash,
            session_id=result.run_id
        )

        store.add(record)

        prev_hash = current_hash
        stored += 1

    result.evidence_count = stored

    events = store.fetch_all_ordered()

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

    store.close()

    recon = reconstruct_from_evidence(events)

    result.incidents = recon["incidents"]
    result.timelines = recon["timelines"]
    result.storylines = recon["storylines"]
    result.narratives = recon["narratives"]
    result.verification = recon["verification"]

    return result

def replay_investigation():
    """
    Read-only reconstruction from existing evidence.
    No collectors. No hashing. No DB writes.
    """
    store = EvidenceStore()
    events = store.fetch_all_ordered()

    return reconstruct_from_evidence(events)