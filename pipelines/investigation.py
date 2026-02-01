from datetime import datetime
import uuid

from collectors.wazuh_collector import WazuhCollector
from normalization.wazuh import normalize
from evidence.chain import compute_hash
from evidence.verify import verify_incident
from evidence.store import EvidenceStore
from core.models.evidence import EvidenceEvent
from core.models.investigation import (
    InvestigationResult,
    EvidenceSummary,
    IncidentSummary,
    TimelineResult,
    StorylineResult,
    NarrativeResult,
    VerificationResult,
)
from incidents.builder import build_incidents, infer_stage_from_dict
from timelines.compression import compress_events
from correlation.storylines import build_storylines
from synthesis.narrative import generate_narrative


def run_investigation() -> InvestigationResult:
    run_id = str(uuid.uuid4())
    started_at = datetime.utcnow()

    store = EvidenceStore()
    collector = WazuhCollector()

    last_event = store.get_last_event()

    prev_hash = last_event.current_hash if last_event else "GENESIS"
    since_ts = last_event.wazuh_timestamp if last_event else "1970-01-01T00:00:00Z"
    since_id = last_event.wazuh_id if last_event else None

    raw_events, _, _ = collector.fetch_since(since_ts, since_id)

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
            session_id=run_id,
        )

        store.add(record)
        prev_hash = current_hash

    events = store.fetch_all_ordered()
    store.close()

    # ------------------------------------------------------------------
    # Evidence summary
    # ------------------------------------------------------------------

    systems = sorted({e.system for e in events})
    start_time = events[0].timestamp if events else None
    end_time = events[-1].timestamp if events else None

    evidence_summary = EvidenceSummary(
        total_events=len(events),
        systems_involved=systems,
        start_time=start_time,
        end_time=end_time,
    )

    # ------------------------------------------------------------------
    # Incidents, timelines, storylines, narratives
    # ------------------------------------------------------------------

    incident_summaries = []
    timeline_results = []
    storyline_results = []
    narrative_results = []

    incidents = build_incidents(events)

    for inc in incidents:
        incident_id = inc["incident_id"]

        incident_summaries.append(
            IncidentSummary(
                incident_id=incident_id,
                start_time=inc["start_time"],
                end_time=inc["end_time"],
                systems=sorted(inc["systems"]),
                event_count=len(inc["events"]),
            )
        )

        timeline = compress_events(inc["events"])
        timeline_results.append(
            TimelineResult(
                incident_id=incident_id,
                events=timeline,
            )
        )

        storylines = build_storylines(timeline)
        for sl in storylines:
            storyline_results.append(
                StorylineResult(
                    storyline_id=sl["storyline_id"],
                    systems=sorted(sl["systems"]),
                    steps=sl["steps"],
                    confidence=sl["confidence"],
                )
            )

        narrative_results.append(
            NarrativeResult(
                incident_id=incident_id,
                text=generate_narrative(timeline, storylines),
            )
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    verification = verify_incident(events)

    verification_result = VerificationResult(
        valid=verification["valid"],
        checked_events=verification["checked_events"],
        message=verification["message"],
    )

    # ------------------------------------------------------------------
    # Final, frozen result
    # ------------------------------------------------------------------

    return InvestigationResult(
        run_id=run_id,
        started_at=started_at,
        evidence_summary=evidence_summary,
        incidents=incident_summaries,
        timelines=timeline_results,
        storylines=storyline_results,
        narratives=narrative_results,
        verification=verification_result,
    )


def replay_investigation() -> InvestigationResult:
    store = EvidenceStore()
    events = store.fetch_all_ordered()
    store.close()

    # Deterministic replay uses the same construction path
    # but skips collection/storage
    run_id = "REPLAY"
    started_at = datetime.utcnow()

    systems = sorted({e.system for e in events})
    start_time = events[0].timestamp if events else None
    end_time = events[-1].timestamp if events else None

    evidence_summary = EvidenceSummary(
        total_events=len(events),
        systems_involved=systems,
        start_time=start_time,
        end_time=end_time,
    )

    incident_summaries = []
    timeline_results = []
    storyline_results = []
    narrative_results = []

    incidents = build_incidents(events)

    for inc in incidents:
        incident_id = inc["incident_id"]

        incident_summaries.append(
            IncidentSummary(
                incident_id=incident_id,
                start_time=inc["start_time"],
                end_time=inc["end_time"],
                systems=sorted(inc["systems"]),
                event_count=len(inc["events"]),
            )
        )

        timeline = compress_events(inc["events"])
        timeline_results.append(
            TimelineResult(
                incident_id=incident_id,
                events=timeline,
            )
        )

        storylines = build_storylines(timeline)
        for sl in storylines:
            storyline_results.append(
                StorylineResult(
                    storyline_id=sl["storyline_id"],
                    systems=sorted(sl["systems"]),
                    steps=sl["steps"],
                    confidence=sl["confidence"],
                )
            )

        narrative_results.append(
            NarrativeResult(
                incident_id=incident_id,
                text=generate_narrative(timeline, storylines),
            )
        )

    verification = verify_incident(events)

    verification_result = VerificationResult(
        valid=verification["valid"],
        checked_events=verification["checked_events"],
        message=verification["message"],
    )

    return InvestigationResult(
        run_id=run_id,
        started_at=started_at,
        evidence_summary=evidence_summary,
        incidents=incident_summaries,
        timelines=timeline_results,
        storylines=storyline_results,
        narratives=narrative_results,
        verification=verification_result,
    )