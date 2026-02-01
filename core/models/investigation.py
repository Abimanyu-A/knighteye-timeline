from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any


@dataclass(frozen=True)
class EvidenceSummary:
    total_events: int
    systems_involved: List[str]
    start_time: datetime | None
    end_time: datetime | None


@dataclass(frozen=True)
class IncidentSummary:
    incident_id: str
    start_time: datetime
    end_time: datetime
    systems: List[str]
    event_count: int


@dataclass(frozen=True)
class TimelineResult:
    incident_id: str
    events: List[Dict[str, Any]]


@dataclass(frozen=True)
class StorylineResult:
    storyline_id: str
    systems: List[str]
    steps: List[Dict[str, Any]]
    confidence: str


@dataclass(frozen=True)
class NarrativeResult:
    incident_id: str
    text: str


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    checked_events: int
    message: str


@dataclass(frozen=True)
class InvestigationResult:
    run_id: str
    started_at: datetime

    evidence_summary: EvidenceSummary
    incidents: List[IncidentSummary]
    timelines: List[TimelineResult]
    storylines: List[StorylineResult]
    narratives: List[NarrativeResult]
    verification: VerificationResult
