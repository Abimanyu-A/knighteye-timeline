# KnightEye-Timeline v1 — InvestigationResult Contract

This document defines the frozen output contract for **KnightEye-Timeline v1**.

The InvestigationResult represents the complete, deterministic outcome of a forensic reconstruction run.
All consumers (API, UI, research tools, exports) must rely on this contract.

Any change to this contract requires a **major version bump**.

---

## △ Purpose

The InvestigationResult contract exists to guarantee:

- Deterministic reconstruction results
- Replay safety and reproducibility
- Stable integration points for downstream consumers
- Separation between forensic evidence and derived intelligence

KnightEye-Timeline v1 guarantees that **given the same evidence**, the InvestigationResult will be identical.


---

## △ Field Definitions

### InvestigationResult
- `run_id`: Unique identifier for the investigation run
- `started_at`: Timestamp when the investigation was executed

---

### EvidenceSummary
High-level summary of ingested evidence.

- `total_events`: Number of EvidenceEvent records used
- `systems_involved`: Sorted list of unique systems
- `start_time`: Earliest event timestamp
- `end_time`: Latest event timestamp

---

### IncidentSummary
Represents a reconstructed investigation unit.

- `incident_id`: Stable incident identifier
- `start_time`: Incident start
- `end_time`: Incident end
- `systems`: Systems involved in the incident
- `event_count`: Number of evidence events grouped

---

### TimelineResult
Compressed, investigation-ready timeline.

- `incident_id`: Owning incident
- `events`: Ordered list of compressed timeline events

---

### StorylineResult
Correlated attack paths across timelines.

- `storyline_id`: Unique storyline identifier
- `systems`: Systems involved
- `steps`: Ordered reasoning steps
- `confidence`: Qualitative confidence label

---

### NarrativeResult
Human-readable investigation summary.

- `incident_id`: Owning incident
- `text`: Narrative explanation

---

### VerificationResult
Evidence chain integrity status.

- `valid`: Whether chain verification passed
- `checked_events`: Number of events verified
- `message`: Verification outcome message

---

## △ Invariants

- InvestigationResult is **read-only**
- No raw EvidenceEvent objects are exposed
- Ordering of lists is deterministic
- Derived intelligence must not mutate evidence
- Replay must produce the same InvestigationResult for the same evidence

---

## △ Versioning Policy

- This contract is frozen for v1
- Any structural change requires:
  - Major version bump
  - Migration strategy
  - Replay compatibility review

---
