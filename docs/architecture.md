# KnightEye-Timeline v1 - Architecture Overview

KnightEye-Timeline is a focused forensic reconstruction engine within the broader **KnightEye ecosystem**.

This document defines the architectural boundaries, responsibilities, and invariants that govern KnightEye-Timeline v1.

The goal is to preserve correctness, replayability, and contributor safety.

---

## △ Scope

KnightEye-Timeline is responsible for:

- Ingesting telemetry (via collectors)
- Preserving forensic evidence
- Reconstructing incidents, timelines, storylines, and narratives
- Providing deterministic, replayable investigation results

KnightEye-Timeline does **not** implement detection, alerting, or SOC orchestration.

---

## △ Layered Architecture

### Collectors
**Purpose:** Telemetry acquisition  
**Examples:** WazuhCollector  

Responsibilities:
- Fetch raw telemetry
- Handle pagination and cursors
- No reasoning or evidence mutation

---

### Normalization
**Purpose:** Raw telemetry → normalized event dictionaries  

Responsibilities:
- Field extraction
- Canonical representation
- No inference or correlation

---

### Evidence
**Purpose:** Forensic truth and chain of custody  

Responsibilities:
- Persistent storage
- Cryptographic chaining
- Evidence verification
- Replay-safe reads

This layer is immutable after ingestion.

---

### Pipelines
**Purpose:** Investigation orchestration  

Responsibilities:
- Coordinate ingestion and reconstruction
- Enforce investigation flow
- Produce InvestigationResult

**Single Source of Truth:**  
`pipelines/investigation.py`

---

### Incident / Timeline / Correlation / Synthesis Engines
**Purpose:** Reasoning and intelligence derivation  

Responsibilities:
- Incident grouping
- Timeline compression
- Storyline correlation
- Narrative synthesis

These layers must never write evidence.

---

### API
**Purpose:** Product interface  

Responsibilities:
- Request handling
- Calling pipelines
- Returning serialized results

No logic is allowed here.

---

### UI
**Purpose:** Presentation only  

Responsibilities:
- Render InvestigationResult
- No inference
- No mutation

---

## △ Allowed Dependencies

- API → Pipelines
- Pipelines → Evidence (read-only)
- Pipelines → Engines
- Engines → Core Models
- Collectors → External systems

---

## △ Forbidden Dependencies

- Evidence → Pipelines
- Evidence → Collectors
- Collectors → Evidence
- API → Evidence
- UI → Pipelines
- Engines → Evidence writes

Violating these boundaries breaks v1 guarantees.

---

## △ Evidence Rules

- Evidence is immutable after insertion
- No derived intelligence may be written back
- Replay must never mutate state
- Verification must operate on stored evidence only

---

## △ Determinism & Replay

KnightEye-Timeline guarantees:

- Replayable reconstruction
- Deterministic outputs for identical evidence
- Separation of ingestion and reconstruction

Replay is read-only and side-effect free.

---

## △ v1 Stability Policy

KnightEye-Timeline v1 is frozen.

The following must not change without a major version bump:
- Evidence schema
- InvestigationResult contract
- Reconstruction pipeline semantics

---
