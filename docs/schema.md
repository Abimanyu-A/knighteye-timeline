# KnightEye Evidence Schema (Frozen – v1)

This document defines the frozen Evidence schema for KnightEye v1.

The Evidence schema represents immutable forensic truth.
Any change to this schema requires a version bump and explicit migration plan.

---

## △ EvidenceEvent

Represents a single observed telemetry event ingested by KnightEye.

### Identity
- event_id (UUID, primary key)
- wazuh_id (unique external identifier)

### Temporal
- timestamp (ingestion time)
- wazuh_timestamp (source event time)

### System Context
- system
- system_type
- source_ip
- agent_id

### Actor & Action
- actor
- action_category
- action_operation
- target

### Severity & Classification
- severity
- stage

### Raw Evidence
- raw_log
- wazuh_index
- rule_id
- mitre

### Chain of Custody
- prev_hash
- current_hash
- session_id

### Investigation Metadata
- incident_id (nullable)

---

## △ Invariants

- EvidenceEvent records are immutable after insertion
- EvidenceEvent records are never updated or deleted
- Derived intelligence must not be written back into EvidenceEvent
- Cryptographic fields must be computed at ingestion time only

---

## △ Access Rules

### May WRITE EvidenceEvent
- collectors
- normalization
- evidence chain logic

### May READ EvidenceEvent
- pipelines
- incident builders
- timeline engines
- correlation engines
- synthesis engines

### Must NOT Modify EvidenceEvent
- correlation
- synthesis
- UI
- API
- research modules

---

## △ Versioning Policy

- v1 schema is frozen
- Any schema change requires:
  - schema version increment
  - migration strategy
  - replay compatibility review

---
