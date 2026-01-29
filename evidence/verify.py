from evidence.chain import compute_hash

def verify_incident(events):
    if not events:
        return {
            "valid": True,
            "message": "No events found for this incident.",
            "checked_events": 0
        }

    prev_hash = events[0].prev_hash

    for idx, ev in enumerate(events):
        event_dict = {
            "system": ev.system,
            "system_type": ev.system_type,
            "source_ip": ev.source_ip,
            "actor": ev.actor,
            "action_category": ev.action_category,
            "action_operation": ev.action_operation,
            "target": ev.target,
            "raw_log": ev.raw_log,
            "severity": ev.severity,
            "wazuh_id": ev.wazuh_id,
            "wazuh_index": ev.wazuh_index,
            "wazuh_timestamp": ev.wazuh_timestamp,
            "rule_id": ev.rule_id,
            "mitre": ev.mitre,
            "agent_id": ev.agent_id,
            "stage": ev.stage
        }

        expected = compute_hash(prev_hash, event_dict)

        if expected != ev.current_hash:
            return {
                "valid": False,
                "message": "Evidence chain integrity violation detected.",
                "checked_events": idx + 1,
                "broken_at": {
                    "position": idx,
                    "event_id": ev.event_id,
                    "expected_hash": expected,
                    "stored_hash": ev.current_hash
                }
            }

        prev_hash = ev.current_hash

    return {
        "valid": True,
        "message": "Evidence chain verified. No tampering detected.",
        "checked_events": len(events)
    }
