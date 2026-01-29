import json

def normalize(alert):
    agent = alert.get("agent", {})
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    pre = alert.get("predecoder", {})
    decoder = alert.get("decoder", {})
    manager = alert.get("manager", {})

    system = (
        pre.get("hostname")
        or data.get("hostname")
        or data.get("host")
        or data.get("computer_name")
        or data.get("win", {}).get("system", {}).get("computer")
        or agent.get("name")                           # fallback: wazuh agent
        or "unknown"
    )

    # --- Collector (chain-of-custody metadata) ---
    collector = manager.get("name") or agent.get("name")

    return {
        "system": system,
        "collector": collector,
        "system_type": decoder.get("name") or agent.get("os", {}).get("name", "unknown"),
        "source_ip": data.get("srcip") or data.get("src_ip"),
        "actor": (
            data.get("srcuser")
            or data.get("user")
            or data.get("dstuser")
            or pre.get("program_name")
            or "unknown"
        ),

        "action_category": (
            rule.get("groups", ["unknown"])[0]
            if rule.get("groups") else "unknown"
        ),

        "action_operation": rule.get("description", "unknown"),
        "target": alert.get("location") or decoder.get("name") or "unknown",

        "raw_log": alert.get("full_log") or json.dumps(alert, sort_keys=True),
        "severity": str(rule.get("level", "0")),

        # Forensic linkage
        "wazuh_id": alert.get("id") or alert.get("_id"),
        "wazuh_index": alert.get("_index"),
        "wazuh_timestamp": alert.get("timestamp") or alert.get("@timestamp"),
        "rule_id": rule.get("id"),
        "mitre": json.dumps(rule.get("mitre"), sort_keys=True) if rule.get("mitre") else None,
        "agent_id": agent.get("id")
    }
