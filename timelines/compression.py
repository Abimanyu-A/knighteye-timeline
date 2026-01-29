from datetime import timedelta
from incidents.builder import infer_stage_from_model

COMPRESSION_WINDOW = timedelta(seconds=2)
IMPORTANT_THRESHOLD = 5


def compress_events(events):
    if not events:
        return []

    compressed = []
    buffer = [events[0]]

    for current in events[1:]:
        last = buffer[-1]

        if "syscheck" in (current.target or "").lower():
            same_pattern = (
                current.system == last.system and
                current.target == last.target and
                infer_stage_from_model(current) == infer_stage_from_model(last)
            )
        else:
            same_pattern = (
                current.system == last.system and
                current.actor == last.actor and
                semantic_label(current) == semantic_label(last) and
                current.target == last.target and
                infer_stage_from_model(current) == infer_stage_from_model(last)
            )

        close_in_time = (current.timestamp - last.timestamp) <= COMPRESSION_WINDOW

        if same_pattern and close_in_time:
            buffer.append(current)
        else:
            compressed.append(build_compressed(buffer))
            buffer = [current]

    if buffer:
        compressed.append(build_compressed(buffer))

    # 🔥 INTELLIGENCE FILTER
    important = [e for e in compressed if e["significance"] >= IMPORTANT_THRESHOLD]

    return important


def build_compressed(buffer):
    first = buffer[0]
    last = buffer[-1]

    block = {
        "start_time": first.timestamp,
        "end_time": last.timestamp,

        "system": first.system,
        "system_type": first.system_type,
        "source_ip": first.source_ip,

        "actor": first.actor,
        "action": semantic_label(first),
        "target": first.target,
        "stage": infer_stage_from_model(first),

        "count": len(buffer),
        "confidence": (
            "high" if len(buffer) > 20 else
            "medium" if len(buffer) > 5 else
            "low"
        )
    }

    block["significance"] = significance_score(block)
    return block


def significance_score(ev):
    score = 0

    stage_weight = {
        "Initial Access": 3,
        "Execution": 4,
        "Privilege Escalation": 5,
        "Persistence": 5,
        "Network Activity": 2,
        "Activity": 1
    }
    score += stage_weight.get(ev["stage"], 1)

    action = (ev["action"] or "").lower()

    if any(x in action for x in ["account", "user", "group"]):
        score += 4
    if any(x in action for x in ["powershell", "script", "command"]):
        score += 3
    if any(x in action for x in ["service", "registry", "scheduled task"]):
        score += 4
    if any(x in action for x in ["executable", "dll", "payload"]):
        score += 4
    if any(x in action for x in ["logon failure", "authentication"]):
        score += 2

    if ev["count"] > 20:
        score += 1

    return score


def semantic_label(ev):
    action = (ev.action_operation or "").lower()
    target = (ev.target or "").lower()

    if "new user added" in action or "new group added" in action:
        return "Account creation / modification"

    if "new windows service created" in action:
        return "Persistence mechanism established"

    if "powershell" in action:
        return "Suspicious script execution"

    if "executable file dropped" in action:
        return "Malware staging activity"

    if "logon failure" in action:
        return "Authentication failures"

    if "syscheck" in target:
        return "Mass filesystem changes"

    if "firewall" in action or "pfsense" in action:
        return "Blocked network activity"

    return ev.action_operation
