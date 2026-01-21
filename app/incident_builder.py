from datetime import timedelta
import uuid
import os
from dotenv import load_dotenv
load_dotenv()

INCIDENT_WINDOW = timedelta(minutes=10)
EXCLUDED_SYSTEMS = {
    os.getenv("WAZUH_SERVER")
}

def build_incidents(events):
    incidents = []
    current = None

    for ev in events:
        
        if ev.system in EXCLUDED_SYSTEMS:
            continue
        
        if is_noise(ev):
            continue

        if not current:
            current = new_incident(ev)
            continue

        if ev.timestamp - current["end_time"] <= INCIDENT_WINDOW and not is_noise(ev):
            current["events"].append(ev)
            current["end_time"] = ev.timestamp
            current["systems"].add(ev.system)
        else:
            incidents.append(finalize(current))
            current = new_incident(ev)

    if current:
        incidents.append(finalize(current))

    return incidents


def new_incident(ev):
    return {
        "incident_id": str(uuid.uuid4()),
        "start_time": ev.timestamp,
        "end_time": ev.timestamp,
        "systems": {ev.system},
        "events": [ev]
    }


def finalize(incident):
    incident["systems"] = list(incident["systems"])
    return incident

def infer_stage_from_dict(ev: dict):
    action_category = (ev.get("action_category") or "").lower()
    system_type = (ev.get("system_type") or "").lower()
    actor = (ev.get("actor") or "").lower()

    if "authentication" in action_category or "sshd" in action_category:
        return "Initial Access"

    if "process" in action_category or "sudo" in action_category or "command" in action_category:
        return "Execution"

    if "firewall" in system_type or "network" in system_type:
        return "Network Activity"

    if "root" in actor or "admin" in actor:
        return "Privilege Escalation"

    return "Activity"


def infer_stage_from_model(ev):
    return infer_stage_from_dict({
        "action_category": ev.action_category,
        "system_type": ev.system_type,
        "actor": ev.actor
    })

def enrich_events(events):
    enriched = []
    for ev in events:
        enriched.append({
            "timestamp": ev.timestamp,
            "system": ev.system,
            "actor": ev.actor,
            "action": ev.action_operation,
            "target": ev.target,
            "stage": infer_stage_from_model(ev)
        })
    return enriched

def generate_narrative(events, storylines=None):
    if not events:
        return "No significant security-relevant activity was detected."

    systems = {e["system"] for e in events}
    stages = [e["stage"] for e in events]

    narrative = []

    # --- Executive summary ---
    narrative.append(
        f"This incident shows evidence of coordinated malicious activity "
        f"across {len(systems)} system(s), involving the stages: "
        f"{', '.join(sorted(set(stages)))}.\n\n"
    )

    # --- Cross-system behavior ---
    if storylines:
        narrative.append("Cross-system attack chains were identified:\n")
        for s in storylines:
            narrative.append(
                f"- A sequence spanning {len(s['systems'])} systems "
                f"with {len(s['steps'])} linked actions, supported by "
                f"{', '.join(s['reasoning'])}.\n"
            )
        narrative.append("\n")

    # --- Critical evidence only ---
    narrative.append("Key supporting evidence:\n")

    for ev in sorted(events, key=lambda x: (-x["significance"], x["start_time"]))[:10]:
        narrative.append(
            f"- [{ev['stage']}] {ev['action']} on {ev['system']} "
            f"({ev['start_time']} → {ev['end_time']}, {ev['count']} events)\n"
        )

    # --- Assessment ---
    narrative.append("\nAssessment:\n")

    actions = " ".join(e["action"].lower() for e in events)

    if "account" in actions:
        narrative.append("- Evidence of account manipulation.\n")
    if "powershell" in actions or "script" in actions:
        narrative.append("- Script-based execution activity detected.\n")
    if "service" in actions or "persistence" in actions:
        narrative.append("- Potential persistence mechanisms were established.\n")
    if len(systems) >= 2:
        narrative.append("- Activity spans multiple systems, indicating lateral behavior.\n")

    narrative.append("- Overall pattern is consistent with early-to-mid stage intrusion activity.\n")

    return "".join(narrative)


def is_noise(ev):
    action = (ev.action_operation or "").lower()
    target = (ev.target or "").lower()
    severity = int(ev.severity or 0)

    if target == "sca":
        return True

    if action.startswith("cis "):
        return True

    if any(x in action for x in ["dpkg", "apt", "systemd", "cron"]):
        return True

    if severity < 5:
        return True

    return False
