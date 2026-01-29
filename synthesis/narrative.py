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


