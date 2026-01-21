import uuid
from datetime import timedelta

LINK_WINDOW = timedelta(seconds=8)

STAGE_ORDER = [
    "Initial Access",
    "Execution",
    "Privilege Escalation",
    "Persistence",
    "Activity",
    "Network Activity"
]

HIGH_VALUE = {
    ("Initial Access", "Execution"),
    ("Execution", "Privilege Escalation"),
    ("Execution", "Network Activity"),
    ("Initial Access", "Network Activity"),
    ("Privilege Escalation", "Persistence"),
}


def build_storylines(compressed_events):
    links = []

    for i in range(len(compressed_events) - 1):
        a = compressed_events[i]
        b = compressed_events[i + 1]

        reasons = []

        if a["system"] != b["system"]:
            reasons.append("cross-system behavior")

        if a.get("source_ip") and a.get("source_ip") == b.get("source_ip"):
            reasons.append("same source")

        if b["start_time"] - a["end_time"] <= LINK_WINDOW:
            reasons.append("temporal proximity")

        if (a["stage"], b["stage"]) in HIGH_VALUE:
            reasons.append("meaningful attack progression")

        if len(reasons) >= 3 and (a["stage"], b["stage"]) in HIGH_VALUE:
            links.append((a, b, reasons))

    return chain_links_into_storylines(links)


def chain_links_into_storylines(links):
    storylines = []
    used = set()

    for a, b, reasons in links:
        if id(a) in used:
            continue

        storyline = {
            "storyline_id": str(uuid.uuid4()),
            "systems": set([a["system"], b["system"]]),
            "steps": [a, b],
            "reasoning": list(set(reasons)),
            "confidence": "medium"
        }

        used.add(id(a))
        used.add(id(b))
        current = b

        for x, y, r in links:
            if x == current:
                storyline["steps"].append(y)
                storyline["systems"].add(y["system"])
                storyline["reasoning"].extend(r)
                used.add(id(y))
                current = y

        storyline["systems"] = list(storyline["systems"])
        storyline["reasoning"] = list(set(storyline["reasoning"]))
        storyline["confidence"] = "high" if len(storyline["steps"]) >= 3 else "medium"

        storylines.append(storyline)

    return storylines
