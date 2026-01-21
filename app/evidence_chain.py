import hashlib
import json

def compute_hash(prev_hash, event_dict):
    canonical = json.dumps(
        event_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )
    payload = (prev_hash + canonical).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
