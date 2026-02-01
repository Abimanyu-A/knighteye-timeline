import requests

class WazuhClient:
    def __init__(self, base_url, username, password, verify_ssl=False):
        self.base_url = base_url
        self.auth = (username, password)
        self.verify_ssl = verify_ssl

    def get_recent_events(self, since_ts, since_id=None, size=500, indices="wazuh-alerts-*"):
        url = f"{self.base_url}/{indices}/_search"

        body = {
            "size": size,
            "sort": [
                {"@timestamp": {"order": "asc"}},
                {"_id": {"order": "asc"}}
            ],
            "query": {
                "range": {
                    "@timestamp": {"gt": since_ts}
                }
            }
        }

        if since_id:
            body["search_after"] = [since_ts, since_id]

        r = requests.get(url, auth=self.auth, json=body, verify=self.verify_ssl)
        r.raise_for_status()
        data = r.json()
        return data.get("hits", {}).get("hits", [])
