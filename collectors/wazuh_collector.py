import os
from dotenv import load_dotenv
from collectors.wazuh_client import WazuhClient

load_dotenv()


class WazuhCollector:
    def __init__(self):
        self.client = WazuhClient(
            base_url=os.getenv("WAZUH_URL"),
            username=os.getenv("WAZUH_USER"),
            password=os.getenv("WAZUH_PASS"),
            verify_ssl=False
        )

    def fetch_since(self, since_ts: str, since_id: str | None):
        all_events = []

        while True:
            batch = self.client.get_recent_events(
                since_ts=since_ts,
                since_id=since_id,
                size=500
            )

            if not batch:
                break

            all_events.extend(batch)

            last = batch[-1]
            since_ts = last["_source"]["@timestamp"]
            since_id = last["_id"]

        return all_events, since_ts, since_id
