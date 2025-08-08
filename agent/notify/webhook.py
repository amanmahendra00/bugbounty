from __future__ import annotations
import requests
from agent.state import Finding, ScanContext


class WebhookNotifier:
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def notify_finding(self, finding: Finding) -> None:
        requests.post(self.webhook_url, json={"type": "finding", "finding": finding.model_dump()}, timeout=10)

    def notify_summary(self, context: ScanContext) -> None:
        payload = {
            "type": "summary",
            "domains": context.domains,
            "assets": context.assets,
            "urls_count": {d: len(u) for d, u in context.urls.items()},
            "findings": [f.model_dump() for f in context.findings],
        }
        requests.post(self.webhook_url, json=payload, timeout=15)