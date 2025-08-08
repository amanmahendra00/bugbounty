from __future__ import annotations
import requests
from agent.state import Finding, ScanContext


class SlackNotifier:
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def notify_finding(self, finding: Finding) -> None:
        text = f":rotating_light: {finding.severity.upper()} {finding.title}\n{finding.url}\n{finding.type} | param={finding.parameter or '-'}"
        requests.post(self.webhook_url, json={"text": text}, timeout=10)

    def notify_summary(self, context: ScanContext) -> None:
        text = (
            f"Scan complete: {len(context.domains)} domains\n"
            f"Assets: {sum(len(v) for v in context.assets.values())}, URLs: {sum(len(v) for v in context.urls.values())}, Findings: {len(context.findings)}"
        )
        requests.post(self.webhook_url, json={"text": text}, timeout=10)