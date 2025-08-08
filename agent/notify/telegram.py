from __future__ import annotations
import requests
from agent.state import Finding, ScanContext


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str) -> None:
        self.api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self.chat_id = chat_id

    def notify_finding(self, finding: Finding) -> None:
        text = f"[Finding] {finding.severity.upper()} {finding.title}\n{finding.url}"
        requests.post(self.api, json={"chat_id": self.chat_id, "text": text}, timeout=10)

    def notify_summary(self, context: ScanContext) -> None:
        text = f"Scan done for {len(context.domains)} domains. Findings: {len(context.findings)}"
        requests.post(self.api, json={"chat_id": self.chat_id, "text": text}, timeout=10)