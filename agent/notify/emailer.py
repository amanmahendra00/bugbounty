from __future__ import annotations
import yagmail
from agent.config import NotificationSettings
from agent.state import Finding, ScanContext


class EmailNotifier:
    def __init__(self, settings: NotificationSettings) -> None:
        self.settings = settings
        self.client = yagmail.SMTP(settings.email_user, settings.email_pass, host=settings.email_host, port=settings.email_port)

    def notify_finding(self, finding: Finding) -> None:
        subject = f"[Agent] {finding.severity.upper()} {finding.title}"
        body = f"{finding.url}\n{finding.type} | param={finding.parameter or '-'}\n{finding.evidence or ''}"
        self.client.send(self.settings.email_to, subject, body)

    def notify_summary(self, context: ScanContext) -> None:
        subject = "[Agent] Scan Summary"
        body = (
            f"Domains: {', '.join(context.domains)}\n"
            f"Assets: {sum(len(v) for v in context.assets.values())}\n"
            f"URLs: {sum(len(v) for v in context.urls.values())}\n"
            f"Findings: {len(context.findings)}\n"
        )
        self.client.send(self.settings.email_to, subject, body)