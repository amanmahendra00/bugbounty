from __future__ import annotations
from typing import List
from agent.config import NotificationSettings
from agent.state import Finding, ScanContext
from agent.notify.slack import SlackNotifier
from agent.notify.webhook import WebhookNotifier
from agent.notify.emailer import EmailNotifier
from agent.notify.telegram import TelegramNotifier


class Notifier:
    def __init__(self, settings: NotificationSettings) -> None:
        self.settings = settings
        self.backends: List[object] = []
        for ch in settings.channels:
            if ch == "slack" and settings.slack_webhook_url:
                self.backends.append(SlackNotifier(settings.slack_webhook_url))
            elif ch == "email" and settings.email_user and settings.email_to and settings.email_host:
                self.backends.append(EmailNotifier(settings))
            elif ch == "webhook" and settings.webhook_url:
                self.backends.append(WebhookNotifier(settings.webhook_url))
            elif ch == "telegram" and settings.telegram_bot_token and settings.telegram_chat_id:
                self.backends.append(TelegramNotifier(settings.telegram_bot_token, settings.telegram_chat_id))

    def notify_finding(self, finding: Finding) -> None:
        for b in self.backends:
            try:
                b.notify_finding(finding)
            except Exception:
                pass

    def notify_summary(self, context: ScanContext) -> None:
        for b in self.backends:
            try:
                b.notify_summary(context)
            except Exception:
                pass