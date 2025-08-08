from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel
import os


class NotificationSettings(BaseModel):
    channels: List[str] = []  # e.g., ["slack", "email", "webhook", "telegram"]
    slack_webhook_url: Optional[str] = None
    webhook_url: Optional[str] = None
    email_user: Optional[str] = None
    email_pass: Optional[str] = None
    email_host: Optional[str] = None
    email_port: int = 587
    email_to: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None


class Settings(BaseModel):
    domains: List[str]
    output_dir: str = "out"
    pipeline_path: str = "examples/pipelines/basic.yaml"
    credentials_path: Optional[str] = None
    notification: NotificationSettings = NotificationSettings()

    @staticmethod
    def from_env_and_args(args: Optional[List[str]] = None) -> "Settings":
        import argparse
        from dotenv import load_dotenv

        load_dotenv()
        parser = argparse.ArgumentParser(description="Advanced AI Security Agent (MVP)")
        parser.add_argument("--domains", required=True, help="Comma-separated domain list")
        parser.add_argument("--pipeline", dest="pipeline_path", default=os.getenv("PIPELINE", "examples/pipelines/basic.yaml"))
        parser.add_argument("--out", dest="output_dir", default=os.getenv("OUTPUT_DIR", "out"))
        parser.add_argument("--credentials", dest="credentials_path", default=os.getenv("CREDENTIALS"))
        parser.add_argument("--notify", dest="notify", default=os.getenv("NOTIFY", ""), help="Comma-separated: slack,email,webhook,telegram")
        parser.add_argument("--slack-webhook", dest="slack_webhook", default=os.getenv("SLACK_WEBHOOK_URL"))
        parser.add_argument("--webhook-url", dest="webhook_url", default=os.getenv("WEBHOOK_URL"))
        parser.add_argument("--email-to", dest="email_to", default=os.getenv("EMAIL_TO"))
        parser.add_argument("--smtp-user", dest="smtp_user", default=os.getenv("SMTP_USER"))
        parser.add_argument("--smtp-pass", dest="smtp_pass", default=os.getenv("SMTP_PASS"))
        parser.add_argument("--smtp-host", dest="smtp_host", default=os.getenv("SMTP_HOST"))
        parser.add_argument("--smtp-port", dest="smtp_port", type=int, default=int(os.getenv("SMTP_PORT", "587")))
        parser.add_argument("--telegram-bot-token", dest="telegram_bot_token", default=os.getenv("TELEGRAM_BOT_TOKEN"))
        parser.add_argument("--telegram-chat-id", dest="telegram_chat_id", default=os.getenv("TELEGRAM_CHAT_ID"))

        ns = parser.parse_args(args=args)
        domains = [d.strip() for d in ns.domains.split(",") if d.strip()]
        channels = [c.strip() for c in ns.notify.split(",") if c.strip()]

        notification = NotificationSettings(
            channels=channels,
            slack_webhook_url=ns.slack_webhook,
            webhook_url=ns.webhook_url,
            email_user=ns.smtp_user,
            email_pass=ns.smtp_pass,
            email_host=ns.smtp_host,
            email_port=ns.smtp_port,
            email_to=ns.email_to,
            telegram_bot_token=ns.telegram_bot_token,
            telegram_chat_id=ns.telegram_chat_id,
        )

        return Settings(
            domains=domains,
            output_dir=ns.output_dir,
            pipeline_path=ns.pipeline_path,
            credentials_path=ns.credentials_path,
            notification=notification,
        )