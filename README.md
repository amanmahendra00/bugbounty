# Advanced AI Security Agent (MVP)

Autonomous(ish) AI security agent to enumerate assets, collect historical URLs, run basic vuln probes (MVP), and send realtime notifications. Extensible via YAML pipelines.

## Features (MVP)
- Recon: crt.sh passive subdomain enum
- Historical URLs: Wayback (waybackurls-like)
- Smart crawling (shallow) and parameter mining (regex)
- Basic vuln probes: reflected XSS (heuristic), open redirect (heuristic)
- Notifications: Slack webhook, Email (SMTP), generic webhook
- Reporting: JSON, Markdown, HTML (Jinja2)
- Pipelines: YAML-defined ordered steps

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure

Create `.env` if needed:
```
SLACK_WEBHOOK_URL=
SMTP_USER=
SMTP_PASS=
SMTP_HOST=
SMTP_PORT=587
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Optional API keys env vars:
```
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
SECURITYTRAILS_API_KEY=
GITHUB_TOKEN=
```

## Usage

```bash
python -m agent.cli --domains example.com --pipeline examples/pipelines/basic.yaml --out out --notify slack,email
```

Multiple domains and credentials:
```bash
python -m agent.cli \
  --domains example.com,example.org \
  --credentials creds/example.har \
  --notify slack \
  --out out
```

## Pipelines

Example YAML:
```yaml
- subdomain_enum
- historical_urls
- crawl
- probe_basic
- report
- notify
```

## Legal
Run only against assets you own or have explicit permission to test.
