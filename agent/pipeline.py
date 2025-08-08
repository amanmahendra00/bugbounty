from __future__ import annotations
from typing import Callable, Dict
from agent.config import Settings
from agent.state import ScanContext
from agent.utils.logging import get_logger
import yaml


logger = get_logger("agent.pipeline")


class PipelineRunner:
    def __init__(self, settings: Settings, context: ScanContext) -> None:
        self.settings = settings
        self.context = context
        self.step_map: Dict[str, Callable[[], None]] = {
            "subdomain_enum": self.step_subdomain_enum,
            "historical_urls": self.step_historical_urls,
            "crawl": self.step_crawl,
            "probe_basic": self.step_probe_basic,
            "report": self.step_report,
            "notify": self.step_notify,
        }

    def load_and_run(self) -> None:
        with open(self.settings.pipeline_path, "r", encoding="utf-8") as f:
            steps = yaml.safe_load(f) or []
        for step in steps:
            func = self.step_map.get(step)
            if not func:
                logger.warning("Unknown step '%s' - skipping", step)
                continue
            logger.info("Running step: %s", step)
            try:
                func()
            except Exception as exc:  # noqa: BLE001 - we want resilience in pipeline
                logger.exception("Step '%s' failed: %s", step, exc)

    def step_subdomain_enum(self) -> None:
        from agent.recon.crtsh import enumerate_subdomains_for_domains

        results = enumerate_subdomains_for_domains(self.context.domains)
        for domain, subs in results.items():
            for sub in subs:
                self.context.add_asset(domain, sub)

    def step_historical_urls(self) -> None:
        from agent.urls.wayback import fetch_wayback_urls_for_domains

        results = fetch_wayback_urls_for_domains(self.context.domains)
        for domain, urls in results.items():
            for url in urls:
                self.context.add_url(domain, url)

    def step_crawl(self) -> None:
        from agent.crawl.crawler import crawl_domains

        results = crawl_domains(self.context.domains)
        for domain, urls in results.items():
            for url in urls:
                self.context.add_url(domain, url)

    def step_probe_basic(self) -> None:
        from agent.probers.basic import run_basic_probes

        findings = run_basic_probes(self.context)
        for f in findings:
            self.context.add_finding(f)
            self._notify_finding(f)

    def _notify_finding(self, finding) -> None:
        from agent.notify.dispatch import Notifier

        notifier = Notifier(self.settings.notification)
        notifier.notify_finding(finding)

    def step_report(self) -> None:
        from agent.reporting.report import generate_reports

        generate_reports(self.context)

    def step_notify(self) -> None:
        from agent.notify.dispatch import Notifier

        notifier = Notifier(self.settings.notification)
        notifier.notify_summary(self.context)