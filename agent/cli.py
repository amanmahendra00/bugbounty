from __future__ import annotations
import os
from agent.config import Settings
from agent.state import ScanContext
from agent.pipeline import PipelineRunner
from agent.utils.logging import get_logger


logger = get_logger("agent.cli")


def main() -> None:
    settings = Settings.from_env_and_args()
    os.makedirs(settings.output_dir, exist_ok=True)
    context = ScanContext(domains=settings.domains, output_dir=settings.output_dir)
    runner = PipelineRunner(settings=settings, context=context)
    logger.info("Starting pipeline: %s", settings.pipeline_path)
    runner.load_and_run()
    logger.info("Pipeline finished. Findings: %d", len(context.findings))


if __name__ == "__main__":
    main()