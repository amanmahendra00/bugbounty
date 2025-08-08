from __future__ import annotations
import os
from typing import Any
from jinja2 import Environment, FileSystemLoader, select_autoescape
from agent.state import ScanContext

try:
    import orjson as _json
except Exception:  # noqa: BLE001
    import json as _json  # type: ignore


def _dumps(obj: Any) -> str:
    try:
        return _json.dumps(obj).decode()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return _json.dumps(obj, indent=2)  # type: ignore[attr-defined]


def generate_reports(context: ScanContext) -> None:
    os.makedirs(context.output_dir, exist_ok=True)
    # JSON
    with open(os.path.join(context.output_dir, "report.json"), "w", encoding="utf-8") as f:
        f.write(_dumps({
            "domains": context.domains,
            "assets": context.assets,
            "urls": context.urls,
            "findings": [fi.model_dump() for fi in context.findings],
        }))
    # Markdown
    md = ["# Scan Report", ""]
    md.append(f"Domains: {', '.join(context.domains)}\n")
    md.append(f"Findings: {len(context.findings)}\n")
    for fi in context.findings:
        md.append(f"- {fi.severity.upper()} {fi.title} — {fi.url}")
    with open(os.path.join(context.output_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    # HTML
    env = Environment(
        loader=FileSystemLoader(searchpath=os.path.join(os.path.dirname(__file__), "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tpl = env.get_template("report.html.j2")
    html = tpl.render(context=context)
    with open(os.path.join(context.output_dir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)