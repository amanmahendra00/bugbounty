from __future__ import annotations
from typing import Dict, List, Set
import requests
from agent.utils.logging import get_logger


logger = get_logger("agent.urls.wayback")


def fetch_wayback_urls(domain: str, limit: int = 2000) -> List[str]:
    # Collapse by urlkey to dedupe similar URLs
    api = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
    }
    try:
        resp = requests.get(api, params=params, timeout=45)
        if resp.status_code != 200:
            logger.warning("wayback non-200 for %s: %s", domain, resp.status_code)
            return []
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("wayback error for %s: %s", domain, exc)
        return []
    # First row is header
    urls: Set[str] = set()
    for row in data[1:limit+1]:
        if not row:
            continue
        url = row[0]
        if url.startswith("http://") or url.startswith("https://"):
            urls.add(url)
    return sorted(urls)


def fetch_wayback_urls_for_domains(domains: List[str]) -> Dict[str, List[str]]:
    return {d: fetch_wayback_urls(d) for d in domains}