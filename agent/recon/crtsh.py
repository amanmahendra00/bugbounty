from __future__ import annotations
from typing import Dict, List, Set
import requests
import time
from agent.utils.logging import get_logger


logger = get_logger("agent.recon.crtsh")


def enumerate_subdomains(domain: str) -> List[str]:
    query = f"%.{domain}"
    url = "https://crt.sh/"  # rate-limit friendly with pauses
    params = {"q": query, "output": "json"}
    try:
        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code != 200:
            logger.warning("crt.sh non-200 for %s: %s", domain, resp.status_code)
            return []
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("crt.sh error for %s: %s", domain, exc)
        return []

    subdomains: Set[str] = set()
    for item in data:
        name_value = item.get("name_value", "")
        for line in name_value.split("\n"):
            v = line.strip().lower().strip(".")
            if not v or "*" in v:
                continue
            if v.endswith(domain):
                subdomains.add(v)
    return sorted(subdomains)


def enumerate_subdomains_for_domains(domains: List[str]) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    for d in domains:
        results[d] = enumerate_subdomains(d)
        time.sleep(1.2)  # be gentle
    return results