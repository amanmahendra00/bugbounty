from __future__ import annotations
from typing import List, Dict
import httpx
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from agent.state import ScanContext, Finding
from agent.utils.logging import get_logger


logger = get_logger("agent.probers.basic")


SUSPICIOUS_REDIRECT_PARAMS = {"next", "url", "return", "return_url", "redirect", "continue", "dest"}
XSS_TEST_VALUE = "__agent_xss_probe__"


def run_basic_probes(context: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    targets: List[str] = []
    for domain in context.domains:
        targets.extend([u for u in context.urls.get(domain, []) if u.startswith("http")])
        # Also include top-level hosts
        targets.append(f"https://{domain}")

    with httpx.Client(follow_redirects=False, timeout=15.0, headers={"User-Agent": "AgentSecurityMVP/1.0"}) as client:
        # Deduplicate
        seen: set[str] = set()
        for url in targets:
            if url in seen:
                continue
            seen.add(url)
            try:
                urlp = urlparse(url)
            except Exception:
                continue
            params = dict(parse_qsl(urlp.query, keep_blank_values=True))
            if not params:
                continue

            # Reflected XSS heuristic: inject token and see if reflected in body
            injected = params.copy()
            # Choose a parameter to test
            some_param = next(iter(injected))
            injected[some_param] = XSS_TEST_VALUE
            test_qs = urlencode(injected, doseq=True)
            test_url = urlunparse((urlp.scheme, urlp.netloc, urlp.path, urlp.params, test_qs, urlp.fragment))
            try:
                resp = client.get(test_url)
            except Exception:
                resp = None
            if resp and resp.status_code < 500 and XSS_TEST_VALUE in (resp.text or ""):
                finding = Finding(
                    id=f"xss:{test_url}",
                    title="Possible reflected XSS",
                    severity="medium",
                    type="xss.reflected",
                    url=test_url,
                    parameter=some_param,
                    payload=XSS_TEST_VALUE,
                    evidence="Token reflected in response body",
                )
                findings.append(finding)

            # Open redirect heuristic
            for param_name in list(params.keys()):
                if param_name.lower() not in SUSPICIOUS_REDIRECT_PARAMS:
                    continue
                inj = params.copy()
                inj[param_name] = "https://example.org"
                test_qs = urlencode(inj, doseq=True)
                test_url = urlunparse((urlp.scheme, urlp.netloc, urlp.path, urlp.params, test_qs, urlp.fragment))
                try:
                    r = client.get(test_url)
                except Exception:
                    r = None
                location = r.headers.get("Location") if r else None
                if r and r.status_code in {301, 302, 303, 307, 308} and location and location.startswith("http"):
                    dest_host = urlparse(location).hostname or ""
                    if dest_host and not dest_host.endswith(urlp.hostname or ""):
                        finding = Finding(
                            id=f"open_redirect:{test_url}",
                            title="Possible open redirect",
                            severity="medium",
                            type="redirect.open",
                            url=test_url,
                            parameter=param_name,
                            payload=inj[param_name],
                            evidence=f"Redirects to {location}",
                        )
                        findings.append(finding)
    return findings