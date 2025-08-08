from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re
import httpx
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from agent.state import ScanContext, Finding
from agent.utils.logging import get_logger

logger = get_logger("agent.probers.xss_advanced")

TOKEN = "__axss__"
CHARSET = list("<>'\"/\\(){}[]=;:,.$-+!@#%*`~|&?")

# Context regexes to infer where the reflection lands
RE_SCRIPT = re.compile(r"<script[^>]*>[^<]{0,400}%s[^<]{0,400}</script>", re.I | re.S)
RE_ATTR_DQ = re.compile(r"\w+\s*=\s*\"[^\"]{0,200}%s[^\"]{0,200}\"", re.I)
RE_ATTR_SQ = re.compile(r"\w+\s*=\s*'[^']{0,200}%s[^']{0,200}'", re.I)
RE_HTML = re.compile(r">[^<]{0,400}%s[^<]{0,400}<", re.I | re.S)


class ReflectionResult:
    def __init__(self, reflected: bool, html_unescaped: bool, context: str):
        self.reflected = reflected
        self.html_unescaped = html_unescaped
        self.context = context  # html|attr|script|unknown


def profile_char_filters(client: httpx.Client, base_url: str, param_name: str, params: Dict[str, str]) -> Dict[str, str]:
    """Return mapping char -> status ('pass' if appears raw, 'encoded' if HTML entity, 'missing' if stripped)."""
    test_value = TOKEN + "".join(CHARSET)
    inj = params.copy()
    inj[param_name] = test_value
    urlp = urlparse(base_url)
    test_qs = urlencode(inj, doseq=True)
    test_url = urlunparse((urlp.scheme, urlp.netloc, urlp.path, urlp.params, test_qs, urlp.fragment))
    try:
        r = client.get(test_url)
        body = r.text or ""
        ct = r.headers.get("Content-Type", "")
        if r.status_code >= 500 or "text/html" not in ct:
            return {}
    except Exception:
        return {}
    statuses: Dict[str, str] = {}
    # find reflection window
    idx = body.find(TOKEN)
    if idx == -1:
        return {}
    window = body[max(0, idx - 500): idx + 500]
    # Evaluate each char occurrence after token
    after = window.split(TOKEN, 1)[-1]
    for ch in CHARSET:
        if after.startswith(ch):
            statuses[ch] = "pass"
        else:
            # look for typical HTML encodings
            encs = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;", "&": "&amp;"}
            if ch in encs and encs[ch] in after[:20]:
                statuses[ch] = "encoded"
            else:
                statuses[ch] = "missing"
    return statuses


def detect_reflection_context(body: str) -> str:
    if RE_SCRIPT.search(body.replace("\n", " ") % TOKEN if "%s" in RE_SCRIPT.pattern else body):
        return "script"
    if RE_ATTR_DQ.search(body) or RE_ATTR_SQ.search(body):
        return "attr"
    if RE_HTML.search(body):
        return "html"
    return "unknown"


def analyze_reflection(body: str) -> ReflectionResult:
    reflected = TOKEN in body
    if not reflected:
        return ReflectionResult(False, False, "none")
    html_unescaped = "&lt;" not in body and "&gt;" not in body
    context = "unknown"
    snippet = body
    try:
        idx = body.find(TOKEN)
        snippet = body[max(0, idx - 300): idx + 300]
        context = detect_reflection_context(snippet)
    except Exception:
        context = "unknown"
    return ReflectionResult(True, html_unescaped, context)


def build_payloads(allowed: Dict[str, str], context: str) -> List[str]:
    a = lambda ch: allowed.get(ch, "missing") == "pass"  # noqa: E731
    p: List[str] = []
    # HTML context payloads
    if context in {"html", "unknown"} and a("<") and a(">"):
        p += [
            f"{TOKEN}<svg/onload=confirm(1)>",
            f"{TOKEN}<img src=x onerror=confirm(1)>",
        ]
    # Attribute context payloads
    if context in {"attr", "unknown"}:
        if a('"') and a(" ") and a("="):
            p += [f"{TOKEN}\" autofocus onfocus=confirm(1) x=\""]
        if a("'") and a(" ") and a("="):
            p += [f"{TOKEN}' autofocus onfocus=confirm(1) x='"]
    # Script context payloads
    if context in {"script", "unknown"}:
        if a("'") and a(";"):
            p += [f"{TOKEN}';confirm(1);//"]
        if a('"') and a(";"):
            p += [f'{TOKEN}";confirm(1);//']
    # Fallback simple reflection probes
    p.append(f"{TOKEN}")
    return p


def verify_payload_reflection(resp: httpx.Response, payload: str) -> bool:
    body = resp.text or ""
    if payload not in body:
        return False
    # filter obvious sanitization
    if "&lt;" in body and "<" in payload:
        return False
    return True


def test_param_for_xss(client: httpx.Client, base_url: str, param_name: str, params: Dict[str, str]) -> Optional[Finding]:
    urlp = urlparse(base_url)
    # 1) Profile chars
    char_status = profile_char_filters(client, base_url, param_name, params)
    # 2) Baseline reflection
    inj = params.copy()
    inj[param_name] = TOKEN
    test_qs = urlencode(inj, doseq=True)
    test_url = urlunparse((urlp.scheme, urlp.netloc, urlp.path, urlp.params, test_qs, urlp.fragment))
    try:
        r = client.get(test_url)
    except Exception:
        return None
    if r.status_code >= 500 or "text/html" not in r.headers.get("Content-Type", ""):
        return None
    rr = analyze_reflection(r.text or "")
    if not rr.reflected:
        return None
    # 3) Payload attempts based on context and char capabilities
    payloads = build_payloads(char_status, rr.context)
    for payload in payloads:
        inj = params.copy()
        inj[param_name] = payload
        test_qs = urlencode(inj, doseq=True)
        xss_url = urlunparse((urlp.scheme, urlp.netloc, urlp.path, urlp.params, test_qs, urlp.fragment))
        try:
            resp = client.get(xss_url)
        except Exception:
            continue
        if resp.status_code >= 500 or "text/html" not in resp.headers.get("Content-Type", ""):
            continue
        body = resp.text or ""
        if not verify_payload_reflection(resp, payload):
            continue
        # Heuristics to reduce false positives: ensure tag appears unescaped when applicable
        if ("<svg" in payload or "<img" in payload) and "<svg" not in body and "<img" not in body:
            continue
        # Passed checks -> likely exploitable reflected XSS
        return Finding(
            id=f"xss_adv:{xss_url}",
            title="Reflected XSS (context-aware)",
            severity="high",
            type="xss.reflected.advanced",
            url=xss_url,
            parameter=param_name,
            payload=payload,
            evidence="Payload reflected unescaped in HTML",
            cvss=6.1,
        )
    return None


def run_advanced_xss(context: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    targets: List[str] = []
    for domain in context.domains:
        targets.extend([u for u in context.urls.get(domain, []) if u.startswith("http")])
        targets.append(f"https://{domain}")
    headers = {"User-Agent": "AgentSecurityMVP/1.0", "Accept": "text/html,application/xhtml+xml"}
    with httpx.Client(follow_redirects=False, timeout=20.0, headers=headers) as client:
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
            for pname in list(params.keys()):
                f = test_param_for_xss(client, url, pname, params)
                if f:
                    findings.append(f)
    return findings