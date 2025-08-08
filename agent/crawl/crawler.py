from __future__ import annotations
from typing import Dict, List, Set
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from agent.utils.logging import get_logger


logger = get_logger("agent.crawl")


async def fetch(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status != 200:
                return ""
            return await resp.text(errors="ignore")
    except Exception:
        return ""


def same_domain(url: str, domain: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host.endswith(domain)
    except Exception:
        return False


def extract_links(html: str, base: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls: Set[str] = set()
    for a in soup.find_all("a", href=True):
        urls.add(urljoin(base, a["href"]))
    for s in soup.find_all("script", src=True):
        urls.add(urljoin(base, s["src"]))
    for f in soup.find_all("form", action=True):
        urls.add(urljoin(base, f["action"]))
    return list(urls)


async def crawl_domain(domain: str) -> List[str]:
    seeds = [f"https://{domain}", f"http://{domain}"]
    visited: Set[str] = set()
    out: Set[str] = set()
    headers = {"User-Agent": "AgentSecurityMVP/1.0"}
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [fetch(session, u) for u in seeds]
        pages = await asyncio.gather(*tasks)
        for url, html in zip(seeds, pages):
            if not html:
                continue
            links = extract_links(html, url)
            for l in links:
                if same_domain(l, domain):
                    out.add(l)
        # Shallow crawl a few internal links
        internal = [u for u in list(out) if same_domain(u, domain)][:30]
        subpages = await asyncio.gather(*[fetch(session, u) for u in internal])
        for url, html in zip(internal, subpages):
            if not html:
                continue
            links = extract_links(html, url)
            for l in links:
                if same_domain(l, domain):
                    out.add(l)
    return sorted(out)


def crawl_domains(domains: List[str]) -> Dict[str, List[str]]:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(asyncio.gather(*[crawl_domain(d) for d in domains]))
    return {d: r for d, r in zip(domains, results)}