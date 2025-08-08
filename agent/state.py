from __future__ import annotations
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class Finding(BaseModel):
    id: str
    title: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    type: str
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    cvss: Optional[float] = None
    authenticated: bool = False
    detected_at: datetime = Field(default_factory=datetime.utcnow)


class ScanContext(BaseModel):
    domains: List[str]
    output_dir: str
    assets: Dict[str, List[str]] = Field(default_factory=dict)  # domain -> subdomains
    urls: Dict[str, List[str]] = Field(default_factory=dict)    # domain -> urls
    findings: List[Finding] = Field(default_factory=list)

    def add_asset(self, domain: str, subdomain: str) -> None:
        self.assets.setdefault(domain, [])
        if subdomain not in self.assets[domain]:
            self.assets[domain].append(subdomain)

    def add_url(self, domain: str, url: str) -> None:
        self.urls.setdefault(domain, [])
        if url not in self.urls[domain]:
            self.urls[domain].append(url)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)