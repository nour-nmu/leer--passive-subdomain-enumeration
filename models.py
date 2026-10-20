
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class TechDetection:
    name: str
    category: str
    version: Optional[str] = None
    confidence: str = "Low"     
    evidence: str = ""           

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class TLSInfo:
    tls_available: bool = False
    tls_success: bool = False
    subject_cn: Optional[str] = None
    issuer: Optional[str] = None
    not_after: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tls_available": self.tls_available,
            "tls_success": self.tls_success,
            "subject_cn": self.subject_cn,
            "issuer": self.issuer,
            "not_after": self.not_after,
            "error": self.error,
        }


@dataclass
class HTTPResult:
    scheme: str
    attempted: bool = False
    reachable: bool = False
    status_code: Optional[int] = None
    method: str = "GET"
    final_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    response_time_ms: Optional[float] = None
    content_type: Optional[str] = None
    page_title: Optional[str] = None
    server: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = "" 
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme": self.scheme,
            "attempted": self.attempted,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "method": self.method,
            "final_url": self.final_url,
            "redirect_chain": self.redirect_chain,
            "response_time_ms": self.response_time_ms,
            "content_type": self.content_type,
            "page_title": self.page_title,
            "server": self.server,
            "error": self.error,
        }


@dataclass
class SubdomainResult:
    subdomain: str
    discovery_sources: List[str] = field(default_factory=list)

    dns_status: str = "NOT_RESOLVED"  
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    dns_error: Optional[str] = None

    http_result: Optional[HTTPResult] = None
    https_result: Optional[HTTPResult] = None
    live: bool = False
    status: str = "NOT_LIVE"      
    final_url: Optional[str] = None

    tls_information: Optional[TLSInfo] = None

    technologies: List[TechDetection] = field(default_factory=list)

    error: Optional[str] = None

    def best_http_result(self) -> Optional[HTTPResult]:
        if self.https_result and self.https_result.reachable:
            return self.https_result
        if self.http_result and self.http_result.reachable:
            return self.http_result
        return self.https_result or self.http_result

    def to_dict(self) -> Dict[str, Any]:
        best = self.best_http_result()
        return {
            "subdomain": self.subdomain,
            "discovery_sources": self.discovery_sources,
            "dns_status": self.dns_status,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "cname": self.cname,
            "dns_error": self.dns_error,
            "http_status": self.http_result.status_code if self.http_result else None,
            "https_status": self.https_result.status_code if self.https_result else None,
            "live": self.live,
            "status": self.status,
            "final_url": self.final_url,
            "redirect_chain": best.redirect_chain if best else [],
            "response_time": best.response_time_ms if best else None,
            "content_type": best.content_type if best else None,
            "page_title": best.page_title if best else None,
            "server": best.server if best else None,
            "technologies": [t.to_dict() for t in self.technologies],
            "tls_information": self.tls_information.to_dict() if self.tls_information else None,
            "error": self.error,
        }
