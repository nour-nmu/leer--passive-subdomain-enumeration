"""
certspotter.py
---------------
Passive subdomain discovery via SSLMate's CertSpotter public API, another
Certificate Transparency log aggregator. The unauthenticated endpoint is
rate-limited but requires no API key for light/basic use.
"""

from typing import Set

import requests

from .base import PassiveProvider
from config import USER_AGENT

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


class CertSpotterProvider(PassiveProvider):
    name = "certspotter"

    def discover(self, domain: str, timeout: int) -> Set[str]:
        found: Set[str] = set()
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        headers = {"User-Agent": USER_AGENT}

        try:
            resp = requests.get(
                CERTSPOTTER_URL, params=params, headers=headers, timeout=timeout
            )
        except requests.exceptions.RequestException:
            return found

        # CertSpotter returns 429 when the (generous) unauthenticated
        # rate limit is hit -- treat this as "no results this run"
        # rather than an error that kills the whole scan.
        if resp.status_code != 200:
            return found

        try:
            data = resp.json()
        except ValueError:
            return found

        if not isinstance(data, list):
            return found

        for entry in data:
            for dns_name in entry.get("dns_names", []) or []:
                if isinstance(dns_name, str):
                    found.add(dns_name.strip().lower())

        return found
