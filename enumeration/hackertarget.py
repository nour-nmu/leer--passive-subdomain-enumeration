"""
hackertarget.py
----------------
Passive subdomain discovery via the HackerTarget "hostsearch" API, which
is backed by their own aggregated passive DNS / historical scan
dataset. No API key is required for the free tier, but it is fairly
strictly rate-limited -- failures/rate-limit responses are treated as
"no additional results" rather than fatal errors.
"""

from typing import Set

import requests

from .base import PassiveProvider
from config import USER_AGENT

HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"


class HackerTargetProvider(PassiveProvider):
    name = "hackertarget"

    def discover(self, domain: str, timeout: int) -> Set[str]:
        found: Set[str] = set()
        params = {"q": domain}
        headers = {"User-Agent": USER_AGENT}

        try:
            resp = requests.get(
                HACKERTARGET_URL, params=params, headers=headers, timeout=timeout
            )
        except requests.exceptions.RequestException:
            return found

        if resp.status_code != 200:
            return found

        text = resp.text.strip()

        # HackerTarget signals errors/rate limits as plain text bodies
        # like "error check your search parameter" or an API count
        # limit message -- not JSON, and not a list of hosts.
        if not text or "error" in text.lower() or "API count exceeded" in text:
            return found

        for line in text.splitlines():
            if "," not in line:
                continue
            host = line.split(",")[0].strip().lower()
            if host:
                found.add(host)

        return found
