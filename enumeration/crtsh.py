"""
crtsh.py
--------
Passive subdomain discovery via crt.sh, a free public search interface
over Certificate Transparency (CT) logs. No API key required.

crt.sh occasionally returns malformed/partial JSON or times out under
load, so parsing is defensive.
"""

import json
import re
from typing import Set

import requests

from .base import PassiveProvider
from config import USER_AGENT

CRTSH_URL = "https://crt.sh/"


class CrtShProvider(PassiveProvider):
    name = "crt.sh"

    def discover(self, domain: str, timeout: int) -> Set[str]:
        found: Set[str] = set()
        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": USER_AGENT}

        try:
            resp = requests.get(
                CRTSH_URL, params=params, headers=headers, timeout=timeout
            )
        except requests.exceptions.RequestException:
            # Network error, timeout, DNS failure reaching crt.sh, etc.
            return found

        if resp.status_code != 200 or not resp.text.strip():
            return found

        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            # crt.sh sometimes returns duplicate JSON objects concatenated
            # together instead of a valid array. Fall back to a regex
            # scan for name_value fields rather than giving up entirely.
            for match in re.findall(r'"name_value":"([^"]+)"', resp.text):
                found.update(self._split_names(match))
            return found

        if isinstance(data, list):
            for entry in data:
                name_value = entry.get("name_value", "")
                found.update(self._split_names(name_value))

        return found

    @staticmethod
    def _split_names(name_value: str) -> Set[str]:
        """crt.sh sometimes packs multiple SANs into one newline-separated field."""
        names = set()
        for raw in name_value.split("\n"):
            raw = raw.strip().lower()
            if raw:
                names.add(raw)
        return names
