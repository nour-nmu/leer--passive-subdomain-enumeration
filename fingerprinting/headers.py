"""
headers.py
----------
Matches HTTP response headers (and Set-Cookie contents) against the
signature database in fingerprints.py.
"""

import re
from typing import Dict, List

from models import TechDetection
from .fingerprints import HEADER_SIGNATURES, COOKIE_SIGNATURES


def detect_from_headers(headers: Dict[str, str]) -> List[TechDetection]:
    detections: List[TechDetection] = []
    if not headers:
        return detections

    # Normalize header keys to lowercase for lookups.
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header_name, signatures in HEADER_SIGNATURES.items():
        value = lower_headers.get(header_name)
        if not value:
            continue
        for sig in signatures:
            match = re.search(sig["pattern"], value, re.IGNORECASE)
            if match:
                version = None
                if match.groups():
                    version = match.group(1)
                detections.append(
                    TechDetection(
                        name=sig["name"],
                        category=sig["category"],
                        version=version,
                        confidence=sig["confidence"],
                        evidence=f"'{header_name.title()}' header",
                    )
                )

    # Set-Cookie can contain multiple cookies; requests may fold them
    # into one comma/semicolon separated string depending on the
    # underlying HTTP library, so just search the raw text.
    set_cookie = lower_headers.get("set-cookie", "")
    if set_cookie:
        for sig in COOKIE_SIGNATURES:
            if re.search(sig["pattern"], set_cookie, re.IGNORECASE):
                detections.append(
                    TechDetection(
                        name=sig["name"],
                        category=sig["category"],
                        version=None,
                        confidence=sig["confidence"],
                        evidence="Set-Cookie header",
                    )
                )

    return detections
