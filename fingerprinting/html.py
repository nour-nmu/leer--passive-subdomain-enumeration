"""
html.py
-------
Matches the (bounded) HTML response body against the signature database
in fingerprints.py to detect CMS platforms, JS frameworks, analytics
tools, etc.
"""

import re
from typing import List

from models import TechDetection
from .fingerprints import HTML_SIGNATURES


def detect_from_html(body_text: str) -> List[TechDetection]:
    detections: List[TechDetection] = []
    if not body_text:
        return detections

    for sig in HTML_SIGNATURES:
        match = re.search(sig["pattern"], body_text, re.IGNORECASE)
        if match:
            version = None
            if match.groups():
                version = match.group(1) or None
            detections.append(
                TechDetection(
                    name=sig["name"],
                    category=sig["category"],
                    version=version,
                    confidence=sig["confidence"],
                    evidence="HTML body signature",
                )
            )

    return detections
