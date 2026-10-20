"""
engine.py
---------
Public entry point for technology detection. Combines header-based and
HTML-based detectors, then de-duplicates results (keeping the
highest-confidence evidence when the same technology is detected more
than once by different signals).
"""

from typing import List, Optional

from models import HTTPResult, TechDetection
from .headers import detect_from_headers
from .html import detect_from_html

_CONFIDENCE_RANK = {"Low": 0, "Medium": 1, "High": 2}


def detect_technologies(http_result: Optional[HTTPResult]) -> List[TechDetection]:
    """
    Run all fingerprinting detectors against a single HTTPResult and
    return a de-duplicated list of TechDetection objects.
    """
    if http_result is None or not http_result.reachable:
        return []

    detections: List[TechDetection] = []
    detections.extend(detect_from_headers(http_result.headers))
    detections.extend(detect_from_html(http_result.body_snippet))

    return _deduplicate(detections)


def _deduplicate(detections: List[TechDetection]) -> List[TechDetection]:
    best_by_name = {}
    for det in detections:
        key = det.name
        existing = best_by_name.get(key)
        if existing is None:
            best_by_name[key] = det
            continue

        # Prefer the entry with higher confidence; if tied, prefer the
        # one that has a version identified.
        existing_rank = _CONFIDENCE_RANK.get(existing.confidence, 0)
        new_rank = _CONFIDENCE_RANK.get(det.confidence, 0)
        if new_rank > existing_rank or (
            new_rank == existing_rank and det.version and not existing.version
        ):
            best_by_name[key] = det

    return list(best_by_name.values())
