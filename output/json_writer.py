"""
json_writer.py
--------------
Writes the complete structured scan results to a JSON file.
"""

import json
import os
from datetime import datetime, timezone
from typing import List

from models import SubdomainResult


def write_json(
    results: List[SubdomainResult],
    domain: str,
    output_path: str,
    force: bool = False,
) -> None:
    if os.path.exists(output_path) and not force:
        raise FileExistsError(
            f"'{output_path}' already exists. Use --force to overwrite."
        )

    payload = {
        "target": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_subdomains": len(results),
        "results": [r.to_dict() for r in results],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
