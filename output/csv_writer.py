"""
csv_writer.py
-------------
Writes a simplified, flat CSV table of scan results.
"""

import csv
import os
from typing import List

from models import SubdomainResult

CSV_COLUMNS = [
    "subdomain",
    "dns_status",
    "live",
    "http_status",
    "https_status",
    "final_url",
    "server",
    "technologies",
    "response_time",
]


def write_csv(
    results: List[SubdomainResult],
    output_path: str,
    force: bool = False,
) -> None:
    if os.path.exists(output_path) and not force:
        raise FileExistsError(
            f"'{output_path}' already exists. Use --force to overwrite."
        )

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for r in results:
            d = r.to_dict()
            writer.writerow(
                {
                    "subdomain": d["subdomain"],
                    "dns_status": d["dns_status"],
                    "live": d["live"],
                    "http_status": d["http_status"] or "",
                    "https_status": d["https_status"] or "",
                    "final_url": d["final_url"] or "",
                    "server": d["server"] or "",
                    "technologies": "; ".join(t["name"] for t in d["technologies"]),
                    "response_time": d["response_time"] or "",
                }
            )
