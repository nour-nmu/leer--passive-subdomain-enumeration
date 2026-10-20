"""
terminal.py
-----------
Renders a clean, readable summary of scan results to the terminal.
"""

from typing import List

from models import SubdomainResult

_STATUS_COLORS = {
    "LIVE": "\033[92m",       # green
    "DNS_ONLY": "\033[93m",   # yellow
    "NOT_LIVE": "\033[90m",   # grey
    "ERROR": "\033[91m",      # red
}
_RESET = "\033[0m"
_PURPLE = "\033[95m"
_ITALIC = "\033[3m"

# Block-letter "LEER" banner, rendered in purple italic to match the
# tool's terminal identity. Kept as a plain string (no runtime
# font-rendering dependency) so the tool has no extra install
# requirement for this.
_BANNER = r"""
 _     _____ _____ ____
| |   | ____| ____|  _ \
| |   |  _| |  _| | |_) |
| |___| |___| |___|  _ <
|_____|_____|_____|_| \_\
"""


def render_banner(use_color: bool = True) -> str:
    """
    Return the LEER banner as a string (used both by the normal scan
    output and by the -h/--help screen), without printing it directly.
    """
    if use_color:
        return f"{_PURPLE}{_ITALIC}{_BANNER}{_RESET}    Passive Subdomain Reconnaissance Toolkit\n"
    return f"{_BANNER}    Passive Subdomain Reconnaissance Toolkit\n"


def print_banner(domain: str, use_color: bool = True) -> None:
    print(render_banner(use_color=use_color))
    print("=" * 60)
    print(f"Target: {domain}")
    print("=" * 60)
    print()


def print_summary_counts(
    passive_count: int, unique_count: int, dns_resolved: int, http_live: int
) -> None:
    print(f"[+] Passive subdomains discovered: {passive_count}")
    print(f"[+] Unique subdomains: {unique_count}")
    print(f"[+] DNS resolved: {dns_resolved}")
    print(f"[+] HTTP/HTTPS reachable: {http_live}")
    print()


def print_results_table(results: List[SubdomainResult], use_color: bool = True) -> None:
    header = f"{'SUBDOMAIN':<28}{'STATUS':<13}{'CODE':<8}{'TECHNOLOGIES'}"
    print(header)
    print("-" * 75)

    # Sort: LIVE first, then DNS_ONLY, then NOT_LIVE, then ERROR; alphabetical within group.
    order = {"LIVE": 0, "DNS_ONLY": 1, "NOT_LIVE": 2, "ERROR": 3}
    sorted_results = sorted(results, key=lambda r: (order.get(r.status, 99), r.subdomain))

    for r in sorted_results:
        best = r.best_http_result()
        code = str(best.status_code) if best and best.status_code else "-"
        techs = ", ".join(t.name for t in r.technologies) if r.technologies else "-"
        print(f"{r.subdomain:<28}{r.status:<13}{code:<8}{techs}")

    print()


def print_provider_errors(provider_errors: dict) -> None:
    if not provider_errors:
        return
    print("[!] Passive source issues:")
    for name, err in provider_errors.items():
        print(f"    - {name}: {err}")
    print()
