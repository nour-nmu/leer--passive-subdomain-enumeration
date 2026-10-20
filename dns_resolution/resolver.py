"""
resolver.py
-----------
Resolves A, AAAA, and CNAME records for a hostname using dnspython.

Classification:
    RESOLVED     - at least one A/AAAA/CNAME record was found
    NOT_RESOLVED - the name genuinely does not exist (NXDOMAIN / NoAnswer)
    ERROR        - something went wrong while asking (timeout, no
                   nameservers reachable, etc.) -- distinct from a
                   confirmed "does not exist"
"""

from typing import Tuple, List, Optional

import dns.resolver
import dns.exception

from config import DNS_TIMEOUT


def _new_resolver(timeout: int) -> "dns.resolver.Resolver":
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def resolve_host(hostname: str, timeout: int = DNS_TIMEOUT) -> Tuple[str, List[str], List[str], Optional[str], Optional[str]]:
    """
    Returns:
        (dns_status, ipv4_list, ipv6_list, cname, error_message)
    """
    resolver = _new_resolver(timeout)

    ipv4: List[str] = []
    ipv6: List[str] = []
    cname: Optional[str] = None
    saw_nxdomain = False
    saw_error = False
    error_message: Optional[str] = None

    # CNAME (best-effort; many hosts won't have one, which is fine)
    try:
        answer = resolver.resolve(hostname, "CNAME")
        if answer:
            cname = str(answer[0].target).rstrip(".")
    except dns.resolver.NXDOMAIN:
        saw_nxdomain = True
    except dns.resolver.NoAnswer:
        pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        saw_error = True
        error_message = f"CNAME lookup: {type(exc).__name__}"
    except Exception as exc:  # noqa: BLE001
        saw_error = True
        error_message = f"CNAME lookup: {exc}"

    # A records
    try:
        answer = resolver.resolve(hostname, "A")
        ipv4 = [str(r) for r in answer]
    except dns.resolver.NXDOMAIN:
        saw_nxdomain = True
    except dns.resolver.NoAnswer:
        pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        saw_error = True
        error_message = error_message or f"A lookup: {type(exc).__name__}"
    except Exception as exc:  # noqa: BLE001
        saw_error = True
        error_message = error_message or f"A lookup: {exc}"

    # AAAA records
    try:
        answer = resolver.resolve(hostname, "AAAA")
        ipv6 = [str(r) for r in answer]
    except dns.resolver.NXDOMAIN:
        saw_nxdomain = True
    except dns.resolver.NoAnswer:
        pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        saw_error = True
        error_message = error_message or f"AAAA lookup: {type(exc).__name__}"
    except Exception as exc:  # noqa: BLE001
        saw_error = True
        error_message = error_message or f"AAAA lookup: {exc}"

    if ipv4 or ipv6 or cname:
        return "RESOLVED", ipv4, ipv6, cname, None

    if saw_error and not saw_nxdomain:
        return "ERROR", ipv4, ipv6, cname, error_message

    return "NOT_RESOLVED", ipv4, ipv6, cname, None
