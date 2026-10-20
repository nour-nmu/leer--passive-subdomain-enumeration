"""
manager.py
----------
Runs every registered passive provider, merges/normalizes/validates the
results, and tracks which source(s) discovered each subdomain.

This is the ONLY place that needs to change to add a new passive
source: add the provider instance to PROVIDERS.
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from .crtsh import CrtShProvider
from .certspotter import CertSpotterProvider
from .hackertarget import HackerTargetProvider
from config import PASSIVE_SOURCE_DELAY

# Registry of active passive providers. Add new provider instances here.
PROVIDERS = [
    CrtShProvider(),
    CertSpotterProvider(),
    HackerTargetProvider(),
]

# A conservative hostname validation pattern (labels of letters/digits/
# hyphens, separated by dots). Rejects anything that isn't a plausible
# DNS name (garbage, emails, wildcards-with-extra-junk, etc.).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _clean_and_validate(raw_host: str, root_domain: str) -> str:
    """
    Normalize a raw discovered hostname and return it if valid & in-scope,
    otherwise return an empty string.
    """
    host = raw_host.strip().lower().rstrip(".")

    # Strip a leading wildcard label; "*.example.com" -> "example.com"
    # is not a concrete host, so wildcard entries are ignored entirely
    # rather than rewritten (per spec: "ignore wildcard records").
    if host.startswith("*."):
        return ""
    if "*" in host:
        return ""

    # Strip protocol/path if a provider ever hands one back.
    host = host.replace("https://", "").replace("http://", "")
    host = host.split("/")[0]

    if not host:
        return ""

    if not _HOSTNAME_RE.match(host):
        return ""

    # Must belong to the requested root domain (either be the root
    # domain itself or a proper subdomain of it).
    if host != root_domain and not host.endswith("." + root_domain):
        return ""

    return host


def run_passive_enumeration(
    root_domain: str, timeout: int = 10
) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """
    Run all providers concurrently.

    Returns:
        subdomain_sources: {subdomain: [provider_name, ...]}
        provider_errors:   {provider_name: error_message}  (only for
                            providers that failed outright)
    """
    subdomain_sources: Dict[str, List[str]] = {}
    provider_errors: Dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=max(1, len(PROVIDERS))) as executor:
        futures = {
            executor.submit(provider.safe_discover, root_domain, timeout): provider
            for provider in PROVIDERS
        }

        for future in as_completed(futures):
            provider = futures[future]
            try:
                name, raw_hosts, error = future.result()
            except Exception as exc:  # noqa: BLE001 - final safety net
                provider_errors[provider.name] = f"{type(exc).__name__}: {exc}"
                continue

            if error:
                provider_errors[name] = error

            for raw_host in raw_hosts:
                clean = _clean_and_validate(raw_host, root_domain)
                if not clean:
                    continue
                subdomain_sources.setdefault(clean, [])
                if name not in subdomain_sources[clean]:
                    subdomain_sources[clean].append(name)

            # Small courtesy delay so we don't hammer providers back-to-back.
            time.sleep(PASSIVE_SOURCE_DELAY)

    return subdomain_sources, provider_errors
