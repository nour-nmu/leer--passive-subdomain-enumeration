#!/usr/bin/env python3
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from cli import parse_args
from config import DEFAULT_CONNECT_TIMEOUT
from enumeration.manager import run_passive_enumeration
from dns_resolution.resolver import resolve_host
from http_checker.checker import check_http, check_tls
from fingerprinting.engine import detect_technologies
from models import SubdomainResult
from output.terminal import (
    print_banner,
    print_summary_counts,
    print_results_table,
    print_provider_errors,
)
from output.json_writer import write_json
from output.csv_writer import write_csv

_INTERRUPTED = False


def _handle_sigint(signum, frame):  # noqa: ARG001
    global _INTERRUPTED
    if _INTERRUPTED:
        print("\n[!] Force exiting.")
        sys.exit(1)
    _INTERRUPTED = True
    print("\n[!] Interrupt received -- finishing in-flight checks, then stopping. "
          "Press Ctrl+C again to force quit.")


def process_subdomain(subdomain: str, sources: list, timeout: int) -> SubdomainResult:
    result = SubdomainResult(subdomain=subdomain, discovery_sources=sources)

    try:
        dns_status, ipv4, ipv6, cname, dns_error = resolve_host(subdomain, timeout=timeout)
        result.dns_status = dns_status
        result.ipv4 = ipv4
        result.ipv6 = ipv6
        result.cname = cname
        result.dns_error = dns_error
    except Exception as exc:  # noqa: BLE001
        result.dns_status = "ERROR"
        result.dns_error = str(exc)
        result.error = "DNS_ERROR"

    if result.dns_status != "RESOLVED":
        result.status = "NOT_LIVE" if result.dns_status == "NOT_RESOLVED" else "ERROR"
        if result.dns_status == "ERROR" and not result.error:
            result.error = "DNS_ERROR"
        return result

    try:
        result.https_result = check_http(subdomain, "https", timeout=timeout)
    except Exception as exc:
        result.https_result = None
        result.error = result.error or f"HTTP_ERROR: {exc}"

    try:
        result.http_result = check_http(subdomain, "http", timeout=timeout)
    except Exception as exc: 
        result.http_result = None
        result.error = result.error or f"HTTP_ERROR: {exc}"

    https_ok = bool(result.https_result and result.https_result.reachable)
    http_ok = bool(result.http_result and result.http_result.reachable)
    result.live = https_ok or http_ok

    if result.live:
        result.status = "LIVE"
        best = result.best_http_result()
        result.final_url = best.final_url if best else None
    else:
        result.status = "DNS_ONLY"

    if result.https_result is not None:
        try:
            result.tls_information = check_tls(subdomain, timeout=DEFAULT_CONNECT_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            from models import TLSInfo
            result.tls_information = TLSInfo(error=str(exc))

    try:
        best = result.best_http_result()
        result.technologies = detect_technologies(best)
    except Exception as exc:  # noqa: BLE001
        result.error = result.error or f"FINGERPRINT_ERROR: {exc}"

    return result


def main():
    signal.signal(signal.SIGINT, _handle_sigint)

    args = parse_args()

    print_banner(args.domain, use_color=not args.no_color)
    print("[*] Running passive enumeration (crt.sh, CertSpotter, HackerTarget)...")

    subdomain_sources, provider_errors = run_passive_enumeration(
        args.domain, timeout=args.timeout
    )

    if args.domain not in subdomain_sources:
        subdomain_sources[args.domain] = ["root-domain"]

    print_provider_errors(provider_errors)

    passive_count = sum(len(v) for v in subdomain_sources.values())
    unique_count = len(subdomain_sources)
    print(f"[*] {unique_count} unique in-scope subdomains to process "
          f"(threads={args.threads}, timeout={args.timeout}s)...\n")

    results = []
    subdomains = list(subdomain_sources.items())

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(process_subdomain, sub, sources, args.timeout): sub
            for sub, sources in subdomains
        }

        completed = 0
        for future in as_completed(futures):
            if _INTERRUPTED:
                pass
            sub = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                result = SubdomainResult(subdomain=sub, error=f"UNKNOWN_ERROR: {exc}")
                result.status = "ERROR"
            results.append(result)
            completed += 1
            print(f"\r[*] Processed {completed}/{len(subdomains)}", end="", flush=True)

    print("\n")

    dns_resolved = sum(1 for r in results if r.dns_status == "RESOLVED")
    http_live = sum(1 for r in results if r.live)

    print_summary_counts(passive_count, unique_count, dns_resolved, http_live)
    print_results_table(results, use_color=not args.no_color)

    if args.output:
        fmt = None
        if args.json:
            fmt = "json"
        elif args.csv:
            fmt = "csv"
        elif args.output.lower().endswith(".csv"):
            fmt = "csv"
        else:
            fmt = "json"

        try:
            if fmt == "csv":
                write_csv(results, args.output, force=args.force)
            else:
                write_json(results, args.domain, args.output, force=args.force)
            print(f"[+] Results written to {args.output} ({fmt.upper()})")
        except FileExistsError as exc:
            print(f"[!] {exc}")
            sys.exit(1)

    if _INTERRUPTED:
        print("[!] Scan stopped early due to interrupt.")
        sys.exit(130)


if __name__ == "__main__":
    main()
