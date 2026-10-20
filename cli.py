"""
cli.py
------
Command-line argument parsing and input normalization for Leer.
"""

import argparse
import re
import sys

from config import DEFAULT_THREADS, MAX_THREADS, DEFAULT_READ_TIMEOUT
from output.terminal import render_banner

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

_EPILOG = """\
Usage examples:
  python3 leer.py -d example.com
  python3 leer.py -d example.com -o results.json
  python3 leer.py -d example.com -o results.csv -t 20
  python3 leer.py -d example.com -T 15 -f

Only run this against domains/hosts you own or are explicitly
authorized to test. Unauthorized scanning may be illegal.
"""


class _BannerHelpAction(argparse.Action):
    """
    Custom -h/--help action that prints the colored LEER banner above
    the normal argparse help text, then exits (same as the default
    help action, just with the banner prepended).
    """

    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(
            option_strings=option_strings, dest=dest, default=default,
            nargs=0, help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        use_color = not ("-n" in sys.argv or "--no-color" in sys.argv)
        print(render_banner(use_color=use_color))
        parser.print_help()
        parser.exit()


def normalize_domain(raw: str) -> str:
    """
    Accepts 'example.com', 'https://example.com', 'http://example.com/'
    and returns the bare root domain 'example.com'.
    """
    value = raw.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0]
    value = value.split(":")[0]  # strip a port if one was included
    value = value.rstrip(".")
    return value


def validate_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leer.py",
        description="Leer - Passive Subdomain Reconnaissance Toolkit",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", action=_BannerHelpAction,
        help="Show this help message and exit.",
    )
    parser.add_argument(
        "-d", "--domain", required=True, metavar="DOMAIN",
        help="Root domain to scan, e.g. example.com",
    )
    parser.add_argument(
        "-o", "--output", metavar="OUTPUT",
        help="Output file path (.json or .csv). Format is inferred from "
        "the extension unless -j/-c is also given.",
    )
    parser.add_argument(
        "-j", "--json", action="store_true",
        help="Force JSON output format for -o.",
    )
    parser.add_argument(
        "-c", "--csv", action="store_true",
        help="Force CSV output format for -o.",
    )
    parser.add_argument(
        "-T", "--timeout", type=int, default=DEFAULT_READ_TIMEOUT, metavar="SEC",
        help=f"Network timeout in seconds (default: {DEFAULT_READ_TIMEOUT}).",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=DEFAULT_THREADS, metavar="N",
        help=f"Concurrent worker threads (default: {DEFAULT_THREADS}, "
        f"max: {MAX_THREADS}).",
    )
    parser.add_argument(
        "-f", "--force", action="store_true",
        help="Overwrite an existing output file if one already exists.",
    )
    parser.add_argument(
        "-n", "--no-color", action="store_true",
        help="Disable ANSI colors in terminal output.",
    )
    return parser


def parse_args(argv=None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)

    args.domain = normalize_domain(args.domain)
    if not validate_domain(args.domain):
        parser.error(
            f"'{args.domain}' does not look like a valid domain name. "
            "Examples of valid input: example.com, https://example.com"
        )

    if args.threads < 1:
        parser.error("-t/--threads must be at least 1.")
    if args.threads > MAX_THREADS:
        print(
            f"[!] -t/--threads capped at {MAX_THREADS} for safety "
            f"(requested {args.threads}).",
            file=sys.stderr,
        )
        args.threads = MAX_THREADS

    if args.timeout < 1:
        parser.error("-T/--timeout must be at least 1 second.")

    return args
