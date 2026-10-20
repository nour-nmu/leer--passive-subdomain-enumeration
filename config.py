"""
config.py
---------
Central place for default configuration values used across the scanner.
Keeping these in one file makes it easy to tune behavior (timeouts,
thread counts, user agent, etc.) without hunting through the codebase.
"""

# Default network timeouts (seconds)
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_READ_TIMEOUT = 8

# Default number of concurrent worker threads for DNS/HTTP checks.
# Kept conservative by default so the tool doesn't hammer targets or
# passive-source APIs.
DEFAULT_THREADS = 10

# Hard upper bound on threads a user can request via --threads.
# This is a safety rail against accidentally overwhelming a target.
MAX_THREADS = 50

# Retry limits for transient network errors (not for bypassing blocks).
MAX_RETRIES = 1

# A descriptive, honest User-Agent. Some passive-source APIs and target
# servers block generic/blank user agents.
USER_AGENT = "passive-recon-scanner/1.0 (+authorized-security-assessment)"

# Small delay (seconds) inserted between requests to the SAME passive
# source to be a good API citizen. This is not a security bypass, just
# basic rate-limiting courtesy.
PASSIVE_SOURCE_DELAY = 0.3

# DNS resolution timeout (seconds)
DNS_TIMEOUT = 5

# Ports checked for HTTP/HTTPS validation. Only the two standard web
# ports are used -- this tool does not perform port scanning.
HTTP_SCHEMES = ["https", "http"]

# Maximum number of redirects to follow before treating it as a
# redirect loop / giving up.
MAX_REDIRECTS = 8

# Default output file protection: don't silently overwrite unless
# --force is passed.
