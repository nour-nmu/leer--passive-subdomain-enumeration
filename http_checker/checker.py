"""
checker.py
----------
Active-but-benign checks against discovered subdomains:
  * Standard HTTP/HTTPS GET requests (status, headers, title, timing).
  * Basic TLS certificate metadata (subject/issuer/expiry) read directly
    off the handshake -- no certificate verification bypass, no
    exploitation, just reading what the server already presents
    publicly to any client.

Only ever connects to hosts that already came from the passive
enumeration + DNS-resolution stages, and only ever on the standard
web ports (80/443) via normal GET requests.
"""

import re
import socket
import ssl
import time
from typing import Optional

import requests
import requests.exceptions

from config import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    MAX_REDIRECTS,
    USER_AGENT,
)
from models import HTTPResult, TLSInfo

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Only read a bounded amount of body content -- enough for title/tech
# fingerprinting, without downloading huge files needlessly.
_MAX_BODY_BYTES = 300_000


def _extract_title(html_text: str) -> Optional[str]:
    match = _TITLE_RE.search(html_text)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:200] if title else None


def check_http(hostname: str, scheme: str, timeout: int = DEFAULT_READ_TIMEOUT) -> HTTPResult:
    """
    Perform a single GET request to scheme://hostname/ and capture the
    relevant details. Every failure mode is caught and reflected in the
    result's `error` field instead of raising.
    """
    result = HTTPResult(scheme=scheme, attempted=True, method="GET")
    url = f"{scheme}://{hostname}/"
    headers = {"User-Agent": USER_AGENT}

    try:
        start = time.perf_counter()
        resp = requests.get(
            url,
            headers=headers,
            timeout=(DEFAULT_CONNECT_TIMEOUT, timeout),
            allow_redirects=True,
            verify=True,          # standard verification for the request itself
            stream=True,          # so we can cap how much body we read
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Read a bounded amount of the body for title/fingerprinting.
        body_bytes = b""
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    break
                body_bytes += chunk
                if len(body_bytes) >= _MAX_BODY_BYTES:
                    break
        except requests.exceptions.RequestException:
            pass  # partial body is fine

        body_text = body_bytes.decode(resp.encoding or "utf-8", errors="ignore")

        result.reachable = True
        result.status_code = resp.status_code
        result.final_url = resp.url
        result.redirect_chain = [r.url for r in resp.history]
        result.response_time_ms = round(elapsed_ms, 2)
        result.content_type = resp.headers.get("Content-Type")
        result.server = resp.headers.get("Server")
        result.headers = dict(resp.headers)
        result.body_snippet = body_text
        result.page_title = _extract_title(body_text) if "html" in (result.content_type or "") else _extract_title(body_text)

        resp.close()

    except requests.exceptions.SSLError as exc:
        result.error = f"SSL_ERROR: {exc}"
    except requests.exceptions.TooManyRedirects as exc:
        result.error = f"REDIRECT_LOOP: {exc}"
    except requests.exceptions.ConnectTimeout:
        result.error = "TIMEOUT: connection timed out"
    except requests.exceptions.ReadTimeout:
        result.error = "TIMEOUT: read timed out"
    except requests.exceptions.ConnectionError as exc:
        # Covers connection refused, DNS errors at request time,
        # connection reset, etc.
        result.error = f"CONNECTION_ERROR: {exc}"
    except requests.exceptions.RequestException as exc:
        result.error = f"HTTP_ERROR: {exc}"
    except Exception as exc:  # noqa: BLE001 - final safety net
        result.error = f"UNKNOWN_ERROR: {exc}"

    return result


def check_tls(hostname: str, port: int = 443, timeout: int = DEFAULT_CONNECT_TIMEOUT) -> TLSInfo:
    """
    Open a raw TLS connection to read certificate metadata. Uses an
    unverified context ON PURPOSE so we can still report subject/issuer
    for self-signed or misconfigured certs (read-only inspection, not a
    verification bypass of anything -- we never trust or act on this
    connection beyond reading the handshake's cert fields).
    """
    info = TLSInfo(tls_available=False, tls_success=False)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            info.tls_available = True
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                info.tls_success = True

                # getpeercert(binary_form=False) needs verify_mode != CERT_NONE
                # to be populated in some Python builds, so parse the DER
                # cert manually for subject/issuer/expiry where possible.
                try:
                    import datetime
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend

                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    cn = cert.subject.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME
                    )
                    issuer_cn = cert.issuer.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME
                    )
                    info.subject_cn = cn[0].value if cn else None
                    info.issuer = issuer_cn[0].value if issuer_cn else None
                    info.not_after = cert.not_valid_after_utc.isoformat() if hasattr(
                        cert, "not_valid_after_utc"
                    ) else cert.not_valid_after.isoformat()
                except ImportError:
                    # `cryptography` not installed -- fall back to ssl's
                    # own (verified-connection-only) parser as best effort.
                    info.error = "cert-detail-parsing-unavailable (install 'cryptography' package)"
                except Exception as exc:  # noqa: BLE001
                    info.error = f"cert-parse-error: {exc}"

    except socket.timeout:
        info.error = "TIMEOUT"
    except (ssl.SSLError, ssl.CertificateError) as exc:
        info.tls_available = True
        info.error = f"SSL_ERROR: {exc}"
    except (ConnectionRefusedError, OSError) as exc:
        info.error = f"CONNECTION_ERROR: {exc}"
    except Exception as exc:  # noqa: BLE001
        info.error = f"UNKNOWN_ERROR: {exc}"

    return info
