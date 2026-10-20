<pre style="color:#a259ff; font-style: italic;">
 _     _____ _____ ____
| |   | ____| ____|  _ \
| |   |  _| |  _| | |_) |
| |___| |___| |___|  _ <
|_____|_____|_____|_| \_\
</pre>

    Passive Subdomain Reconnaissance Toolkit

# Leer

A modular Python tool for **passive subdomain enumeration**, **DNS/HTTP(S)
validation**, and **technology fingerprinting**. Discovers subdomains from
public Certificate Transparency logs and passive-DNS-style APIs, then
safely checks which ones are alive and what they're running.

> ⚠️ **Authorized use only.** This tool must only be run against domains
> you own, or that you have explicit written permission to assess. The
> author/maintainer is not responsible for misuse. Passive discovery
> queries public third-party datasets; the active checks (DNS lookups and
> normal HTTP GET requests) still contact the target infrastructure and
> should only be performed with proper authorization.

## What this tool does — and does not do

**Does:**
- Discover subdomains using **passive** sources only (Certificate
  Transparency logs, passive-DNS-style APIs) — never brute force.
- Resolve DNS records (A / AAAA / CNAME) for discovered names.
- Make normal HTTP/HTTPS GET requests to check reachability.
- Read publicly-presented TLS certificate metadata (subject, issuer,
  expiry) directly from the handshake.
- Passively fingerprint technology from response headers and HTML.

**Does NOT:**
- Brute-force subdomains, directories, or credentials.
- Perform port scanning.
- Attempt to exploit vulnerabilities or bypass authentication.
- Evade WAFs/security controls or send malicious payloads.
- Crawl private/authenticated areas of a site.

## Installation

```bash
git clone <this-repo> leer
cd leer
python3 -m venv venv          # optional but recommended
source venv/bin/activate
pip install -r requirements.txt
```

On Kali/Debian-based systems where `pip` refuses system-wide installs
(PEP 668), either use the venv above or run:

```bash
pip install -r requirements.txt --break-system-packages
```

Requires **Python 3.9+**.

## Usage

```bash
python3 leer.py -d example.com
```

Run `python3 leer.py -h` any time to see the full help screen (shown
below) with the banner, every flag, and usage examples.

### Options

| Flag              | Description                                                      |
|-------------------|-------------------------------------------------------------------|
| `-d`, `--domain`   | Root domain to scan (required). Accepts `example.com`, `https://example.com`, `http://example.com/`. |
| `-o`, `--output`   | Path to write results to (`.json` or `.csv`).                    |
| `-j`, `--json`     | Force JSON output format regardless of file extension.           |
| `-c`, `--csv`      | Force CSV output format regardless of file extension.            |
| `-T`, `--timeout`  | Network timeout in seconds (default: 8).                         |
| `-t`, `--threads`  | Concurrent worker threads for DNS/HTTP checks (default: 10, max: 50). |
| `-f`, `--force`    | Overwrite an existing output file instead of refusing.           |
| `-n`, `--no-color` | Disable ANSI colors/italics in terminal output (banner + table).  |
| `-h`, `--help`     | Show the banner and usage help, then exit.                       |

### Example commands

```bash
# Basic scan
python3 leer.py -d example.com

# Save full structured results as JSON
python3 leer.py -d example.com -o results.json

# Save a simplified table as CSV, with more threads
python3 leer.py -d example.com -o results.csv -t 20

# Slower/more reliable networks: raise the timeout
python3 leer.py -d example.com -T 15

# Overwrite an existing output file
python3 leer.py -d example.com -o results.json -f

# Plain output, no colors (useful when piping to a file/log)
python3 leer.py -d example.com -n
```

### Example: `-h` output

```
 _     _____ _____ ____
| |   | ____| ____|  _ \
| |   |  _| |  _| | |_) |
| |___| |___| |___|  _ <
|_____|_____|_____|_| \_\

    Passive Subdomain Reconnaissance Toolkit

usage: leer.py [-h] -d DOMAIN [-o OUTPUT] [-j] [-c] [-T SEC] [-t N] [-f] [-n]

Leer - Passive Subdomain Reconnaissance Toolkit

options:
  -h, --help            Show this help message and exit.
  -d DOMAIN, --domain DOMAIN
                        Root domain to scan, e.g. example.com
  -o OUTPUT, --output OUTPUT
                        Output file path (.json or .csv). Format is inferred
                        from the extension unless -j/-c is also given.
  -j, --json            Force JSON output format for -o.
  -c, --csv             Force CSV output format for -o.
  -T SEC, --timeout SEC
                        Network timeout in seconds (default: 8).
  -t N, --threads N     Concurrent worker threads (default: 10, max: 50).
  -f, --force           Overwrite an existing output file if one already
                        exists.
  -n, --no-color        Disable ANSI colors in terminal output.

Usage examples:
  python3 leer.py -d example.com
  python3 leer.py -d example.com -o results.json
  python3 leer.py -d example.com -o results.csv -t 20
  python3 leer.py -d example.com -T 15 -f

Only run this against domains/hosts you own or are explicitly
authorized to test. Unauthorized scanning may be illegal.
```

*(The banner renders in purple italics on terminals that support ANSI
italics; `-n` disables it entirely.)*

### Example: scan output

```
 _     _____ _____ ____
| |   | ____| ____|  _ \
| |   |  _| |  _| | |_) |
| |___| |___| |___|  _ <
|_____|_____|_____|_| \_\

    Passive Subdomain Reconnaissance Toolkit

============================================================
Target: example.com
============================================================

[*] Running passive enumeration (crt.sh, CertSpotter, HackerTarget)...
[*] 24 unique in-scope subdomains to process (threads=10, timeout=8s)...

[*] Processed 24/24

[+] Passive subdomains discovered: 27
[+] Unique subdomains: 24
[+] DNS resolved: 21
[+] HTTP/HTTPS reachable: 18

SUBDOMAIN                   STATUS       CODE    TECHNOLOGIES
---------------------------------------------------------------------------
www.example.com              LIVE         200     Nginx, React
api.example.com              LIVE         200     Nginx, Laravel
admin.example.com            LIVE         403     Cloudflare, Nginx
old.example.com               LIVE         301     Apache
mail.example.com             DNS_ONLY     -       -
dev.example.com               NOT_LIVE     -       -

[+] Results written to results.json (JSON)
```

### Example: JSON output (`-o results.json`)

```json
{
  "target": "example.com",
  "generated_at": "2026-08-22T17:24:25.225004+00:00",
  "total_subdomains": 1,
  "results": [
    {
      "subdomain": "www.example.com",
      "discovery_sources": ["crt.sh", "certspotter"],
      "dns_status": "RESOLVED",
      "ipv4": ["93.184.216.34"],
      "ipv6": [],
      "cname": null,
      "dns_error": null,
      "http_status": 200,
      "https_status": 200,
      "live": true,
      "status": "LIVE",
      "final_url": "https://www.example.com/",
      "redirect_chain": [],
      "response_time": 46.21,
      "content_type": "text/html",
      "page_title": "Example Domain",
      "server": "nginx",
      "technologies": [
        {
          "name": "Nginx",
          "category": "Web Server",
          "version": "1.18.0",
          "confidence": "High",
          "evidence": "'Server' header"
        }
      ],
      "tls_information": {
        "tls_available": true,
        "tls_success": true,
        "subject_cn": "www.example.com",
        "issuer": "Let's Encrypt",
        "not_after": "2026-09-20T00:08:48+00:00",
        "error": null
      },
      "error": null
    }
  ]
}
```

### Example: CSV output (`-o results.csv`)

```
subdomain,dns_status,live,http_status,https_status,final_url,server,technologies,response_time
www.example.com,RESOLVED,True,200,200,https://www.example.com/,nginx,Nginx,46.21
```

## Passive enumeration providers

All discovery sources are unauthenticated and require no API key. Each
lives in its own module under `enumeration/`, implementing a common
`PassiveProvider` interface (`enumeration/base.py`), so adding a new
source only means dropping in a new file and registering it in
`enumeration/manager.py`.

| Provider        | Module                        | Source type                                   |
|------------------|-------------------------------|------------------------------------------------|
| crt.sh           | `enumeration/crtsh.py`        | Certificate Transparency log search            |
| CertSpotter      | `enumeration/certspotter.py`  | Certificate Transparency log aggregator (SSLMate) |
| HackerTarget      | `enumeration/hackertarget.py` | Aggregated passive DNS / historical scan data  |

All providers run concurrently. If one fails (timeout, rate limit,
malformed response), the manager logs the issue and continues with
whatever the other providers found — a single source failing never
stops the scan.

Results from every provider are merged, lowercased, deduplicated,
validated as real hostnames, checked to belong to the requested root
domain, and stripped of wildcard entries (`*.example.com`) before
anything downstream sees them.

## How each stage works

### 1. DNS resolution (`dns_resolution/resolver.py`)
For each discovered subdomain, the tool queries `A`, `AAAA`, and `CNAME`
records using `dnspython`. A subdomain is classified:
- `RESOLVED` — at least one record was found.
- `NOT_RESOLVED` — the name doesn't exist (NXDOMAIN / no answer).
- `ERROR` — the lookup itself failed (timeout, no reachable resolver),
  which is different from a confirmed non-existent name.

A subdomain without an HTTP response is **not** assumed dead — it may
run a non-HTTP service, so DNS-resolved-but-not-web-reachable hosts are
reported as `DNS_ONLY`, not `NOT_LIVE`.

### 2. HTTP/HTTPS validation (`http_checker/checker.py`)
For each DNS-resolved subdomain, the tool sends a standard GET request
to both `https://` and `http://`. It records the status code, final URL
after redirects, redirect chain, response time, `Server` header,
`Content-Type`, and page `<title>`. Any 2xx–5xx response counts as
**reachable** (`LIVE`) — a `403` or `404` still proves the host answers
HTTP requests, it's just not "content available."

Connection failures, DNS errors at request time, TLS errors, timeouts,
and redirect loops are all caught individually and recorded in the
result's `error` field rather than crashing the scan.

### 3. TLS information
For HTTPS-reachable hosts, the tool opens a raw TLS connection purely to
read the certificate's subject CN, issuer, and expiration date — the
same information any browser sees during the handshake. It does not
attempt to bypass certificate validation for anything beyond this
read-only inspection, and never uses the connection to authenticate or
act on the target's behalf.

### 4. Technology fingerprinting (`fingerprinting/`)
A small, extensible engine (`engine.py`) runs two passive detectors:
- `headers.py` — matches known technology signals in response headers
  (`Server`, `X-Powered-By`, `X-Generator`, `Via`, `Set-Cookie`, etc.).
- `html.py` — matches known signatures in the HTML body (meta
  generator tags, well-known asset paths, JS framework markers, etc.).

All signatures live in `fingerprinting/fingerprints.py` as plain data —
add a new technology by adding a new pattern there, no code changes
required elsewhere. Every detection includes:
```
name, category, version (if identifiable), confidence, evidence
```
Weak or ambiguous matches are marked `Low`/`Medium` confidence rather
than asserted outright, and a version number is only included when it
was actually captured from a signature match — never guessed.

## Output formats

### JSON (`-o results.json`)
Full structured results for every subdomain: DNS records, HTTP/HTTPS
details for both schemes, TLS info, and the full technology list with
evidence.

### CSV (`-o results.csv`)
A simplified, flat table with columns:
`subdomain, dns_status, live, http_status, https_status, final_url,
server, technologies, response_time`.

By default the tool **will not overwrite an existing output file** —
pass `-f`/`--force` to allow it.

## Project structure

```
leer/
├── leer.py                  # Orchestrates the full scan pipeline (entry point)
├── cli.py                   # Argument parsing, domain normalization, -h banner
├── config.py                # Central defaults (timeouts, threads, etc.)
├── models.py                # Shared dataclasses for results
│
├── enumeration/
│   ├── base.py               # Common PassiveProvider interface
│   ├── crtsh.py
│   ├── certspotter.py
│   ├── hackertarget.py
│   └── manager.py            # Runs providers concurrently, merges results
│
├── dns_resolution/
│   └── resolver.py
│
├── http_checker/
│   └── checker.py            # HTTP(S) GET checks + TLS cert inspection
│
├── fingerprinting/
│   ├── engine.py
│   ├── headers.py
│   ├── html.py
│   └── fingerprints.py       # Signature database (data only)
│
├── output/
│   ├── terminal.py           # Banner + results table rendering
│   ├── json_writer.py
│   └── csv_writer.py
│
└── requirements.txt
```

> Note: the DNS and HTTP packages are named `dns_resolution/` and
> `http_checker/` (rather than `dns/`/`http/`) to avoid shadowing the
> `dnspython` and standard-library `http` packages they depend on.

## Extending the tool

- **New passive source:** add a class in `enumeration/` implementing
  `PassiveProvider.discover()`, then register an instance in
  `enumeration/manager.py`'s `PROVIDERS` list.
- **New technology signature:** add an entry to
  `fingerprinting/fingerprints.py` (`HEADER_SIGNATURES`,
  `HTML_SIGNATURES`, or `COOKIE_SIGNATURES`).

## Error handling

The scanner is built to never let one failure abort the whole run.
Errors are caught at the provider, DNS, HTTP, TLS, and fingerprinting
layers individually and surfaced per-subdomain via a `status`/`error`
field, using categories such as:

```
DNS_ERROR, TIMEOUT, CONNECTION_ERROR, SSL_ERROR, HTTP_ERROR,
API_ERROR, INVALID_DOMAIN
```

Press `Ctrl+C` at any time to interrupt a running scan gracefully — the
tool finishes in-flight checks and reports the results gathered so far
rather than crashing.
