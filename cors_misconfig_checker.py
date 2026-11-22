#!/usr/bin/env python3
"""CORS Misconfiguration Checker - audit a website's CORS headers.

A small, dependency-free Python CLI that sends a cross-origin request
to a site (with an attacker-controlled Origin, the way a malicious
page would), reads the Access-Control-Allow-Origin and related CORS
headers it gets back, and grades the configuration A-F with
plain-language findings and fixes. It can also analyse header values
passed directly with --headers, which needs no network at all.

Standard library only (urllib, ssl, json, argparse). No third-party
packages, no telemetry, nothing is stored. The checker only sends
read-only GET and OPTIONS requests and never logs in or submits data.

Usage:
    python3 cors_misconfig_checker.py https://example.com
    python3 cors_misconfig_checker.py https://example.com --json
    python3 cors_misconfig_checker.py --headers \\
        "Access-Control-Allow-Origin: https://evil.example; \\
         Access-Control-Allow-Credentials: true"
    python3 cors_misconfig_checker.py https://example.com --fail-on high
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

__version__ = "1.0.0"

DEFAULT_ORIGIN = "https://evil.example"
DEDUCTIONS = {"high": 25, "medium": 10, "low": 3}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# A preflight cache longer than a day means a bad preflight answer
# keeps being reused instead of re-checked.
MAX_AGE_LIMIT = 86400

# Header names, lower-cased for case-insensitive lookup.
ACAO = "access-control-allow-origin"
ACAC = "access-control-allow-credentials"
ACEH = "access-control-expose-headers"
ACAM = "access-control-allow-methods"
ACAH = "access-control-allow-headers"
ACMA = "access-control-max-age"


@dataclass
class Finding:
    severity: str
    header: str
    message: str
    fix: str

    def as_dict(self):
        return {
            "severity": self.severity,
            "header": self.header,
            "message": self.message,
            "fix": self.fix,
        }


@dataclass
class Report:
    url: str | None
    origin: str
    headers: dict | None = None
    preflight_headers: dict | None = None
    preflight_status: int | None = None
    cors_enabled: bool = False
    findings: list = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    status: int | None = None

    def as_dict(self):
        return {
            "url": self.url,
            "status": self.status,
            "origin": self.origin,
            "cors_enabled": self.cors_enabled,
            "headers": self.headers,
            "preflight_headers": self.preflight_headers,
            "preflight_status": self.preflight_status,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.as_dict() for f in self.findings],
        }


def parse_headers(text):
    """Parse "Name: value; Name: value" into {lower-name: value}.

    Names are lower-cased so lookups are case-insensitive. Entries
    without a colon are malformed and ignored silently, and a value
    may itself contain colons (only the first one splits). Returns
    an empty dict for a missing or blank string.
    """
    headers = {}
    if not text:
        return headers
    for part in text.split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        name, value = part.split(":", 1)
        name = name.strip().lower()
        if name:
            headers[name] = value.strip()
    return headers


def _header_value(headers, name):
    """Case-insensitive header lookup on a plain dict."""
    if not headers:
        return None
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _is_true(value):
    return value is not None and value.strip().lower() == "true"


def _contains_wildcard(value):
    if not value:
        return False
    return "*" in [item.strip() for item in value.split(",")]


def _vary_includes_origin(headers):
    vary = _header_value(headers, "vary")
    if not vary:
        return False
    return "origin" in [item.strip().lower()
                        for item in vary.split(",")]


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _check_allow_origin(headers, origin, findings):
    """Check the main response's Access-Control-Allow-Origin."""
    acao = _header_value(headers, ACAO)
    if acao is None:
        # No finding: CORS is not enabled, so the browser blocks
        # cross-origin reads. That is the safe default.
        return False
    acao = acao.strip()
    creds = _is_true(_header_value(headers, ACAC))
    reflected = acao == origin

    if acao == "null":
        findings.append(Finding(
            "high", ACAO,
            "Access-Control-Allow-Origin is the literal string "
            "'null', which sandboxed iframes and data: URLs send as "
            "their origin, so an attacker page can read responses "
            "meant for no website at all.",
            "Never reflect or allow the 'null' origin. Allow-list "
            "only the exact origins the site genuinely serves."))
    elif reflected and creds:
        findings.append(Finding(
            "high", ACAO,
            "Access-Control-Allow-Origin echoes the request Origin "
            "and Access-Control-Allow-Credentials is true, so any "
            "website can read authenticated responses from this "
            "site, including a logged-in victim's data.",
            "Stop reflecting arbitrary origins. Allow-list only the "
            "exact origins the site serves, and keep credentials "
            "off unless a listed origin genuinely needs them."))
    elif reflected:
        findings.append(Finding(
            "medium", ACAO,
            "Access-Control-Allow-Origin echoes the request Origin, "
            "so any website can read responses that need no "
            "credentials, such as public API data or CSRF tokens.",
            "Stop reflecting arbitrary origins. Allow-list only the "
            "exact origins the site serves."))
    elif acao == "*" and creds:
        findings.append(Finding(
            "medium", ACAO,
            "Access-Control-Allow-Origin is '*' with "
            "Access-Control-Allow-Credentials: true. Browsers refuse "
            "to expose credentialed responses when ACAO is '*', so "
            "this is a broken configuration that signals sloppy "
            "CORS and breaks legitimate credentialed use, not a "
            "direct credential leak.",
            "Replace '*' with the exact origins that need access, "
            "and keep credentials enabled only for those origins."))
    elif acao == "*":
        findings.append(Finding(
            "low", ACAO,
            "Access-Control-Allow-Origin is '*', so any website can "
            "read the response. That is fine for genuinely public "
            "data and wrong for anything sensitive.",
            "If the response is ever sensitive, replace '*' with an "
            "allow-list of the exact origins that need access."))
    # A fixed specific origin that does not match the test origin is
    # an allow-list behaving correctly: no finding.
    if reflected and not _vary_includes_origin(headers):
        findings.append(Finding(
            "low", "Vary",
            "The origin is reflected but there is no 'Vary: Origin' "
            "header, so a shared cache can serve one origin's CORS "
            "response to another origin.",
            "Send 'Vary: Origin' on every response that varies by "
            "Origin, so caches keep each origin's response apart."))
    return True


def _check_preflight(preflight, main_headers, findings):
    """Check the OPTIONS preflight response, if one was received."""
    if not preflight:
        return
    # Credentials for the preflight come from its own header when
    # present, otherwise from the main response.
    creds_value = _header_value(preflight, ACAC)
    if creds_value is None:
        creds_value = _header_value(main_headers, ACAC)
    creds = _is_true(creds_value)

    methods = _header_value(preflight, ACAM)
    if _contains_wildcard(methods):
        if creds:
            findings.append(Finding(
                "medium", ACAM,
                "The preflight allows any method ('*') with "
                "credentials, so a malicious site can make "
                "credentialed cross-origin requests with any HTTP "
                "method the server accepts.",
                "List only the methods the API genuinely needs, "
                "such as GET and POST, instead of '*'."))
        else:
            findings.append(Finding(
                "low", ACAM,
                "The preflight allows any method ('*'). That is "
                "only low risk without credentials, but it is wider "
                "than any API needs.",
                "List only the methods the API genuinely needs, "
                "such as GET and POST, instead of '*'."))
    allowed_headers = _header_value(preflight, ACAH)
    if _contains_wildcard(allowed_headers):
        if creds:
            findings.append(Finding(
                "medium", ACAH,
                "The preflight allows any request header ('*') with "
                "credentials, so a malicious site can send "
                "credentialed cross-origin requests carrying any "
                "header, including Authorization.",
                "List only the headers the API genuinely needs, "
                "such as Content-Type, instead of '*'."))
        else:
            findings.append(Finding(
                "low", ACAH,
                "The preflight allows any request header ('*'). "
                "That is only low risk without credentials, but it "
                "is wider than any API needs.",
                "List only the headers the API genuinely needs, "
                "such as Content-Type, instead of '*'."))
    max_age = _header_value(preflight, ACMA)
    if max_age is not None:
        try:
            seconds = int(max_age.strip())
        except ValueError:
            seconds = None
        if seconds is not None and seconds > MAX_AGE_LIMIT:
            findings.append(Finding(
                "low", ACMA,
                "Access-Control-Max-Age is %d seconds (over a day), "
                "so browsers cache this preflight answer for a long "
                "time and a bad CORS decision keeps being reused."
                % seconds,
                "Lower Access-Control-Max-Age to 86400 seconds (one "
                "day) or less."))


def _check_expose_headers(headers, findings):
    exposed = _header_value(headers, ACEH)
    if _contains_wildcard(exposed):
        findings.append(Finding(
            "low", ACEH,
            "Access-Control-Expose-Headers is '*', so any website "
            "that can read the response can also read every "
            "response header, including ones meant to stay hidden.",
            "List only the headers cross-origin scripts genuinely "
            "need to read, instead of '*'."))


def analyze_cors(headers, preflight_headers=None, origin=DEFAULT_ORIGIN,
                 url=None):
    """Analyse CORS headers and return a Report.

    Pure function of the header values: no network, so it is easy to
    test offline. `headers` is the main response's CORS headers as a
    dict; `preflight_headers` the OPTIONS response's, or None when no
    preflight was received.
    """
    report = Report(url=url, origin=origin, headers=headers or {},
                    preflight_headers=preflight_headers)
    report.cors_enabled = _check_allow_origin(
        headers or {}, origin, report.findings)
    _check_expose_headers(headers or {}, report.findings)
    _check_preflight(preflight_headers, headers or {}, report.findings)

    report.score = max(
        0, 100 - sum(DEDUCTIONS[f.severity] for f in report.findings))
    report.grade = grade_for(report.score)
    report.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return report


def _cors_headers_from(response_headers):
    """Pick the CORS headers out of a response's header mapping."""
    wanted = (ACAO, ACAC, ACEH, "vary")
    return {name: response_headers.get(name)
            for name in wanted if response_headers.get(name) is not None}


def _preflight_headers_from(response_headers):
    wanted = (ACAO, ACAC, ACAM, ACAH, ACMA)
    return {name: response_headers.get(name)
            for name in wanted if response_headers.get(name) is not None}


def fetch_cors(url, origin=DEFAULT_ORIGIN, timeout=15):
    """GET a URL with an Origin header, then send an OPTIONS preflight.

    Returns (final_url, status, headers, preflight_headers,
    preflight_status). A preflight that fails (non-2xx/3xx status,
    no CORS headers, or a network error) is returned as empty
    headers with a None status, never raised. Raises ValueError for
    a bad URL and URLError/OSError when the main request fails.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError("URL must start with http:// or https://")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url, headers={"User-Agent": "cors-misconfig-checker/1.0",
                      "Origin": origin})
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx) as resp:
            final_url = resp.url
            status = resp.status
            headers = _cors_headers_from(resp.headers)
    except urllib.error.HTTPError as exc:
        # An error page can still carry CORS headers worth auditing.
        final_url = exc.url
        status = exc.code
        headers = _cors_headers_from(exc.headers)

    preflight_headers = {}
    preflight_status = None
    preflight_req = urllib.request.Request(
        final_url, method="OPTIONS",
        headers={"User-Agent": "cors-misconfig-checker/1.0",
                 "Origin": origin,
                 "Access-Control-Request-Method": "GET",
                 "Access-Control-Request-Headers":
                     "authorization, content-type"})
    try:
        with urllib.request.urlopen(preflight_req, timeout=timeout,
                                    context=ctx) as resp:
            preflight_status = resp.status
            preflight_headers = _preflight_headers_from(resp.headers)
    except urllib.error.HTTPError as exc:
        preflight_status = exc.code
        preflight_headers = _preflight_headers_from(exc.headers)
    except (urllib.error.URLError, OSError):
        # A preflight that cannot be completed is not a crash: the
        # main response is still audited on its own.
        preflight_headers = {}
        preflight_status = None
    return final_url, status, headers, preflight_headers, preflight_status


def _display_name(name):
    """Canonical capitalisation of a header name for display."""
    display = {
        ACAO: "Access-Control-Allow-Origin",
        ACAC: "Access-Control-Allow-Credentials",
        ACEH: "Access-Control-Expose-Headers",
        ACAM: "Access-Control-Allow-Methods",
        ACAH: "Access-Control-Allow-Headers",
        ACMA: "Access-Control-Max-Age",
        "vary": "Vary",
    }
    return display.get(name.lower(), name)


def format_report(report):
    """Render a Report as plain text."""
    lines = []
    title = report.url or "CORS header analysis"
    lines.append("CORS report: %s" % title)
    lines.append("Score: %d/100  Grade: %s" % (report.score, report.grade))
    lines.append("")
    lines.append("  Tested origin: %s" % report.origin)
    if report.headers:
        for name in (ACAO, ACAC, ACEH, "vary"):
            value = _header_value(report.headers, name)
            if value is not None:
                lines.append("  %s: %s" % (_display_name(name), value))
    else:
        lines.append("  CORS headers: none sent")
    if report.preflight_headers:
        lines.append("  Preflight:")
        for name in (ACAM, ACAH, ACAC, ACMA):
            value = _header_value(report.preflight_headers, name)
            if value is not None:
                lines.append("    %s: %s" % (_display_name(name), value))
        if report.preflight_status is not None:
            lines.append("    (preflight status: %d)"
                         % report.preflight_status)
    elif report.preflight_status is not None:
        lines.append("  Preflight: status %d, no CORS headers"
                     % report.preflight_status)
    else:
        lines.append("  Preflight: no response (not a CORS endpoint, "
                     "or the preflight failed)")
    if report.findings:
        lines.append("")
        lines.append("Findings (%d):" % len(report.findings))
        for finding in report.findings:
            lines.append("  [%s] %s: %s"
                         % (finding.severity.upper(),
                            _display_name(finding.header),
                            finding.message))
            lines.append("        Fix: %s" % finding.fix)
    else:
        lines.append("")
        if report.cors_enabled:
            lines.append("No findings: this site only allows a fixed, "
                         "named origin, so cross-origin reads from "
                         "other sites are blocked.")
        else:
            lines.append("No findings: CORS is not enabled, so the "
                         "browser blocks cross-origin reads. That is "
                         "the safe default; no website can read "
                         "responses from this site.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit a website's CORS configuration.")
    parser.add_argument("url", nargs="?",
                        help="Website URL to audit (https://example.com).")
    parser.add_argument("--origin", default=DEFAULT_ORIGIN,
                        help="Origin to test with (default: %s)."
                             % DEFAULT_ORIGIN)
    parser.add_argument("--headers",
                        help="Analyse CORS headers directly, as a "
                             "semicolon-separated list of \"Name: "
                             "value\" pairs (no network needed).")
    parser.add_argument("--preflight-headers",
                        help="Preflight response headers in the same "
                             "format, used with --headers.")
    parser.add_argument("--json", action="store_true",
                        help="Print the report as JSON.")
    parser.add_argument("--fail-on",
                        choices=["high", "medium", "low", "none"],
                        default="none",
                        help="Exit 1 when findings at or above this "
                             "severity are found (default: none).")
    args = parser.parse_args(argv)

    if args.headers and args.url:
        parser.error("--headers and a URL cannot be used together.")
    if args.preflight_headers and not args.headers:
        parser.error("--preflight-headers needs --headers (offline "
                     "mode); a live audit fetches its own preflight.")
    if not args.headers and not args.url:
        parser.error("Give a URL to audit or headers with --headers.")

    try:
        if args.headers:
            headers = parse_headers(args.headers)
            preflight = parse_headers(args.preflight_headers)
            report = analyze_cors(headers, preflight_headers=preflight,
                                  origin=args.origin)
        else:
            final_url, status, headers, preflight, preflight_status = \
                fetch_cors(args.url, origin=args.origin)
            report = analyze_cors(headers, preflight_headers=preflight,
                                  origin=args.origin, url=final_url)
            report.status = status
            report.preflight_status = preflight_status
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2
    except (urllib.error.URLError, OSError) as exc:
        print("Error: could not reach the site (%s)" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(format_report(report))

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= threshold
               for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
