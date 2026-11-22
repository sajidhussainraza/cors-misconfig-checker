# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No (pre-release)   |

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security problem.**

Email the details to **info@cyberlegends.org** with the subject
`[cors-misconfig-checker] Security report`. Include:

- What the issue is and what it affects
- Steps to reproduce it, if you have them
- The version or commit you tested against

You will get an acknowledgement within 7 days, and a fix or a plan for
one within 30 days for confirmed issues. Please do not disclose the
issue publicly until a fix is released.

## What This Tool Does (and Does Not Do)

- CORS Misconfiguration Checker only sends anonymous, read-only HTTP
  GET and OPTIONS requests to the URL you give it. It never logs in,
  never submits data, and never stores anything.
- It has no dependencies, no network calls besides the audit request
  and its preflight, and no telemetry.
- It reads only the CORS response headers
  (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`,
  `Access-Control-Expose-Headers`, `Vary`,
  `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`,
  `Access-Control-Max-Age`). It does not execute JavaScript, follow
  login flows, or audit configurations that only appear after
  authentication.
- It deliberately sends an attacker-style Origin
  (`https://evil.example` by default) to see whether the server
  reflects it. Only run it against your own sites, or sites you have
  permission to test.
- A low score is a finding about a website's headers, not a
  vulnerability in this tool. If a site's configuration looks wrong,
  check with that site's owner before treating it as a live exploit.
