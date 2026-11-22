# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-20

### Added

- Dependency-free Python CLI that audits a site's CORS configuration
  and grades it A-F with a 0-100 score.
- Live audit sends a GET with an attacker-controlled Origin plus an
  OPTIONS preflight, and reads `Access-Control-Allow-Origin`,
  `Access-Control-Allow-Credentials`,
  `Access-Control-Expose-Headers`, `Vary`,
  `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`,
  and `Access-Control-Max-Age`.
- Plain-language findings with a concrete fix for every issue:
  reflected origin with credentials, `null` origin, reflected
  origin without credentials, `*` with or without credentials,
  missing `Vary: Origin`, wildcard preflight methods and headers,
  wildcard exposed headers, and a preflight cache over one day.
- Safe-default awareness: a site that sends no
  `Access-Control-Allow-Origin` at all scores 100, because the
  browser blocks cross-origin reads.
- Offline mode (`--headers`, with `--preflight-headers`), a custom
  test origin (`--origin`, default `https://evil.example`),
  machine-readable output (`--json`), and a CI gate
  (`--fail-on {high,medium,low,none}`, default `none`).
- Exit codes 0 (pass), 1 (findings at or above `--fail-on`),
  2 (usage or network error).
- 41 tests (stdlib `unittest`, no pytest needed), including a live
  audit of github.com that skips when the network is unreachable.
- Full repository standard: README, CONTRIBUTING.md, Code of Conduct,
  Security policy, issue and pull request templates, CI workflow,
  `.gitignore`, `.editorconfig`, and original SVG banner and logo.

### Fixed

- Nothing yet; this is the first release.

## [Unreleased]

- Nothing yet. See the [roadmap](README.md#roadmap) for what is planned.
