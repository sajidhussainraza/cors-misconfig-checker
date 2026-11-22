"""Tests for cors_misconfig_checker.py.

Run with:  python3 tests/run_tests.py
(or: python3 -m pytest tests/ -q, if pytest is installed)

The offline tests need no network. The live test audits github.com
and is skipped automatically when the network is unreachable.
"""

import json
import os
import subprocess
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cors_misconfig_checker import (  # noqa: E402
    analyze_cors,
    fetch_cors,
    format_report,
    grade_for,
    parse_headers,
)

ORIGIN = "https://evil.example"
SAFE = {"Access-Control-Allow-Origin": "https://app.example"}


class TestParseHeaders(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(parse_headers(None), {})
        self.assertEqual(parse_headers(""), {})

    def test_names_lowercased(self):
        parsed = parse_headers(
            "Access-Control-Allow-Origin: *; Vary: Origin")
        self.assertEqual(parsed["access-control-allow-origin"], "*")
        self.assertEqual(parsed["vary"], "Origin")

    def test_value_may_contain_colons(self):
        parsed = parse_headers(
            "Access-Control-Allow-Origin: https://evil.example")
        self.assertEqual(parsed["access-control-allow-origin"],
                         "https://evil.example")

    def test_malformed_entries_ignored(self):
        parsed = parse_headers(
            "Access-Control-Allow-Origin: *; garbage-no-colon; "
            "Vary: Origin; : empty-name")
        self.assertEqual(parsed["access-control-allow-origin"], "*")
        self.assertEqual(parsed["vary"], "Origin")
        self.assertNotIn("", parsed)

    def test_trailing_semicolon_and_spaces(self):
        parsed = parse_headers(
            "Access-Control-Allow-Origin: * ;  Vary: Origin ;")
        self.assertEqual(parsed["access-control-allow-origin"], "*")
        self.assertEqual(parsed["vary"], "Origin")


class TestGrades(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(grade_for(100), "A")
        self.assertEqual(grade_for(90), "A")
        self.assertEqual(grade_for(89), "B")
        self.assertEqual(grade_for(75), "B")
        self.assertEqual(grade_for(74), "C")
        self.assertEqual(grade_for(60), "C")
        self.assertEqual(grade_for(59), "D")
        self.assertEqual(grade_for(40), "D")
        self.assertEqual(grade_for(39), "F")
        self.assertEqual(grade_for(0), "F")


class TestAnalyzeCors(unittest.TestCase):
    def test_no_acao_is_safe_default(self):
        report = analyze_cors({}, origin=ORIGIN)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.findings, [])
        self.assertFalse(report.cors_enabled)
        text = format_report(report)
        self.assertIn("CORS is not enabled", text)
        self.assertIn("safe default", text)

    def test_reflected_origin_with_credentials_is_high(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN,
             "Access-Control-Allow-Credentials": "true",
             "Vary": "Origin"}, origin=ORIGIN)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "high")
        self.assertEqual(report.score, 75)
        self.assertEqual(report.grade, "B")
        self.assertTrue(report.cors_enabled)

    def test_null_origin_is_high_with_credentials(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": "null",
             "Access-Control-Allow-Credentials": "true"},
            origin=ORIGIN)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "high")
        self.assertIn("null", report.findings[0].message)

    def test_null_origin_is_high_without_credentials(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": "null"}, origin=ORIGIN)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "high")

    def test_reflected_origin_without_credentials_is_medium(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN, "Vary": "Origin"},
            origin=ORIGIN)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "medium")
        self.assertEqual(report.score, 90)
        self.assertEqual(report.grade, "A")

    def test_wildcard_with_credentials_is_medium(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": "*",
             "Access-Control-Allow-Credentials": "true"},
            origin=ORIGIN)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "medium")
        self.assertIn("Browsers refuse", report.findings[0].message)

    def test_wildcard_without_credentials_is_low(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": "*"}, origin=ORIGIN)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "low")
        self.assertEqual(report.score, 97)

    def test_fixed_origin_is_safe(self):
        report = analyze_cors(SAFE, origin=ORIGIN)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.findings, [])
        self.assertTrue(report.cors_enabled)

    def test_missing_vary_with_reflected_origin_is_low(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN}, origin=ORIGIN)
        vary = [f for f in report.findings if f.header == "Vary"]
        self.assertEqual(len(vary), 1)
        self.assertEqual(vary[0].severity, "low")
        # Medium for the reflection plus low for the missing Vary.
        self.assertEqual(report.score, 87)

    def test_vary_origin_suppresses_cache_finding(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN,
             "Vary": "Origin, Accept-Encoding"}, origin=ORIGIN)
        self.assertFalse(any(f.header == "Vary"
                             for f in report.findings))

    def test_wildcard_methods_with_credentials_is_medium(self):
        report = analyze_cors(
            SAFE,
            preflight_headers={
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Credentials": "true"},
            origin=ORIGIN)
        methods = [f for f in report.findings
                   if f.header == "access-control-allow-methods"]
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].severity, "medium")

    def test_wildcard_methods_without_credentials_is_low(self):
        report = analyze_cors(
            SAFE,
            preflight_headers={
                "Access-Control-Allow-Methods": "GET, POST, *"},
            origin=ORIGIN)
        methods = [f for f in report.findings
                   if f.header == "access-control-allow-methods"]
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].severity, "low")

    def test_wildcard_headers_with_credentials_is_medium(self):
        report = analyze_cors(
            SAFE,
            preflight_headers={
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Credentials": "true"},
            origin=ORIGIN)
        headers = [f for f in report.findings
                   if f.header == "access-control-allow-headers"]
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0].severity, "medium")

    def test_wildcard_headers_without_credentials_is_low(self):
        report = analyze_cors(
            SAFE,
            preflight_headers={
                "Access-Control-Allow-Headers": "authorization, *"},
            origin=ORIGIN)
        headers = [f for f in report.findings
                   if f.header == "access-control-allow-headers"]
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0].severity, "low")

    def test_preflight_creds_fall_back_to_main_response(self):
        # No credentials header on the preflight itself: the main
        # response's credentials value decides the severity.
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN,
             "Access-Control-Allow-Credentials": "true",
             "Vary": "Origin"},
            preflight_headers={
                "Access-Control-Allow-Methods": "*"},
            origin=ORIGIN)
        methods = [f for f in report.findings
                   if f.header == "access-control-allow-methods"]
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].severity, "medium")

    def test_expose_headers_wildcard_is_low(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": "https://app.example",
             "Access-Control-Expose-Headers": "*"}, origin=ORIGIN)
        exposed = [f for f in report.findings
                   if f.header == "access-control-expose-headers"]
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0].severity, "low")

    def test_max_age_over_limit_is_low(self):
        report = analyze_cors(
            SAFE,
            preflight_headers={
                "Access-Control-Max-Age": "86401"},
            origin=ORIGIN)
        max_age = [f for f in report.findings
                   if f.header == "access-control-max-age"]
        self.assertEqual(len(max_age), 1)
        self.assertEqual(max_age[0].severity, "low")

    def test_max_age_at_limit_is_fine(self):
        report = analyze_cors(
            SAFE,
            preflight_headers={
                "Access-Control-Max-Age": "86400"},
            origin=ORIGIN)
        self.assertFalse(any(f.header == "access-control-max-age"
                             for f in report.findings))
        self.assertEqual(report.score, 100)

    def test_max_age_not_a_number_is_ignored(self):
        report = analyze_cors(
            SAFE,
            preflight_headers={
                "Access-Control-Max-Age": "tomorrow"},
            origin=ORIGIN)
        self.assertEqual(report.score, 100)

    def test_no_preflight_means_no_preflight_findings(self):
        report = analyze_cors(SAFE, preflight_headers=None,
                              origin=ORIGIN)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.findings, [])

    def test_findings_sorted_high_first(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN,
             "Access-Control-Allow-Credentials": "true"},
            preflight_headers={
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Max-Age": "90000"},
            origin=ORIGIN)
        severities = [f.severity for f in report.findings]
        self.assertEqual(severities, sorted(
            severities, key={"high": 0, "medium": 1, "low": 2}.get))

    def test_every_finding_has_message_and_fix(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN,
             "Access-Control-Allow-Credentials": "true",
             "Access-Control-Expose-Headers": "*"},
            preflight_headers={
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Max-Age": "90000"},
            origin=ORIGIN)
        self.assertGreater(len(report.findings), 0)
        for finding in report.findings:
            self.assertTrue(finding.message)
            self.assertTrue(finding.fix)

    def test_json_round_trip(self):
        report = analyze_cors(
            {"Access-Control-Allow-Origin": ORIGIN,
             "Access-Control-Allow-Credentials": "true",
             "Vary": "Origin"}, origin=ORIGIN)
        data = json.loads(json.dumps(report.as_dict()))
        self.assertEqual(data["score"], report.score)
        self.assertEqual(data["grade"], report.grade)
        self.assertEqual(data["origin"], ORIGIN)
        self.assertTrue(data["cors_enabled"])
        self.assertEqual(len(data["findings"]), len(report.findings))
        self.assertIn("fix", data["findings"][0])

    def test_text_report_mentions_score_and_grade(self):
        text = format_report(analyze_cors(SAFE, origin=ORIGIN))
        self.assertIn("100/100", text)
        self.assertIn("Grade: A", text)
        self.assertIn("No findings", text)


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "cors_misconfig_checker.py")
        return subprocess.run([sys.executable, path, *args],
                              capture_output=True, text=True, timeout=60)

    def test_headers_mode(self):
        result = self.run_cli(
            "--headers",
            "Access-Control-Allow-Origin: https://app.example")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Score: 100/100", result.stdout)

    def test_headers_mode_json(self):
        result = self.run_cli(
            "--headers",
            "Access-Control-Allow-Origin: https://evil.example; "
            "Access-Control-Allow-Credentials: true; Vary: Origin",
            "--json")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["grade"], "B")
        self.assertEqual(data["score"], 75)
        self.assertGreater(len(data["findings"]), 0)

    def test_preflight_headers_mode(self):
        result = self.run_cli(
            "--headers",
            "Access-Control-Allow-Origin: https://app.example",
            "--preflight-headers",
            "Access-Control-Allow-Methods: *; "
            "Access-Control-Max-Age: 90000")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Score: 94/100", result.stdout)

    def test_origin_flag_changes_the_test(self):
        result = self.run_cli(
            "--headers",
            "Access-Control-Allow-Origin: https://attacker.test; "
            "Vary: Origin",
            "--origin", "https://attacker.test")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Score: 90/100", result.stdout)

    def test_fail_on_high_exits_1(self):
        result = self.run_cli(
            "--headers",
            "Access-Control-Allow-Origin: https://evil.example; "
            "Access-Control-Allow-Credentials: true; Vary: Origin",
            "--fail-on", "high")
        self.assertEqual(result.returncode, 1)

    def test_fail_on_high_passes_safe(self):
        result = self.run_cli(
            "--headers",
            "Access-Control-Allow-Origin: https://app.example",
            "--fail-on", "high")
        self.assertEqual(result.returncode, 0)

    def test_fail_on_low_exits_1_on_wildcard(self):
        result = self.run_cli(
            "--headers",
            "Access-Control-Allow-Origin: *",
            "--fail-on", "low")
        self.assertEqual(result.returncode, 1)

    def test_bad_url_exits_2(self):
        result = self.run_cli("not-a-url")
        self.assertEqual(result.returncode, 2)

    def test_no_args_exits_2(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)

    def test_headers_and_url_together_exits_2(self):
        result = self.run_cli(
            "--headers", "Access-Control-Allow-Origin: *",
            "https://example.com")
        self.assertEqual(result.returncode, 2)


class TestLiveAudit(unittest.TestCase):
    def test_github_sends_no_cors(self):
        try:
            (url, status, headers, preflight,
             preflight_status) = fetch_cors("https://github.com")
        except (urllib.error.URLError, OSError) as exc:
            self.skipTest("network unreachable: %s" % exc)
        self.assertEqual(status, 200)
        report = analyze_cors(headers, preflight_headers=preflight,
                              origin=ORIGIN, url=url)
        # github.com sends no ACAO header, so CORS is not enabled
        # and the safe default applies.
        self.assertFalse(report.cors_enabled)
        self.assertEqual(report.score, 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
