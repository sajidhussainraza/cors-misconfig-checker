# Contributing to CORS Misconfiguration Checker

Thanks for helping make CORS Misconfiguration Checker better. This is
a small, dependency-free tool, and contributions that keep it that way
are especially welcome.

## Quick steps

1. Fork the repository and clone your fork.
2. Create a branch for your change:
   `git checkout -b fix/describe-the-change`
3. Make the change. Keep the tool Python standard library only; do not
   add third-party dependencies.
4. Add or update tests in `tests/` for any behaviour you change.
5. Run the full suite and make sure all tests pass:
   `python3 tests/run_tests.py`
6. Run a smoke check of the CLI:
   `python3 cors_misconfig_checker.py --headers "Access-Control-Allow-Origin: https://app.example"`
7. Open a pull request describing the change and why it helps. Fill in
   the pull request template.

## What to work on

- A new check for a real CORS hardening rule, with tests and a README
  entry in the "What it checks" table.
- Better plain-language wording for a finding or its fix.
- Documentation fixes, typo corrections, and clearer examples.
- Bug reports: include the command you ran, the headers or URL
  involved, and the output you got versus what you expected.

## Ground rules

- **No new dependencies.** The whole point of this tool is that it
  runs on a clean machine with only Python 3.10+.
- **No behaviour change without a test.** Every new check or scoring
  change needs a test in `tests/test_cors_misconfig_checker.py`.
- **Keep scores honest.** Do not tune deductions to flatter a
  particular site. Deductions are 25 / 10 / 3 per high / medium / low
  finding, and grade bands are A 90+, B 75+, C 60+, D 40+, F below 40.
- **Keep the README truthful.** Document only what the code actually
  does. If you are unsure about a claim, mark it `TODO: verify`
  instead of guessing.
- **Test against your own sites only, or sites you have permission to
  test.** The tool sends an attacker-style Origin header on purpose;
  use it responsibly.
- **No secrets, ever.** The tool sends only anonymous read-only GET
  and OPTIONS requests. Never add credentials, tokens, or tracking.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a security issue

Do not open a public issue for a security problem. See
[SECURITY.md](SECURITY.md) for how to report it privately.
