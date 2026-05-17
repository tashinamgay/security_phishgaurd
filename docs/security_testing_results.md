# Security Testing Results

## SAST: Bandit

Command:

```bash
python -m bandit -r backend -x backend\venv,backend\tests -lll -f txt -o docs\security\bandit_report.txt
```

Result:

- High severity issues: 0
- Report saved to `docs/security/bandit_report.txt`
- Screenshot saved to `docs/screenshots/bandit_report.png`

Remediation completed:

- Flask debug mode was changed from hardcoded `debug=True` to environment-controlled `FLASK_DEBUG`.
- CSRF protection was re-enabled for browser forms.

## Dependency scan: pip-audit

Command:

```bash
python -m pip_audit -r backend\requirements.txt --desc --format json --output docs\security\pip_audit_report.json
```

Result:

- Known vulnerable dependencies found: 0
- Report saved to `docs/security/pip_audit_report.json`
- Screenshot saved to `docs/screenshots/pip_audit_summary.png`

## Functional and security regression tests: pytest

Command:

```bash
python -m pytest tests -v --cov=src --cov-report=term-missing
```

Result:

- Tests passed: 56
- Total coverage: 47%
- Report saved to `docs/testing/pytest_coverage.txt`
- Screenshot saved to `docs/screenshots/pytest_coverage.png`

## OWASP Top 10 mapping

Broken Access Control:

- Added a regression test proving analysts cannot export another user's PDF analysis report.
- Relevant test: `test_pdf_export_blocks_access_to_other_users_analysis`.

Security Misconfiguration:

- Removed hardcoded Flask debug mode.
- Relevant test: `test_flask_debug_mode_is_not_hardcoded_true`.

Cross-Site Request Forgery:

- Re-enabled CSRF for browser forms.
- Kept API endpoints separately exempt for Postman testing.
- Relevant tests: `test_csrf_enabled_by_default`, `test_browser_form_post_without_csrf_is_rejected`, and `test_json_analyse_api_is_csrf_exempt_for_postman_testing`.

Vulnerable and Outdated Components:

- Added pip-audit dependency scan.
- Current result: no known vulnerable dependencies found.
