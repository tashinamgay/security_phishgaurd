# PhishGuard DevSecOps Changes

Date: 2026-05-17

## Security configuration fixes

- Re-enabled CSRF protection for browser forms by default.
- Exempted only the JSON API endpoints used for Postman testing.
- Removed hardcoded `debug=True`; Flask debug mode is now controlled by the `FLASK_DEBUG` environment variable.
- Fixed a broken access control issue in PDF export so analysts cannot export another user's analysis by guessing an ID.

## Pipeline improvements

The GitHub Actions pipeline now follows the required DevSecOps flow:

```text
Build -> SAST -> Dependency Scan -> Test -> DAST -> Deploy Gate
```

Implemented stages:

- Build and dependency installation.
- Bandit SAST scan with an uploaded report.
- pip-audit dependency vulnerability scan with an uploaded report.
- pytest with coverage and an uploaded test report.
- OWASP ZAP baseline DAST scan against the running Flask app.
- Deploy gate that only runs after the security and test stages complete.

## Additional tests added

Added focused tests for:

- CSRF enabled by default.
- Browser form POST rejected without CSRF token.
- JSON API endpoint remains available for Postman testing without CSRF.
- Flask debug mode is not hardcoded.
- Invalid 2FA token rejection.
- ML training rejects invalid CSV input.
- PDF export blocks access to other users' analysis records.

## Evidence files

- `docs/testing/pytest_coverage.txt`
- `docs/security/bandit_report.txt`
- `docs/security/pip_audit_report.json`
- `docs/security/pip_audit_summary.txt`
- `docs/screenshots/pytest_coverage.png`
- `docs/screenshots/bandit_report.png`
- `docs/screenshots/pip_audit_summary.png`
