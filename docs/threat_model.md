# PhishGuard Threat Model

## Scope

This threat model covers the PhishGuard web application, its authentication system, phishing analysis workflow, MongoDB data storage, report exports, and DevSecOps testing pipeline.

## STRIDE Analysis

| STRIDE category | Example threat | Mitigation |
|---|---|---|
| Spoofing | Attacker tries to log in as another user | bcrypt password hashing, 2FA, failed-login logging |
| Tampering | User modifies or deletes another user's analysis | login-required routes, ownership checks, admin-only controls |
| Repudiation | User denies suspicious login activity | login attempts recorded with username, IP address, timestamp, and success/failure |
| Information disclosure | User guesses another analysis ID and downloads PDF | PDF export now verifies record ownership before returning the file |
| Denial of service | Repeated login attempts overload authentication | failed-attempt limit and performance testing with Locust |
| Elevation of privilege | Analyst accesses admin pages | `@admin_required` RBAC decorator on admin functions |

## OWASP Top 10 Mapping

### A01: Broken Access Control

Risk:

- Analyst or unauthenticated user accesses admin-only pages.
- Analyst downloads another user's analysis report.

Controls:

- `@login_required` protects dashboard routes.
- `@admin_required` protects admin routes.
- PDF export checks that the current user owns the analysis unless the user is admin.

Evidence:

- `tests/test_security_controls.py`
- `docs/testing/pytest_coverage.txt`

### A05: Security Misconfiguration

Risk:

- Flask debug mode exposes development debugger in production.
- CSRF disabled globally.

Controls:

- Debug mode is controlled by the `FLASK_DEBUG` environment variable.
- CSRF is enabled by default for browser forms.

Evidence:

- `docs/security/bandit_report.txt`
- `tests/test_security_controls.py`

### A06: Vulnerable and Outdated Components

Risk:

- Third-party dependency contains known CVEs.

Controls:

- pip-audit dependency scan is included in the CI pipeline.
- Local scan evidence is saved under `docs/security/`.

Evidence:

- `docs/security/pip_audit_report.json`
- `docs/security/pip_audit_summary.txt`

### A07: Identification and Authentication Failures

Risk:

- Brute force login attempts.
- Weak authentication flow.

Controls:

- bcrypt password hashing.
- 2FA support.
- failed-login logging and failed-attempt limit.

Evidence:

- `backend/src/auth/routes.py`
- `backend/src/auth/twofa.py`
- `docs/incident_response.md`

## Risk Register

| ID | Risk | Likelihood | Impact | Response |
|---|---|---|---|---|
| R1 | User accesses another user's report | Medium | High | Ownership check added to PDF export |
| R2 | Debug mode enabled in production | Medium | High | Debug now controlled by environment variable |
| R3 | CSRF on form submissions | Medium | Medium | CSRF enabled for browser forms |
| R4 | Dependency vulnerability | Medium | Medium | pip-audit added to local evidence and CI |
| R5 | Brute force login attempt | Medium | Medium | Failed attempts logged; lockout behavior documented |

## Ethical Boundary

All testing must target only the PhishGuard coursework application and authorised local or CI environments. ZAP and other security tools must not be pointed at third-party systems without permission.
