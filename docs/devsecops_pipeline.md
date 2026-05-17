# PhishGuard DevSecOps Pipeline

## Pipeline Goal

The DevSecOps pipeline integrates security checks into the software delivery process. The goal is to make security testing repeatable and automatic instead of leaving it until the end of the project.

## Pipeline Flow

```text
Push / Pull Request
  |
  v
Build
  |
  +--> SAST: Bandit
  |
  +--> Dependency Scan: pip-audit
  |
  v
Tests: pytest + coverage
  |
  v
DAST: OWASP ZAP baseline scan
  |
  v
Deploy Gate
```

## Stage Details

### 1. Build

Purpose:

- Install Python dependencies from `backend/requirements.txt`.
- Confirm the project can be set up in a clean environment.

Failure condition:

- Missing packages or dependency installation failure.

### 2. SAST: Bandit

Purpose:

- Scan Python source code for insecure coding patterns.

Configuration:

- Scans backend code.
- Excludes virtual environment and test folders.
- Produces `docs/security/bandit_report.txt`.

Evidence:

- Local evidence file: `docs/security/bandit_report.txt`
- Screenshot: `docs/screenshots/bandit_report.png`

### 3. Dependency Scan: pip-audit

Purpose:

- Check Python dependencies for known vulnerabilities.

Configuration:

- Reads `backend/requirements.txt`.
- Produces JSON report.

Evidence:

- `docs/security/pip_audit_report.json`
- `docs/security/pip_audit_summary.txt`
- `docs/screenshots/pip_audit_summary.png`

### 4. Tests: pytest and coverage

Purpose:

- Run functional and security regression tests.
- Confirm access control, CSRF behavior, API behavior, ML validation, 2FA rejection, and phishing analysis logic.

Evidence:

- `docs/testing/pytest_coverage.txt`
- `docs/screenshots/pytest_coverage.png`

Current verified result:

```text
56 tests passed
47% total coverage
```

### 5. DAST: OWASP ZAP

Purpose:

- Run a dynamic baseline scan against the running Flask application.
- Identify common web security misconfigurations.

Configuration:

- Pipeline starts the Flask app in non-debug mode.
- ZAP scans `http://127.0.0.1:5000`.
- ZAP report is uploaded as a CI artifact.

### 6. Deploy Gate

Purpose:

- Deployment is allowed only after build, security scans, tests, and DAST complete.

Current status:

- The coursework pipeline uses a deploy gate/confirmation step rather than real production deployment.

## Pipeline File

The CI/CD workflow is defined in:

```text
.github/workflows/security.yml
```
