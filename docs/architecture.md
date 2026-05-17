# PhishGuard Architecture

## Overview

PhishGuard is a phishing email detection web application built with a Flask backend, Jinja2 templates, and MongoDB. The application lets authenticated users submit email content or email files, then analyses URLs, headers, attachments, keywords, and ML prediction results to assign a phishing risk score.

## Architecture Diagram

```text
User Browser
  |
  | HTTPS / HTTP requests
  v
Flask Web Application
  |
  |-- auth/
  |     Login, registration, RBAC, 2FA, admin user management
  |
  |-- dashboard/
  |     Analysis pages, reports, quarantine, security panel
  |
  |-- email_analysis/
  |     Email parser, URL checker, header checker, attachment checker
  |
  |-- pattern_engine/
  |     Risk scoring, keyword rules, ML classifier, quarantine logic
  |
  | PyMongo
  v
MongoDB Database
  |
  |-- users
  |-- login_logs
  |-- analyses
  |-- quarantine
```

## Security Architecture

| Layer | Security control |
|---|---|
| Authentication | Flask-Login sessions and bcrypt password hashing |
| Authorisation | Role-Based Access Control with admin and analyst roles |
| 2FA | TOTP-based 2FA using PyOTP and authenticator apps |
| CSRF | Flask-WTF CSRF protection for browser forms |
| API testing | JSON API endpoints are separately CSRF-exempt for Postman testing |
| Input handling | Email uploads limited to `.txt` and `.eml`; ML upload expects CSV |
| Access control | Analysis result and PDF export routes check record ownership |
| Secrets | Runtime secrets loaded from `.env`; `.env` excluded from clean submission zip |
| Monitoring | Login attempts are logged for security review |

## Main User Flow

1. User registers or logs in.
2. Admin approves pending users and manages roles.
3. User enables 2FA.
4. User submits an email for analysis.
5. PhishGuard parses the email and checks URLs, headers, attachments, and keywords.
6. Risk scorer classifies the email as GREEN, YELLOW, or RED.
7. RED emails are quarantined for admin review.
8. User or admin exports reports as PDF or CSV.

## Module Ownership

| Area | Main files |
|---|---|
| Authentication and RBAC | `backend/src/auth/` |
| Email analysis | `backend/src/email_analysis/` |
| Pattern and ML engine | `backend/src/pattern_engine/` |
| Dashboard and reporting | `backend/src/dashboard/` |
| DevSecOps pipeline | `.github/workflows/security.yml` |
