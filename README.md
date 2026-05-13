# 🛡️ PhishGuard — Phishing Email Detector
> ICT932 Cybersecurity Assessment 3 — Group Project

---

## 👥 Team Members

| Member | Role | GitHub Branch |
|--------|------|---------------|
| **Tashi** | Auth & Security Lead | feature/auth |
| **Giovanni** | Email Analysis Lead | feature/email-engine |
| **Masaba** | Pattern & Risk Engine Lead | feature/pattern-engine |
| **Aditi** | Frontend & DevOps Lead | feature/dashboard |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/tashinamgay/phishing-email-detector.git
cd phishing-email-detector
```

### 2. Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
```

### 3. Configure .env
```bash
copy .env.example .env
```
Edit `.env` and add your MongoDB Atlas URI:
```
SECRET_KEY=phishguard-secret-key-2024
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/phishguard_ict932?retryWrites=true&w=majority&appName=Cluster0
FLASK_ENV=development
OPENAI_API_KEY=optional
```

### 4. Run
```bash
python app.py
```
Open: **http://localhost:5000**

> ⭐ First user to register = Admin automatically!

---

## 📁 Project Structure

```
├── backend/
│   ├── app.py                    ← Start server here
│   ├── src/
│   │   ├── auth/                 ← Tashi: Login, RBAC, 2FA
│   │   ├── email_analysis/       ← Giovanni: Parser, URLs, Headers
│   │   ├── pattern_engine/       ← Masaba: Scoring, ML, Quarantine
│   │   ├── dashboard/            ← Aditi: Routes, PDF/CSV
│   │   └── database/             ← MongoDB helpers
│   ├── tests/                    ← All unit tests
│   └── locustfile.py             ← Performance testing
└── frontend/
    ├── templates/                ← All HTML pages
    └── static/                   ← CSS + JS
```

---

## ✅ Features

- 🔐 Secure login with RBAC (Admin/Analyst)
- 📱 Two-Factor Authentication (2FA)
- 👥 Admin: approve/suspend/delete/change role
- 🔍 URL analysis (suspicious domains, shorteners)
- 📋 Header analysis (spoofed sender detection)
- 🔑 Keyword matching (urgency, financial, credentials, job scams)
- 📎 Attachment safety checking
- 🤖 AI explanation of findings
- 🧠 ML classifier (optional)
- 🔴 RED/YELLOW/GREEN risk scoring
- 🔒 Auto-quarantine RED emails
- 📥 PDF + CSV export
- 📊 Admin security panel
- 📱 Fully responsive design

---

## 🧪 Running Tests

```bash
cd backend
pytest tests/ -v --cov=src
```

## 🔐 Security Scanning

```bash
# SAST - Bandit
bandit -r src/ -ll -f txt

# Dependency scan
pip install pip-audit
python -m pip_audit

# Performance test
python -m locust -f locustfile.py --host=http://localhost:5000
```

## 🔄 CI/CD Pipeline

```
Push to GitHub → Build → Bandit SAST → Safety Check → pytest → Deploy
```
