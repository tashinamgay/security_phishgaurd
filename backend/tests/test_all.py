# backend/tests/test_all.py
# Unit tests for all modules
# Run with: pytest tests/ -v
#
# SIMPLE EXPLANATION:
# Tests verify each function works correctly
# Run before committing to make sure nothing is broken
# GitHub Actions CI/CD runs these automatically on every push

import pytest

# ══════════════════════════════════════════════════════════
# AUTH TESTS - Member: Tashi
# ══════════════════════════════════════════════════════════

from app import create_app

@pytest.fixture
def client():
    """Create test Flask app with in-memory settings."""
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,  # disable CSRF for testing
        MONGO_URI='mongodb://localhost:27017/phishguard_test'
    )
    with app.test_client() as c:
        yield c


def test_register_page_loads(client):
    """Register page should load successfully."""
    r = client.get('/auth/register')
    assert r.status_code == 200


def test_login_page_loads(client):
    """Login page should load successfully."""
    r = client.get('/auth/login')
    assert r.status_code == 200


# ══════════════════════════════════════════════════════════
# EMAIL ANALYSIS TESTS - Member: Giovanni
# ══════════════════════════════════════════════════════════

from src.email_analysis.url_checker import check_urls
from src.email_analysis.attachment import check_attachments
from src.email_analysis.parser import parse_email


def test_suspicious_tld_flagged():
    """URLs with suspicious TLDs like .xyz should be flagged."""
    result = check_urls(['http://fakebank.xyz/login'])
    assert len(result) > 0


def test_url_shortener_flagged():
    """URL shorteners like bit.ly should be flagged."""
    result = check_urls(['https://bit.ly/abc123'])
    assert len(result) > 0


def test_safe_url_not_flagged():
    """Known safe URLs like google.com should NOT be flagged."""
    result = check_urls(['https://www.google.com'])
    assert len(result) == 0


def test_dangerous_attachment_flagged():
    """Executable attachments like .exe should be flagged as HIGH."""
    result = check_attachments(['virus.exe'])
    assert len(result) > 0
    assert result[0]['severity'] == 'HIGH'


def test_double_extension_flagged():
    """Double extension files like invoice.pdf.exe should be flagged."""
    result = check_attachments(['invoice.pdf.exe'])
    assert len(result) > 0


def test_safe_pdf_not_flagged():
    """Regular PDF files should NOT be flagged."""
    result = check_attachments(['report.pdf'])
    assert len(result) == 0


def test_email_parser_extracts_subject():
    """Parser should correctly extract email subject."""
    raw    = 'Subject: Test Email\nFrom: a@b.com\n\nHello'
    parsed = parse_email(raw)
    assert parsed['subject'] == 'Test Email'


# ══════════════════════════════════════════════════════════
# PATTERN ENGINE TESTS - Member: Masaba
# ══════════════════════════════════════════════════════════

from src.pattern_engine.risk_scorer import score_email


def test_red_risk_for_phishing_email():
    """Email with spoofed header, bad URL and dangerous attachment = RED."""
    result = score_email({
        'body_text': 'urgent verify now bank account wire transfer',
        'header_findings': ['SPF authentication failed'],
        'suspicious_urls': [{'url': 'http://evil.xyz', 'reasons': ['Bad TLD']}],
        'attachment_findings': [{'filename': 'virus.exe', 'severity': 'HIGH',
                                  'reason': 'Executable file'}],
    })
    assert result['risk_level'] == 'RED'
    assert result['risk_score'] >= 70


def test_green_risk_for_safe_email():
    """Clean email with no indicators should be GREEN."""
    result = score_email({
        'body_text': 'Hi team, meeting tomorrow at 10am.',
        'header_findings': [],
        'suspicious_urls': [],
        'attachment_findings': [],
    })
    assert result['risk_level'] == 'GREEN'
    assert result['risk_score'] < 40


def test_job_scam_detected():
    """Job scam email should be flagged."""
    result = score_email({
        'body_text': 'we are pleased to offer you a job position salary no interview required send passport',
        'header_findings': [],
        'suspicious_urls': [],
        'attachment_findings': [],
    })
    assert result['risk_score'] > 0
    assert len(result['reasons']) > 0


def test_reasons_populated_for_risky_email():
    """Risk reasons list should not be empty for suspicious emails."""
    result = score_email({
        'body_text': 'click here immediately account suspended urgent',
        'header_findings': ['Reply-To mismatch'],
        'suspicious_urls': [],
        'attachment_findings': [],
    })
    assert len(result['reasons']) > 0
