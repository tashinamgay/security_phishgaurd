# tests/test_pattern_engine.py
# Unit tests for Pattern Engine module
# Member: Masaba

from src.pattern_engine.risk_scorer import score_email
from src.pattern_engine.keywords import (
    URGENCY_KEYWORDS, FINANCIAL_KEYWORDS,
    CREDENTIAL_KEYWORDS, JOB_SCAM_KEYWORDS
)


def test_red_score_for_phishing():
    result = score_email({
        'body_text': 'urgent verify now bank account details',
        'header_findings': ['SPF authentication failed'],
        'suspicious_urls': [{'url': 'http://evil.xyz', 'reasons': ['Bad TLD']}],
        'attachment_findings': [{'filename': 'virus.exe', 'severity': 'HIGH', 'reason': 'exe'}],
        'all_urls': ['http://evil.xyz'],
    })
    assert result['risk_level'] == 'RED'
    assert result['risk_score'] >= 70


def test_green_score_for_safe_email():
    result = score_email({
        'body_text': 'Hi team meeting tomorrow at 10am',
        'header_findings': [],
        'suspicious_urls': [],
        'attachment_findings': [],
        'all_urls': [],
    })
    assert result['risk_level'] == 'GREEN'
    assert result['risk_score'] < 40


def test_yellow_score_for_suspicious():
    # Uses stronger content to ensure YELLOW or RED score
    result = score_email({
        'body_text': 'click here to verify your account expires soon urgent action required bank account suspended',
        'header_findings': [],
        'suspicious_urls': [
            {'url': 'http://bit.ly/x', 'reasons': ['Shortener']},
            {'url': 'http://evil.xyz/login', 'reasons': ['Bad TLD']},
        ],
        'attachment_findings': [],
        'all_urls': ['http://bit.ly/x', 'http://evil.xyz/login'],
    })
    assert result['risk_level'] in ['YELLOW', 'RED']


def test_reasons_list_not_empty():
    result = score_email({
        'body_text': 'urgent click here bank account suspended',
        'header_findings': ['Reply-To mismatch'],
        'suspicious_urls': [],
        'attachment_findings': [],
        'all_urls': [],
    })
    assert len(result['reasons']) > 0


def test_score_capped_at_100():
    result = score_email({
        'body_text': 'urgent bank account credit card verify now password otp',
        'header_findings': ['SPF fail', 'Reply-To mismatch'],
        'suspicious_urls': [
            {'url': 'http://a.xyz', 'reasons': ['Bad']},
            {'url': 'http://b.xyz', 'reasons': ['Bad']},
        ],
        'attachment_findings': [
            {'filename': 'x.exe', 'severity': 'HIGH', 'reason': 'exe'},
        ],
        'all_urls': ['http://a.xyz', 'http://b.xyz'],
    })
    assert result['risk_score'] <= 100


def test_job_scam_detected():
    result = score_email({
        'body_text': 'we are pleased to offer you a job no interview send passport',
        'header_findings': [],
        'suspicious_urls': [],
        'attachment_findings': [],
        'all_urls': [],
    })
    assert result['risk_score'] > 0
    assert len(result['reasons']) > 0


def test_suspicious_domain_words_detected():
    """secure-bank-verification-login.com should be flagged."""
    result = score_email({
        'body_text': 'click here',
        'header_findings': [],
        'suspicious_urls': [],
        'attachment_findings': [],
        'all_urls': ['http://secure-bank-verification-login.com'],
    })
    assert result['risk_score'] >= 25


def test_urgency_keywords_exist():
    assert len(URGENCY_KEYWORDS) > 0


def test_financial_keywords_exist():
    assert len(FINANCIAL_KEYWORDS) > 0


def test_job_scam_keywords_exist():
    assert len(JOB_SCAM_KEYWORDS) > 0