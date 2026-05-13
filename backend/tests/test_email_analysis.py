# tests/test_email_analysis.py
# Unit tests for Email Analysis module
# Member: Giovanni

from src.email_analysis.url_checker import check_urls
from src.email_analysis.attachment import check_attachments
from src.email_analysis.header_checker import check_headers
from src.email_analysis.parser import parse_email


# URL Tests
def test_suspicious_tld_flagged():
    assert len(check_urls(['http://fakebank.xyz/login'])) > 0


def test_url_shortener_flagged():
    assert len(check_urls(['https://bit.ly/abc123'])) > 0


def test_safe_url_not_flagged():
    assert len(check_urls(['https://www.google.com'])) == 0


def test_ip_address_flagged():
    assert len(check_urls(['http://192.168.1.1/login'])) > 0


def test_http_flagged():
    result = check_urls(['http://suspicious-site.xyz'])
    assert len(result) > 0


# Attachment Tests
def test_exe_flagged_as_high():
    result = check_attachments(['virus.exe'])
    assert result[0]['severity'] == 'HIGH'


def test_double_extension_flagged():
    assert len(check_attachments(['invoice.pdf.exe'])) > 0


def test_pdf_not_flagged():
    assert len(check_attachments(['report.pdf'])) == 0


def test_zip_flagged_as_medium():
    result = check_attachments(['files.zip'])
    assert result[0]['severity'] == 'MEDIUM'


# Parser Tests
def test_parser_extracts_subject():
    raw = 'Subject: Test Email\nFrom: a@b.com\n\nHello'
    assert parse_email(raw)['subject'] == 'Test Email'


def test_parser_extracts_sender():
    raw = 'Subject: Test\nFrom: sender@test.com\n\nBody'
    assert 'sender@test.com' in parse_email(raw)['from']


def test_parser_extracts_urls():
    raw = 'Subject: Test\nFrom: a@b.com\n\nClick http://evil.xyz/login'
    assert len(parse_email(raw)['urls']) > 0


# Header Tests
def test_reply_to_mismatch_detected():
    parsed = {
        'from': 'PayPal <support@paypal.com>',
        'reply_to': 'hacker@evil.ru',
        'headers': {}
    }
    assert len(check_headers(parsed)) > 0


def test_clean_headers_not_flagged():
    parsed = {
        'from': 'John <john@company.com>',
        'reply_to': 'john@company.com',
        'headers': {}
    }
    assert len(check_headers(parsed)) == 0
