# backend/src/email_analysis/__init__.py
# Email Analysis module - parses emails and checks for phishing
# Member: Giovanni
#
# HOW IT WORKS:
# 1. parse_email()       - splits email into subject, body, URLs, attachments
# 2. check_urls()        - checks each URL for suspicious patterns
# 3. check_headers()     - checks if sender is spoofed
# 4. check_attachments() - checks if attachments are dangerous
# Returns one dict that Masaba's risk_scorer uses to calculate RED/YELLOW/GREEN

from src.email_analysis.parser import parse_email
from src.email_analysis.url_checker import check_urls
from src.email_analysis.header_checker import check_headers
from src.email_analysis.attachment import check_attachments


def analyse_email(raw_text):
    """Run full analysis pipeline on raw email text."""
    parsed = parse_email(raw_text)
    return {
        'subject':             parsed['subject'],
        'sender':              parsed['from'],
        'reply_to':            parsed['reply_to'],
        'body_text':           parsed['body_text'],
        'all_urls':            parsed['urls'],
        'suspicious_urls':     check_urls(parsed['urls']),
        'header_findings':     check_headers(parsed),
        'attachment_findings': check_attachments(parsed['attachments']),
        'attachments':         parsed['attachments'],
    }
