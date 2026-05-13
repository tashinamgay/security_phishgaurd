# backend/src/email_analysis/header_checker.py
# Detects spoofed email senders using header analysis
# Member: Giovanni
#
# SIMPLE EXPLANATION:
# Email headers contain hidden information about where email came from
# Phishers trick victims by showing a fake sender name/address
#
# COMMON TRICKS WE DETECT:
# 1. Reply-To != From (reply goes to attacker, not the displayed sender)
# 2. Display name says "PayPal" but email comes from evil.xyz
# 3. SPF check failed (server not authorized to send for that domain)
# 4. Return-Path differs from From address

import re

# Brands commonly faked in email display names
BRANDS = [
    'paypal', 'apple', 'microsoft', 'amazon', 'google',
    'bank', 'irs', 'netflix', 'nab', 'anz', 'westpac'
]


def check_headers(parsed):
    """
    Check email headers for spoofing indicators.
    Returns list of finding strings.
    """
    findings  = []
    from_addr = parsed.get('from', '')      # full From: header
    reply_to  = parsed.get('reply_to', '')  # Reply-To: header
    headers   = parsed.get('headers', {})

    # Check 1: Reply-To is different domain from From
    # Trick: email looks like it's from bank@realbank.com
    # but replies go to hacker@evil.com
    if reply_to and _domain(reply_to) != _domain(from_addr):
        findings.append(
            f'Reply-To ({_domain(reply_to)}) differs from '
            f'From domain ({_domain(from_addr)})'
        )

    # Check 2: Display name impersonates a brand
    # e.g. From: "PayPal Support" <attacker@evil.xyz>
    display = _display_name(from_addr)
    domain  = _domain(from_addr)
    if display:
        for brand in BRANDS:
            if brand in display.lower() and brand not in domain.lower():
                findings.append(
                    f'Display name "{display}" impersonates {brand} '
                    f'but sends from {domain}'
                )

    # Check 3: SPF authentication failed
    # SPF = Sender Policy Framework - proves server can send for that domain
    spf = headers.get('Received-SPF', '')
    if spf and 'fail' in spf.lower():
        findings.append('SPF authentication failed - sender cannot be verified')

    # Check 4: Return-Path mismatch
    # Return-Path = where bounced emails go - should match From
    return_path = headers.get('Return-Path', '')
    if return_path and _domain(return_path) != _domain(from_addr):
        findings.append('Return-Path domain does not match From domain')

    return findings


def _domain(email_str):
    """Extract domain from email string e.g. user@domain.com -> domain.com"""
    m = re.search(r'@([\w.\-]+)', email_str)
    return m.group(1).lower() if m else ''


def _display_name(email_str):
    """Extract display name e.g. 'PayPal Support <x@y.com>' -> 'PayPal Support'"""
    m = re.match(r'^"?([^"<]+)"?\s*<', email_str)
    return m.group(1).strip() if m else ''
