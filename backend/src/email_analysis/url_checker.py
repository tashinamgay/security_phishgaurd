# backend/src/email_analysis/url_checker.py
# Checks URLs for suspicious phishing patterns
# Member: Giovanni
#
# SIMPLE EXPLANATION:
# Phishing emails use tricks in their URLs to look legitimate:
# - Suspicious domains (.xyz .tk .ru) - cheap domains used by scammers
# - URL shorteners (bit.ly) - hide the real destination
# - IP addresses instead of names (http://192.168.1.1)
# - Brand names in fake domains (paypal.evil.xyz)
# - Too many subdomains (verify.login.paypal.evil.com)
# - HTTP instead of HTTPS (not encrypted)

from urllib.parse import urlparse
import re

# Cheap domain extensions commonly used by phishers
SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.ru',
    '.pw', '.top', '.click', '.gq', '.loan', '.work'
]

# URL shorteners hide the real destination link
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
    'ow.ly', 'shorte.st', 'adf.ly', 'is.gd'
]

# Brands commonly copied in phishing emails
IMPERSONATED = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon',
    'netflix', 'facebook', 'irs', 'bank', 'nab', 'anz', 'westpac'
]


def check_urls(urls):
    """
    Check each URL for phishing patterns.
    Returns list of suspicious URLs with reasons.
    """
    suspicious = []
    for url in urls:
        reasons = []
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check 1: Suspicious domain extension
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    reasons.append(f'Suspicious TLD: {tld}')

            # Check 2: URL shortener hides real destination
            for s in URL_SHORTENERS:
                if s in domain:
                    reasons.append(f'URL shortener detected: {s}')

            # Check 3: IP address instead of domain name
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]):
                reasons.append('IP address used instead of domain name')

            # Check 4: Brand name in domain but not official site
            # e.g. paypal.secure-login.xyz has paypal but is NOT paypal.com
            for brand in IMPERSONATED:
                if brand in domain and not domain.endswith(f'{brand}.com'):
                    reasons.append(f'Possible brand impersonation: {brand}')

            # Check 5: Too many subdomains = suspicious
            if domain.count('.') > 3:
                reasons.append('Excessive subdomains - possible spoofed domain')

            # Check 6: HTTP is not encrypted (legitimate sites use HTTPS)
            if parsed.scheme == 'http':
                reasons.append('Insecure HTTP link (not HTTPS)')

        except Exception:
            reasons.append('Malformed URL detected')

        if reasons:
            suspicious.append({'url': url, 'reasons': reasons})

    return suspicious
