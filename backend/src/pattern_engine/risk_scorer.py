# backend/src/pattern_engine/risk_scorer.py
# Calculates RED / YELLOW / GREEN risk score
# Member: Masaba (Pattern & Risk Engine Lead)
#
# SCORING POINTS:
# Spoofed header          = +30 each
# Dangerous attachment    = +25 HIGH / +10 MEDIUM
# Suspicious URL          = +10 each (max 30)
# Suspicious domain words = +25 (e.g. secure-bank-verify-login.com)
# Urgency keywords        = +8 each (max 24)
# Financial keywords      = +5 each (max 15)
# Credential keywords     = +8 each (max 16)
# Job scam keywords       = +10 each (max 30)
# Multiple categories     = +15 bonus (if 2+ categories triggered)
# Suspicious login link   = +15
# Urgency action phrases  = +10 each
# Credit card pattern     = +5

import re
from src.pattern_engine.keywords import ALL_CATEGORIES

# Suspicious words commonly found in phishing domain names
SUSPICIOUS_DOMAIN_WORDS = [
    'verify', 'verification', 'secure', 'login', 'update',
    'confirm', 'account', 'suspend', 'banking', 'bank',
    'paypal', 'amazon', 'microsoft', 'apple', 'google',
    'netflix', 'irs', 'alert', 'warning', 'security'
]


def score_email(analysis):
    """
    Calculate risk score from email analysis dict.
    Returns: {'risk_level': RED/YELLOW/GREEN, 'risk_score': 0-100, 'reasons': [...]}
    """
    score   = 0
    reasons = []
    body    = (analysis.get('body_text') or '').lower()

    # ── 1. Header spoofing (+30 each) ────────────────────
    for f in analysis.get('header_findings', []):
        score += 30
        reasons.append(f'[HEADER] {f}')

    # ── 2. Dangerous attachments ─────────────────────────
    for af in analysis.get('attachment_findings', []):
        score += 25 if af['severity'] == 'HIGH' else 10
        reasons.append(f'[ATTACHMENT] {af["filename"]}: {af["reason"]}')

    # ── 3. Suspicious URLs (+10 each, max 30) ────────────
    sus = analysis.get('suspicious_urls', [])
    score += min(len(sus) * 10, 30)
    for u in sus:
        for r in u['reasons']:
            reasons.append(f'[URL] {u["url"][:70]}: {r}')

    # ── 4. Suspicious domain words check ─────────────────
    # Catches domains like: secure-bank-verification-login.com
    # which have multiple suspicious words but no bad TLD
    all_urls = analysis.get('all_urls', [])
    for url in all_urls:
        url_lower = url.lower()
        hits = [w for w in SUSPICIOUS_DOMAIN_WORDS if w in url_lower]
        if len(hits) >= 2:
            score += 25
            reasons.append(
                f'[URL] Highly suspicious domain — multiple phishing '
                f'words detected: {", ".join(hits[:5])}'
            )
            break  # only count once

    # ── 5. Keywords in body ───────────────────────────────
    caps    = {'urgency': 24, 'financial': 15, 'credentials': 16, 'job_scam': 30}
    weights = {'urgency':  8, 'financial':  5, 'credentials':  8, 'job_scam': 10}
    categories_triggered = 0

    for cat, kws in ALL_CATEGORIES.items():
        pts    = 0
        cap    = caps.get(cat, 20)
        weight = weights.get(cat, 5)
        for kw in kws:
            if kw in body and pts < cap:
                pts += weight
                reasons.append(
                    f'[KEYWORD:{cat.upper()}] "{kw}" found in email body'
                )
        if pts > 0:
            categories_triggered += 1
        score += min(pts, cap)

    # ── 6. Bonus: multiple categories triggered ───────────
    if categories_triggered >= 2:
        score += 15
        reasons.append(
            f'[PATTERN] {categories_triggered} phishing keyword categories '
            f'detected simultaneously — elevated risk'
        )

    # ── 7. Suspicious login/verify link in body ──────────
    if re.search(
        r'https?://[^\s]*(?:login|verify|confirm|secure|update|suspend)[^\s]*',
        body, re.I
    ):
        score += 15
        reasons.append('[PATTERN] Suspicious verify/login/suspend link in body')

    # ── 8. Urgency action phrases ─────────────────────────
    urgency_patterns = [
        (r'account.{0,20}suspend',               'Account suspension threat detected'),
        (r'suspend.{0,20}account',               'Account suspension threat detected'),
        (r'verify.{0,20}immediately',            'Immediate verification demand'),
        (r'immediately.{0,20}verify',            'Immediate verification demand'),
        (r'click.{0,20}link.{0,20}login',        'Click link to login demand'),
        (r'login.{0,20}username.{0,20}password', 'Username and password request'),
        (r'failure.{0,20}verify',                'Failure to verify threat'),
        (r'unusual.{0,20}activity',              'Unusual activity claim detected'),
        (r'permanent.{0,20}clos',                'Permanent account closure threat'),
    ]
    for pattern, msg in urgency_patterns:
        if re.search(pattern, body, re.I):
            score += 10
            reasons.append(f'[PATTERN] {msg}')

    # ── 9. Credit card number pattern ────────────────────
    if re.search(r'\b(?:\d[ -]?){13,16}\b', body):
        score += 5
        reasons.append('[PATTERN] Possible credit card number in body')

    # ── 10. Cap score at 100 ─────────────────────────────
    score = min(score, 100)

    if score >= 70:
        level = 'RED'
    elif score >= 40:
        level = 'YELLOW'
    else:
        level = 'GREEN'

    return {'risk_level': level, 'risk_score': score, 'reasons': reasons}
