# backend/src/database/collections.py
# MongoDB collection names and document templates
# Member: Tashi
#
# SIMPLE EXPLANATION:
# MongoDB stores data as documents (like JSON/Python dicts)
# Collections are like tables in SQL
# We define templates here so every document has the same structure
#
# Collections used:
#   users      - all user accounts
#   analyses   - all email scan results
#   quarantine - RED emails held for admin review
#   login_logs - every login attempt for security monitoring

from datetime import datetime
from bson import ObjectId

# Collection names - used in routes.py to access the right collection
USERS      = 'users'
ANALYSES   = 'analyses'
QUARANTINE = 'quarantine'
LOGIN_LOGS = 'login_logs'


def new_user(username, email, password_hash, role='analyst', status='pending'):
    """
    Create a new user document.
    - First user: role=admin, status=active (set in auth/routes.py)
    - All others: role=analyst, status=pending (wait for Tashi to approve)
    """
    return {
        'username':      username,
        'email':         email,
        'password_hash': password_hash,  # NEVER store plain password - always bcrypt hash
        'role':          role,           # admin or analyst
        'status':        status,         # active, pending, or suspended
        'twofa_secret':  None,           # PyOTP secret key - set when 2FA enabled
        'twofa_enabled': False,          # True after user scans QR and confirms
        'created_at':    datetime.utcnow(),
    }


def new_analysis(user_id, subject, sender, body,
                 risk_level, risk_score, reasons,
                 url_count, sus_url_count, attach_count,
                 ai_explanation=None):
    """Create a new email analysis result document."""
    return {
        'user_id':              ObjectId(user_id),  # links to user who ran analysis
        'email_subject':        subject,
        'email_sender':         sender,
        'email_body':           body[:2000] if body else '',  # save first 2000 chars only
        'risk_level':           risk_level,           # RED, YELLOW, or GREEN
        'risk_score':           risk_score,           # number from 0 to 100
        'reasons':              reasons,              # list of findings shown on results page
        'ai_explanation':       ai_explanation,       # plain English explanation from AI
        'url_count':            url_count,            # total URLs found in email
        'suspicious_url_count': sus_url_count,        # URLs that failed security checks
        'attachment_count':     attach_count,         # number of file attachments
        'is_quarantined':       False,                # set True if RED email auto-quarantined
        'analysed_at':          datetime.utcnow(),
    }


def new_quarantine(analysis_id, raw_content):
    """Create a quarantine record - stores RED emails safely."""
    return {
        'analysis_id':    ObjectId(analysis_id),  # links to the analysis record
        'raw_content':    raw_content,             # full raw email text stored safely
        'quarantined_at': datetime.utcnow(),
        'released_by':    None,     # admin user id - set when admin releases it
        'released_at':    None,     # timestamp - set when admin releases it
    }


def new_login_log(username, ip, success):
    """Create a login attempt log - used for security monitoring."""
    return {
        'username':  username,
        'ip':        ip,        # IP address of login attempt
        'success':   success,   # True = logged in OK, False = wrong password
        'timestamp': datetime.utcnow(),
    }
