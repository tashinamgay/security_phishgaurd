# backend/src/pattern_engine/keywords.py
# Phishing keyword lists for pattern matching
# Member: Masaba (Pattern & Risk Engine Lead)
#
# SIMPLE EXPLANATION:
# Phishing emails use specific words to trick victims
# We search the email body for these words
# Each match adds points to the risk score
#
# 4 CATEGORIES:
# 1. URGENCY     - pressure to act fast without thinking
# 2. FINANCIAL   - lure with money or request financial details
# 3. CREDENTIALS - ask for passwords or personal documents
# 4. JOB_SCAM    - fake job offers to get personal details

# Words that create urgency - phishers rush victims to act without thinking
URGENCY_KEYWORDS = [
    'urgent', 'immediate action', 'act now', 'account suspended',
    'account will be closed', 'verify now', 'limited time',
    'expires soon', 'last chance', 'final notice', 'within 24 hours',
    'within 48 hours', 'unauthorized access', 'click here immediately',
    'your account has been compromised', 'failure to respond',
    'no interview required', 'act immediately', 'respond now',
    'time sensitive',
]

# Financial words used to lure victims
FINANCIAL_KEYWORDS = [
    'bank account', 'credit card', 'wire transfer', 'payment required',
    'invoice attached', 'tax refund', 'claim your prize', 'you have won',
    'lottery', 'unclaimed funds', 'bitcoin', 'cryptocurrency',
    'gift card', 'western union', 'money transfer', 'billing information',
    'salary processing', 'salary of', 'per month', 'send your bank',
    'bank details', 'account details', 'processing fee', 'send money',
]

# Words requesting passwords or personal documents
CREDENTIAL_KEYWORDS = [
    'enter your password', 'confirm your password', 'reset your password',
    'verify your identity', 'confirm your account', 'update your information',
    'social security', 'security question', 'pin number', 'otp',
    'one time password', 'mother maiden name', 'passport copy',
    'send your passport', 'passport details', 'id copy',
    'driving licence', 'personal details', 'date of birth',
]

# Fake job offer words - get personal details via fake employment
JOB_SCAM_KEYWORDS = [
    'job offer', 'job position', 'work from home', 'earn from home',
    'no interview', 'no experience', 'guaranteed salary', 'weekly payment',
    'part time job', 'online job', 'home based job', 'immediate hiring',
    'we are pleased to offer', 'job opportunity', 'employment offer',
    'kindly send', 'please send your', 'send your details',
]

# All categories - risk_scorer.py loops through this dict
ALL_CATEGORIES = {
    'urgency':     URGENCY_KEYWORDS,
    'financial':   FINANCIAL_KEYWORDS,
    'credentials': CREDENTIAL_KEYWORDS,
    'job_scam':    JOB_SCAM_KEYWORDS,
}
