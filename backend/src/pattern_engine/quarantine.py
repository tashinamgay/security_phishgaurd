# backend/src/pattern_engine/quarantine.py
# Email quarantine - isolates RED (high risk) emails
# Member: Masaba (Pattern & Risk Engine Lead)
#
# SIMPLE EXPLANATION:
# When an email scores RED it is automatically quarantined
# Quarantined emails are stored separately for admin review
# Admin can review and release or keep them quarantined
#
# HOW IT WORKS:
# 1. RED email detected by risk_scorer
# 2. quarantine_email() saves it to quarantine collection
# 3. Admin sees it on Quarantine page
# 4. Admin clicks Release to let it through

from datetime import datetime
from bson import ObjectId
from src.database import get_db
from src.database.collections import QUARANTINE, ANALYSES, new_quarantine


def quarantine_email(analysis_id, raw_content):
    """
    Save a RED email to quarantine.
    Called automatically when risk_level == RED.
    Skips if already quarantined to avoid duplicates.
    """
    db = get_db()

    # Skip if already quarantined
    if db[QUARANTINE].find_one({'analysis_id': ObjectId(analysis_id)}):
        return

    # Save email to quarantine collection
    db[QUARANTINE].insert_one(new_quarantine(analysis_id, raw_content))

    # Update analysis record to show it's quarantined
    db[ANALYSES].update_one(
        {'_id': ObjectId(analysis_id)},
        {'$set': {'is_quarantined': True}}
    )


def release_email(quarantine_id, admin_id):
    """
    Admin releases an email from quarantine after reviewing it.
    Records which admin released it and when.
    """
    db = get_db()
    q  = db[QUARANTINE].find_one({'_id': ObjectId(quarantine_id)})
    if not q:
        return False

    # Mark as released with admin details
    db[QUARANTINE].update_one(
        {'_id': ObjectId(quarantine_id)},
        {'$set': {
            'released_by': ObjectId(admin_id),  # which admin released it
            'released_at': datetime.utcnow(),   # when it was released
        }}
    )

    # Update analysis to show no longer quarantined
    db[ANALYSES].update_one(
        {'_id': q['analysis_id']},
        {'$set': {'is_quarantined': False}}
    )
    return True


def get_quarantined():
    """Return all emails currently in quarantine (not yet released)."""
    return list(get_db()[QUARANTINE].find(
        {'released_by': None}  # only unreleased emails
    ).sort('quarantined_at', -1))
