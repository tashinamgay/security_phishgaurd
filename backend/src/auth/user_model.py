# backend/src/auth/user_model.py
# Flask-Login User class for MongoDB
# Member: Tashi
#
# SIMPLE EXPLANATION:
# Flask-Login needs a User class to manage login sessions
# MongoDB returns plain Python dicts - this class wraps them
# so Flask-Login can work with MongoDB users
#
# Flask-Login needs these properties:
#   get_id()         - returns user ID as string
#   is_authenticated - True if logged in
#   is_active        - False if suspended (blocks login)
#   is_anonymous     - True if not logged in

from flask_login import UserMixin
from bson import ObjectId


class MongoUser(UserMixin):
    """Wraps a MongoDB user dict so Flask-Login can manage sessions."""

    def __init__(self, user_doc):
        # Pull fields from MongoDB document
        self.id            = str(user_doc['_id'])  # must be string for Flask-Login
        self.username      = user_doc.get('username', '')
        self.email         = user_doc.get('email', '')
        self.role          = user_doc.get('role', 'analyst')
        self.status        = user_doc.get('status', 'active')
        self.twofa_secret  = user_doc.get('twofa_secret')
        self.twofa_enabled = user_doc.get('twofa_enabled', False)

    def get_id(self):
        """Flask-Login stores this ID in the session cookie."""
        return self.id

    @property
    def is_active(self):
        """
        Flask-Login checks this on every request.
        Returns False for suspended/pending users so they cannot log in.
        """
        return self.status == 'active'
