# backend/src/auth/rbac.py
# Role-Based Access Control (RBAC) decorators
# Member: Tashi
#
# SIMPLE EXPLANATION:
# These decorators restrict who can access certain pages
# @admin_required - only Admin users can access this page
#
# HOW TO USE:
#   @app.route('/admin-page')
#   @login_required    <- must be logged in
#   @admin_required    <- must be admin
#   def admin_page():
#       ...

from functools import wraps
from flask import abort
from flask_login import current_user


def admin_required(f):
    """Block anyone who is not an Admin. Returns 403 Forbidden."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check logged in AND has admin role
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # 403 = Forbidden
        return f(*args, **kwargs)
    return decorated
