# backend/src/auth/routes.py
# Login, Register, Logout, 2FA, Admin user management
# Member: Tashi (Auth & Security Lead)

from flask import (Blueprint, render_template, redirect,
                   url_for, flash, request, session, jsonify)
from flask_login import login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from bson import ObjectId

from src.database import get_db
from src.database.collections import (USERS, LOGIN_LOGS, new_user, new_login_log)
from src.auth.user_model import MongoUser
from src.auth.rbac import admin_required
from src.auth.twofa import generate_secret, generate_qr_code, verify_token

auth_bp   = Blueprint('auth', __name__, url_prefix='/auth')
bcrypt    = Bcrypt()
MAX_FAILS = 5


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db       = get_db()
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if db[USERS].find_one({'username': username}):
            flash('Username already taken.', 'danger')
            return redirect(url_for('auth.register'))
        if db[USERS].find_one({'email': email}):
            flash('Email already registered.', 'danger')
            return redirect(url_for('auth.register'))

        user_count = db[USERS].count_documents({})
        if user_count == 0:
            role, status = 'admin', 'active'
        else:
            role, status = 'analyst', 'pending'

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        doc    = new_user(username, email, hashed, role, status)
        db[USERS].insert_one(doc)

        if role == 'admin':
            flash('Admin account created! You have full access.', 'success')
        else:
            flash('Account created! Please wait for admin approval.', 'warning')
        return redirect(url_for('auth.login'))

    db = get_db()
    is_first_user = db[USERS].count_documents({}) == 0
    return render_template('auth/register.html', is_first_user=is_first_user)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        db       = get_db()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip       = request.remote_addr
        doc      = db[USERS].find_one({'username': username})

        if doc and doc.get('status') == 'pending':
            flash('Your account is pending admin approval.', 'warning')
            db[LOGIN_LOGS].insert_one(new_login_log(username, ip, False))
            return redirect(url_for('auth.login'))

        if doc and doc.get('status') == 'suspended':
            flash('Your account has been suspended. Contact administrator.', 'danger')
            db[LOGIN_LOGS].insert_one(new_login_log(username, ip, False))
            return redirect(url_for('auth.login'))

        fails = db[LOGIN_LOGS].count_documents({'username': username, 'success': False})
        if fails >= MAX_FAILS:
            flash('Too many failed attempts. Contact administrator.', 'danger')
            return redirect(url_for('auth.login'))

        if doc and bcrypt.check_password_hash(doc['password_hash'], password):
            db[LOGIN_LOGS].insert_one(new_login_log(username, ip, True))
            user = MongoUser(doc)
            if user.twofa_enabled:
                session['pre_2fa_user_id'] = str(doc['_id'])
                return redirect(url_for('auth.verify_2fa'))
            login_user(user)
            return redirect(url_for('dashboard.index'))
        else:
            db[LOGIN_LOGS].insert_one(new_login_log(username, ip, False))
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html')


@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    uid = session.get('pre_2fa_user_id')
    if not uid:
        return redirect(url_for('auth.login'))
    doc = get_db()[USERS].find_one({'_id': ObjectId(uid)})
    if not doc:
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        if verify_token(doc['twofa_secret'], request.form.get('token', '')):
            session.pop('pre_2fa_user_id', None)
            login_user(MongoUser(doc))
            return redirect(url_for('dashboard.index'))
        flash('Invalid code. Try again.', 'danger')
    return render_template('auth/verify_2fa.html')


@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    db  = get_db()
    doc = db[USERS].find_one({'_id': ObjectId(current_user.id)})
    if not doc.get('twofa_secret'):
        secret = generate_secret()
        db[USERS].update_one({'_id': ObjectId(current_user.id)},
                             {'$set': {'twofa_secret': secret}})
        doc['twofa_secret'] = secret
    qr = generate_qr_code(doc['twofa_secret'], current_user.username)
    if request.method == 'POST':
        if verify_token(doc['twofa_secret'], request.form.get('token', '')):
            db[USERS].update_one({'_id': ObjectId(current_user.id)},
                                 {'$set': {'twofa_enabled': True}})
            flash('2FA enabled successfully!', 'success')
            return redirect(url_for('dashboard.index'))
        flash('Invalid token. Try again.', 'danger')
    return render_template('auth/setup_2fa.html', qr_code=qr)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('auth.login'))


# ── Admin: User Management ────────────────────────────────

@auth_bp.route('/admin/users')
@login_required
@admin_required
def manage_users():
    db            = get_db()
    users         = list(db[USERS].find().sort('created_at', 1))
    pending_count = db[USERS].count_documents({'status': 'pending'})
    return render_template('auth/manage_users.html',
                           users=users, pending_count=pending_count)


@auth_bp.route('/admin/users/approve/<uid>', methods=['POST'])
@login_required
@admin_required
def approve_user(uid):
    db  = get_db()
    doc = db[USERS].find_one({'_id': ObjectId(uid)})
    db[USERS].update_one({'_id': ObjectId(uid)}, {'$set': {'status': 'active'}})
    flash(f'User {doc["username"]} approved and activated.', 'success')
    return redirect(url_for('auth.manage_users'))


@auth_bp.route('/admin/users/suspend/<uid>', methods=['POST'])
@login_required
@admin_required
def suspend_user(uid):
    if str(uid) == current_user.id:
        flash('You cannot suspend your own account.', 'danger')
        return redirect(url_for('auth.manage_users'))
    db  = get_db()
    doc = db[USERS].find_one({'_id': ObjectId(uid)})
    db[USERS].update_one({'_id': ObjectId(uid)}, {'$set': {'status': 'suspended'}})
    flash(f'User {doc["username"]} suspended.', 'warning')
    return redirect(url_for('auth.manage_users'))


@auth_bp.route('/admin/users/delete/<uid>', methods=['POST'])
@login_required
@admin_required
def delete_user(uid):
    if str(uid) == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('auth.manage_users'))
    db  = get_db()
    doc = db[USERS].find_one({'_id': ObjectId(uid)})
    db[USERS].delete_one({'_id': ObjectId(uid)})
    flash(f'User {doc["username"]} deleted permanently.', 'danger')
    return redirect(url_for('auth.manage_users'))


@auth_bp.route('/admin/users/changerole/<uid>', methods=['POST'])
@login_required
@admin_required
def change_role(uid):
    """Toggle user role between admin and analyst."""
    if str(uid) == current_user.id:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('auth.manage_users'))
    db       = get_db()
    doc      = db[USERS].find_one({'_id': ObjectId(uid)})
    new_role = 'admin' if doc['role'] == 'analyst' else 'analyst'
    db[USERS].update_one({'_id': ObjectId(uid)}, {'$set': {'role': new_role}})
    flash(f'{doc["username"]} is now {new_role}.', 'success')
    return redirect(url_for('auth.manage_users'))


# ══════════════════════════════════════════════════════════
# JSON API ENDPOINTS — For Postman Testing
# ══════════════════════════════════════════════════════════

@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    """JSON login endpoint for API testing."""
    db       = get_db()
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({
            'status':  'error',
            'message': 'Username and password are required'
        }), 400

    doc = db[USERS].find_one({'username': username})

    if not doc:
        return jsonify({
            'status':  'error',
            'message': 'Invalid username or password'
        }), 401

    if doc.get('status') == 'pending':
        return jsonify({
            'status':  'error',
            'message': 'Account pending admin approval'
        }), 403

    if doc.get('status') == 'suspended':
        return jsonify({
            'status':  'error',
            'message': 'Account suspended. Contact administrator'
        }), 403

    if not bcrypt.check_password_hash(doc['password_hash'], password):
        return jsonify({
            'status':  'error',
            'message': 'Invalid username or password'
        }), 401

    return jsonify({
        'status':       'success',
        'message':      'Login successful',
        'user_id':      str(doc['_id']),
        'username':     doc['username'],
        'role':         doc['role'],
        'requires_2fa': doc.get('twofa_enabled', False)
    }), 200


@auth_bp.route('/api/register', methods=['POST'])
def api_register():
    """JSON register endpoint for API testing."""
    db       = get_db()
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({
            'status':  'error',
            'message': 'Username, email and password required'
        }), 400

    if db[USERS].find_one({'username': username}):
        return jsonify({
            'status':  'error',
            'message': 'Username already taken'
        }), 409

    user_count = db[USERS].count_documents({})
    role   = 'admin'  if user_count == 0 else 'analyst'
    status = 'active' if user_count == 0 else 'pending'

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    db[USERS].insert_one(new_user(username, email, hashed, role, status))

    return jsonify({
        'status':         'success',
        'message':        'Account created successfully',
        'username':       username,
        'role':           role,
        'account_status': status
    }), 201