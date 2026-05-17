# backend/src/dashboard/routes.py
# All dashboard page routes
# Member: Aditi (Frontend & DevOps Lead)

import json, os, tempfile
from flask import (Blueprint, render_template, request,
                   redirect, url_for, flash, Response, jsonify)
from flask_login import login_required, current_user
from bson import ObjectId

from src.database import get_db
from src.database.collections import (ANALYSES, LOGIN_LOGS, QUARANTINE, new_analysis)
from src.email_analysis import analyse_email
from src.email_analysis.ai_explainer import get_ai_explanation
from src.pattern_engine.risk_scorer import score_email
from src.pattern_engine.quarantine import (quarantine_email, release_email, get_quarantined)
from src.pattern_engine.ml_classifier import (predict, model_exists, train_model, generate_sample_dataset)
from src.dashboard.reports import generate_pdf, generate_csv
from src.auth.rbac import admin_required

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    """Main dashboard showing analysis history and stats."""
    db = get_db()
    if current_user.role == 'admin':
        analyses = list(db[ANALYSES].find().sort('analysed_at', -1))
    else:
        analyses = list(db[ANALYSES].find(
            {'user_id': ObjectId(current_user.id)}).sort('analysed_at', -1))
    total  = len(analyses)
    red    = sum(1 for a in analyses if a['risk_level'] == 'RED')
    yellow = sum(1 for a in analyses if a['risk_level'] == 'YELLOW')
    green  = sum(1 for a in analyses if a['risk_level'] == 'GREEN')
    return render_template('dashboard/dashboard.html',
                           analyses=analyses,
                           total=total, red=red, yellow=yellow, green=green)


@dashboard_bp.route('/analyse', methods=['GET', 'POST'])
@login_required
def analyse():
    """Upload .txt/.eml file or fill in email fields for analysis."""
    if request.method == 'POST':
        raw = ''

        if 'email_file' in request.files and request.files['email_file'].filename:
            file     = request.files['email_file']
            filename = file.filename.lower()
            if not (filename.endswith('.txt') or filename.endswith('.eml')):
                flash('Invalid file type! Only .txt and .eml files accepted.', 'danger')
                return redirect(url_for('dashboard.analyse'))
            raw = file.read().decode('utf-8', errors='ignore')
        else:
            subject  = request.form.get('email_subject', '').strip()
            from_    = request.form.get('email_from', '').strip()
            body     = request.form.get('email_text', '').strip()

            if not body and not subject:
                flash('Please upload a file or fill in the email details.', 'warning')
                return redirect(url_for('dashboard.analyse'))

            if subject:  raw += f'Subject: {subject}\n'
            if from_:    raw += f'From: {from_}\n'
            raw += f'\n{body}'

        result    = analyse_email(raw)
        scored    = score_email(result)
        ml_result = predict(result.get('body_text', ''))
        ai_exp    = get_ai_explanation(
            scored['risk_level'], scored['risk_score'],
            scored['reasons'], result.get('subject', ''), result.get('sender', '')
        )

        db  = get_db()
        doc = new_analysis(
            user_id       = current_user.id,
            subject       = result.get('subject', 'N/A'),
            sender        = result.get('sender', 'N/A'),
            body          = result.get('body_text', ''),
            risk_level    = scored['risk_level'],
            risk_score    = scored['risk_score'],
            reasons       = scored['reasons'],
            url_count     = len(result.get('all_urls', [])),
            sus_url_count = len(result.get('suspicious_urls', [])),
            attach_count  = len(result.get('attachments', [])),
            ai_explanation= ai_exp,
        )
        if ml_result:
            doc['ml_prediction'] = ml_result

        inserted = db[ANALYSES].insert_one(doc)

        if scored['risk_level'] == 'RED':
            quarantine_email(str(inserted.inserted_id), raw)

        return redirect(url_for('dashboard.results', aid=str(inserted.inserted_id)))

    return render_template('dashboard/analyse.html')


@dashboard_bp.route('/results/<aid>')
@login_required
def results(aid):
    """Show detailed analysis results."""
    db     = get_db()
    record = db[ANALYSES].find_one({'_id': ObjectId(aid)})
    if not record:
        flash('Analysis not found.', 'danger')
        return redirect(url_for('dashboard.index'))
    if current_user.role != 'admin' and str(record['user_id']) != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard.index'))
    return render_template('dashboard/results.html',
                           record=record, aid=aid,
                           reasons=record.get('reasons', []))


@dashboard_bp.route('/delete/<aid>', methods=['POST'])
@login_required
def delete_analysis(aid):
    """Delete an analysis record."""
    db     = get_db()
    record = db[ANALYSES].find_one({'_id': ObjectId(aid)})
    if not record:
        flash('Analysis not found.', 'danger')
        return redirect(url_for('dashboard.index'))
    if current_user.role != 'admin' and str(record['user_id']) != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard.index'))
    db[ANALYSES].delete_one({'_id': ObjectId(aid)})
    flash('Analysis deleted.', 'success')
    return redirect(url_for('dashboard.index'))


@dashboard_bp.route('/quarantine')
@login_required
@admin_required
def quarantine():
    """Admin view of quarantined emails."""
    db          = get_db()
    quarantined = get_quarantined()
    enriched    = []
    for q in quarantined:
        analysis = db[ANALYSES].find_one({'_id': q['analysis_id']})
        q['subject']    = analysis.get('email_subject', 'Unknown Subject') if analysis else 'N/A'
        q['sender']     = analysis.get('email_sender', 'Unknown Sender')   if analysis else 'N/A'
        q['risk_score'] = analysis.get('risk_score', 0)                    if analysis else 0
        enriched.append(q)
    return render_template('dashboard/quarantine.html', quarantined=enriched)


@dashboard_bp.route('/quarantine/release/<qid>', methods=['POST'])
@login_required
@admin_required
def release(qid):
    """Admin releases email from quarantine."""
    release_email(qid, current_user.id)
    flash('Email released from quarantine.', 'success')
    return redirect(url_for('dashboard.quarantine'))


@dashboard_bp.route('/ml-train', methods=['GET', 'POST'])
@login_required
@admin_required
def ml_train():
    """Admin trains ML phishing classifier."""
    result = None
    if request.method == 'POST':
        action = request.form.get('action', 'train')
        if action == 'sample':
            path  = os.path.join(tempfile.gettempdir(), 'sample_phishing.csv')
            count = generate_sample_dataset(path)
            result = train_model(path)
            if 'status' in result:
                result['note'] = (
                    f'Trained on {count} sample emails. '
                    f'Upload real Nazario dataset for better accuracy.'
                )
        elif action == 'train':
            if 'dataset' not in request.files or not request.files['dataset'].filename:
                flash('Please upload a CSV file.', 'danger')
                return redirect(url_for('dashboard.ml_train'))
            f    = request.files['dataset']
            path = os.path.join(tempfile.gettempdir(), f'phishing_{f.filename}')
            f.save(path)
            result = train_model(path)
    return render_template('dashboard/ml_train.html',
                           result=result, model_exists=model_exists())


@dashboard_bp.route('/export/pdf/<aid>')
@login_required
def export_pdf(aid):
    """Download analysis as PDF."""
    db     = get_db()
    record = db[ANALYSES].find_one({'_id': ObjectId(aid)})
    if not record:
        flash('Not found.', 'danger')
        return redirect(url_for('dashboard.index'))
    if current_user.role != 'admin' and str(record['user_id']) != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard.index'))
    return Response(generate_pdf(record),
                    mimetype='application/pdf',
                    headers={'Content-Disposition':
                             f'attachment; filename=phishguard_{aid[:8]}.pdf'})


@dashboard_bp.route('/export/csv')
@login_required
def export_csv():
    """Download all analyses as CSV."""
    db = get_db()
    if current_user.role == 'admin':
        analyses = list(db[ANALYSES].find())
    else:
        analyses = list(db[ANALYSES].find({'user_id': ObjectId(current_user.id)}))
    return Response(generate_csv(analyses),
                    mimetype='text/csv',
                    headers={'Content-Disposition':
                             'attachment; filename=phishguard_analyses.csv'})


@dashboard_bp.route('/admin/security')
@login_required
@admin_required
def security_panel():
    """Admin security panel — login monitoring."""
    db       = get_db()
    attempts = list(db[LOGIN_LOGS].find().sort('timestamp', -1).limit(100))
    pipeline = [
        {'$match':  {'success': False}},
        {'$group':  {'_id': '$username', 'cnt': {'$sum': 1}}},
        {'$sort':   {'cnt': -1}},
    ]
    failed = list(db[LOGIN_LOGS].aggregate(pipeline))
    return render_template('dashboard/admin_security.html',
                           attempts=attempts, failed=failed)


# ══════════════════════════════════════════════════════════
# JSON API ENDPOINTS — For Postman Testing
# ══════════════════════════════════════════════════════════

@dashboard_bp.route('/api/analyse', methods=['POST'])
def api_analyse():
    """JSON analyse endpoint for Postman API testing."""
    data       = request.get_json() or {}
    email_text = data.get('email_text', '').strip()

    if not email_text:
        return jsonify({
            'status':  'error',
            'message': 'email_text is required'
        }), 400

    result = analyse_email(email_text)
    scored = score_email(result)
    ai_exp = get_ai_explanation(
        scored['risk_level'], scored['risk_score'],
        scored['reasons'], result.get('subject', ''),
        result.get('sender', '')
    )

    return jsonify({
        'status':          'success',
        'risk_level':      scored['risk_level'],
        'risk_score':      scored['risk_score'],
        'subject':         result.get('subject', 'N/A'),
        'sender':          result.get('sender', 'N/A'),
        'url_count':       len(result.get('all_urls', [])),
        'suspicious_urls': len(result.get('suspicious_urls', [])),
        'findings':        scored['reasons'][:5],
        'ai_explanation':  ai_exp,
    }), 200
