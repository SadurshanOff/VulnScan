import hmac
import os
import secrets
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, g
import scanner.scanner as vuln_scanner
from scanner.target import validate_target
from monitor import config, db, verify, worker

app = Flask(__name__)
# Set VULNSCAN_SECRET_KEY to keep sessions valid across restarts
app.secret_key = os.environ.get('VULNSCAN_SECRET_KEY') or os.urandom(32)

# Global variable for simplicity
scan_results = {}

def get_db():
    if 'db' not in g:
        g.db = db.connect()
        db.init_db(g.db)
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()

def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = csrf_token

@app.before_request
def check_csrf():
    if request.method == 'POST':
        sent = request.form.get('csrf_token', '')
        expected = session.get('csrf_token')
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, 'Invalid or missing CSRF token')

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not config.ADMIN_PASSWORD:
        flash('Set VULNSCAN_ADMIN_PASSWORD to enable the dashboard.', 'danger')
    elif request.method == 'POST':
        if hmac.compare_digest(request.form.get('password', ''), config.ADMIN_PASSWORD):
            session['admin'] = True
            next_url = request.args.get('next', '')
            return redirect(next_url if next_url.startswith('/') and not next_url.startswith('//') else url_for('sites'))
        flash('Wrong password', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        target_url = (request.form.get('target_url') or '').strip()
        if not target_url:
            flash('Please enter a valid URL', 'danger')
        elif (error := validate_target(target_url)):
            flash(error, 'danger')
        else:
            results = vuln_scanner.start_scan(target_url)
            global scan_results
            scan_results = results
            return redirect(url_for('results'))
    return render_template('index.html')

@app.route('/results')
@login_required
def results():
    return render_template('results.html', results=scan_results)

@app.route('/guidance')
@login_required
def guidance():
    return render_template('guidance.html', results=scan_results)

@app.route('/sites', methods=['GET', 'POST'])
@login_required
def sites():
    conn = get_db()
    if request.method == 'POST':
        url = (request.form.get('url') or '').strip().rstrip('/') + '/'
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('owner_email') or '').strip()
        chat_id = (request.form.get('telegram_chat_id') or '').strip()
        if (error := validate_target(url)):
            flash(error, 'danger')
        elif not name:
            flash('Please enter a client or site name', 'danger')
        elif not email and not chat_id:
            flash('Add an email address or a Telegram chat id so alerts can be delivered', 'danger')
        else:
            try:
                site_id = db.add_site(conn, url, name, email, chat_id, verify.new_token())
            except db.sqlite3.IntegrityError:
                flash('That site is already being monitored', 'danger')
            else:
                flash('Site added. Ask the owner to publish the verification file, then click Verify.', 'info')
                return redirect(url_for('site_detail', site_id=site_id))
    return render_template('sites.html', sites=db.list_sites(conn))

def load_site(site_id):
    site = db.get_site(get_db(), site_id)
    if site is None:
        abort(404)
    return site

@app.route('/sites/<int:site_id>')
@login_required
def site_detail(site_id):
    site = load_site(site_id)
    conn = get_db()
    return render_template('site.html', site=site,
                           pending=db.open_findings(conn, site_id, 'pending'),
                           approved=db.open_findings(conn, site_id, 'approved'),
                           dismissed=db.open_findings(conn, site_id, 'dismissed'),
                           unnotified=db.unnotified_approved(conn, site_id),
                           scans=db.recent_scans(conn, site_id),
                           verification_url=verify.verification_url(site['url']))

@app.route('/sites/<int:site_id>/verify', methods=['POST'])
@login_required
def site_verify(site_id):
    site = load_site(site_id)
    if verify.check_ownership(site['url'], site['verify_token']):
        db.set_verified(get_db(), site_id, True)
        flash('Ownership verified. The agent will scan this site on its next run.', 'info')
    else:
        flash(f'Verification file not found at {verify.verification_url(site["url"])}', 'danger')
    return redirect(url_for('site_detail', site_id=site_id))

@app.route('/sites/<int:site_id>/scan', methods=['POST'])
@login_required
def site_scan(site_id):
    site = load_site(site_id)
    if not site['authorised_on']:
        flash('Record the client\'s written authorisation before scanning this site', 'danger')
    elif not site['verified_at']:
        flash('Verify ownership before scanning this site', 'danger')
    else:
        opened, resolved = worker.run_scan(get_db(), site)
        flash(f'Scan finished: {len(opened)} new, {len(resolved)} fixed', 'info')
    return redirect(url_for('site_detail', site_id=site_id))

@app.route('/sites/<int:site_id>/authorisation', methods=['POST'])
@login_required
def site_authorisation(site_id):
    load_site(site_id)
    authorised_on = (request.form.get('authorised_on') or '').strip()
    reference = (request.form.get('authorisation_ref') or '').strip()
    if not authorised_on or not reference:
        flash('Enter the date the client signed and a reference to the signed document', 'danger')
    else:
        db.set_authorisation(get_db(), site_id, authorised_on, reference,
                             (request.form.get('scope_notes') or '').strip(),
                             request.form.get('active_tests') == '1')
        flash('Authorisation recorded', 'info')
    return redirect(url_for('site_detail', site_id=site_id))

@app.route('/findings/<int:finding_id>/review', methods=['POST'])
@login_required
def finding_review(finding_id):
    conn = get_db()
    row = db.get_finding(conn, finding_id)
    if row is None:
        abort(404)
    status = request.form.get('status')
    if status not in db.STATUSES:
        abort(400)
    db.review_finding(conn, finding_id, status, (request.form.get('analyst_note') or '').strip())
    return redirect(url_for('site_detail', site_id=row['site_id']))

@app.route('/sites/<int:site_id>/notify', methods=['POST'])
@login_required
def site_notify(site_id):
    site = load_site(site_id)
    sent = worker.notify_client(get_db(), site)
    if sent:
        flash(f'Approved findings sent to the client by {" and ".join(sent)}', 'info')
    else:
        flash('Nothing was sent: no new approved findings, or no working alert channel', 'danger')
    return redirect(url_for('site_detail', site_id=site_id))

@app.route('/sites/<int:site_id>/report')
@login_required
def site_report(site_id):
    site = load_site(site_id)
    conn = get_db()
    days = request.args.get('days', 30, type=int)
    return render_template('report.html', site=site, days=days, generated_at=db.now(),
                           findings=db.open_findings(conn, site_id, 'approved'),
                           fixed=db.resolved_since(conn, site_id, db.later(days=-days)),
                           last_scan=next(iter(db.recent_scans(conn, site_id, 1)), None))

@app.route('/sites/<int:site_id>/delete', methods=['POST'])
@login_required
def site_delete(site_id):
    load_site(site_id)
    db.delete_site(get_db(), site_id)
    flash('Site removed', 'info')
    return redirect(url_for('sites'))

if __name__ == '__main__':
    # Never enable debug on a reachable host: the Werkzeug debugger allows code execution
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
