import os
import sqlite3
from datetime import datetime, date
from functools import wraps

from flask import (Flask, g, session, redirect, url_for, request,
                   render_template, flash, abort)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production-please')

DATABASE = os.path.join(os.path.dirname(__file__), 'appointments.db')


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode())
    # Seed admin user if not present
    existing = db.execute('SELECT id FROM users WHERE role = ?', ('admin',)).fetchone()
    if not existing:
        db.execute(
            'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
            ('Admin', 'admin@example.com', generate_password_hash('admin123'), 'admin')
        )
        db.commit()


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bitte melden Sie sich zuerst an.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bitte melden Sie sich zuerst an.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('client_dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['role'] = user['role']
            return redirect(url_for('index'))
        flash('E-Mail oder Passwort ungültig.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not name or not email or not password:
            flash('Alle Felder sind erforderlich.', 'danger')
        elif password != confirm:
            flash('Passwörter stimmen nicht überein.', 'danger')
        elif len(password) < 6:
            flash('Passwort muss mindestens 6 Zeichen haben.', 'danger')
        else:
            db = get_db()
            try:
                db.execute(
                    'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
                    (name, email, generate_password_hash(password), 'client')
                )
                db.commit()
                flash('Registrierung erfolgreich! Bitte melden Sie sich an.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Diese E-Mail-Adresse ist bereits registriert.', 'danger')
    return render_template('register.html')


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    status_filter = request.args.get('status', 'all')
    today = date.today().isoformat()

    if status_filter == 'all':
        appointments = db.execute(
            '''SELECT a.*, u.name as client_name, u.email as client_email
               FROM appointments a JOIN users u ON a.client_id = u.id
               ORDER BY a.date DESC, a.time DESC'''
        ).fetchall()
    else:
        appointments = db.execute(
            '''SELECT a.*, u.name as client_name, u.email as client_email
               FROM appointments a JOIN users u ON a.client_id = u.id
               WHERE a.status = ?
               ORDER BY a.date DESC, a.time DESC''',
            (status_filter,)
        ).fetchall()

    counts = db.execute(
        '''SELECT status, COUNT(*) as cnt FROM appointments GROUP BY status'''
    ).fetchall()
    count_map = {r['status']: r['cnt'] for r in counts}
    today_count = db.execute(
        "SELECT COUNT(*) FROM appointments WHERE date = ? AND status != 'cancelled'",
        (today,)
    ).fetchone()[0]

    clients = db.execute(
        "SELECT id, name, email FROM users WHERE role = 'client' ORDER BY name"
    ).fetchall()

    return render_template(
        'admin/dashboard.html',
        appointments=appointments,
        count_map=count_map,
        today_count=today_count,
        clients=clients,
        status_filter=status_filter,
        today=today,
    )


@app.route('/admin/create', methods=['GET', 'POST'])
@admin_required
def admin_create():
    db = get_db()
    clients = db.execute(
        "SELECT id, name, email FROM users WHERE role = 'client' ORDER BY name"
    ).fetchall()
    if request.method == 'POST':
        client_id = request.form.get('client_id', '')
        title = request.form.get('title', '').strip()
        appt_date = request.form.get('date', '').strip()
        appt_time = request.form.get('time', '').strip()
        duration = request.form.get('duration', '60')
        notes = request.form.get('notes', '').strip()
        if not all([client_id, title, appt_date, appt_time]):
            flash('Bitte alle Pflichtfelder ausfüllen.', 'danger')
        else:
            db.execute(
                '''INSERT INTO appointments (client_id, title, date, time, duration, status, notes)
                   VALUES (?, ?, ?, ?, ?, 'confirmed', ?)''',
                (client_id, title, appt_date, appt_time, int(duration), notes or None)
            )
            db.commit()
            flash('Termin wurde erfolgreich erstellt.', 'success')
            return redirect(url_for('admin_dashboard'))
    return render_template('admin/create.html', clients=clients)


@app.route('/admin/confirm/<int:appt_id>', methods=['POST'])
@admin_required
def admin_confirm(appt_id):
    db = get_db()
    db.execute(
        "UPDATE appointments SET status = 'confirmed' WHERE id = ?", (appt_id,)
    )
    db.commit()
    flash('Termin bestätigt.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/cancel/<int:appt_id>', methods=['POST'])
@admin_required
def admin_cancel(appt_id):
    db = get_db()
    db.execute(
        "UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appt_id,)
    )
    db.commit()
    flash('Termin abgesagt.', 'info')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/<int:appt_id>', methods=['POST'])
@admin_required
def admin_delete(appt_id):
    db = get_db()
    db.execute('DELETE FROM appointments WHERE id = ?', (appt_id,))
    db.commit()
    flash('Termin gelöscht.', 'info')
    return redirect(url_for('admin_dashboard'))


# ---------------------------------------------------------------------------
# Client routes
# ---------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def client_dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    db = get_db()
    user_id = session['user_id']
    upcoming = db.execute(
        '''SELECT * FROM appointments WHERE client_id = ? AND status != 'cancelled'
           ORDER BY date ASC, time ASC''',
        (user_id,)
    ).fetchall()
    cancelled = db.execute(
        "SELECT * FROM appointments WHERE client_id = ? AND status = 'cancelled' ORDER BY date DESC",
        (user_id,)
    ).fetchall()
    return render_template('client/dashboard.html', upcoming=upcoming, cancelled=cancelled)


@app.route('/book', methods=['GET', 'POST'])
@login_required
def client_book():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        appt_date = request.form.get('date', '').strip()
        appt_time = request.form.get('time', '').strip()
        duration = request.form.get('duration', '60')
        notes = request.form.get('notes', '').strip()
        if not all([title, appt_date, appt_time]):
            flash('Bitte alle Pflichtfelder ausfüllen.', 'danger')
        else:
            try:
                appt_d = datetime.strptime(appt_date, '%Y-%m-%d').date()
                if appt_d < date.today():
                    flash('Das Datum darf nicht in der Vergangenheit liegen.', 'danger')
                    return render_template('client/book.html')
            except ValueError:
                flash('Ungültiges Datum.', 'danger')
                return render_template('client/book.html')
            db = get_db()
            db.execute(
                '''INSERT INTO appointments (client_id, title, date, time, duration, status, notes)
                   VALUES (?, ?, ?, ?, ?, 'pending', ?)''',
                (session['user_id'], title, appt_date, appt_time, int(duration), notes or None)
            )
            db.commit()
            flash('Terminanfrage gesendet. Wir bestätigen Ihren Termin bald.', 'success')
            return redirect(url_for('client_dashboard'))
    return render_template('client/book.html')


@app.route('/cancel/<int:appt_id>', methods=['POST'])
@login_required
def client_cancel(appt_id):
    db = get_db()
    appt = db.execute(
        'SELECT * FROM appointments WHERE id = ? AND client_id = ?',
        (appt_id, session['user_id'])
    ).fetchone()
    if not appt:
        abort(403)
    db.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appt_id,))
    db.commit()
    flash('Termin wurde abgesagt.', 'info')
    return redirect(url_for('client_dashboard'))


# ---------------------------------------------------------------------------
# Error pages
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='Kein Zugriff.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Seite nicht gefunden.'), 404


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

@app.template_filter('format_date')
def format_date(value):
    try:
        return datetime.strptime(value, '%Y-%m-%d').strftime('%d.%m.%Y')
    except Exception:
        return value


@app.template_filter('weekday')
def weekday_filter(value):
    days = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So']
    try:
        d = datetime.strptime(value, '%Y-%m-%d')
        return days[d.weekday()]
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    with app.app_context():
        init_db()
        print('Admin-Zugangsdaten: admin@example.com / admin123')
    app.run(debug=True, host='0.0.0.0', port=5000)
