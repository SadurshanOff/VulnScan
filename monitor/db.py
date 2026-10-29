import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

from monitor import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    owner_email TEXT,
    telegram_chat_id TEXT,
    verify_token TEXT NOT NULL,
    verified_at TEXT,
    interval_hours INTEGER NOT NULL,
    next_scan_at TEXT,
    last_scan_at TEXT,
    last_digest_at TEXT,
    authorised_on TEXT,
    authorisation_ref TEXT,
    scope_notes TEXT,
    active_tests INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    opened INTEGER NOT NULL DEFAULT 0,
    resolved INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    check_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    fix TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    analyst_note TEXT,
    reviewed_at TEXT,
    notified_at TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS findings_open ON findings(site_id, resolved_at);
"""

# Columns added after the first release, applied to existing databases by init_db
MIGRATIONS = {
    'sites': [('authorised_on', 'TEXT'), ('authorisation_ref', 'TEXT'), ('scope_notes', 'TEXT'),
              ('active_tests', 'INTEGER NOT NULL DEFAULT 0')],
    'findings': [('evidence', "TEXT NOT NULL DEFAULT ''"), ('status', "TEXT NOT NULL DEFAULT 'pending'"),
                 ('analyst_note', 'TEXT'), ('reviewed_at', 'TEXT'), ('notified_at', 'TEXT')],
}

# pending: waiting for analyst review; approved: shown to the client; dismissed: false positive
STATUSES = ('pending', 'approved', 'dismissed')

SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def later(hours=0, days=0):
    return (datetime.now(timezone.utc) + timedelta(hours=hours, days=days)).isoformat(timespec='seconds')

def connect(path=None):
    conn = sqlite3.connect(path or config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db(conn):
    conn.executescript(SCHEMA)
    for table, columns in MIGRATIONS.items():
        existing = {row['name'] for row in conn.execute(f'PRAGMA table_info({table})')}
        for name, definition in columns:
            if name not in existing:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
    conn.commit()

def fingerprint(site_id, finding):
    raw = f"{site_id}|{finding['check']}|{finding['key']}"
    return hashlib.sha256(raw.encode()).hexdigest()

def add_site(conn, url, name, owner_email, telegram_chat_id, verify_token, interval_hours=None):
    cur = conn.execute(
        'INSERT INTO sites (url, name, owner_email, telegram_chat_id, verify_token, interval_hours, created_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (url, name, owner_email or None, telegram_chat_id or None, verify_token,
         interval_hours or config.SCAN_INTERVAL_HOURS, now()))
    conn.commit()
    return cur.lastrowid

def get_site(conn, site_id):
    return conn.execute('SELECT * FROM sites WHERE id = ?', (site_id,)).fetchone()

def list_sites(conn):
    return conn.execute(
        "SELECT s.*, "
        "(SELECT COUNT(*) FROM findings f WHERE f.site_id = s.id AND f.resolved_at IS NULL AND f.status = 'approved') AS open_count, "
        "(SELECT COUNT(*) FROM findings f WHERE f.site_id = s.id AND f.resolved_at IS NULL AND f.status = 'pending') AS pending_count "

        'FROM sites s ORDER BY s.name').fetchall()

def delete_site(conn, site_id):
    conn.execute('DELETE FROM sites WHERE id = ?', (site_id,))
    conn.commit()

def due_sites(conn):
    return conn.execute(
        'SELECT * FROM sites WHERE verified_at IS NOT NULL AND authorised_on IS NOT NULL '
        'AND (next_scan_at IS NULL OR next_scan_at <= ?)',
        (now(),)).fetchall()

def set_verified(conn, site_id, verified):
    if verified:
        # Start the digest clock at verification so the first scan does not also send a summary
        conn.execute('UPDATE sites SET verified_at = ?, last_digest_at = ? WHERE id = ?', (now(), now(), site_id))
    else:
        conn.execute('UPDATE sites SET verified_at = NULL WHERE id = ?', (site_id,))
    conn.commit()

def schedule_next(conn, site):
    conn.execute('UPDATE sites SET last_scan_at = ?, next_scan_at = ? WHERE id = ?',
                 (now(), later(hours=site['interval_hours']), site['id']))
    conn.commit()

def mark_digest_sent(conn, site_id):
    conn.execute('UPDATE sites SET last_digest_at = ? WHERE id = ?', (now(), site_id))
    conn.commit()

def _by_severity(rows):
    return sorted(rows, key=lambda r: SEVERITY_ORDER.get(r['severity'], 9))

def open_findings(conn, site_id, status=None):
    query = 'SELECT * FROM findings WHERE site_id = ? AND resolved_at IS NULL'
    params = [site_id]
    if status:
        query += ' AND status = ?'
        params.append(status)
    return _by_severity(conn.execute(query, params).fetchall())

def get_finding(conn, finding_id):
    return conn.execute('SELECT * FROM findings WHERE id = ?', (finding_id,)).fetchone()

def review_finding(conn, finding_id, status, note=None):
    if status not in STATUSES:
        raise ValueError(f'Unknown status {status}')
    conn.execute('UPDATE findings SET status = ?, analyst_note = ?, reviewed_at = ? WHERE id = ?',
                 (status, note or None, now(), finding_id))
    conn.commit()

def unnotified_approved(conn, site_id):
    return _by_severity(conn.execute(
        "SELECT * FROM findings WHERE site_id = ? AND resolved_at IS NULL AND status = 'approved' "
        'AND notified_at IS NULL', (site_id,)).fetchall())

def mark_notified(conn, rows):
    conn.executemany('UPDATE findings SET notified_at = ? WHERE id = ?', [(now(), row['id']) for row in rows])
    conn.commit()

def resolved_since(conn, site_id, since):
    """Approved findings that have been fixed since the given time."""
    return _by_severity(conn.execute(
        "SELECT * FROM findings WHERE site_id = ? AND resolved_at >= ? AND status = 'approved'",
        (site_id, since)).fetchall())

def set_authorisation(conn, site_id, authorised_on, reference, scope_notes, active_tests):
    conn.execute('UPDATE sites SET authorised_on = ?, authorisation_ref = ?, scope_notes = ?, active_tests = ? '
                 'WHERE id = ?', (authorised_on or None, reference or None, scope_notes or None,
                                  1 if active_tests else 0, site_id))
    conn.commit()

def recent_scans(conn, site_id, limit=20):
    return conn.execute('SELECT * FROM scans WHERE site_id = ? ORDER BY id DESC LIMIT ?',
                        (site_id, limit)).fetchall()

def record_scan(conn, site_id, started_at, findings, error=None):
    """Store a scan's findings and return (opened, resolved) lists of finding rows."""
    timestamp = now()
    current = {fingerprint(site_id, f): f for f in findings}
    existing = {row['fingerprint']: row for row in open_findings(conn, site_id)}

    opened, resolved = [], []
    for fp, f in current.items():
        if fp in existing:
            conn.execute('UPDATE findings SET last_seen = ?, severity = ?, title = ?, detail = ?, evidence = ? WHERE id = ?',
                         (timestamp, f['severity'], f['title'], f['detail'], f.get('evidence', ''), existing[fp]['id']))
        else:
            cur = conn.execute(
                'INSERT INTO findings (site_id, fingerprint, check_name, severity, title, detail, fix, evidence, '
                'first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (site_id, fp, f['check'], f['severity'], f['title'], f['detail'], f['fix'], f.get('evidence', ''),
                 timestamp, timestamp))
            opened.append(conn.execute('SELECT * FROM findings WHERE id = ?', (cur.lastrowid,)).fetchone())
    # A failed scan proves nothing about old findings, so only a clean run resolves them
    if error is None:
        for fp, row in existing.items():
            if fp not in current:
                conn.execute('UPDATE findings SET resolved_at = ? WHERE id = ?', (timestamp, row['id']))
                resolved.append(row)

    conn.execute(
        'INSERT INTO scans (site_id, started_at, finished_at, status, opened, resolved, error) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (site_id, started_at, timestamp, 'failed' if error else 'ok', len(opened), len(resolved), error))
    conn.commit()
    return opened, resolved
