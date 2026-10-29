"""Background agent: scans every verified site when it is due and alerts on changes.

Run with `python -m monitor.worker` (loops forever) or `--once` (one pass, for cron).
"""
import argparse
import logging
import time
from datetime import datetime, timedelta, timezone

from monitor import checks, config, db, notify, verify

log = logging.getLogger('vulnscan.worker')

def run_scan(conn, site):
    """Scan one site, store results and send alerts. Returns (opened, resolved)."""
    started_at = db.now()
    if not verify.check_ownership(site['url'], site['verify_token']):
        log.warning('Site %s failed ownership verification; pausing monitoring', site['url'])
        db.set_verified(conn, site['id'], False)
        notify.notify(site, *notify.format_unverified(site))
        return [], []

    findings, error = checks.run_all(site['url'])
    opened, resolved = db.record_scan(conn, site['id'], started_at, findings, error)
    db.schedule_next(conn, site)
    if error:
        log.warning('Scan of %s failed: %s', site['url'], error)
    if opened or resolved:
        notify.notify(site, *notify.format_changes(site, opened, resolved))
    log.info('Scanned %s: %d new, %d resolved', site['url'], len(opened), len(resolved))
    return opened, resolved

def digest_due(site):
    if not site['last_digest_at']:
        return True
    last = datetime.fromisoformat(site['last_digest_at'])
    return datetime.now(timezone.utc) - last >= timedelta(days=config.DIGEST_INTERVAL_DAYS)

def run_due(conn):
    for site in db.due_sites(conn):
        try:
            run_scan(conn, site)
        except Exception:
            log.exception('Unexpected error scanning %s', site['url'])
            db.schedule_next(conn, site)
            continue
        site = db.get_site(conn, site['id'])
        if site['verified_at'] and digest_due(site):
            notify.notify(site, *notify.format_digest(site, db.open_findings(conn, site['id'])))
            db.mark_digest_sent(conn, site['id'])

def main():
    parser = argparse.ArgumentParser(description='VulnScan Monitor worker')
    parser.add_argument('--once', action='store_true', help='scan due sites once and exit')
    parser.add_argument('--poll-seconds', type=int, default=60)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')

    conn = db.connect()
    db.init_db(conn)
    while True:
        run_due(conn)
        if args.once:
            break
        time.sleep(args.poll_seconds)

if __name__ == '__main__':
    main()
