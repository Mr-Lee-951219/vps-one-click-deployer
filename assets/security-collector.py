"""Persistent, bounded Fail2ban event collection; Python stdlib only on Debian."""
import argparse
import ipaddress
import json
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path('/var/lib/nodepilot/security')
JAIL = 'nodepilot-sshd'
SCOPE = 'ssh'
JAIL_FILE = '/etc/fail2ban/jail.d/nodepilot-sshd.local'
BEIJING = timezone(timedelta(hours=8))
EVENT = re.compile(r'\[' + JAIL + r'\]\s+(Found|Ban|Unban)\s+(\S+)')


def set_scope(scope):
    global ROOT, JAIL, EVENT, SCOPE, JAIL_FILE
    if scope not in ('ssh', 'panel'):
        raise ValueError('防护对象无效')
    SCOPE = scope
    ROOT = Path('/var/lib/nodepilot/security' + ('/panel' if scope == 'panel' else ''))
    JAIL = 'nodepilot-panel' if scope == 'panel' else 'nodepilot-sshd'
    JAIL_FILE = '/etc/fail2ban/jail.d/' + JAIL + '.local'
    EVENT = re.compile(r'\[' + JAIL + r'\]\s+(Found|Ban|Unban)\s+(\S+)')


def parse_event(line, timestamp=None):
    match = EVENT.search(line)
    if not match:
        return None
    try:
        ip = str(ipaddress.ip_address(match[2]))
        if timestamp is None:
            timestamp = datetime.strptime(line[:23], '%Y-%m-%d %H:%M:%S,%f').timestamp()
        return {'ts': float(timestamp), 'ip': ip, 'kind': match[1]}
    except (ValueError, TypeError):
        return None


def connect_db(root=ROOT):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(root / 'events.sqlite', timeout=20)
    db.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, ts REAL, ip TEXT, kind TEXT)')
    db.execute('CREATE INDEX IF NOT EXISTS events_time ON events(ts)')
    db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)')
    db.commit()
    return db


def get_meta(db, key, default=None):
    row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else default


def put_meta(db, key, value):
    db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value)))


def collect_file(db, path):
    stat = path.stat()
    key = 'file:' + str(stat.st_dev) + ':' + str(stat.st_ino)
    state = get_meta(db, key, {'offset': 0, 'generation': 0})
    if stat.st_size < state['offset']:
        state = {'offset': 0, 'generation': state['generation'] + 1}
    consumed = 0
    with path.open('rb') as stream:
        stream.seek(state['offset'])
        while consumed < 8 * 1024**2:
            offset = stream.tell()
            line = stream.readline(65536)
            if not line or not line.endswith(b'\n'):
                break
            consumed += len(line)
            event = parse_event(line.decode('utf-8', 'replace'))
            if event:
                identity = key + ':' + str(state['generation']) + ':' + str(offset)
                db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?)', (identity, event['ts'], event['ip'], event['kind']))
            state['offset'] = stream.tell()
    put_meta(db, key, state)


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=25)
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 1, ''


def collect(db, log=None):
    if log is None:
        code, target = command(['fail2ban-client','get','logtarget'])
        log = Path(target) if code == 0 and Path(target).is_absolute() else Path('/var/log/fail2ban.log')
        if code == 0 and not Path(target).is_absolute():
            log = Path('/var/lib/nodepilot/security/no-file-log')
    db.execute('BEGIN IMMEDIATE')
    try:
        if log.exists():
            # Read the rotated file before the current one. Persist each inode's offset.
            rotated = log.with_name(log.name + '.1')
            if rotated.exists():
                collect_file(db, rotated)
            collect_file(db, log)
            source = str(log)
        else:
            cursor = get_meta(db, 'journal_cursor')
            args = ['journalctl', '-u', 'fail2ban', '--no-pager', '-o', 'json', '--since', '90 days ago']
            if cursor:
                args += ['--after-cursor', cursor]
            # Stream up to a bounded number of records; do not silently jump to the tail.
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as process:
                try:
                    for n, line in enumerate(process.stdout):
                        if n >= 50000:
                            break
                        try:
                            entry = json.loads(line)
                            message = entry.get('MESSAGE', '')
                            event = parse_event(message, int(entry['__REALTIME_TIMESTAMP']) / 1e6)
                            if event:
                                db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?)', ('journal:' + entry['__CURSOR'], event['ts'], event['ip'], event['kind']))
                            put_meta(db, 'journal_cursor', entry['__CURSOR'])
                        except (ValueError, KeyError, TypeError):
                            continue
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=5)
            source = 'systemd journal'
        now = time.time()
        db.execute('DELETE FROM events WHERE ts < ?', (now - 90 * 86400,))
        if get_meta(db, 'started') is None:
            put_meta(db, 'started', now)
        put_meta(db, 'updated', now)
        put_meta(db, 'source', source)
        db.commit()
    except Exception:
        db.rollback()
        raise


def summarize(db, days, active, now=None):
    now = time.time() if now is None else now
    today = datetime.fromtimestamp(now, BEIJING).replace(hour=0, minute=0, second=0, microsecond=0)
    since = (today - timedelta(days=days - 1)).timestamp()
    grouped = db.execute("SELECT ip, SUM(kind='Found'), SUM(kind='Ban'), MAX(ts) FROM events WHERE ts>=? AND ts<=? GROUP BY ip", (since, now)).fetchall()
    rows = {ip: {'ip': ip, 'failures': failures, 'bans': bans, 'last': last, 'banned': ip in active} for ip, failures, bans, last in grouped}
    for ip in active:
        rows.setdefault(ip, {'ip': ip, 'failures': 0, 'bans': 0, 'last': 0, 'banned': True})
    metrics = {'failed_ips': sum(x['failures'] > 0 for x in rows.values()),
               'failures': sum(x['failures'] for x in rows.values()),
               'bans': sum(x['bans'] for x in rows.values()), 'currently_banned': len(active)}
    ordered = sorted(rows.values(), key=lambda x: (x['banned'], x['failures'], x['last']), reverse=True)
    return {'metrics': metrics, 'rows': ordered[:200], 'row_count': len(ordered), 'since': since, 'days': days}


def report(db, days):
    code, output = command(['fail2ban-client', 'get', JAIL, 'banip'])
    active = set()
    if code == 0:
        for token in output.replace(',', ' ').split():
            try:
                active.add(str(ipaddress.ip_address(token.strip("[]'\""))))
            except ValueError:
                pass
    result = summarize(db, days, active)
    state_error = code != 0 and Path(JAIL_FILE).exists()
    if state_error:
        result['metrics']['currently_banned'] = None
        for row in result['rows']:
            row['banned'] = None
    _, ban_times = command(['fail2ban-client', 'get', JAIL, 'banip', '--with-time']) if code == 0 else (1, '')
    _, service = command(['systemctl', 'is-active', 'fail2ban'])
    _, collector = command(['systemctl', 'is-active', 'nodepilot-security-stats.timer'])
    policy = json.loads((ROOT / 'policy.json').read_text()) if (ROOT / 'policy.json').exists() else {}
    result.update(scope=SCOPE, enabled=code == 0, installed=True, state_error=state_error, service=service, collector=collector, policy=policy,
                  ban_times=ban_times, updated=get_meta(db, 'updated'), started=get_meta(db, 'started'),
                  source=get_meta(db, 'source'), note='统计 ' + ('3x-ui 面板' if SCOPE == 'panel' else 'SSH') + ' 登录失败日志；失败不一定是恶意爆破。历史保留 90 天，IP 去重；明细最多 200 行。')
    if state_error:
        result['note'] += ' 防护规则已配置，但 Fail2ban 状态读取失败，请检查服务日志；当前封禁数量未知。'
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--days', type=int, choices=(1, 7, 30, 90), default=1)
    parser.add_argument('--scope', choices=('ssh', 'panel'), default='ssh')
    parser.add_argument('--all', action='store_true')
    args = parser.parse_args()
    if args.all and not args.collect:
        parser.error('--all is only used for collection')
    scopes = ('ssh', 'panel') if args.all else (args.scope,)
    errors = []
    for scope in scopes:
        set_scope(scope)
        if args.all and not (ROOT / 'policy.json').exists():
            continue
        db = connect_db(ROOT)
        try:
            collect(db)
            if not args.collect:
                print(json.dumps(report(db, args.days), ensure_ascii=False))
        except Exception as ex:
            errors.append(scope + ': ' + str(ex))
        finally:
            db.close()
    if errors:
        raise RuntimeError('; '.join(errors))


if __name__ == '__main__':
    main()
