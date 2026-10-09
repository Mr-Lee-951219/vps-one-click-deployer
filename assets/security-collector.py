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


def set_scope(scope, jail=None):
    global ROOT, JAIL, EVENT, SCOPE, JAIL_FILE
    if scope not in ('ssh', 'panel'):
        raise ValueError('防护对象无效')
    SCOPE = scope
    jail = jail or ('nodepilot-panel' if scope == 'panel' else 'nodepilot-sshd')
    if jail not in (('sshd', 'nodepilot-sshd') if scope == 'ssh' else ('nodepilot-panel',)):
        raise ValueError('防护规则名称无效')
    ROOT = Path('/var/lib/nodepilot/security' + ('/panel' if scope == 'panel' else ('/sshd' if jail == 'sshd' else '')))
    JAIL = jail
    JAIL_FILE = '/etc/fail2ban/jail.d/' + ('zzzz-nodepilot-sshd' if jail == 'sshd' else jail) + '.local'
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


def connect_db(root=ROOT, readonly=False):
    if not readonly:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(':memory:' if readonly else root / 'events.sqlite', timeout=20)
    db.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, ts REAL, ip TEXT, kind TEXT)')
    db.execute('CREATE INDEX IF NOT EXISTS events_time ON events(ts)')
    db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)')
    if readonly:
        put_meta(db, 'ephemeral', True)
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
        if get_meta(db, 'ephemeral', False) and state['offset'] == 0 and stat.st_size > 8 * 1024**2:
            # Existing manual servers are read without a persisted cursor. Prefer recent
            # records instead of repeatedly scanning only the oldest part of a large log.
            stream.seek(stat.st_size - 8 * 1024**2)
            stream.readline(65536)
            state['offset'] = stream.tell()
            put_meta(db, 'partial', True)
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
    if state['offset'] < stat.st_size:
        put_meta(db, 'partial', True)


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=25)
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 1, ''


def logging_path(output):
    # The client normally wraps the value in "Current logging target is:\n`- ...".
    for line in output.splitlines():
        value = line.strip().removeprefix('`- ').removeprefix('|- ').strip()
        if value.startswith('/') or Path(value).is_absolute():
            return Path(value)
    return None


def collect(db, log=None):
    if log is None:
        code, target = command(['fail2ban-client','get','logtarget'])
        log = logging_path(target) if code == 0 else Path('/var/log/fail2ban.log')
        if log is None:
            log = Path('/var/lib/nodepilot/security/no-file-log')
    db.execute('BEGIN IMMEDIATE')
    try:
        put_meta(db, 'partial', False)
        put_meta(db, 'log_available', True)
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
                records = 0
                try:
                    for n, line in enumerate(process.stdout):
                        records += 1
                        if n >= 50000:
                            put_meta(db, 'partial', True)
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
                if (not records and not cursor) or process.returncode not in (0, -15):
                    put_meta(db, 'log_available', False)
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


def status_counts(output):
    """Parse named status fields; never infer counters from the number of log rows."""
    result = {}
    for field, key in [('Currently failed', 'currently_failed'), ('Total failed', 'total_failed'),
                       ('Currently banned', 'currently_banned'), ('Total banned', 'total_banned')]:
        match = re.search(r'\b' + field + r':\s*(\d+)\s*$', output, re.M)
        result[key] = int(match[1]) if match else None
    return result


def choose_jail(scope, requested='auto'):
    if scope == 'panel':
        if requested not in ('auto', 'nodepilot-panel'):
            raise ValueError('防护规则名称无效')
        return 'nodepilot-panel', []
    if requested not in ('auto', 'sshd', 'nodepilot-sshd'):
        raise ValueError('防护规则名称无效')
    _, output = command(['fail2ban-client', 'status'])
    match = re.search(r'Jail list:\s*(.*)', output)
    active = {name.strip() for name in match[1].split(',')} if match else set()
    available = [name for name in ('sshd', 'nodepilot-sshd') if name in active]
    if requested != 'auto':
        return requested, available
    if available:
        return available[0], available
    if Path('/etc/fail2ban/jail.d/nodepilot-sshd.local').exists():
        return 'nodepilot-sshd', available
    return 'sshd', available


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
    status_code, status_output = command(['fail2ban-client', 'status', JAIL])
    totals = status_counts(status_output) if status_code == 0 else {}
    code, output = command(['fail2ban-client', 'get', JAIL, 'banip'])
    active = set()
    if code == 0:
        for token in output.replace(',', ' ').split():
            try:
                active.add(str(ipaddress.ip_address(token.strip("[]'\""))))
            except ValueError:
                pass
    result = summarize(db, days, active)
    action_error = ''
    action_code, action_output = command(['fail2ban-client', 'get', JAIL, 'actions']) if status_code == 0 else (1, '')
    action_names = [line.strip().removeprefix('`- ').removeprefix('|- ').strip() for line in action_output.splitlines()]
    action_names = [name for name in action_names if re.fullmatch(r'[A-Za-z0-9_.:-]+', name)]
    if status_code == 0 and (action_code != 0 or not action_names):
        action_error = '封禁动作缺失或读取失败；规则能统计不代表能执行封禁，请重新启用 / 更新防护。'
    elif status_code == 0:
        firewall_action = False
        for name in action_names[:16]:
            ban_code, ban = command(['fail2ban-client', 'get', JAIL, 'action', name, 'actionban'])
            if ban_code == 0 and re.search(r'\b(?:nft|iptables|ip6tables)(?:-nft|-legacy)?\b', ban):
                firewall_action = True
                break
        if not firewall_action:
            action_error = '未确认可用的防火墙封禁动作；请核对动作命令与防护规则。'
    state_error = (code != 0 and (status_code == 0 or Path(JAIL_FILE).exists())) or (status_code != 0 and code == 0)
    if code != 0:
        result['metrics']['currently_banned'] = None
        for row in result['rows']:
            row['banned'] = None
    _, ban_times = command(['fail2ban-client', 'get', JAIL, 'banip', '--with-time']) if code == 0 else (1, '')
    _, service = command(['systemctl', 'is-active', 'fail2ban'])
    _, collector = command(['systemctl', 'is-active', 'nodepilot-security-stats.timer'])
    policy = json.loads((ROOT / 'policy.json').read_text()) if (ROOT / 'policy.json').exists() else {}
    managed = bool(policy)
    log_available = get_meta(db, 'log_available', True)
    if not log_available:
        for key in ('failed_ips', 'failures', 'bans'):
            result['metrics'][key] = None
    partial = get_meta(db, 'partial', False)
    result.update(scope=SCOPE, jail=JAIL, enabled=code == 0 and status_code == 0 and not action_error, installed=bool(managed or status_code == 0), managed=managed,
                  action_error=action_error, action_names=action_names,
                  active_ips=sorted(active) if code == 0 else None,
                  state_error=state_error, service=service, collector=collector if managed else '未安装（刷新时读取已有日志）', policy=policy,
                  totals=totals, status_output=status_output if status_code == 0 else '', log_available=log_available, partial=partial,
                  ban_times=ban_times, updated=get_meta(db, 'updated'), started=get_meta(db, 'started'),
                  source=get_meta(db, 'source'), note='按天统计来自可读取的 ' + JAIL + ' 失败与封禁日志；已删除的日志无法补回。累计计数来自 Fail2ban status，可能随服务或规则重启重置，与按天统计分别显示。明细最多 200 行。')
    if not managed:
        result['note'] += ' 当前仅兼容读取已有规则与日志，未安装采集服务或修改防护配置。'
    if action_error:
        result['note'] += ' ' + action_error
    if not log_available:
        result['note'] += ' 历史日志读取失败，按天统计未确认；请参考累计计数和当前封禁列表。'
    if partial:
        result['note'] += ' 日志超过单次读取上限，本次按天统计不完整。'
    if not result['enabled'] and not state_error and not action_error:
        result['note'] += ' 此规则未运行或 Fail2ban 不可用；有历史记录也不代表当前在防护。'
    if state_error:
        result['note'] += ' 防护规则已配置，但 Fail2ban 状态读取失败，请检查服务日志；当前封禁数量未知。'
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--days', type=int, choices=(1, 7, 30, 90), default=1)
    parser.add_argument('--scope', choices=('ssh', 'panel'), default='ssh')
    parser.add_argument('--jail', choices=('auto', 'sshd', 'nodepilot-sshd', 'nodepilot-panel'), default='auto')
    parser.add_argument('--all', action='store_true')
    args = parser.parse_args()
    if args.all and not args.collect:
        parser.error('--all is only used for collection')
    scopes = (('ssh', 'nodepilot-sshd'), ('ssh', 'sshd'), ('panel', 'nodepilot-panel')) if args.all else ((args.scope, args.jail),)
    errors = []
    for scope, requested in scopes:
        jail, available = (requested, []) if args.all else choose_jail(scope, requested)
        set_scope(scope, jail)
        if args.all and not (ROOT / 'policy.json').exists():
            continue
        readonly = not (ROOT / 'policy.json').exists()
        db = connect_db(ROOT, readonly=readonly)
        try:
            try:
                collect(db)
            except (OSError, sqlite3.Error, subprocess.SubprocessError) as ex:
                if args.collect:
                    raise
                put_meta(db, 'log_available', False)
                put_meta(db, 'log_error', str(ex))
            if not args.collect:
                result = report(db, args.days)
                result['available_jails'] = available
                print(json.dumps(result, ensure_ascii=False))
        except Exception as ex:
            errors.append(scope + ': ' + str(ex))
        finally:
            db.close()
    if errors:
        raise RuntimeError('; '.join(errors))


if __name__ == '__main__':
    main()
