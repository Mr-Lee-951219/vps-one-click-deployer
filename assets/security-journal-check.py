"""Read-only guard for Debian's stock sshd jail on journald-only hosts."""
import configparser
import hashlib
import json
from pathlib import Path
import subprocess


def inspect(root=Path('/etc/fail2ban'), auth_log=Path('/var/log/auth.log'), conffiles=None):
    if auth_log.exists():
        return {'compatible': False, 'reason': '传统 SSH 日志存在，不自动修改默认规则'}
    if conffiles is None:
        conffiles = subprocess.check_output(
            ['dpkg-query', '-W', '-f=${Conffiles}', 'fail2ban'], text=True, timeout=10)
    hashes = {parts[0]: parts[1] for line in conffiles.splitlines()
              if len(parts := line.split()) >= 2}
    for relative in ('jail.conf', 'filter.d/sshd.conf'):
        path = root / relative
        digest = hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()
        if hashes.get(str(path)) != digest:
            return {'compatible': False, 'reason': '默认 SSH 规则或过滤器已被修改，请检查自定义日志来源'}
    defaults = configparser.ConfigParser(interpolation=None)
    defaults.read(root / 'jail.d/defaults-debian.conf')
    if not defaults.has_section('sshd') or not defaults.getboolean('sshd', 'enabled', fallback=False):
        return {'compatible': False, 'reason': '未识别到 Debian 默认 SSH 规则'}
    candidates = [root / 'jail.local']
    candidates += sorted((root / 'jail.d').glob('*.conf')) + sorted((root / 'jail.d').glob('*.local'))
    for path in candidates:
        if not path.exists() or path.name in ('nodepilot-sshd.local', 'zz-nodepilot-journal.local'):
            continue
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(path)
        # Inherited DEFAULT options count too; an administrator's choice wins.
        if parser.has_section('sshd'):
            if any(key in parser['sshd'] for key in ('backend', 'logpath', 'filter', 'journalmatch')):
                return {'compatible': False, 'reason': '已有自定义 SSH 日志设置，未自动覆盖'}
        elif any(key in parser.defaults() for key in ('backend', 'logpath', 'filter', 'journalmatch')):
            return {'compatible': False, 'reason': '已有自定义默认日志设置，未自动覆盖'}
    return {'compatible': True, 'reason': 'Debian 默认 sshd 规则缺少传统日志，可使用 systemd 日志'}


if __name__ == '__main__':
    try:
        result = inspect()
    except Exception as error:
        result = {'compatible': False, 'reason': '日志兼容检查失败：' + str(error)}
    print(json.dumps(result, ensure_ascii=False))
