"""Read the running panel's real port/log path; do not change its settings."""
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess


def output(args):
    return subprocess.check_output(args, text=True, timeout=20).strip()


def inspect():
    version = output(['/usr/local/x-ui/x-ui', '-v']).lstrip('v')
    if version != '3.9.0':
        raise RuntimeError('面板登录防护当前适配 3x-ui v3.9.0，未修改其他版本的规则')
    pid = int(output(['systemctl', 'show', 'x-ui', '--property=MainPID', '--value']))
    if pid <= 0:
        raise RuntimeError('3x-ui 面板未运行，请先启动面板')
    environ = dict(entry.split('=', 1) for entry in Path('/proc/' + str(pid) + '/environ').read_bytes().decode().split('\0') if '=' in entry)
    db_folder = Path(environ.get('XUI_DB_FOLDER') or '/etc/x-ui')
    db_path = db_folder / 'x-ui.db'
    with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True) as db:
        settings = dict(db.execute('SELECT key,value FROM settings'))
        node_ports = {int(row[0]) for row in db.execute('SELECT port FROM inbounds')}
    port = int(settings.get('webPort', '2053'))
    if not 1 <= port <= 65535 or port in node_ports:
        raise RuntimeError('面板端口无效或与节点端口共用，未设置封禁')
    listen = settings.get('webListen', '')
    if listen and ipaddress.ip_address(listen).is_loopback:
        raise RuntimeError('面板仅监听本机，无需公网封禁；反向代理入口需要单独适配')
    proxies = settings.get('trustedProxyCIDRs', '127.0.0.1/32,::1/128')
    for item in proxies.split(','):
        if item.strip() and not ipaddress.ip_network(item.strip(), strict=False).is_loopback:
            raise RuntimeError('面板配置了外部可信代理，不能用直连端口规则保护代理入口')
    listeners = output(['ss', '-H', '-lntp']).splitlines()
    if not any(len(row.split()) > 3 and row.split()[3].endswith(':' + str(port)) and 'pid=' + str(pid) + ',' in row for row in listeners):
        raise RuntimeError('无法确认 3x-ui 进程正在监听此面板端口，未设置封禁')
    log_folder = Path(environ.get('XUI_LOG_FOLDER') or '/var/log/x-ui')
    if not log_folder.is_absolute():
        log_folder = Path(os.readlink('/proc/' + str(pid) + '/cwd')) / log_folder
    log_path = log_folder / '3xui.log'
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(log_path)) or '..' in log_path.parts:
        raise RuntimeError('自定义面板日志路径不受支持，请使用无空格的绝对路径')
    try:
        with log_path.open('rb') as stream:
            stream.read(1)
    except OSError as ex:
        raise RuntimeError('无法读取面板登录日志 ' + str(log_path) + '，未启用封禁') from ex
    return {'port': port, 'logpath': str(log_path), 'version': version, 'listen': listen}


if __name__ == '__main__':
    print(json.dumps(inspect()))
