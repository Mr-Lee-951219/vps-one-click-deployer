"""Manage independent SSH and panel jails without replacing the host firewall."""
import ipaddress
import json
import re
import shlex
import time

PANEL_JAIL = 'nodepilot-panel'
PANEL_ROOT = '/var/lib/nodepilot/security/panel'
PANEL_FILE = '/etc/fail2ban/jail.d/nodepilot-panel.local'
PANEL_FILTER = '/etc/fail2ban/filter.d/nodepilot-panel.conf'
JAIL = 'nodepilot-sshd'
ROOT = '/var/lib/nodepilot/security'
JAIL_FILE = '/etc/fail2ban/jail.d/nodepilot-sshd.local'
JOURNAL_FILE = '/etc/fail2ban/jail.d/zz-nodepilot-journal.local'
JOURNAL_CONFIG = '# NodePilot: Debian stock sshd jail on a journald-only host.\n[sshd]\nbackend = systemd\n'
READY_CHECK = 'command -v fail2ban-client >/dev/null && command -v nft >/dev/null && python3 -c "import systemd.journal" >/dev/null 2>&1 && echo ready || true'
WAIT_READY = '''for attempt in $(seq 1 30); do
    if fail2ban-client ping >/dev/null 2>&1; then echo ready; exit 0; fi
    if systemctl is-failed --quiet fail2ban; then break; fi
    sleep 1
done
echo 'Fail2ban 服务未能就绪，请查看下方诊断' >&2
exit 1'''
DIAGNOSTICS = 'journalctl -u fail2ban -n 25 --no-pager 2>&1; test ! -f /var/log/fail2ban.log || tail -n 25 /var/log/fail2ban.log 2>&1'


def validate_policy(payload):
    result = {}
    for key, low, high in (('maxretry', 2, 30), ('findtime', 60, 86400), ('bantime', 60, 31536000)):
        value = payload.get(key)
        if key == 'bantime' and value == -1:
            result[key] = -1
        elif type(value) is not int or not low <= value <= high:
            raise ValueError('请检查失败次数、观察时间和封禁时长')
        else:
            result[key] = value
    networks = payload.get('whitelist', [])
    if not isinstance(networks, list) or len(networks) > 32:
        raise ValueError('白名单最多填写 32 个 IP 或网段')
    result['whitelist'] = list(dict.fromkeys(str(ipaddress.ip_network(x.strip(), strict=False)) for x in networks))
    result['increment'] = bool(payload.get('increment', True)) and result['bantime'] != -1
    return result


def jail_config(policy, port, peer='', scope='ssh', logpath=''):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('防护端口无效')
    if scope not in ('ssh', 'panel'):
        raise ValueError('防护对象无效')
    if scope == 'panel' and (not re.fullmatch(r'/[A-Za-z0-9_./-]+', logpath) or '..' in logpath.split('/')):
        raise ValueError('面板日志路径无效')
    policy = validate_policy(policy)
    ignore = ['127.0.0.0/8', '::1'] + policy['whitelist']
    if peer:
        ignore.append(str(ipaddress.ip_address(peer)))
    source = (['filter = sshd', 'backend = systemd',
               'journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd']
              if scope == 'ssh' else ['filter = nodepilot-panel', 'backend = polling', 'logpath = ' + logpath,
                                     'action = nftables-multiport[name=nodepilot-panel, port="' + str(port) + '", protocol=tcp]'])
    return '\n'.join([
        '# Managed by NodePilot; other jails are left untouched.',
        '[' + (JAIL if scope == 'ssh' else PANEL_JAIL) + ']', 'enabled = true', *source,
        'port = ' + str(port), 'protocol = tcp', 'usedns = no',
        'banaction = nftables-multiport', 'ignoreip = ' + ' '.join(dict.fromkeys(ignore)),
        'maxretry = ' + str(policy['maxretry']), 'findtime = ' + str(policy['findtime']),
        'bantime = ' + str(policy['bantime']),
        'bantime.increment = ' + str(policy['increment']).lower(),
        'bantime.multipliers = 1 24 168',
        'bantime.maxtime = ' + str(max(604800, policy['bantime'])), '',
    ])


TIMER = '''cat > /etc/systemd/system/nodepilot-security-stats.service <<'NP_SERVICE'
[Unit]
Description=NodePilot SSH and panel security statistics
[Service]
Type=oneshot
UMask=0077
TimeoutStartSec=150
ExecStart=/usr/bin/python3 /var/lib/nodepilot/security/collector.py --collect --all
NP_SERVICE
cat > /etc/systemd/system/nodepilot-security-stats.timer <<'NP_TIMER'
[Unit]
Description=Collect NodePilot login security statistics every minute
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
NP_TIMER
systemctl daemon-reload
systemctl enable --now nodepilot-security-stats.timer
systemctl start nodepilot-security-stats.service
'''


class SecurityMixin:
    def security_context(self, payload=None):
        scope = (payload or {}).get('scope', 'ssh')
        if scope not in ('ssh', 'panel'):
            raise ValueError('防护对象无效')
        return {'scope': scope, 'jail': JAIL if scope == 'ssh' else PANEL_JAIL,
                'root': ROOT if scope == 'ssh' else PANEL_ROOT,
                'file': JAIL_FILE if scope == 'ssh' else PANEL_FILE,
                'label': 'SSH' if scope == 'ssh' else '3x-ui 面板'}

    def security_command(self, days, payload=None):
        if days not in (1, 7, 30, 90):
            raise ValueError('统计范围无效')
        ctx = self.security_context(payload)
        return 'python3 ' + ROOT + '/collector.py --days ' + str(days) + (' --scope panel' if ctx['scope'] == 'panel' else '')

    def security_status(self, payload=None):
        ctx = self.security_context(payload)
        self.ssh.connect()
        days = (payload or {}).get('days', 1)
        command = self.security_command(days, payload)
        if not self.ssh.exists(ROOT + '/collector.py') or (ctx['scope'] == 'panel' and not self.ssh.exists(ctx['root'] + '/policy.json')):
            return {'scope': ctx['scope'], 'enabled': False, 'installed': False, 'days': days, 'rows': [], 'metrics': {},
                    'note': '尚未通过本软件启用 ' + ctx['label'] + ' 防爆破；启用后开始记录，历史最多保留 90 天。'}
        result = json.loads(self.ssh.run(command, timeout=90))
        result['scope'] = ctx['scope']
        if ctx['scope'] == 'panel' and result.get('enabled'):
            policy = result.get('policy') or self.ssh.json(ctx['root'] + '/policy.json', {})
            result['policy'] = policy
            try:
                target = self.panel_security_target()
                if target['port'] != policy.get('port') or target['logpath'] != policy.get('logpath'):
                    raise RuntimeError('面板端口或日志路径已改变，请重新启用 / 更新面板防护')
            except Exception as ex:
                result['target_error'] = str(ex)
                result['note'] = result.get('note', '') + '\n' + str(ex)
        current = result['metrics']['currently_banned']
        state = '规则需检查或更新' if result.get('target_error') else ('已启用' if result['enabled'] else '未启用或状态不可用')
        self.log(ctx['label'] + ' 防爆破：' + state + '；当前封禁 ' + (str(current)+' 个 IP' if current is not None else '读取失败'))
        return result

    def panel_security_target(self):
        # Read the live process environment, database settings and actual listener.
        source = (self.assets / 'panel-security-check.py').read_text(encoding='utf-8')
        target = json.loads(self.ssh.run("python3 - <<'NP_PANEL'\n" + source + "\nNP_PANEL", timeout=90))
        port = target.get('port')
        if type(port) is not int or not 1 <= port <= 65535 or port == self.settings.ssh_port:
            raise ValueError('面板端口无效或与 SSH 共用，未设置封禁')
        return target

    def security_apply(self, payload):
        if payload.get('endpoint') != self.settings.host + ':' + str(self.settings.ssh_port):
            raise ValueError('目标服务器变化，请重新设置防爆破规则')
        ctx = self.security_context(payload)
        root, jail, jail_file, label = ctx['root'], ctx['jail'], ctx['file'], ctx['label']
        policy = validate_policy(payload)
        self.ssh.connect()
        self.ssh.run('install -d -m 700 /var/lib/nodepilot ' + ROOT + ' ' + root)
        self.ssh.lock()
        # The actual connected source is allowlisted before the jail becomes active.
        peer = self.ssh.run('printf "%s" "$SSH_CONNECTION"').split()
        if not peer:
            raise RuntimeError('无法确认当前管理连接的来源 IP，未启用封禁规则')
        peer = str(ipaddress.ip_address(peer[0]))
        target = self.panel_security_target() if ctx['scope'] == 'panel' else {'port': self.settings.ssh_port}
        config = jail_config(policy, target['port'], peer, ctx['scope'], target.get('logpath', ''))
        self.ssh.run('test "$(id -u)" = 0 && . /etc/os-release && test "$ID" = debian && test "$VERSION_ID" = 12')
        if self.ssh.run(READY_CHECK).strip() != 'ready':
            self.ssh.run('rm -f -- /var/lib/nodepilot/jobs/security-dependencies.status')
            setup='/var/lib/nodepilot/jobs/security-package-setup.py'
            self.ssh.run('install -d -m 700 /var/lib/nodepilot/jobs')
            self.ssh.write(setup,(self.assets/'security-packages.py').read_bytes(),0o700)
            self.ssh.job('security-dependencies','python3 '+setup+' --reference-utc '+str(int(time.time())),1200)
            if self.ssh.run(READY_CHECK).strip() != 'ready':
                raise RuntimeError('防护组件安装未通过回读检查，请检查右侧安装日志后重试')
        else:
            self.log('SSH 防护组件已就绪，跳过软件源刷新与重复安装。')
        old = self.ssh.read(jail_file) if self.ssh.exists(jail_file) else None
        old_filter = self.ssh.read(PANEL_FILTER) if ctx['scope'] == 'panel' and self.ssh.exists(PANEL_FILTER) else None
        old_journal = self.ssh.read(JOURNAL_FILE) if self.ssh.exists(JOURNAL_FILE) else None
        journal_changed = False
        old_policy = self.ssh.json(root + '/policy.json', None)
        self.ssh.write(ROOT + '/collector.py', (self.assets / 'security-collector.py').read_bytes(), 0o700)
        try:
            self.ssh.write(jail_file, config)
            if ctx['scope'] == 'panel':
                self.ssh.write(PANEL_FILTER, (self.assets / 'nodepilot-panel.conf').read_bytes())
            try:
                self.ssh.run('fail2ban-client -t', timeout=90)
            except Exception as ex:
                if 'Have not found any log file for sshd jail' not in str(ex):
                    raise
                checker = ROOT + '/journal-check.py'
                self.ssh.write(checker, (self.assets / 'security-journal-check.py').read_bytes(), 0o700)
                compatible = json.loads(self.ssh.run('python3 ' + checker))
                if not compatible.get('compatible'):
                    raise RuntimeError(str(ex) + '\n' + compatible.get('reason', '无法确认默认日志配置')) from ex
                if old_journal is not None and old_journal != JOURNAL_CONFIG.encode():
                    raise RuntimeError('日志兼容配置已被手动修改，未自动覆盖。\n' + str(ex)) from ex
                self.log('识别到 Debian 默认 SSH 规则缺少 /var/log/auth.log，切换为读取 systemd 日志。')
                journal_changed = True
                self.ssh.write(JOURNAL_FILE, JOURNAL_CONFIG)
                self.ssh.run('fail2ban-client -t', timeout=90)
            self.ssh.run('systemctl enable --now fail2ban', timeout=90)
            self.ssh.run(WAIT_READY, timeout=45)
            self.ssh.run('fail2ban-client reload ' + jail, timeout=90)
            self.ssh.run('fail2ban-client status ' + jail)
            if ctx['scope'] == 'panel' and 'nftables' not in self.ssh.run('fail2ban-client get ' + jail + ' actions'):
                raise RuntimeError('面板规则未加载实际防火墙封禁动作，未确认生效')
        except Exception as ex:
            self.log('防爆破启用失败，具体原因：' + str(ex))
            try:
                self.log('Fail2ban 诊断：\n' + self.ssh.run(DIAGNOSTICS, check=False, timeout=30)[-6000:])
            except Exception as diagnostic_error:
                self.log('读取诊断未完成：' + str(diagnostic_error))
            rollback_errors = []
            # Restore files independently so one failed operation cannot skip the others.
            for path, previous in ([(jail_file, old)] + ([(PANEL_FILTER, old_filter)] if ctx['scope'] == 'panel' else [])
                                   + ([(JOURNAL_FILE, old_journal)] if journal_changed else [])):
                try:
                    if previous is None:
                        self.ssh.run('rm -f -- ' + path)
                    else:
                        self.ssh.write(path, previous)
                    if self.ssh.exists(path) != (previous is not None) or (previous is not None and self.ssh.read(path) != previous):
                        raise RuntimeError('配置文件回读不一致')
                except Exception as rollback_error:
                    rollback_errors.append(path + '：' + str(rollback_error))
            try:
                if self.ssh.run('fail2ban-client ping >/dev/null 2>&1 && echo ready || true').strip() == 'ready':
                    if old is None:
                        active = self.ssh.run('fail2ban-client status '+jail+' >/dev/null 2>&1 && echo active || true').strip()
                        if active:
                            self.ssh.run('fail2ban-client stop ' + jail)
                    else:
                        self.ssh.run('fail2ban-client reload ' + jail)
            except Exception as rollback_error:
                rollback_errors.append('运行规则：' + str(rollback_error))
            rollback = '已回读恢复原配置文件；请刷新确认防护状态。'
            if rollback_errors:
                rollback = '恢复原规则未全部完成：' + '；'.join(rollback_errors)
            self.log(rollback)
            raise RuntimeError('防爆破启用失败：\n' + str(ex)[-1800:] + '\n\n' + rollback + '\n详细诊断已显示在右侧日志。') from ex
        if old_policy is not None:
            self.ssh.write_json(root + '/previous-policy.json', old_policy)
        policy.update(port=target['port'], management_ip=peer, scope=ctx['scope'])
        if ctx['scope'] == 'panel':
            policy['logpath'] = target['logpath']
        self.ssh.write_json(root + '/policy.json', policy)
        try:
            self.ssh.run("bash -se <<'NP'\n" + TIMER + '\nNP', timeout=90)
        except Exception as ex:
            raise RuntimeError(label + ' 防护规则已启用，但统计定时任务未能启动。请刷新防护状态并检查 nodepilot-security-stats 服务日志；不要重复部署节点。') from ex
        self.log(label + ' 防爆破已启用，仅保护 TCP ' + str(target['port']) + '；当前管理来源 ' + peer + ' 已加入白名单。')
        return self.security_status({'scope': ctx['scope'], 'days': payload.get('days', 1)})

    def security_disable(self, payload=None):
        if (payload or {}).get('endpoint') != self.settings.host + ':' + str(self.settings.ssh_port):
            raise ValueError('目标服务器变化，请重新选择防护规则')
        ctx = self.security_context(payload)
        self.ssh.connect()
        if not self.ssh.exists(ctx['file']):
            return self.security_status(payload)
        self.ssh.run('install -d -m 700 /var/lib/nodepilot ' + ROOT)
        self.ssh.lock()
        running = self.ssh.run('fail2ban-client status '+ctx['jail']+' >/dev/null 2>&1 && echo active || true').strip()
        if running:
            self.ssh.run('fail2ban-client stop ' + ctx['jail'])
            if self.ssh.run('fail2ban-client status '+ctx['jail']+' >/dev/null 2>&1 && echo active || true').strip():
                raise RuntimeError(ctx['label'] + ' 防护仍在运行，未删除规则；请检查 Fail2ban 日志')
        elif not self.ssh.run('systemctl is-active fail2ban || true').strip() == 'active':
            raise RuntimeError('Fail2ban 服务不可用，无法确认封禁已解除；请通过服务商控制台检查')
        self.ssh.run('mv -f -- ' + ctx['file'] + ' ' + ctx['root'] + '/disabled-jail.conf')
        self.log('已停用本软件的 ' + ctx['label'] + ' 防爆破；其他防护规则与历史统计保持。')
        return self.security_status(payload)

    def security_restore(self, payload):
        ctx = self.security_context(payload)
        self.ssh.connect()
        previous = self.ssh.json(ctx['root'] + '/previous-policy.json', None)
        if not previous:
            raise ValueError('没有上一次防爆破配置可恢复')
        return self.security_apply({**previous, 'scope': ctx['scope'], 'endpoint': payload['endpoint'], 'days': payload.get('days', 1)})

    def security_unban(self, payload):
        if payload.get('endpoint') != self.settings.host + ':' + str(self.settings.ssh_port):
            raise ValueError('目标服务器变化，请重新选择封禁 IP')
        ctx = self.security_context(payload)
        ip = str(ipaddress.ip_address(payload.get('ip', '')))
        self.ssh.connect()
        self.ssh.run('fail2ban-client set ' + ctx['jail'] + ' unbanip ' + shlex.quote(ip))
        result = self.security_status(payload)
        if result.get('state_error') or any(row['ip']==ip and row['banned'] for row in result['rows']):
            raise RuntimeError('无法确认此 IP 已解封，请刷新防护统计后检查')
        self.log('已回读确认解除 ' + ctx['label'] + ' 封禁：' + ip)
        return result

