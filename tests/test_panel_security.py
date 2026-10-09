import configparser
import importlib.util
import json
import io
from pathlib import Path, PurePosixPath
import re
import sys

import pytest
from test_security import FakeSSH, Manager, payload, policy, line
from deployer.security import (JAIL, JAIL_FILE, ROOT, PANEL_JAIL, PANEL_FILE,
                               PANEL_FILTER, PANEL_ROOT, jail_config, TIMER)


def load_asset(name):
    spec = importlib.util.spec_from_file_location(name, Path('assets') / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def panel_payload():
    return {**payload(), 'scope': 'panel'}


class PanelSSH(FakeSSH):
    def __init__(self):
        super().__init__()
        self.running_jails = {JAIL}
        self.target = {'port': 29528, 'logpath': '/var/log/x-ui/3xui.log', 'version': '3.9.0'}
        self.fail_filter_write = False

    def write(self, path, data, mode=None):
        if self.fail_filter_write and path == PANEL_FILTER and data != b'old filter':
            raise RuntimeError('filter write failed')
        super().write(path, data, mode)

    def run(self, command, **kwargs):
        self.commands.append(command)
        if command.startswith("python3 - <<'NP_PANEL'"):
            return json.dumps(self.target)
        if command.startswith('fail2ban-client reload '):
            jail = command.split()[2]
            if self.fail_reload and jail == PANEL_JAIL:
                raise RuntimeError('panel reload error')
            self.running_jails.add(jail)
            return ''
        if command.startswith('fail2ban-client stop '):
            self.running_jails.discard(command.split()[2])
            return ''
        if command == 'fail2ban-client get ' + PANEL_JAIL + ' actions':
            return 'nftables-multiport'
        if command.startswith('fail2ban-client status ') and 'echo active' in command:
            return 'active' if command.split()[2] in self.running_jails else ''
        if command.startswith('mv -f -- '):
            self.files.pop(command.split()[3], None)
            return ''
        if command.startswith('python3 ' + ROOT + '/collector.py'):
            jail = PANEL_JAIL if '--scope panel' in command else JAIL
            return json.dumps({'enabled': jail in self.running_jails, 'installed': True,
                               'rows': [], 'metrics': {'currently_banned': 0}})
        return super().run(command, **kwargs)


def manager():
    value = Manager()
    value.ssh = PanelSSH()
    value.ssh.files[JAIL_FILE] = b'ssh rule'
    value.ssh.files[ROOT + '/policy.json'] = policy()
    return value


def test_panel_rule_uses_live_port_and_does_not_touch_ssh_or_nodes():
    m = manager()
    result = m.security_apply(panel_payload())
    assert result['scope'] == 'panel' and result['enabled']
    rule = m.ssh.files[PANEL_FILE]
    assert 'port = 29528' in rule and '54887' not in rule
    assert 'backend = polling' in rule and 'logpath = /var/log/x-ui/3xui.log' in rule
    assert 'allports' not in rule and 'protocol = tcp' in rule
    assert '203.0.113.9' in rule and PANEL_FILTER in m.ssh.files
    assert m.ssh.files[JAIL_FILE] == b'ssh rule'
    assert m.ssh.files[ROOT + '/policy.json'] == policy()
    assert m.ssh.files[PANEL_ROOT + '/policy.json']['port'] == 29528
    assert '--collect --all' in TIMER


@pytest.mark.parametrize('failure', ['reload', 'filter-write'])
def test_panel_failure_restores_filter_and_rule_without_stopping_ssh(failure):
    m = manager()
    m.ssh.files[PANEL_FILE] = b'old panel rule'
    m.ssh.files[PANEL_FILTER] = b'old filter'
    m.ssh.fail_reload = failure == 'reload'
    m.ssh.fail_filter_write = failure == 'filter-write'
    with pytest.raises(RuntimeError):
        m.security_apply(panel_payload())
    assert m.ssh.files[PANEL_FILE] == b'old panel rule'
    assert m.ssh.files[PANEL_FILTER] == b'old filter'
    assert m.ssh.files[JAIL_FILE] == b'ssh rule'
    assert JAIL in m.ssh.running_jails
    assert PANEL_ROOT + '/policy.json' not in m.ssh.files


def test_panel_stop_and_unban_are_scoped_and_history_is_preserved():
    m = manager()
    m.security_apply(panel_payload())
    m.security_unban({**panel_payload(), 'ip': '198.51.100.2'})
    assert 'fail2ban-client set nodepilot-panel unbanip 198.51.100.2' in m.ssh.commands
    m.security_disable(panel_payload())
    assert PANEL_FILE not in m.ssh.files and PANEL_JAIL not in m.ssh.running_jails
    assert JAIL in m.ssh.running_jails and JAIL_FILE in m.ssh.files
    assert PANEL_ROOT + '/policy.json' in m.ssh.files


def test_panel_restore_cannot_restore_ssh_policy():
    m = manager()
    m.ssh.files[ROOT + '/previous-policy.json'] = policy()
    with pytest.raises(ValueError, match='没有上一次'):
        m.security_restore(panel_payload())
    m.ssh.files[PANEL_ROOT + '/previous-policy.json'] = policy()
    m.security_restore(panel_payload())
    assert PANEL_FILE in m.ssh.files and m.ssh.files[JAIL_FILE] == b'ssh rule'


def test_changed_panel_port_does_not_continue_to_show_protected():
    m = manager()
    m.security_apply(panel_payload())
    m.ssh.target['port'] = 29600
    result = m.security_status(panel_payload())
    assert result['enabled'] and result['target_error']
    assert '重新启用' in result['note']
    assert result['policy']['port'] == 29528


def test_jail_without_firewall_action_is_not_reported_successful():
    m = manager()
    original = m.ssh.run
    def run(command, **kwargs):
        if command == 'fail2ban-client get ' + PANEL_JAIL + ' actions':
            return ''
        return original(command, **kwargs)
    m.ssh.run = run
    with pytest.raises(RuntimeError, match='实际防火墙'):
        m.security_apply(panel_payload())
    assert PANEL_FILE not in m.ssh.files and JAIL_FILE in m.ssh.files


@pytest.mark.parametrize('changes', [{'scope': 'bad; reboot'}, {'endpoint': 'wrong'}])
def test_invalid_panel_target_is_rejected_before_any_remote_command(changes):
    m = manager()
    with pytest.raises(ValueError):
        m.security_apply({**panel_payload(), **changes})
    assert not m.ssh.commands


def test_shared_ssh_port_and_unsafe_log_path_never_create_a_panel_jail():
    m = manager()
    m.ssh.target['port'] = m.settings.ssh_port
    with pytest.raises(ValueError, match='共用'):
        m.security_apply(panel_payload())
    assert PANEL_FILE not in m.ssh.files
    for bad in ['/var/log/x-ui/a\nenabled=true', '/var/log/../auth.log']:
        with pytest.raises(ValueError):
            jail_config(policy(), 29528, scope='panel', logpath=bad)


def test_filter_matches_real_warning_formats_ipv6_and_rejects_username_ip_injection():
    config = configparser.ConfigParser()
    config.read('assets/nodepilot-panel.conf', encoding='utf-8')
    regex = config.get('Definition', 'failregex').replace('<HOST>', '(?P<host>[0-9a-fA-F:.]+)')
    pattern = re.compile(regex)
    for reason in ('invalid credentials', 'invalid 2FA code', 'too many failed attempts'):
        for ip in ('198.51.100.2', '2001:db8::7'):
            message = f' WARNING - failed login: username="admin", IP="{ip}", reason="{reason}"'
            assert pattern.fullmatch(message)['host'] == ip
            assert pattern.fullmatch(message + ', blocked_until=2026-10-09T09:00:00+08:00')
    username = r'victim\", IP=\"203.0.113.99'
    message = f'WARNING - failed login: username="{username}", IP="198.51.100.2", reason="invalid credentials"'
    assert pattern.fullmatch(message)['host'] == '198.51.100.2'
    assert not pattern.fullmatch(message.replace('WARNING', 'INFO'))
    assert not pattern.fullmatch('logged in successfully: username="admin", IP="198.51.100.2"')
    assert not pattern.fullmatch('unexpected text ' + message)
    assert config.get('Definition', 'datepattern') == '^%Y/%m/%d %H:%M:%S'


def test_statistics_use_separate_databases_and_do_not_double_count(tmp_path, monkeypatch):
    collector = load_asset('security-collector')
    log = tmp_path / 'fail2ban.log'
    log.write_text(line() + line('Ban') + line(ip='198.51.100.3').replace(JAIL, PANEL_JAIL)
                   + line('Ban', '198.51.100.3').replace(JAIL, PANEL_JAIL))
    results = []
    for scope in ('ssh', 'panel'):
        collector.set_scope(scope)
        root = tmp_path / scope
        monkeypatch.setattr(collector, 'ROOT', root)
        db = collector.connect_db(root)
        collector.collect(db, log)
        db.close()
        db = collector.connect_db(root)
        collector.collect(db, log)
        results.append(collector.summarize(db, 1, set()))
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 2
        db.close()
    assert results[0]['rows'][0]['ip'] == '198.51.100.2'
    assert results[1]['rows'][0]['ip'] == '198.51.100.3'
    assert all(result['metrics']['failures'] == 1 and result['metrics']['bans'] == 1 for result in results)


def test_all_collection_continues_with_other_scope_if_one_fails(tmp_path, monkeypatch):
    collector = load_asset('security-collector')
    original = collector.set_scope
    for scope in ('ssh', 'panel'):
        (tmp_path / scope).mkdir()
        (tmp_path / scope / 'policy.json').write_text('{}')
    def set_scope(scope):
        original(scope)
        collector.ROOT = tmp_path / scope
    called = []
    def collect(db):
        called.append(collector.SCOPE)
        if collector.SCOPE == 'ssh':
            raise RuntimeError('SSH log unavailable')
    monkeypatch.setattr(collector, 'set_scope', set_scope)
    monkeypatch.setattr(collector, 'collect', collect)
    monkeypatch.setattr(sys, 'argv', ['collector.py', '--collect', '--all'])
    with pytest.raises(RuntimeError, match='SSH log unavailable'):
        collector.main()
    assert called == ['ssh', 'panel']


@pytest.mark.parametrize('issue', ['none', 'version', 'loopback', 'proxy', 'shared-node', 'listener', 'missing-log'])
def test_panel_preflight_reads_actual_service_and_rejects_unsupported_targets(monkeypatch, issue):
    checker = load_asset('panel-security-check')
    settings = {'webPort': '29528', 'webListen': '127.0.0.1' if issue == 'loopback' else '0.0.0.0',
                'trustedProxyCIDRs': '0.0.0.0/0' if issue == 'proxy' else '127.0.0.1/32,::1/128'}
    class RemotePath(PurePosixPath):
        def read_bytes(self):
            assert str(self) == '/proc/100/environ'
            return b'XUI_LOG_FOLDER=/var/log/custom\0'
        def open(self, mode):
            assert str(self) == '/var/log/custom/3xui.log'
            if issue == 'missing-log':
                raise FileNotFoundError()
            return io.BytesIO(b'log')
    class Database:
        def __enter__(self):return self
        def __exit__(self, *args):pass
        def execute(self, sql):
            assert sql.startswith('SELECT')
            return settings.items() if 'settings' in sql else [(29528 if issue == 'shared-node' else 20001,)]
    def connect(database_uri, **kwargs):
        assert database_uri == 'file:///etc/x-ui/x-ui.db?mode=ro' and kwargs == {'uri': True}
        return Database()
    def output(args):
        if args[0] == '/usr/local/x-ui/x-ui':return '3.8.0' if issue == 'version' else '3.9.0'
        if args[0] == 'systemctl':return '100'
        if args[0] == 'ss':return '' if issue == 'listener' else 'LISTEN 0 4096 0.0.0.0:29528 0.0.0.0:* users:(("x-ui",pid=100,fd=3))'
        raise AssertionError(args)
    monkeypatch.setattr(checker, 'Path', RemotePath)
    monkeypatch.setattr(checker, 'output', output)
    monkeypatch.setattr(checker.sqlite3, 'connect', connect)
    if issue == 'none':
        assert checker.inspect()['logpath'] == '/var/log/custom/3xui.log'
        assert checker.inspect()['port'] == 29528
    else:
        with pytest.raises(RuntimeError):checker.inspect()


def test_panel_ui_switch_clears_ssh_counts_and_routes_actions_to_panel(tmp_path, monkeypatch):
    monkeypatch.setenv('QT_QPA_PLATFORM', 'offscreen')
    monkeypatch.setenv('NODEPILOT_HOME', str(tmp_path))
    from PySide6.QtWidgets import QApplication
    from deployer.gui import Window, configure
    app = QApplication.instance() or QApplication([])
    configure(app)
    w = Window()
    w.render_security({'scope': 'ssh', 'enabled': True, 'installed': True, 'rows': [],
                       'metrics': {'failures': 123}})
    w.security_scope.setCurrentIndex(1)
    assert not w.security_data and '123' not in w.security_metrics.text()
    assert '3x-ui 面板' in w.security_apply_button.text()
    assert w.security_payload()['scope'] == 'panel'
    w.render_security({'scope': 'ssh', 'enabled': True, 'metrics': {'failures': 999}})
    assert not w.security_data
    w.render_security({'scope': 'panel', 'enabled': True, 'installed': True, 'rows': [],
                       'metrics': {'failures': 5}, 'policy': {**policy(), 'port': 29528}})
    assert 'TCP 29528' in w.security_summary.text() and '3x-ui 面板' in w.security_summary.text()
    calls = []
    w.confirm_action = lambda *args: calls.append(args)
    w.security_disable_button.click()
    assert calls[-1][0] == 'security_disable' and calls[-1][2]['scope'] == 'panel'
    w.close()
