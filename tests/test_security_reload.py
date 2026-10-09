"""Regression for Fail2ban 1.0.2's lost actions after changing a jail action."""
import json
import pytest
from test_security import Manager, payload, policy, collector
from deployer.security import JAIL_FILE, ROOT


OLD = b'[sshd]\nenabled=true\naction=iptables-multiport\n'


def realistic_manager(*, bad_port=False, empty_rollback=False):
    m = Manager(); original = m.ssh.run
    m.ssh.files[JAIL_FILE] = OLD; m.ssh.running = True
    m.ssh.files[ROOT + '/sshd/policy.json'] = policy()
    state = {'action': 'iptables-multiport', 'restarts': 0}
    def run(command, **kwargs):
        if command.startswith('fail2ban-client reload '):
            m.ssh.commands.append(command)
            if '--restart' in command:
                state['restarts'] += 1
                current = m.ssh.files.get(JAIL_FILE, b'')
                state['action'] = ('nftables-multiport' if 'nftables' in str(current) else 'iptables-multiport')
                if empty_rollback and state['restarts'] > 1: state['action'] = ''
            else:
                state['action'] = ''  # actual 1.0.2 reload defect
            m.ssh.running = True
            return ''
        if command.endswith(' actions'):
            m.ssh.commands.append(command)
            return 'The jail sshd has the following actions:\n' + state['action'] if state['action'] else 'No actions for jail sshd'
        if command.endswith(' actionban') or command.endswith(' actionunban'):
            m.ssh.commands.append(command)
            executable = 'nft' if state['action'].startswith('nftables') else 'iptables'
            return executable + (' add element inet f2b-table addresses { <ip> }' if executable == 'nft' else ' -I f2b-sshd 1 -s <ip> -j REJECT')
        if command.endswith(' port') and bad_port: return '22'
        return original(command, **kwargs)
    m.ssh.run = run
    return m, state


def test_action_switch_recreates_only_selected_jail_and_reads_port():
    m, state = realistic_manager()
    assert m.security_apply(payload())['enabled']
    assert state['action'] == 'nftables-multiport' and state['restarts'] == 1
    assert 'fail2ban-client get sshd action nftables-multiport port' in m.ssh.commands
    assert not any(c == 'fail2ban-client reload sshd' or (c.startswith('fail2ban-client ') and '--all' in c) or 'systemctl restart' in c for c in m.ssh.commands)


def test_wrong_live_port_restores_files_and_recreates_old_runtime_action():
    m, state = realistic_manager(bad_port=True)
    with pytest.raises(RuntimeError, match='实际端口') as error:
        m.security_apply(payload())
    assert state['action'] == 'iptables-multiport' and state['restarts'] == 2
    assert m.ssh.files[JAIL_FILE] == OLD
    assert m.ssh.files[ROOT + '/sshd/policy.json'] == policy()
    assert '并核对运行规则' in str(error.value)


def test_rollback_without_firewall_action_is_reported_incomplete():
    m, state = realistic_manager(bad_port=True, empty_rollback=True)
    with pytest.raises(RuntimeError) as error: m.security_apply(payload())
    assert state['action'] == '' and m.ssh.files[JAIL_FILE] == OLD
    assert '恢复原规则未全部完成' in str(error.value)
    assert '并核对运行规则' not in str(error.value)


def test_invalid_configuration_does_not_recreate_a_running_jail():
    m, state = realistic_manager(); original = m.ssh.run
    def run(command, **kwargs):
        if command == 'fail2ban-client -t': raise RuntimeError('configuration invalid')
        return original(command, **kwargs)
    m.ssh.run = run
    with pytest.raises(RuntimeError, match='configuration invalid'): m.security_apply(payload())
    assert state['restarts'] == 0 and state['action'] == 'iptables-multiport'
    assert m.ssh.files[JAIL_FILE] == OLD


def test_rollback_preserves_inactive_state_even_with_an_existing_config_file():
    m, state = realistic_manager(bad_port=True); m.ssh.running = False
    with pytest.raises(RuntimeError, match='实际端口'): m.security_apply(payload())
    assert not m.ssh.running and m.ssh.files[JAIL_FILE] == OLD
    assert state['restarts'] == 1


def test_failed_disable_restores_a_stopped_jail_with_its_original_action():
    m, state = realistic_manager(); original = m.ssh.run
    def run(command, **kwargs):
        if command == 'fail2ban-client -t': raise RuntimeError('configuration invalid')
        return original(command, **kwargs)
    m.ssh.run = run
    with pytest.raises(RuntimeError, match='已核对恢复'): m.security_disable(payload())
    assert m.ssh.running and state['action'] == 'iptables-multiport'
    assert m.ssh.files[JAIL_FILE] == OLD and state['restarts'] == 1


@pytest.mark.parametrize('field,value', [('actionban','echo no firewall'), ('actionunban',''), ('protocol','udp')])
def test_present_action_name_is_not_enough(field, value):
    m, state = realistic_manager(); original = m.ssh.run
    def run(command, **kwargs):
        if state['action'] == 'nftables-multiport' and command.endswith(' ' + field): return value
        return original(command, **kwargs)
    m.ssh.run = run
    with pytest.raises(RuntimeError): m.security_apply(payload())
    assert state['action'] == 'iptables-multiport'


@pytest.mark.parametrize('action_code,output,ban', [(0,'No actions for jail sshd',''),(1,'',''),(0,'mail-only','sendmail admin@example.com')])
def test_statistics_keep_counts_but_do_not_claim_protection_without_firewall(tmp_path, monkeypatch, action_code, output, ban):
    c = collector; monkeypatch.setattr(c, 'ROOT', tmp_path)
    db = c.connect_db(tmp_path / 'db')
    def command(args):
        if args[:2] == ['fail2ban-client','status']: return 0,'Status for the jail: sshd\nTotal failed: 91\nTotal banned: 17'
        if args[-1] == 'actions': return action_code, output
        if args[-1] == 'actionban': return 0,ban
        if args[-1] == 'banip': return 0,'198.51.100.2'
        return 0,'active'
    monkeypatch.setattr(c, 'command', command)
    result = c.report(db, 1); db.close()
    assert not result['enabled'] and result['action_error']
    assert result['totals']['total_failed'] == 91 and result['metrics']['currently_banned'] == 1


def test_ui_shows_missing_action_instead_of_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv('QT_QPA_PLATFORM','offscreen'); monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    from PySide6.QtWidgets import QApplication
    from deployer.gui import Window, configure
    app = QApplication.instance() or QApplication([]); configure(app)
    w = Window()
    w.render_security({'scope':'ssh','jail':'sshd','enabled':False,'installed':True,'action_error':'封禁动作缺失',
                       'totals':{'total_failed':91},'rows':[],'metrics':{'currently_banned':0},'policy':{}})
    assert '封禁动作异常' in w.security_summary.text() and '91' in w.security_totals.text()
    w.close()
