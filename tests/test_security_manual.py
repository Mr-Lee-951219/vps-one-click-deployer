"""Compatibility with existing manual sshd jails, without deploying NodePilot."""
import importlib.util
import json
from pathlib import Path
import pytest
from test_security import Manager, payload, policy, line
from deployer.security import JAIL_FILE, LEGACY_FILE, ROOT, jail_config


def reader():
    spec=importlib.util.spec_from_file_location('manual_collector',Path('assets/security-collector.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


STATUS='''Status for the jail: sshd
|- Filter
|  |- Currently failed: 15
|  |- Total failed: 91
`- Actions
   |- Currently banned: 16
   |- Total banned: 17
   `- Banned IP list: 198.51.100.2 2001:db8::7'''


def test_plain_and_formatted_log_targets_are_supported():
    c=reader()
    assert str(c.logging_path('Current logging target is:\n`- /var/log/fail2ban.log')).replace('\\','/')=='/var/log/fail2ban.log'
    assert str(c.logging_path('/var/log/fail2ban.log')).replace('\\','/')=='/var/log/fail2ban.log'
    assert c.logging_path('Current logging target is:\n`- STDOUT') is None


def test_live_status_counts_are_separate_from_daily_log_counts():
    c=reader()
    assert c.status_counts(STATUS)==dict(currently_failed=15,total_failed=91,currently_banned=16,total_banned=17)
    assert all(value is None for value in c.status_counts('ERROR not running').values())


@pytest.mark.parametrize('names,expected', [('sshd','sshd'),('nodepilot-sshd','nodepilot-sshd'),
                                         ('nodepilot-panel, nodepilot-sshd, sshd','sshd')])
def test_auto_selection_prefers_manual_sshd_and_preserves_legacy_fallback(monkeypatch,names,expected):
    c=reader();monkeypatch.setattr(c,'command',lambda args:(0,'Status\n`- Jail list: '+names))
    assert c.choose_jail('ssh')[0]==expected
    assert c.choose_jail('ssh','nodepilot-sshd')[0]=='nodepilot-sshd'


def test_manual_and_legacy_log_events_never_mix_databases_or_counts(tmp_path):
    c=reader();log=tmp_path/'log'
    log.write_text(line().replace('nodepilot-sshd','sshd')+line('Ban').replace('nodepilot-sshd','sshd')+line(ip='198.51.100.9'))
    roots=[]
    for jail,expected in [('sshd',2),('nodepilot-sshd',1)]:
        c.set_scope('ssh',jail);roots.append(c.ROOT)
        db=c.connect_db(tmp_path/jail,readonly=True);c.collect(db,log)
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==expected
        assert not (tmp_path/jail).exists()
        db.close()
    assert roots[0]!=roots[1]


def test_large_manual_logs_read_recent_events_and_report_partial_history(tmp_path):
    c=reader();c.set_scope('ssh','sshd')
    log=tmp_path/'log';log.write_bytes(b'old unrelated record\n'*(8*1024**2//21+10)+line('Ban').replace('nodepilot-sshd','sshd').encode())
    db=c.connect_db(tmp_path/'never-created',readonly=True);c.collect(db,log)
    assert c.get_meta(db,'partial') is True
    assert db.execute('SELECT kind FROM events').fetchall()==[('Ban',)]
    assert not (tmp_path/'never-created').exists();db.close()


def test_existing_manual_server_without_nodepilot_returns_counts_and_banned_ips(tmp_path,monkeypatch):
    c=reader();c.set_scope('ssh','sshd');monkeypatch.setattr(c,'ROOT',tmp_path/'not-installed')
    db=c.connect_db(c.ROOT,readonly=True)
    def command(args):
        if args==['fail2ban-client','status','sshd']:return 0,STATUS
        if args==['fail2ban-client','get','sshd','banip']:return 0,'198.51.100.2 2001:db8::7'
        if args[-1]=='actions':return 0,'iptables-multiport'
        if args[-1]=='actionban':return 0,'iptables -I f2b-sshd 1 -s <ip> -j REJECT'
        return 0,'active'
    monkeypatch.setattr(c,'command',command)
    result=c.report(db,1)
    assert result['enabled'] and result['installed'] and not result['managed']
    assert result['jail']=='sshd' and result['totals']['total_failed']==91
    assert result['metrics']['currently_banned']==2 and len(result['rows'])==2
    assert not c.ROOT.exists();db.close()


def test_no_history_log_keeps_live_counters_and_marks_daily_counts_unknown(tmp_path,monkeypatch):
    c=reader();c.set_scope('ssh','sshd');monkeypatch.setattr(c,'ROOT',tmp_path)
    db=c.connect_db(tmp_path/'memory',readonly=True);c.put_meta(db,'log_available',False)
    monkeypatch.setattr(c,'command',lambda args:(0,STATUS) if args[:2]==['fail2ban-client','status'] else (0,''))
    result=c.report(db,1)
    assert result['totals']['total_failed']==91 and result['metrics']['failures'] is None
    assert '未确认' in result['note'];db.close()


def test_failed_standard_update_reloads_existing_manual_rule_instead_of_stopping_it():
    m=Manager();m.ssh.running=True;m.ssh.fail_reload=True
    manual='/etc/fail2ban/jail.d/sshd.local';m.ssh.files[manual]=b'[sshd]\nenabled = true\n'
    with pytest.raises(RuntimeError):m.security_apply(payload())
    assert m.ssh.files[manual]==b'[sshd]\nenabled = true\n' and JAIL_FILE not in m.ssh.files
    assert 'fail2ban-client stop sshd' not in m.ssh.commands


def test_legacy_update_does_not_create_second_standard_ssh_jail():
    m=Manager();m.ssh.files[LEGACY_FILE]=b'old rule'
    m.security_apply({**payload(),'jail':'nodepilot-sshd'})
    assert '[nodepilot-sshd]' in m.ssh.files[LEGACY_FILE] and JAIL_FILE not in m.ssh.files
    assert ROOT+'/policy.json' in m.ssh.files


def test_disable_standard_rule_keeps_manual_file_and_persists_disabled_override():
    m=Manager();m.ssh.running=True
    manual='/etc/fail2ban/jail.d/sshd.local';m.ssh.files[manual]=b'manual settings'
    m.security_disable({**payload(),'jail':'sshd'})
    assert m.ssh.files[manual]==b'manual settings'
    assert '[sshd]\nenabled = false' in m.ssh.files[JAIL_FILE]
    assert 'stop sshd' in '\n'.join(m.ssh.commands)


@pytest.mark.parametrize('value',['sshd; reboot','sshd\nenabled=false','nodepilot-panel'])
def test_invalid_ssh_jail_is_rejected_before_remote_command(value):
    m=Manager()
    with pytest.raises(ValueError):m.security_apply({**payload(),'jail':value})
    assert not m.ssh.commands


def test_unban_requires_pinned_jail_and_checks_ips_beyond_table_limit():
    m=Manager()
    with pytest.raises(ValueError,match='刷新'):m.security_unban({**payload(),'ip':'198.51.100.2'})
    m.ssh.running=True
    m.security_status=lambda data:dict(enabled=True,metrics={'currently_banned':201},rows=[],active_ips=['198.51.100.2'])
    with pytest.raises(RuntimeError,match='无法确认'):m.security_unban({**payload(),'jail':'sshd','ip':'198.51.100.2'})


def test_ui_shows_same_counters_as_terminal_and_clears_when_jail_changes(tmp_path,monkeypatch):
    monkeypatch.setenv('QT_QPA_PLATFORM','offscreen');monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    from PySide6.QtWidgets import QApplication
    from deployer.gui import Window,configure
    app=QApplication.instance() or QApplication([]);configure(app);w=Window()
    result=dict(scope='ssh',jail='sshd',enabled=True,installed=True,rows=[],policy={},
                metrics=dict(failures=31,currently_banned=16),totals=dict(total_failed=91,total_banned=17,currently_failed=15))
    w.render_security(result)
    assert '91' in w.security_totals.text() and '17' in w.security_totals.text()
    assert 'sshd' in w.security_summary.text() and '31' in w.security_metrics.text()
    assert w.security_action_payload()['jail']=='sshd'
    w.security_jail.setCurrentIndex(2)
    assert not w.security_data and '91' not in w.security_totals.text()
    w.render_security(result);assert not w.security_data
    w.close()
