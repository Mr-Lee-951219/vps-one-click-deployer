import importlib.util
import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import pytest
from deployer.security import SecurityMixin, validate_policy, jail_config, ROOT, JAIL_FILE, JAIL, JOURNAL_FILE, WAIT_READY

spec=importlib.util.spec_from_file_location('collector',Path('assets/security-collector.py'))
collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)


def policy(**changes):
    return dict(maxretry=5,findtime=600,bantime=3600,increment=True,whitelist=['203.0.113.7/32'],**changes)


def line(kind='Found',ip='198.51.100.2',when=None):
    when=when or datetime.now()
    return when.strftime('%Y-%m-%d %H:%M:%S,000')+' fail2ban.actions [111]: NOTICE [nodepilot-sshd] '+kind+' '+ip+'\n'


def test_rules_protect_actual_ssh_only_and_allow_management_source():
    text=jail_config(policy(),54887,'2001:db8::7')
    assert 'port = 54887' in text and 'port = 22' not in text
    assert 'banaction = nftables-multiport' in text and 'allports' not in text
    assert '2001:db8::7' in text and '203.0.113.7/32' in text
    assert 'backend = systemd' in text and '_SYSTEMD_UNIT=ssh.service' in text
    p=policy();p['bantime']=-1
    assert 'bantime = -1' in jail_config(p,2222) and not validate_policy(p)['increment']


@pytest.mark.parametrize('key,value',[('maxretry',True),('maxretry',1),('findtime',0),('bantime',-2),('whitelist',['0.0.0.0/0\nenabled=false']),('whitelist','any')])
def test_invalid_rules_never_become_shell_or_config_input(key,value):
    p=policy();p[key]=value
    with pytest.raises(ValueError):validate_policy(p)
    with pytest.raises(ValueError):jail_config(policy(),0)


@pytest.mark.parametrize('kind',['Found','Ban','Unban'])
def test_event_parser_handles_ipv4_ipv6_and_rejects_restore_or_other_jail(kind):
    event=collector.parse_event(line(kind,'2001:0db8::1'))
    assert event['kind']==kind and event['ip']=='2001:db8::1'
    assert collector.parse_event(line('Restore Ban')) is None
    assert collector.parse_event(line().replace('nodepilot-sshd','unrelated')) is None
    assert collector.parse_event(line(ip='not-ip')) is None


def test_log_cursor_survives_restart_and_rename_rotation_without_recounting(tmp_path):
    log=tmp_path/'fail2ban.log';log.write_text(line()+line('Ban'))
    db=collector.connect_db(tmp_path/'db');collector.collect(db,log);collector.collect(db,log);db.close()
    log.rename(tmp_path/'fail2ban.log.1');log.write_text(line(ip='198.51.100.3'))
    db=collector.connect_db(tmp_path/'db');collector.collect(db,log)
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==3
    with log.open('a') as stream:stream.write(line('Ban','198.51.100.3').rstrip('\n'))
    collector.collect(db,log);assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==3
    with log.open('a') as stream:stream.write('\n')
    collector.collect(db,log);assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==4
    db.close()


def test_metrics_distinguish_unique_ips_failures_bans_and_active_ips_outside_window(tmp_path):
    db=collector.connect_db(tmp_path/'db');now=datetime(2026,10,8,12,tzinfo=collector.BEIJING).timestamp()
    for n,(ts,ip,kind) in enumerate([(now-1,'198.51.100.2','Found'),(now-2,'198.51.100.2','Found'),(now-3,'198.51.100.2','Ban'),(now-86400,'198.51.100.3','Found'),(now+3600,'198.51.100.4','Found')]):
        db.execute('INSERT INTO events VALUES (?,?,?,?)',(str(n),ts,ip,kind))
    result=collector.summarize(db,1,{'198.51.100.9'},now)
    assert result['metrics']==dict(failed_ips=1,failures=2,bans=1,currently_banned=1)
    assert next(row for row in result['rows'] if row['ip']=='198.51.100.9')['failures']==0
    assert collector.summarize(db,7,set(),now)['metrics']['failed_ips']==2
    for n in range(210):db.execute('INSERT INTO events VALUES (?,?,?,?)',('extra'+str(n),now-10,'2001:db8::'+format(n+1,'x'),'Found'))
    result=collector.summarize(db,1,set(),now)
    assert len(result['rows'])==200 and result['metrics']['failed_ips']==211 and result['metrics']['failures']==212
    db.close()


def test_collector_retains_90_days_and_uses_configured_log_target(tmp_path,monkeypatch):
    log=tmp_path/'custom.log';log.write_text(line(when=datetime.now()-timedelta(days=91))+line())
    monkeypatch.setattr(collector,'command',lambda args:(0,str(log)))
    db=collector.connect_db(tmp_path/'db');collector.collect(db)
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0]==1
    assert collector.get_meta(db,'source')==str(log)
    db.close()


class FakeSSH:
    def __init__(self):
        self.files={};self.commands=[];self.jobs=[];self.running=False;self.fail_reload=False;self.fail_stop=False;self.active_ips=[]
    def connect(self):pass
    def lock(self):pass
    def exists(self,path):return path in self.files
    def read(self,path):return self.files[path]
    def json(self,path,default=None):return self.files.get(path,default)
    def write(self,path,data,mode=None):self.files[path]=data
    def write_json(self,path,data):self.files[path]=data
    def job(self,*args):self.jobs.append(args)
    def run(self,command,**kwargs):
        self.commands.append(command)
        if '$SSH_CONNECTION' in command:return '203.0.113.9 54000 192.0.2.1 54887'
        if command.startswith('command -v'):return 'ready'
        if command.startswith('fail2ban-client reload'):
            if self.fail_reload:raise RuntimeError('reload error')
            self.running=True
        if command == WAIT_READY or command.startswith('fail2ban-client ping'):return 'ready'
        if command.startswith('fail2ban-client stop'):
            if self.fail_stop:raise RuntimeError('stop error')
            self.running=False
        if command.startswith('fail2ban-client status') and 'echo active' in command:return 'active' if self.running else ''
        if command.startswith('systemctl is-active'):return 'active'
        if command.startswith('mv -f'):self.files.pop(JAIL_FILE,None)
        if command.startswith('rm -f -- '):self.files.pop(command[len('rm -f -- '):],None)
        if command.startswith('python3 '+ROOT):return json.dumps(dict(enabled=self.running,installed=True,rows=[dict(ip=ip,banned=True) for ip in self.active_ips],metrics={'currently_banned':len(self.active_ips)}))
        return ''


class Manager(SecurityMixin):
    def __init__(self):
        self.settings=SimpleNamespace(host='192.0.2.1',ssh_port=54887)
        self.ssh=FakeSSH();self.assets=Path('assets');self.log=lambda text:None


def payload():return {**policy(),'endpoint':'192.0.2.1:54887','days':1}


def test_failed_enable_restores_prior_jail_without_replacing_host_firewall():
    m=Manager();m.ssh.files[JAIL_FILE]=b'previous jail';m.ssh.fail_reload=True
    with pytest.raises(RuntimeError,match='reload error'):m.security_apply(payload())
    assert m.ssh.files[JAIL_FILE]==b'previous jail'
    assert not any('flush' in text or 'sshd_config' in text or 'nft -f' in text for text in m.ssh.commands)
    assert ROOT+'/policy.json' not in m.ssh.files


def test_journald_only_debian_retries_configuration_and_waits_for_socket():
    m=Manager();original=m.ssh.run;attempts=[];logs=[];m.log=logs.append
    def run(command,**kwargs):
        if command=='fail2ban-client -t':
            attempts.append(command)
            if JOURNAL_FILE not in m.ssh.files:
                raise RuntimeError('Have not found any log file for sshd jail')
        if command=='python3 '+ROOT+'/journal-check.py':return '{"compatible":true}'
        return original(command,**kwargs)
    m.ssh.run=run
    assert m.security_apply(payload())['enabled']
    assert len(attempts)==2 and '[sshd]\nbackend = systemd' in m.ssh.files[JOURNAL_FILE]
    assert m.ssh.commands.index(WAIT_READY)<m.ssh.commands.index('fail2ban-client reload '+JAIL)
    assert any('systemd 日志' in log for log in logs)


def test_custom_log_source_is_not_overwritten_and_original_error_is_visible():
    m=Manager();original=m.ssh.run;logs=[];m.log=logs.append
    def run(command,**kwargs):
        if command=='fail2ban-client -t':raise RuntimeError('Have not found any log file for sshd jail')
        if command=='python3 '+ROOT+'/journal-check.py':return '{"compatible":false,"reason":"custom log source"}'
        return original(command,**kwargs)
    m.ssh.run=run
    with pytest.raises(RuntimeError,match='custom log source'):m.security_apply(payload())
    assert JOURNAL_FILE not in m.ssh.files and JAIL_FILE not in m.ssh.files
    assert any('Have not found' in log for log in logs)


def test_start_failure_restores_compatibility_file_and_keeps_diagnostics():
    m=Manager();original=m.ssh.run;logs=[];m.log=logs.append
    def run(command,**kwargs):
        if command=='fail2ban-client -t' and JOURNAL_FILE not in m.ssh.files:
            raise RuntimeError('Have not found any log file for sshd jail')
        if command=='python3 '+ROOT+'/journal-check.py':return '{"compatible":true}'
        if command==WAIT_READY:raise RuntimeError('socket did not become ready')
        return original(command,**kwargs)
    m.ssh.run=run
    with pytest.raises(RuntimeError,match='socket did not become ready'):m.security_apply(payload())
    assert JOURNAL_FILE not in m.ssh.files and JAIL_FILE not in m.ssh.files
    assert any('Fail2ban 诊断' in log for log in logs)
    assert ROOT+'/policy.json' not in m.ssh.files


def test_enable_keeps_rollback_policy_and_checks_endpoint_before_mutation():
    m=Manager();bad=payload();bad['endpoint']='192.0.2.2:54887'
    with pytest.raises(ValueError):m.security_apply(bad)
    assert not m.ssh.commands
    m.ssh.files[ROOT+'/policy.json']=policy()
    assert m.security_apply(payload())['enabled']
    assert m.ssh.files[ROOT+'/policy.json']['management_ip']=='203.0.113.9'
    assert ROOT+'/previous-policy.json' in m.ssh.files
    assert '54887' in m.ssh.files[JAIL_FILE]


def test_disable_and_unban_do_not_claim_success_when_readback_fails():
    m=Manager();m.ssh.files[JAIL_FILE]='jail';m.ssh.running=True;m.ssh.fail_stop=True
    with pytest.raises(RuntimeError):m.security_disable(payload())
    assert JAIL_FILE in m.ssh.files
    m.ssh.fail_stop=False;m.security_disable(payload())
    assert JAIL_FILE not in m.ssh.files and not m.ssh.running
    m.ssh.files[ROOT+'/collector.py']='collector';m.ssh.active_ips=['198.51.100.2']
    with pytest.raises(RuntimeError,match='无法确认'):m.security_unban({**payload(),'ip':'198.51.100.2'})
    with pytest.raises(ValueError):m.security_unban({**payload(),'ip':'198.51.100.2; reboot'})


def test_ui_statistics_are_nested_in_protection_card_and_https_uses_existing_entry(tmp_path,monkeypatch):
    monkeypatch.setenv('QT_QPA_PLATFORM','offscreen');monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    from PySide6.QtWidgets import QApplication,QLabel
    from deployer.gui import Window,configure
    app=QApplication.instance() or QApplication([]);configure(app);w=Window();w.show()
    assert w.security_card.header.text()=='防爆破' and not w.security_card.isExpanded()
    assert '查看统计项' in [label.text() for label in w.security_card.findChildren(QLabel)]
    assert not w.security_auto.isChecked()
    called=[];w.start=lambda *args:called.append(args)
    w.refresh_security_if_visible();assert not called
    w.security_https();assert w.certificate_card.isExpanded() and w.tls.currentData()=='domain'
    w.render_security(dict(enabled=True,installed=True,metrics={'failed_ips':3,'failures':25,'currently_banned':2,'bans':4},rows=[],collector='active'))
    assert '25' in w.security_metrics.text() and '2' in w.security_metrics.text()
    w.inputs['host'].setText('192.0.2.77');w.inputs['ssh_port'].setValue(2222);w.load_server_record()
    assert not w.security_data and w.security_table.rowCount()==0
    w.close()


def test_statistics_start_failure_reports_that_protection_is_already_active():
    m=Manager();original=m.ssh.run
    def run(command,**kwargs):
        if command.startswith("bash -se <<'NP'"):raise RuntimeError('timer unavailable')
        return original(command,**kwargs)
    m.ssh.run=run
    with pytest.raises(RuntimeError,match='防护规则已启用'):m.security_apply(payload())
    assert m.ssh.running and JAIL_FILE in m.ssh.files


def test_report_does_not_show_zero_bans_when_configured_jail_cannot_be_read(tmp_path,monkeypatch):
    db=collector.connect_db(tmp_path/'db');original=Path.exists
    monkeypatch.setattr(collector,'ROOT',tmp_path)
    monkeypatch.setattr(Path,'exists',lambda path:True if str(path).replace('\\','/').endswith('jail.d/nodepilot-sshd.local') else original(path))
    monkeypatch.setattr(collector,'command',lambda args:(1,''))
    report=collector.report(db,1)
    assert report['state_error'] and report['metrics']['currently_banned'] is None
    assert '未知' in report['note']
    db.close()
