import copy
import json
import socket
import uuid
from pathlib import Path
import pytest
from deployer.models import Settings
from deployer.domain_certificate import check_domain
from deployer import scripts
from deployer.public_panel import deployment_access,panel_rules,renew_script
from test_public_panel import record,manager


def test_dns_only_resolution_requires_current_ip_and_rejects_extra_aaaa(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(socket.AF_INET,1,6,'',('192.0.2.1',80))])
    assert check_domain('node.example.com','192.0.2.1')['matches']
    with pytest.raises(ValueError):check_domain('node.example.com','192.0.2.2')
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(socket.AF_INET,1,6,'',('192.0.2.1',80)),(socket.AF_INET6,1,6,'',('2001:db8::1',80,0,0))])
    with pytest.raises(ValueError,match='AAAA'):check_domain('node.example.com','192.0.2.1')
    def missing(*a,**kw):raise socket.gaierror('not found')
    monkeypatch.setattr(socket,'getaddrinfo',missing)
    with pytest.raises(ValueError,match='尚未解析'):check_domain('node.example.com','192.0.2.1')


def test_domain_mode_needs_no_email_token_and_reserves_validation_port():
    s=Settings(host='192.0.2.1',ssh_port=2222,password='ssh-test',tls_mode='domain',domain='node.example.com')
    s.validate();assert not s.email and not s.cf_token
    s.panel_port=80
    with pytest.raises(ValueError,match='TCP 80'):s.validate()
    s.panel_port=8080;s.ssh_port=80
    with pytest.raises(ValueError,match='TCP 80'):s.validate()
    script=scripts.http_certificate_script('node.example.com')
    assert '--standalone' in script and '--server letsencrypt' in script and 'socat' in script
    assert '--accountemail' not in script and 'cloudflare.env' not in script and 'dns_cf' not in script
    assert '-checkhost node.example.com' in script and '--reloadcmd' in script


def test_http_certificate_firewall_rule_survives_sync_and_renewal_uses_no_credentials(monkeypatch):
    r=record();r['certificate']={'domain':'node.example.com','cert':'/cert','key':'/key','selfsigned':False,'method':'http'}
    r['panel_access']=deployment_access(r)
    rules=panel_rules(r,r['rules'])
    assert rules[0]['service']=='管理面板' and rules[-1]['port']==80
    assert panel_rules(r,rules)==rules
    assert 'cloudflare' not in renew_script('node.example.com',method='http')
    import subprocess
    monkeypatch.setattr(Path,'read_text',lambda *a,**kw:json.dumps(r));commands=[]
    monkeypatch.setattr(subprocess,'run',lambda args,**kw:commands.append(kw['input']) or type('R',(),{'returncode':2})())
    with pytest.raises(SystemExit) as done:exec(scripts.RENEW_CERTIFICATES,{})
    assert done.value.code==0 and len(commands)==1 and 'cloudflare' not in commands[0]


def test_prepare_rejects_port_conflict_before_changes_and_issues_only_http(monkeypatch):
    import deployer.engine as module
    monkeypatch.setattr(module,'check_domain',lambda *a:{'matches':True})
    e,old,saved,commands,files,jobs,*_=manager(monkeypatch)
    e.settings.domain='node.example.com';e.settings.tls_mode='domain';old['acme_http']=False
    original=e.ssh.run
    e.ssh.run=lambda command,**kw:'LISTEN 0 128 0.0.0.0:80 0.0.0.0:*' if command=='ss -H -lnt' else original(command,**kw)
    with pytest.raises(ValueError,match='占用'):e.prepare_domain_certificate(old)
    assert not jobs and not files
    e.ssh.run=original;e.prepare_domain_certificate(old)
    assert jobs[0][0].startswith('certificate-http-') and '--standalone' in jobs[0][1]
    assert old['rules'][-1]['port']==80 and not any('cloudflare' in path for path in files)


def test_ui_and_guide_remove_both_fields_and_describe_validation_port(monkeypatch):
    from PySide6.QtWidgets import QApplication,QLabel,QPushButton
    from deployer.gui import Window,Guide,configure
    from deployer.guide import STEPS
    monkeypatch.setenv('QT_QPA_PLATFORM','offscreen')
    root=Path('test-artifacts')/('domain-ui-'+uuid.uuid4().hex);root.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(root.resolve()))
    app=QApplication.instance() or QApplication([]);configure(app);w=Window()
    assert 'email' not in w.inputs and 'cf_token' not in w.inputs
    w.inputs['hy2'].setChecked(False);w.tls.setCurrentIndex(w.tls.findData('domain'));w.inputs['domain'].setText('node.example.com');w.confirm_certificate()
    assert w.certificate_confirmation and w.settings(False).tls_mode=='domain'
    guide=Guide(w);text='\n'.join(t+' '+description for t,description,_ in STEPS)
    assert 'TCP 80' in text and 'Token' not in text and '联系邮箱' not in text
    w.certificate_card.setExpanded(True);w.show();app.processEvents();w.stack.widget(0).ensureWidgetVisible(w.inputs['domain']);app.processEvents()
    w.grab().save('test-artifacts/ui-domain-v152.png')
    guide.close();w.close()


def test_existing_vless_only_server_can_add_panel_certificate_without_changing_node(monkeypatch):
    import deployer.engine as module
    monkeypatch.setattr(module,'check_domain',lambda *a:{'matches':True})
    monkeypatch.setattr(module,'save_secret',lambda *a:None);monkeypatch.setattr(module,'save_public',lambda *a:None)
    e,r,saved,commands,files,jobs,backups,*_=manager(monkeypatch)
    e.settings.password='ssh-test';e.settings.domain='node.example.com';e.settings.tls_mode='domain';e.settings.hy2=False
    r['settings']=e.settings.public_dict();r['settings'].update(tls_mode='selfsigned',domain='')
    r['identity'].update(uuid='keep-uuid',reality_public='keep-public',short_id='keep-short')
    node={'remark':'NodePilot · VLESS','protocol':'vless','port':15001,'settings':'unchanged','streamSettings':'unchanged'}
    original=copy.deepcopy(node);original_identity=copy.deepcopy(r['identity'])
    class API:
        def list(self):return [node]
        def update(self,*a):pytest.fail('VLESS REALITY must not be modified for a panel certificate')
    e.panel=lambda r:API()
    old_run=e.ssh.run
    e.ssh.run=lambda command,**kw:'dGVzdA==' if '-outform DER' in command else old_run(command,**kw)
    def enable(record):
        record=copy.deepcopy(record);record['panel_access']=deployment_access(record);record['rules']=panel_rules(record,record['rules']);return record
    e.apply_automatic_panel=enable
    result=e.apply_certificate()
    assert backups and node==original and result['identity']==original_identity
    assert result['certificate']['method']=='http' and result['panel_access']['domain']=='node.example.com'
    assert result['rules'][-1]['port']==80 and any(name=='renewal-v3' for name,_ in jobs)
