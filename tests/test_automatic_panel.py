import copy
import json
import uuid
from pathlib import Path
import pytest
from deployer.engine import Engine
from deployer.models import Settings
from deployer.public_panel import deployment_access,public_url,panel_configure_script
from test_public_panel import record,manager


def test_ip_and_domain_entry_selection_and_default_ports():
    r=record();r['panel_access']=deployment_access(r)
    assert public_url(r)=='http://192.0.2.1:15000/secret-path/'
    assert '-listenIP 0.0.0.0' in panel_configure_script(r) and 'cert -reset' in panel_configure_script(r)
    r['ports']['panel']=80;assert public_url(r)=='http://192.0.2.1/secret-path/'
    r['certificate']={'selfsigned':True,'domain':'nodepilot.local'}
    assert deployment_access(r)=={'public':True,'scheme':'http'}
    r['certificate']={'selfsigned':False,'domain':'node.example.com','cert':'/cert.pem','key':'/key.pem'}
    r['panel_access']=deployment_access(r);r['ports']['panel']=443
    assert public_url(r)=='https://node.example.com/secret-path/'
    assert '-webCert /cert.pem' in panel_configure_script(r)
    assert r['panel_access']['credential_file']=='cloudflare.env'


def test_existing_ip_conversion_preserves_credentials_and_nodes(monkeypatch):
    e,old,saved,commands,files,jobs,backups,cloud=manager(monkeypatch)
    original=e.ssh.run
    e.ssh.run=lambda command,**kw: 'LISTEN 0 128 0.0.0.0:15000 0.0.0.0:*' if command=='ss -H -lnt' else original(command,**kw)
    result=e.enable_automatic_panel()
    assert backups and saved==[result] and not cloud and not jobs
    assert result['identity']==old['identity'] and result['ports']==old['ports']
    assert result['rules'][0]['service']=='管理面板' and result['rules'][1:]==old['rules']
    assert public_url(result).startswith('http://192.0.2.1:15000/')


def test_automatic_failure_restores_original_and_does_not_persist(monkeypatch):
    e,old,saved,commands,*_=manager(monkeypatch,fail=True);before=copy.deepcopy(old)
    with pytest.raises(RuntimeError):e.enable_automatic_panel()
    assert old==before and not saved
    assert '-listenIP 127.0.0.1' in commands[-1]


@pytest.mark.parametrize('domain', ['', 'node.example.com'])
def test_deploy_generates_public_entry_without_a_separate_setup(monkeypatch,domain):
    import deployer.engine as module
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    monkeypatch.setattr(module,'save_secret',lambda *a:None);monkeypatch.setattr(module,'save_public',lambda *a:None)
    monkeypatch.setattr(module,'check_domain',lambda *a:{'matches':True})
    monkeypatch.setattr(module,'Cloudflare',lambda token:type('CF',(),{'ensure_address':lambda *a:{'zone_id':'zone'}})())
    s=Settings(host='192.0.2.1',ssh_port=2222,password='ssh-pass',hy2=False,firewall=True,
               panel_user='manager',panel_password='panel-password',panel_port=15000,vless_port=15001,
               tls_mode='cloudflare' if domain else 'selfsigned',domain=domain,email='test@example.com',cf_token='cf-token')
    e=Engine(s);stored={};jobs=[];commands=[]
    class SSH:
        def lock(self):pass
        def run(self,command,**kwargs):
            commands.append(command)
            if 'setting -getApiToken' in command:return 'apiToken: secret-token'
            if '-outform DER' in command:return 'dGVzdA=='
            if command.startswith('ss -H'):return 'LISTEN 0 128 0.0.0.0:15000 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:15001 0.0.0.0:*'
            if command.startswith('sysctl'):return 'bbr'
            return ''
        def json(self,path):return copy.deepcopy(stored.get(path))
        def write_json(self,path,data):stored[path]=copy.deepcopy(data)
        def write(self,*a):pass
        def exists(self,*a):return False
        def job(self,name,script,*a):jobs.append((name,script))
    e.ssh=SSH();e.inspect=lambda:{'root':True,'os':'ID=debian\nVERSION_ID="12"','arch':'x86_64','free_gb':5,'listeners':'','panel_installed':False}
    class API:
        def list(self):return []
        def ensure(self,node):pass
        def call(self,*a):pass
    e.panel=lambda r:API();e.current_bbr=lambda:{'algorithm':'bbr'}
    result=e.deploy()
    assert result['stage']=='installed' and result['rules'][0]['service']=='管理面板'
    assert result['settings']['panel_public']
    assert public_url(result).startswith('https://node.example.com:15000/' if domain else 'http://192.0.2.1:15000/')
    assert bool(result.get('certificate'))==bool(domain)
    assert any('-listenIP 0.0.0.0' in c for c in commands)
    assert any(name.startswith('firewall-') for name,_ in jobs)


def test_result_copy_icons_and_removed_maintenance_card(monkeypatch):
    from PySide6.QtWidgets import QApplication,QLabel
    from deployer.gui import Window,configure
    monkeypatch.setenv('QT_QPA_PLATFORM','offscreen')
    root=Path('test-artifacts')/('automatic-ui-'+uuid.uuid4().hex);root.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(root.resolve()))
    app=QApplication.instance() or QApplication([]);configure(app);w=Window()
    r=record();r['panel_access']=deployment_access(r);w.record=r;w.show_record(r)
    for key,value in [('link',public_url(r)),('username',r['identity']['panel_user']),('password',r['identity']['panel_password'])]:
        btn=w.result_copy_buttons[key];assert not btn.icon().isNull() and btn.isEnabled()
        btn.click();assert QApplication.clipboard().text()==value and btn.toolTip()=='已复制'
    assert not any('公网面板链接'==label.text() for label in w.findChildren(QLabel))
    w.nav.setCurrentIndex(1);w.show();app.processEvents();w.grab().save('test-artifacts/ui-results-v151.png')
    w.inputs['host'].setText('192.0.2.240');w.inputs['ssh_port'].setValue(2222)
    w.inputs['ssh_port'].editingFinished.emit()
    assert not w.result_user.text() and not w.result_password.text() and not w.public_link.text()
    assert not any(btn.isEnabled() for btn in w.result_copy_buttons.values())
    w.inputs['host'].clear();w.inputs['host'].editingFinished.emit();w.close()


def test_ip_renewal_skips_domain_tasks_and_reused_cert_uses_original_token(monkeypatch):
    import subprocess
    from deployer import scripts
    r=record();r['panel_access']=deployment_access(r);commands=[]
    monkeypatch.setattr(Path,'read_text',lambda *a,**k:json.dumps(r))
    monkeypatch.setattr(subprocess,'run',lambda args,**kw:commands.append(kw['input']) or type('R',(),{'returncode':2})())
    with pytest.raises(SystemExit) as done:exec(scripts.RENEW_CERTIFICATES,{})
    assert done.value.code==0 and not commands
    r['certificate']={'selfsigned':False,'domain':'node.example.com','cert':'/cert','key':'/key'}
    r['panel_access']=deployment_access(r)
    with pytest.raises(SystemExit):exec(scripts.RENEW_CERTIFICATES,{})
    assert len(commands)==1 and 'cloudflare.env' in commands[0] and 'cloudflare-panel.env' not in commands[0]
