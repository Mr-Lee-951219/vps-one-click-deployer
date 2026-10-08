import os
os.environ['QT_QPA_PLATFORM']='offscreen'
import copy,json,base64,hashlib,sqlite3,uuid
from pathlib import Path
import pytest
from deployer.models import Settings
from deployer.panel import build_inbounds,Panel
from deployer.maintenance import MaintenanceMixin,client_rows,bbr_label,date_text
from deployer.portable_backup import seal,unseal,validate_bundle,valid_name
from deployer.storage import saved_servers,remember_server,save_server_limits,forget_server
from deployer.gui import Window,configure
from PySide6.QtWidgets import QApplication

def sandbox(monkeypatch):
    root=Path('test-artifacts')/('maintenance-'+uuid.uuid4().hex);root.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(root.resolve()))
    return root

def nodes():
    clients=[{'email':'user-a','id':'keep-uuid','enable':True,'totalGB':40*1024**3,'expiryTime':2000000000000,'subId':'keep-sub','flow':'xtls-rprx-vision'}]
    return [{'id':7,'remark':'VLESS','port':15000,'protocol':'vless','settings':json.dumps({'clients':clients}),
             'clientStats':[{'email':'user-a','up':3*1024**3,'down':2*1024**3}]}]

class FakePanel:
    def __init__(self):self.nodes=nodes();self.calls=[]
    def list(self):return copy.deepcopy(self.nodes)
    def update_client(self,inbound_id,client):
        self.calls.append(('update',inbound_id,copy.deepcopy(client)))
        self.nodes[0]['settings']=json.dumps({'clients':[client]})
    def reset_client(self,email):
        self.calls.append(('reset',email));self.nodes[0]['clientStats'][0].update(up=0,down=0)

class Manager(MaintenanceMixin):
    def __init__(self):
        self.settings=Settings(host='192.0.2.1',ssh_port=2222);self.api=FakePanel();self.log=lambda _:None
        self.ssh=type('SSH',(),{'lock':lambda _:None})()
    def load_remote(self):return {}
    def panel(self,record):return self.api

def request(manager,mode,changes=None):
    row=client_rows(manager.api.list())[0]
    return {'endpoint':'192.0.2.1:2222','inbound_id':7,'email':'user-a','mode':mode,
            'before':{k:row[k] for k in ('total','expiry','enable')},'changes':changes or {}}

def test_dual_protocol_budget_is_split_not_doubled():
    s=Settings(quota_gb=101,expiry=2000000000000)
    identity={'uuid':'id','hy2_password':'auth','reality_private':'private','reality_public':'public','short_id':'sid'}
    cert={'domain':'nodepilot.local','cert':'cert','key':'key','selfsigned':True,'fingerprint':'f'*64}
    inbounds=build_inbounds(s,{'vless':15000,'hy2':15001},identity,cert)
    users=[json.loads(n['settings'])['clients'][0] for n in inbounds]
    assert sum(x['totalGB'] for x in users)==101*1024**3
    assert all(x['expiryTime']==2000000000000 for x in users)
    s.hy2=False;assert s.quota_bytes('vless')==101*1024**3
    s.hy2=True;s.split_quota=True;s.vless_quota_gb=30;s.hy2_quota_gb=72
    with pytest.raises(ValueError):s.validate_limits()
    s.hy2_quota_gb=0
    with pytest.raises(ValueError):s.validate_limits()

def test_expiry_update_preserves_identity_usage_and_enable():
    m=Manager();before=copy.deepcopy(client_rows(m.api.list())[0])
    result=m.change_client(request(m,'limits',{'totalGB':80*1024**3,'expiryTime':2100000000000}))
    after=result[0]
    assert after['used']==before['used'] and after['enable']
    for k in ('id','subId','flow'):assert after['client'][k]==before['client'][k]
    assert [c[0] for c in m.api.calls]==['update']

def test_reset_is_separate_and_stale_or_wrong_server_is_rejected():
    m=Manager();payload=request(m,'limits',{'totalGB':20})
    payload['endpoint']='192.0.2.2:2222'
    with pytest.raises(RuntimeError):m.change_client(payload)
    assert not m.api.calls
    payload=request(m,'limits',{'totalGB':20});payload['before']['expiry']=1
    with pytest.raises(RuntimeError):m.change_client(payload)
    result=m.change_client(request(m,'reset'))
    assert result[0]['used']==0 and result[0]['total']==40*1024**3 and result[0]['expiry']==2000000000000

def test_shared_user_reset_is_not_silently_global():
    m=Manager();m.api.nodes.append({**copy.deepcopy(m.api.nodes[0]),'id':8})
    with pytest.raises(RuntimeError):m.change_client(request(m,'reset'))
    assert not m.api.calls

def test_bbr_label_never_guesses_version_from_installed_kernel():
    assert '未使用' in bbr_label({'algorithm':'cubic','module_version':'3'})
    assert '未确认' in bbr_label({'algorithm':'bbr','module_version':''})
    assert 'BBRv3' in bbr_label({'algorithm':'bbr','module_version':'3'})
    assert '已生效' in bbr_label({'algorithm':'bbr','active':True})

def test_saved_servers_do_not_store_login_secrets_or_mix_limits(monkeypatch):
    sandbox(monkeypatch)
    a=Settings(host='192.0.2.1',ssh_port=2222,password='secret-auth',private_key='private-file',cf_token='secret-cf',quota_gb=100)
    b=Settings(host='192.0.2.2',ssh_port=2222,quota_gb=200)
    remember_server(a);remember_server(b)
    a.quota_gb=125;save_server_limits(a)
    items=saved_servers();text=json.dumps(items)
    assert 'secret-auth' not in text and 'private-file' not in text and 'secret-cf' not in text
    assert [x['limits']['quota_gb'] for x in items]==[200,125]
    forget_server(items[0]['id']);assert len(saved_servers())==1

def bundle(root):
    path=root/'db.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE settings(key TEXT,value TEXT)')
        for name in ('users','inbounds','api_tokens'):db.execute('CREATE TABLE '+name+'(id INTEGER PRIMARY KEY)')
    record={'settings':Settings(host='192.0.2.1',ssh_port=2222).public_dict(),'ports':{'panel':15000,'vless':15001},
            'identity':{'panel_user':'manager','panel_password':'secret-panel','panel_path':'/path/','api_token':'secret-api'}}
    files={}
    for name,raw in {'x-ui.db':path.read_bytes(),'deployment.json':json.dumps(record).encode(),
                     'certs/hy2/key.pem':b'secret-key','acme/account.conf':b'secret-cf-token'}.items():
        files[name]={'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
    return {'format':1,'panel_version':'v3.9.0','files':files}

def test_portable_backup_password_integrity_and_path_protection(monkeypatch):
    root=sandbox(monkeypatch);value=bundle(root)
    raw=seal(value,'independent-backup-password')
    assert b'secret-key' not in raw and b'secret-api' not in raw and b'secret-cf-token' not in raw
    assert unseal(raw,'independent-backup-password')==value
    with pytest.raises(ValueError):unseal(raw,'wrong-password')
    with pytest.raises(ValueError):unseal(raw[:-1]+bytes([raw[-1]^1]),'independent-backup-password')
    for name in ('../etc/shadow','acme/../../etc/shadow','C:\\Windows\\file','/etc/x-ui/x-ui.db','certs//key'):
        assert not valid_name(name)
    bad=copy.deepcopy(value);bad['files']['acme/../../tmp/test']=bad['files']['certs/hy2/key.pem']
    with pytest.raises(ValueError):validate_bundle(bad)
    bad=copy.deepcopy(value);bad['files']['x-ui.db']['sha256']='0'*64
    with pytest.raises(ValueError):validate_bundle(bad)

def test_main_ui_per_server_limits_and_blank_credentials(monkeypatch):
    sandbox(monkeypatch)
    remember_server(Settings(host='192.0.2.1',ssh_port=2222,quota_gb=100))
    remember_server(Settings(host='192.0.2.2',ssh_port=2222,quota_gb=200))
    app=QApplication.instance() or QApplication([]);configure(app)
    w=Window();w.show();app.processEvents()
    assert w.saved_btn.isVisible() and not w.inputs['host'].text()
    w.inputs['host'].setText('192.0.2.1');w.inputs['ssh_port'].setValue(2222);w.load_server_record()
    assert w.settings(False).quota_gb==100
    w.inputs['password'].setText('session-secret')
    w.inputs['host'].setText('192.0.2.2');w.load_server_record()
    assert w.settings(False).quota_gb==200 and not w.inputs['password'].text()
    assert '192.0.2.2:2222' in w.maintenance_target.text()
    assert w.bbr_modes['keep'].isChecked()
    w.limits.unit_tb.setChecked(True);w.limits.quota.setText('1')
    assert w.settings(False).quota_gb==1024
    w.limits.expiry_on.setChecked(True);w.limits.expiry.setDateTime(__import__('PySide6.QtCore',fromlist=['QDateTime']).QDateTime.fromString('2027-01-01 00:00','yyyy-MM-dd HH:mm'))
    assert date_text(w.settings(False).expiry)=='2027-01-01 00:00'
    w.nav.setCurrentIndex(2);app.processEvents();assert w.logs.isVisible()
    w.grab().save('test-artifacts/ui-maintenance-v140.png')
    w.close()

def test_panel_new_json_objects_and_client_payload_preserved():
    p=Panel('http://localhost/','token');calls=[]
    original=nodes()[0];original['settings']=json.loads(original['settings']);original['streamSettings']={'network':'tcp'}
    p.call=lambda method,path,payload=None: calls.append((method,path,payload)) or [copy.deepcopy(original)]
    assert isinstance(p.list()[0]['settings'],str)
    client={'email':'user+example','id':'same','totalGB':100}
    p.update_client(7,client)
    assert 'user%2Bexample?inboundIds=7' in calls[-1][1] and calls[-1][2]==client

def test_restore_clean_system_and_existing_server_preflight(monkeypatch):
    root=sandbox(monkeypatch);data=bundle(root)
    raw=base64.b64decode(data['files']['deployment.json']['data']);record=json.loads(raw)
    record['settings']['hy2']=False
    record['identity'].update(uuid='keep-uuid',reality_public='public',short_id='sid')
    raw=json.dumps(record).encode();data['files']['deployment.json']={'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
    path=root/'recovery.npbackup';path.write_bytes(seal(data,'recovery-password'))
    import deployer.testing as testing
    monkeypatch.setattr(testing,'test_nodes',lambda settings,record,log:{'VLESS':{'status':'实际 HTTPS 流量通过'}})
    from deployer.engine import Engine,ASSETS,INSTALL_HASH
    from deployer.storage import Redactor
    class Remote:
        def __init__(self,current=None):self.current=current;self.commands=[];self.writes=[];self.jobs=[]
        def exists(self,path):return False
        def json(self,path,default=None):
            return self.current if path.endswith('/deployment.json') else default
        def lock(self):self.commands.append('LOCK')
        def run(self,command,**kwargs):
            self.commands.append(command)
            if command=='/usr/local/x-ui/x-ui -v':return '3.9.0'
            if command=='ss -H -lntup':return 'tcp 0 0 127.0.0.1:15000 *:*\ntcp 0 0 0.0.0.0:15001 *:*'
            if command.startswith('sysctl -n'):return 'cubic'
            return ''
        def write(self,path,data,mode=0o600):self.writes.append((path,data,mode))
        def write_json(self,path,data):self.writes.append((path,data,0o600))
        def job(self,name,script,timeout):self.jobs.append((name,script))
    def engine(current=None,listeners=''):
        e=object.__new__(Engine);e.ssh=Remote(current);e.settings=Settings(host='192.0.2.1',ssh_port=2222)
        e.redact=Redactor();e.log=lambda _:None;e.progress=lambda *_:None;e.tunnel=None
        e.inspect=lambda:{'root':True,'os':'ID=debian\nVERSION_ID="12"','arch':'x86_64','panel_installed':bool(current),'listeners':listeners}
        e.panel=lambda _:type('Panel',(),{'list':lambda _:[]})()
        e.saved=[];e.persist=lambda r:e.saved.append(copy.deepcopy(r))
        return e
    payload={'path':str(path),'password':'recovery-password'}
    e=engine();result=e.import_backup(payload)
    assert result['identity']['uuid']=='keep-uuid' and result['settings']['ssh_port']==2222
    assert len(e.ssh.jobs)==1 and e.ssh.jobs[0][0].startswith('restore-install-')
    commands='\n'.join(e.ssh.commands)
    assert 'apt-get install -y -qq sqlite3' in commands and 'nodepilot-cert-renew.timer' in commands
    assert not any('bbrv3' in job[0] for job in e.ssh.jobs)
    assert result['bbr']=='cubic' and result['restore_test']['VLESS']['status']=='实际 HTTPS 流量通过'
    e=engine(copy.deepcopy(record),':15000 \n:15001 ')
    e.import_backup(payload)
    assert not e.ssh.jobs
    backup_index=next(i for i,c in enumerate(e.ssh.commands) if '.backup' in c)
    stop_index=next(i for i,c in enumerate(e.ssh.commands) if 'systemctl stop x-ui' in c)
    assert backup_index<stop_index
    e=engine(None,':15001 ')
    with pytest.raises(RuntimeError):e.import_backup(payload)
    assert not e.ssh.jobs and not e.ssh.writes

def test_migrate_old_deployments_once_without_importing_password(monkeypatch):
    sandbox(monkeypatch)
    from deployer.storage import save_secret,migrate_saved_servers
    save_secret('192_0_2_8_2222',{'settings':{**Settings(host='192.0.2.8',ssh_port=2222).public_dict(),'password':'old-hidden-auth'},'ports':{'panel':15000}})
    assert migrate_saved_servers()==1
    assert saved_servers()[0]['host']=='192.0.2.8' and 'old-hidden-auth' not in json.dumps(saved_servers())
    forget_server(saved_servers()[0]['id'])
    assert migrate_saved_servers()==0 and not saved_servers()

def test_saved_server_dialog_connect_and_delete(monkeypatch):
    sandbox(monkeypatch)
    remember_server(Settings(host='192.0.2.10',ssh_port=2222,name='服务器 A'))
    import deployer.gui as gui
    import deployer.maintenance_ui as mui
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QDialog,QPushButton,QMessageBox
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();started=[]
    monkeypatch.setattr(gui.Worker,'start',lambda worker:started.append((worker.action,worker.settings)))
    monkeypatch.setattr(mui.QInputDialog,'getText',lambda *a,**kw:('session-only-password',True))
    def choose():
        d=next(d for d in app.topLevelWidgets() if isinstance(d,QDialog) and d.isVisible() and d.windowTitle()=='已保存服务器')
        next(b for b in d.findChildren(QPushButton) if b.text()=='选择连接').click()
    QTimer.singleShot(30,choose);window.saved_servers_dialog()
    assert started[0][0]=='inspect' and started[0][1].host=='192.0.2.10'
    assert started[0][1].password=='session-only-password' and 'session-only-password' not in json.dumps(saved_servers())
    monkeypatch.setattr(mui.QMessageBox,'question',lambda *a,**kw:QMessageBox.Yes)
    def remove():
        d=next(d for d in app.topLevelWidgets() if isinstance(d,QDialog) and d.isVisible() and d.windowTitle()=='已保存服务器')
        next(b for b in d.findChildren(QPushButton) if b.text()=='删除').click();d.reject()
    QTimer.singleShot(30,remove);window.saved_servers_dialog()
    assert not saved_servers()
    window.close()



