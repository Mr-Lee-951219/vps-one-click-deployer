import copy
import hashlib
import json
import uuid
from pathlib import Path
import pytest
from deployer.models import Settings
from deployer.engine import Engine
from deployer.public_panel import public_url,panel_rules,validate_public,panel_configure_script


def record():
    return {'settings':{'host':'192.0.2.1','ssh_port':2222},'ports':{'panel':15000,'vless':15001},
            'identity':{'panel_user':'manager','panel_password':'unchanged-password','panel_path':'/secret-path/','api_token':'test-token'},
            'rules':[{'service':'VLESS','port':15001,'protocol':'TCP','source':'0.0.0.0/0'}]}


def payload():
    return {'endpoint':'192.0.2.1:2222','domain':'panel.example.com','email':'test@example.com','cf_token':'private-cf-token','port':8443}


def test_public_url_and_rules_survive_node_sync_without_duplicate_panel_rule():
    r=record();assert not public_url(r)
    r['panel_access']={'public':True,'domain':'panel.example.com'}
    assert public_url(r)=='https://panel.example.com:15000/secret-path/'
    rules=panel_rules(r,r['rules']);assert rules[0]['protocol']=='TCP' and rules[0]['port']==15000
    assert panel_rules(r,rules)==rules
    r['ports']['panel']=443;assert public_url(r)=='https://panel.example.com/secret-path/'
    r['panel_access']['public']=False
    assert panel_rules(r,rules)==r['rules']


def test_public_validation_rejects_wrong_server_domain_port_and_missing_token():
    settings=Settings(host='192.0.2.1',ssh_port=2222)
    assert validate_public(payload(),settings)=='panel.example.com'
    for key,value in [('endpoint','192.0.2.2:2222'),('domain','https://bad.example.com'),('port',2222),('port',65536),('cf_token',''),('email','not-email')]:
        invalid=payload();invalid[key]=value
        with pytest.raises(ValueError):validate_public(invalid,settings)


def manager(monkeypatch,fail=False):
    import deployer.public_panel as module
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    cloud=[]
    class CF:
        def __init__(self,token):pass
        def ensure_address(self,domain,host):cloud.append((domain,host));return {'zone_id':'zone'}
    monkeypatch.setattr(module,'Cloudflare',CF)
    e=Engine(Settings(host='192.0.2.1',ssh_port=2222));old=record();saved=[];commands=[];files={};jobs=[];backups=[]
    class SSH:
        def lock(self):pass
        def run(self,command,**kwargs):
            commands.append(command)
            if command=='ss -H -lntu':return 'tcp LISTEN 0 128 0.0.0.0:15001 0.0.0.0:*'
            if command=='ss -H -lnt':return 'LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*'
            return ''
        def exists(self,path):return True
        def write(self,path,data,*args):files[path]=data
        def write_json(self,path,value):files[path]=copy.deepcopy(value)
        def job(self,name,script,*args):jobs.append((name,script))
    class API:
        def list(self):
            if fail:raise RuntimeError('failed API verification')
            return []
    e.ssh=SSH();e.load_remote=lambda:old;e.make_backup_connected=lambda:backups.append('backup')
    e.panel=lambda r:API();e.persist=lambda r:saved.append(copy.deepcopy(r))
    return e,old,saved,commands,files,jobs,backups,cloud


def test_enable_public_https_keeps_nodes_credentials_and_separate_cf_secret(monkeypatch):
    e,old,saved,commands,files,jobs,backups,cloud=manager(monkeypatch)
    result=e.configure_public_panel(payload())
    assert backups and cloud==[('panel.example.com','192.0.2.1')]
    assert result['identity']==old['identity'] and result['ports']['vless']==old['ports']['vless']
    assert result['ports']['panel']==8443 and result['rules'][0]['service']=='管理面板'
    assert saved==[result] and payload()['cf_token'] not in json.dumps(result)
    assert '/var/lib/nodepilot/cloudflare-panel.env' in files and '/var/lib/nodepilot/cloudflare.env' not in files
    assert any('-webCertKey' in c and '-listenIP 0.0.0.0' in c for c in commands)
    assert any(name=='renewal-v2' for name,_ in jobs)


def test_failed_public_api_check_rolls_back_original_entry_and_record(monkeypatch):
    e,old,saved,commands,files,*_=manager(monkeypatch,fail=True)
    before=copy.deepcopy(old)
    with pytest.raises(RuntimeError):e.configure_public_panel(payload())
    assert old==before and not saved
    assert any('-listenIP 127.0.0.1' in c and 'cert -reset' in c for c in commands)
    assert files['/var/lib/nodepilot/rules.json']==before['rules']


def test_disable_public_returns_loopback_and_preserves_node_rules(monkeypatch):
    e,old,saved,commands,*_=manager(monkeypatch)
    old['panel_access']={'public':True,'domain':'panel.example.com','cert':'/var/lib/nodepilot/certs/panel.example.com/fullchain.pem','key':'/var/lib/nodepilot/certs/panel.example.com/key.pem'}
    old['rules']=panel_rules(old,old['rules'])
    result=e.disable_public_panel({'endpoint':'192.0.2.1:2222'})
    assert not public_url(result) and not result['settings']['panel_public']
    assert [r['service'] for r in result['rules']]==['VLESS'] and saved==[result]
    assert any('cert -reset' in c and '-listenIP 127.0.0.1' in c for c in commands)


def test_https_panel_checks_fingerprint_over_local_tunnel():
    import ssl,threading,datetime,ipaddress
    from http.server import HTTPServer,BaseHTTPRequestHandler
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import requests
    from deployer.panel import Panel
    root=Path('test-artifacts')/('public-tls-'+uuid.uuid4().hex);root.mkdir(parents=True)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'panel.example.com')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=5))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('panel.example.com')]),critical=False).sign(key,hashes.SHA256()))
    (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    received=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get('Authorization'));body=b'{"success":true,"obj":[]}'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=HTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'key.pem')
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base='https://127.0.0.1:'+str(server.server_port)+'/path/'
    good=Panel(base,'private-api-token',cert.fingerprint(hashes.SHA256()).hex())
    bad=Panel(base,'must-not-be-sent','0'*64)
    try:
        assert good.list()==[]
        with pytest.raises(requests.exceptions.SSLError):bad.list()
        assert received==['Bearer private-api-token']
    finally:
        good.session.close();bad.session.close();server.shutdown();server.server_close();thread.join(timeout=3)


def test_public_link_in_ui_and_worker_does_not_keep_an_ssh_tunnel(monkeypatch):
    import os
    os.environ['QT_QPA_PLATFORM']='offscreen'
    from PySide6.QtWidgets import QApplication,QDialog
    from PySide6.QtCore import QTimer
    from deployer.gui import Window,Worker,configure
    import deployer.gui as module
    root=Path('test-artifacts')/('public-ui-'+uuid.uuid4().hex);root.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(root.resolve()))
    r=record();r['panel_access']={'public':True,'domain':'panel.example.com'}
    class FakeEngine:
        def __init__(self,*args):
            self.settings=args[0];self.ssh=type('SSH',(),{})();self.progress=lambda *args:None
        def load_remote(self):return r
        def panel(self,r):pytest.fail('Opening a public link must not create a local tunnel')
        def close(self):pass
    monkeypatch.setattr(module,'Engine',FakeEngine)
    values=[];worker=Worker(Settings(),'open');worker.result.connect(values.append);worker.run()
    assert not worker.keep and values[0]['url']==public_url(r)
    app=QApplication.instance() or QApplication([]);configure(app);w=Window();w.record=r;w.show_record(r)
    assert w.public_link.text()==public_url(r)
    w.copy_public_panel();assert QApplication.clipboard().text()==public_url(r)
    w.inputs['host'].setText('192.0.2.1');w.inputs['ssh_port'].setValue(2222);w.show();app.processEvents()
    assert not hasattr(w,'public_panel_dialog')
    w.close()


def test_cert_renewal_loads_each_domains_own_token(monkeypatch):
    import subprocess
    from deployer import scripts
    r=record();r['certificate']={'domain':'hy2.example.net','selfsigned':False}
    r['panel_access']={'public':True,'domain':'panel.example.com'}
    original=Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda p,*a,**k:json.dumps(r) if p.name=='deployment.json' else original(p,*a,**k))
    commands=[]
    monkeypatch.setattr(subprocess,'run',lambda args,**kw:commands.append(kw['input']) or type('R',(),{'returncode':2})())
    with pytest.raises(SystemExit) as done:exec(scripts.RENEW_CERTIFICATES,{})
    assert done.value.code==0
    assert len(commands)==2 and 'cloudflare.env' in commands[0] and 'hy2.example.net' in commands[0]
    assert 'cloudflare-panel.env' in commands[1] and 'panel.example.com' in commands[1]
