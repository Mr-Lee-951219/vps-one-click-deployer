import base64
import json
from urllib.parse import urlparse,parse_qs
import pytest
from deployer.models import Settings,allocate_ports,port_rules,new_identity
from deployer.panel import node_links,client_config,build_inbounds,Panel
from deployer.cloudflare import Cloudflare
from deployer.storage import Redactor,protect

def test_port_plan_survives_retry_and_separates_protocols():
    s=Settings(host='192.0.2.10',ssh_port=2222,password='example')
    p=allocate_ports(s,{10001,10002,2222})
    assert len(set(p.values()))==3
    assert not set(p.values()) & {10001,10002,2222}
    assert allocate_ports(s,set(),p)==p
    rules=port_rules(s,p)
    assert [(x['protocol'],x['port']) for x in rules]==[('TCP',p['vless']),('UDP',p['hy2'])]
    assert p['panel'] not in [x['port'] for x in rules]

def test_conflicting_ports_fail_instead_of_rebinding():
    s=Settings(host='192.0.2.10',ssh_port=2222,password='example',panel_port=2222)
    with pytest.raises(ValueError):s.validate()
    s.panel_port=12345
    with pytest.raises(ValueError):allocate_ports(s,{12345})

def test_secret_protection_and_installer_redaction():
    raw=b'password-that-must-never-be-stored-plaintext'
    sealed=protect(raw)
    assert raw not in sealed and protect(sealed,True)==raw
    redact=Redactor(['known-secret'])
    output=redact('Password:    unknown-password\nAPI Token:   new-token\napiToken: abc\nHTTP known-secret')
    assert 'unknown-password' not in output and 'new-token' not in output and 'abc' not in output and 'known-secret' not in output

def test_cf_dns_conflict_does_not_modify_mail_or_old_records(monkeypatch):
    cf=Cloudflare('fake'); mutations=[]
    monkeypatch.setattr(cf,'check',lambda *a:{'records':[{'type':'A','content':'1.2.3.4','proxied':True},{'type':'MX','content':'mail.example.com'}],'zone_id':'zone'})
    monkeypatch.setattr(cf,'call',lambda *a,**k:mutations.append((a,k)))
    with pytest.raises(RuntimeError):cf.ensure_address('hy2.example.com','5.6.7.8')
    assert mutations==[]

def test_hy2_export_always_pins_self_signed_certificate():
    s=Settings(host='192.0.2.10',ssh_port=2222,password='example'); identity=new_identity(); identity.update(reality_public='key',reality_private='private')
    cert={'domain':'nodepilot.local','selfsigned':True,'fingerprint':'a'*64,'fingerprint_b64':base64.b64encode(bytes.fromhex('a'*64)).decode(),'cert':'/cert.pem','key':'/key.pem'}
    ports={'panel':12300,'vless':12301,'hy2':12302}
    links=node_links(s,ports,identity,cert)
    params=parse_qs(urlparse(links['HY2']).query)
    assert params['pinSHA256']==['a'*64]
    config=client_config(s,ports,identity,cert,'HY2',1080)
    assert config['outbounds'][0]['streamSettings']['tlsSettings']['pinnedPeerCertSha256']==cert['fingerprint']
    nodes=build_inbounds(s,ports,identity,cert)
    assert [(n['protocol'],n['port']) for n in nodes]==[('vless',12301),('hysteria',12302)]

def test_existing_node_idempotent_but_conflict_is_not_overwritten():
    p=Panel('http://localhost/','token')
    p.list=lambda:[{'remark':'NodePilot','protocol':'vless','port':12345,'id':1}]
    assert p.ensure({'remark':'NodePilot','protocol':'vless','port':12345})['id']==1
    with pytest.raises(RuntimeError):p.ensure({'remark':'NodePilot','protocol':'vless','port':12346})

def test_job_logs_keep_split_utf8_and_credentials_intact_for_redaction(monkeypatch):
    from deployer.ssh import SSH
    from deployer.storage import Redactor
    import deployer.ssh as module
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    secret='split-secret-value'
    full=('正在执行\ncredential='+secret+'\n任务结束').encode()
    boundaries=[2,full.index(secret.encode())+5,len(full)]
    shown=[]
    class ProbeSSH(SSH):
        def __init__(self):self.log=lambda text:shown.append(Redactor([secret])(text));self.frame=0
        def run(self,*a,**kw):return 'alive'
        def exists(self,*a):return True
        def json(self,path,default=None):return {'code':0} if self.frame==3 else default
        def read(self,path):
            result=full[:boundaries[self.frame]];self.frame+=1;return result
    ProbeSSH().job('test-stream','unused',timeout=5)
    combined='\n'.join(shown)
    assert '正在执行' in combined and '任务结束' in combined
    assert '\ufffd' not in combined and secret not in combined and '[已隐藏]' in combined
