import importlib.util
import json
import socket
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime,timezone,timedelta
import paramiko
import pytest
from deployer.errors import friendly_error
from deployer.models import Settings
from deployer.engine import Engine
from deployer.ssh import SSH,ConnectionCancelled
from deployer.maintenance import MaintenanceMixin
from deployer import network


def test_connection_errors_explain_next_step_without_password_echo():
    assert '当前密码' in friendly_error(paramiko.AuthenticationException('secret-password'))
    assert 'secret-password' not in friendly_error(paramiko.AuthenticationException('secret-password'))
    assert '实际 SSH 端口' in friendly_error(paramiko.ssh_exception.NoValidConnectionsError({('192.0.2.1',2222):ConnectionRefusedError()}))
    assert '后台' in friendly_error(TimeoutError())
    assert '无法解析' in friendly_error(socket.gaierror())


def test_resume_uses_remote_protocol_ports_identity_and_current_connection():
    e=Engine(Settings(host='192.0.2.7',ssh_port=54887,password='current-password',hy2=False))
    record=dict(stage='prepared',settings=Settings(host='old.example',ssh_port=22,hy2=True,tls_mode='selfsigned').public_dict(),ports={'panel':15000,'vless':15001,'hy2':15002},identity={'panel_user':'original-admin','panel_password':'original-panel-password','uuid':'original-uuid'})
    e.load_remote=lambda:record;calls=[];e.deploy=lambda:calls.append(e.settings) or record
    e.resume_deploy()
    assert calls[0].host=='192.0.2.7' and calls[0].ssh_port==54887 and calls[0].password=='current-password'
    assert calls[0].hy2 and calls[0].hy2_port==15002 and calls[0].panel_user=='original-admin'
    assert calls[0].panel_password=='original-panel-password'
    record['stage']='installed';e.resume_deploy();assert len(calls)==1


def test_stop_waiting_does_not_launch_or_kill_server_jobs():
    ssh=SSH(Settings());ssh.cancel_requested=lambda:True
    ssh.run=lambda *_:pytest.fail('Should not issue a server command before cancelled job')
    with pytest.raises(ConnectionCancelled):ssh.job('install','apt-get install test')
    ssh.cancel_requested=lambda:False;commands=[]
    ssh.run=lambda command:commands.append(command) or ''
    ssh.json=lambda *args: {}
    ssh.exists=lambda path:True
    ssh.read=lambda path:b''
    ssh.write=lambda *args:None
    # A prepared call can stop polling its detached task without terminating it.
    calls=[False,True];ssh.cancel_requested=lambda:calls.pop(0)
    with pytest.raises(ConnectionCancelled):ssh.job('install','apt-get install test')
    assert not any('kill -9' in command or 'pkill' in command or 'systemctl stop' in command for command in commands)


def test_real_qdisc_is_not_inferred_from_default_sysctl(monkeypatch):
    spec=importlib.util.spec_from_file_location('bbr_probe',Path('assets/bbr-probe.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    def value(args):
        if args[:2]==['ip','-j']:return '[{"dev":"ens7"}]'
        if args[:2]==['tc','-j']:return '[{"kind":"fq_codel","root":true}]'
        if args[:2]==['sysctl','-n']:return 'fq' if 'default_qdisc' in args[-1] else 'bbr'
        return ''
    monkeypatch.setattr(module,'value',value)
    status=module.collect()
    assert status['qdisc']=='fq' and status['actual_qdisc']=='fq_codel' and status['interface']=='ens7'


def test_certificate_status_explains_days_and_includes_renewal_failures():
    manager=MaintenanceMixin();manager.load_remote=lambda:{'certificate':{'cert':'/cert.pem','selfsigned':False,'method':'http'}}
    expiry=datetime.now(timezone.utc)+timedelta(days=5)
    commands=[]
    def run(command,**kwargs):
        commands.append(command)
        if '-enddate' in command:return expiry.strftime('notAfter=%b %d %H:%M:%S %Y GMT')
        return 'Result=exit-code\nExecMainStatus=1'
    manager.ssh=SimpleNamespace(run=run)
    result=manager.certificate_status()
    assert '即将到期' in result and '剩余 4 天' in result and 'ExecMainStatus=1' in result
    assert 'systemctl show' in commands[-1] and 'journalctl' in commands[-1]


def test_download_is_bounded_and_ignores_system_proxy(monkeypatch):
    states=[]
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):states.append('closed')
        def raise_for_status(self):pass
        def iter_content(self,size):
            for _ in range(30):yield b'x'*4
    class Session(Response):
        def get(self,*args,**kw):
            assert self.trust_env is False and kw['stream'];return Response()
    monkeypatch.setattr(network.requests,'Session',Session)
    assert network.download(limit=9)['bytes']==9 and states.count('closed')==2


def test_node_speed_core_is_cleaned_up_when_download_fails(tmp_path,monkeypatch):
    import hashlib
    (tmp_path/'core').mkdir();core=tmp_path/'core/xray.exe';core.write_bytes(b'fake-owned-core')
    (tmp_path/'core/provenance.json').write_text(json.dumps({'xray_sha256':hashlib.sha256(core.read_bytes()).hexdigest()}))
    monkeypatch.setattr(network,'client_config',lambda *args:{})
    process=SimpleNamespace(poll=lambda:None,terminate=lambda:events.append('terminate'),wait=lambda **kw:events.append('wait'))
    events=[];monkeypatch.setattr(network.subprocess,'Popen',lambda *args,**kw:process)
    monkeypatch.setattr(network.tempfile,'tempdir',str(tmp_path))
    class Connection:
        def __enter__(self):return self
        def __exit__(self,*args):pass
    monkeypatch.setattr(network.socket,'create_connection',lambda *args,**kw:Connection())
    with pytest.raises(RuntimeError):
        with network.local_client(tmp_path,Settings(),{'ports':{},'identity':{}},'vless'):
            raise RuntimeError('download failed')
    assert events==['terminate','wait']
