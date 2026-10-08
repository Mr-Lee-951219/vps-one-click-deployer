import os,uuid,json
os.environ['QT_QPA_PLATFORM']='offscreen'
from pathlib import Path
from deployer.models import Settings
from deployer.storage import (save_authenticated_password,load_login_password,clear_saved_ssh_credentials,
    remember_server,forget_server,server_id,login_name,home)
from deployer.gui import Window,configure
from PySide6.QtWidgets import QApplication,QDialog,QPushButton
from PySide6.QtCore import QTimer

def local(monkeypatch):
    path=Path('test-artifacts')/('password-'+uuid.uuid4().hex);path.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(path.resolve()));return path

def test_saved_login_encrypted_scoped_and_survives_legacy_cleanup(monkeypatch):
    root=local(monkeypatch)
    s=Settings(host='192.0.2.5',ssh_port=2222,password='not-plaintext-in-files',remember_password=True)
    remember_server(s);save_authenticated_password(s)
    data=(root/(login_name(server_id(s.host,s.ssh_port))+'.protected')).read_bytes()
    assert s.password.encode() not in data
    assert s.password not in (root/'servers.json').read_text()
    assert s.password not in json.dumps(s.public_dict())
    clear_saved_ssh_credentials()
    assert load_login_password(s.host,s.ssh_port,'root')==s.password
    assert load_login_password(s.host,s.ssh_port,'another-user')==''
    assert load_login_password(s.host,22,'root')==''
    assert load_login_password('192.0.2.6',s.ssh_port,'root')==''

def test_opt_out_and_server_delete_remove_only_target_password(monkeypatch):
    local(monkeypatch)
    a=Settings(host='192.0.2.5',ssh_port=2222,password='first-password',remember_password=True)
    b=Settings(host='192.0.2.6',ssh_port=2222,password='second-password',remember_password=True)
    for s in (a,b):remember_server(s);save_authenticated_password(s)
    a.remember_password=False;save_authenticated_password(a)
    assert load_login_password(a.host,a.ssh_port,'root')==''
    assert load_login_password(b.host,b.ssh_port,'root')==b.password
    a.remember_password=True;save_authenticated_password(a);forget_server(server_id(a.host,a.ssh_port))
    assert load_login_password(a.host,a.ssh_port,'root')==''
    assert load_login_password(b.host,b.ssh_port,'root')==b.password

def test_restart_autofill_and_saved_server_connect_without_prompt(monkeypatch):
    local(monkeypatch)
    s=Settings(host='192.0.2.5',ssh_port=2222,password='saved-session-password',remember_password=True)
    remember_server(s);save_authenticated_password(s)
    import deployer.gui as gui
    import deployer.maintenance_ui as mui
    app=QApplication.instance() or QApplication([]);configure(app)
    w=Window();assert not w.inputs['password'].text()
    w.inputs['host'].setText(s.host);w.inputs['ssh_port'].setValue(s.ssh_port);w.load_server_record()
    assert w.inputs['password'].text()==s.password and w.inputs['remember_password'].isChecked()
    w.close();w=Window();started=[]
    monkeypatch.setattr(gui.Worker,'start',lambda worker:started.append(worker.settings))
    def unexpected(*args,**kwargs):raise AssertionError('saved password must avoid another prompt')
    monkeypatch.setattr(mui.QInputDialog,'getText',unexpected)
    def choose():
        d=next(d for d in app.topLevelWidgets() if isinstance(d,QDialog) and d.isVisible() and d.windowTitle()=='已保存服务器')
        next(b for b in d.findChildren(QPushButton) if b.text()=='选择连接').click()
    QTimer.singleShot(30,choose);w.saved_servers_dialog()
    assert started[0].password==s.password and started[0].remember_password
    w.forget_password()
    assert not w.inputs['password'].text() and not w.inputs['remember_password'].isChecked()
    assert not load_login_password(s.host,s.ssh_port,'root')
    w.close()

def test_authentication_failure_does_not_overwrite_saved_password(monkeypatch):
    local(monkeypatch)
    from deployer.ssh import SSH
    import paramiko,pytest
    good=Settings(host='192.0.2.5',ssh_port=2222,password='previous-good-password',remember_password=True)
    save_authenticated_password(good)
    settings=Settings(host=good.host,ssh_port=good.ssh_port,password='wrong-new-password',remember_password=True)
    ssh=SSH(settings)
    class Client:
        def get_transport(self):return None
        def connect(self,*args,**kwargs):raise paramiko.AuthenticationException('Authentication failed.')
    ssh.client=Client()
    with pytest.raises(paramiko.AuthenticationException):ssh.connect()
    assert load_login_password(good.host,good.ssh_port,'root')==good.password


def test_switching_servers_and_users_never_reuses_other_password(monkeypatch):
    local(monkeypatch)
    for host,password in (('192.0.2.5','first-password'),('192.0.2.6','second-password')):
        s=Settings(host=host,ssh_port=2222,password=password,remember_password=True)
        remember_server(s);save_authenticated_password(s)
    app=QApplication.instance() or QApplication([]);configure(app);w=Window()
    w.inputs['host'].setText('192.0.2.5');w.inputs['ssh_port'].setValue(2222);w.load_server_record()
    assert w.inputs['password'].text()=='first-password'
    w.inputs['host'].setText('192.0.2.6');w.load_server_record()
    assert w.inputs['password'].text()=='second-password'
    w.inputs['username'].setText('another-user');w.load_saved_login()
    assert not w.inputs['password'].text()
    w.close()

