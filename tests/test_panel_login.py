import json
import shlex
import uuid
from pathlib import Path
import bcrypt
import pytest
from deployer.models import Settings,new_identity,validate_panel_login,random_panel_password
from deployer.engine import Engine


def test_panel_credentials_are_distinct_and_not_public_or_logged():
    s=Settings(panel_user='my.admin',panel_password="my-pass' $word",password='different-ssh')
    identity=new_identity(s)
    assert identity['panel_user']==s.panel_user and identity['panel_password']==s.panel_password
    from deployer.scripts import install_script
    install=install_script(identity,{'panel':15000},'192.0.2.1')
    exports={shlex.split(line)[1].split('=',1)[0]:shlex.split(line)[1].split('=',1)[1] for line in install.splitlines() if line.startswith('export XUI_')}
    assert exports['XUI_USERNAME']==s.panel_user and exports['XUI_PASSWORD']==s.panel_password
    assert s.panel_password not in repr(s) and 'panel_password' not in s.public_dict()
    messages=[];e=Engine(s,log=messages.append);e.log('panel='+s.panel_password)
    assert s.panel_password not in '\n'.join(messages)
    for username,password in [('',s.panel_password),('bad name',s.panel_password),('admin','short'),('admin','x'*73),('admin','abc\n123456')]:
        with pytest.raises(ValueError):validate_panel_login(username,password)
    generated={random_panel_password() for _ in range(12)}
    assert len(generated)==12
    for password in generated:validate_panel_login('admin',password)


def test_panel_change_quotes_password_and_persists_only_after_hash_check():
    s=Settings(host='192.0.2.1',ssh_port=2222);e=Engine(s)
    password="new' $password"
    record={'identity':{'panel_user':'old','panel_password':'old-password'},'settings':{}}
    payload={'endpoint':'192.0.2.1:2222','username':'custom-admin','password':password}
    commands=[];saved=[]
    class SSH:
        def lock(self):pass
        def run(self,command):
            commands.append(command)
            if '-json' in command:return json.dumps([{'username':payload['username'],'password':bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()}])
            return ''
    e.ssh=SSH();e.load_remote=lambda:record;e.persist=lambda r:saved.append(r)
    result=e.change_panel_login(payload)
    assert result['identity']['panel_password']==password and saved==[record]
    command=next(c for c in commands if '-username' in c)
    assert shlex.split(command)[-1]==password
    assert 'before-panel-login.db' in commands[0]
    payload['endpoint']='192.0.2.2:2222'
    with pytest.raises(RuntimeError):e.change_panel_login(payload)
    assert len(saved)==1


def test_failed_panel_readback_keeps_existing_record():
    e=Engine(Settings(host='192.0.2.1',ssh_port=2222));record={'identity':{'panel_user':'old','panel_password':'old-password'},'settings':{}}
    e.load_remote=lambda:record
    class SSH:
        def lock(self):pass
        def run(self,command):return '[]' if '-json' in command else ''
    e.ssh=SSH();e.persist=lambda r:pytest.fail('Failed readback must not store new credentials')
    with pytest.raises(RuntimeError):e.change_panel_login({'endpoint':'192.0.2.1:2222','username':'new','password':'new-password'})
    assert record['identity']['panel_user']=='old'


def test_ui_panel_password_can_be_typed_generated_and_revealed(monkeypatch):
    import os
    os.environ['QT_QPA_PLATFORM']='offscreen'
    from PySide6.QtWidgets import QApplication,QLineEdit
    from deployer.gui import Window,configure
    path=Path('test-artifacts')/('panel-ui-'+uuid.uuid4().hex);path.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(path.resolve()))
    app=QApplication.instance() or QApplication([]);configure(app);w=Window()
    assert w.inputs['panel_user'].text()==''
    w.inputs['panel_user'].setText('my-admin');w.inputs['panel_password'].setText('typed-password')
    assert w.settings(False).panel_password=='typed-password'
    w.panel_password_random.click();generated=w.inputs['panel_password'].text()
    assert generated!='typed-password'
    w.panel_password_show.click();assert w.inputs['panel_password'].echoMode()==QLineEdit.Normal
    w.panel_password_show.click();assert w.inputs['panel_password'].echoMode()==QLineEdit.Password
    assert not w.inputs['host'].text() and not w.inputs['ssh_port'].text()
    w.show();w.ports_card.setExpanded(True);app.processEvents()
    w.grab().save('test-artifacts/ui-panel-login-v142.png');w.close()


def test_missing_panel_account_stops_deploy_before_connecting(monkeypatch):
    import os
    os.environ['QT_QPA_PLATFORM']='offscreen'
    from PySide6.QtWidgets import QApplication
    import deployer.gui as gui
    path=Path('test-artifacts')/('panel-gate-'+uuid.uuid4().hex);path.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(path.resolve()))
    app=QApplication.instance() or QApplication([]);gui.configure(app);w=gui.Window()
    notices=[];started=[]
    monkeypatch.setattr(gui.QMessageBox,'warning',lambda parent,title,text:notices.append(text))
    monkeypatch.setattr(gui.Worker,'start',lambda worker:started.append(worker))
    w.inputs['host'].setText('192.0.2.1');w.inputs['ssh_port'].setValue(2222)
    w.inputs['password'].setText('test-only-password');w.inputs['hy2'].setChecked(False)
    w.start('deploy')
    assert not started and '面板账号' in notices[-1] and w.ports_card.isExpanded()
    w.close()
