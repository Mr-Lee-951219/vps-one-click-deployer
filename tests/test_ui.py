import os
os.environ['QT_QPA_PLATFORM']='offscreen'
from PySide6.QtWidgets import QApplication
from deployer.gui import Window,Guide,configure

def test_pages_and_guide_do_not_block_or_require_network(monkeypatch):
    from pathlib import Path
    import uuid
    tmp_path=Path('test-artifacts')/('ui-'+uuid.uuid4().hex)
    tmp_path.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    app=QApplication.instance() or QApplication([]); configure(app)
    window=Window(); window.show(); app.processEvents()
    assert window.stack.count()==4
    for i in range(4):
        window.nav.setCurrentIndex(i); app.processEvents()
        assert window.stack.currentIndex()==i
        assert window.logs.isVisible()
        assert window.deploy_footer.isVisible()==(i==0)
    guide=Guide(window); guide.save(0,True)
    from deployer.storage import load_public
    assert load_public('guide-progress-http')['0'] is True
    assert not window.inputs['password'].text()
    window.close()

def test_hy2_deploy_requires_explicit_certificate_confirmation(monkeypatch):
    from pathlib import Path
    import uuid
    tmp_path=Path("test-artifacts")/("cert-"+uuid.uuid4().hex);tmp_path.mkdir(parents=True)
    import deployer.gui as gui
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    notices=[];started=[]
    monkeypatch.setattr(gui.QMessageBox,'information',lambda parent,title,text:notices.append((title,text)))
    monkeypatch.setattr(gui.Worker,'start',lambda worker:started.append(worker.settings))
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.show();window.inputs['host'].setText('192.0.2.10');window.inputs['ssh_port'].setValue(2222);window.inputs['password'].setText('test-only')
    window.inputs['panel_user'].setText('test-admin')
    window.start('deploy');app.processEvents()
    assert not started and not window.active
    assert notices[-1][0]=='请先设置 HY2 证书'
    assert window.certificate_card.isExpanded() and window.tls.isVisible()
    window.tls.setCurrentIndex(window.tls.findData('selfsigned'))
    window.start('deploy');assert not started
    window.confirm_certificate();window.start('deploy')
    assert len(started)==1 and started[0].tls_mode=='selfsigned'
    window.close()

def test_cloudflare_confirmation_validates_fields_and_expires_on_edit(monkeypatch):
    from pathlib import Path
    import uuid
    tmp_path=Path("test-artifacts")/("cert-"+uuid.uuid4().hex);tmp_path.mkdir(parents=True)
    import deployer.gui as gui
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    notices=[];started=[]
    monkeypatch.setattr(gui.QMessageBox,'information',lambda parent,title,text:notices.append(text))
    monkeypatch.setattr(gui.Worker,'start',lambda worker:started.append(worker.settings))
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.inputs['host'].setText('192.0.2.10');window.inputs['ssh_port'].setValue(2222);window.inputs['password'].setText('test-only')
    window.tls.setCurrentIndex(window.tls.findData('cloudflare'))
    window.confirm_certificate();assert window.certificate_confirmation is None
    assert 'email' not in window.inputs and 'cf_token' not in window.inputs
    window.inputs['domain'].setText('hy2.example.com');window.confirm_certificate()
    assert window.certificate_confirmation and '部署时签发' in window.certificate_status.text()
    window.inputs['domain'].setText('node.example.com');window.start('deploy')
    assert window.certificate_confirmation is None and not started
    window.close()

def test_vless_only_bypasses_hy2_gate_and_guide_uses_generic_domains(monkeypatch):
    from pathlib import Path
    import uuid
    tmp_path=Path("test-artifacts")/("cert-"+uuid.uuid4().hex);tmp_path.mkdir(parents=True)
    import deployer.gui as gui
    from deployer.guide import STEPS
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path));started=[]
    monkeypatch.setattr(gui.Worker,'start',lambda worker:started.append(worker.settings))
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.inputs['host'].setText('192.0.2.10');window.inputs['ssh_port'].setValue(2222);window.inputs['password'].setText('test-only');window.inputs['hy2'].setChecked(False)
    window.inputs['panel_user'].setText('test-admin')
    window.start('deploy');assert len(started)==1 and not started[0].hy2
    guide=Guide(window)
    from PySide6.QtWidgets import QLabel
    text='\n'.join(w.text() for w in guide.findChildren(QLabel))
    assert 'hy2.example.com' in text
    assert not window.inputs['domain'].text() and 'node.example.com' in window.inputs['domain'].placeholderText()
    guide.close();window.close()

def test_startup_notice_requires_confirmation_each_time(monkeypatch):
    from pathlib import Path
    import uuid
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QLabel,QDialog,QPushButton
    tmp=Path('test-artifacts')/('startup-'+uuid.uuid4().hex);tmp.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp))
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.show();seen=[]
    for _ in range(2):
        def confirm():
            dialog=next(w for w in app.topLevelWidgets() if isinstance(w,QDialog) and w.objectName()=='systemPrompt' and w.isVisible())
            seen.append('\n'.join(w.text() for w in dialog.findChildren(QLabel)))
            next(b for b in dialog.findChildren(QPushButton) if b.text()=='已确认，继续').click()
        QTimer.singleShot(50,confirm)
        assert window.system_notice()
    assert len(seen)==2 and all('Debian 12' in t and '可以直接继续' in t for t in seen)
    labels=[w.text() for w in window.findChildren(QLabel)]
    assert 'Windows  ·  Debian 12' not in labels and '实时执行窗口' not in labels
    assert '面板通过 SSH 隧道访问，部署时保留原 SSH 端口。' not in labels
    window.close()

def test_worker_logs_stream_before_completion_and_remain_visible(monkeypatch):
    from pathlib import Path
    import uuid,time
    from PySide6.QtCore import QEventLoop,QTimer
    from deployer.storage import Redactor
    import deployer.gui as gui
    tmp=Path('test-artifacts')/('stream-'+uuid.uuid4().hex);tmp.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp))
    class ProbeEngine:
        def __init__(self,s,log,progress,trust,trust_changed=None):
            self.settings=s;self.ssh=type('SSH',(),{})()
            self.redact=Redactor([s.password]);self.log=lambda t:log(self.redact(t));self.progress=progress
        def diagnose(self):
            self.progress(20,'连接检查');self.log('first output test-secret')
            time.sleep(.15)
            self.progress(80,'状态读取');self.log('second output')
            return 'diagnostic complete'
        def close(self):pass
    monkeypatch.setattr(gui,'Engine',ProbeEngine)
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.show();window.inputs['host'].setText('192.0.2.10');window.inputs['ssh_port'].setValue(2222);window.inputs['password'].setText('test-secret')
    loop=QEventLoop();seen=[]
    watcher=QTimer();watcher.setInterval(10)
    def watch():
        if 'first output' in window.logs.toPlainText() and window.active and window.active.isRunning():
            window.nav.setCurrentIndex(2);seen.append(window.logs.isVisible())
    watcher.timeout.connect(watch);watcher.start()
    window.start('diagnose');window.active.finished.connect(loop.quit);QTimer.singleShot(3000,loop.quit);loop.exec();watcher.stop();app.processEvents()
    assert seen and all(seen)
    assert 'second output' in window.logs.toPlainText() and 'diagnostic complete' in window.logs.toPlainText()
    assert 'test-secret' not in window.logs.toPlainText()
    assert (window.active is None or not window.active.isRunning()) and not window.timer.isActive()
    assert window.inputs['host'].isEnabled()
    window.follow.setChecked(False);window.logs.verticalScrollBar().setValue(0)
    window.append_log('new output after paused scroll');assert window.logs.verticalScrollBar().value()==0
    window.clear_logs();assert not window.logs.toPlainText()
    window.append_log('new output after clear');assert 'new output after clear' in window.logs.toPlainText()
    window.close()

def test_cloud_security_group_prompt_uses_actual_ports(monkeypatch):
    from pathlib import Path
    import uuid
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QLabel,QDialog
    tmp=Path('test-artifacts')/('prompt-'+uuid.uuid4().hex);tmp.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp))
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window()
    window.record={'settings':{'ssh_port':2222},'rules':[{'service':'VLESS','port':25001,'protocol':'TCP','source':'0.0.0.0/0'},{'service':'HY2','port':25002,'protocol':'UDP','source':'0.0.0.0/0'}]}
    captured=[]
    def check():
        dialog=next(w for w in app.topLevelWidgets() if isinstance(w,QDialog) and w.isVisible())
        captured.append('\n'.join(w.text() for w in dialog.findChildren(QLabel)))
        dialog.grab().save('test-artifacts/ui-security-group.png')
        dialog.accept()
    QTimer.singleShot(100,check)
    window.security_group_notice()
    assert '入站 TCP  25001' in captured[0] and '入站 UDP  25002' in captured[0]
    assert '2222' in captured[0] and '面板使用 SSH 隧道' in captured[0]
    window.close()

def test_blank_server_collapsible_cards_and_random_port_button(monkeypatch):
    from pathlib import Path
    import uuid
    from PySide6.QtWidgets import QSpinBox
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from deployer.storage import save_public
    tmp=Path('test-artifacts')/('cards-'+uuid.uuid4().hex);tmp.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp))
    save_public('last-server',{'host':'192.0.2.30','ssh_port':2222,'panel_port':0,'vless_port':0,'hy2_port':0})
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.show();app.processEvents()
    assert not window.inputs['host'].text() and not window.inputs['ssh_port'].text()
    assert not window.findChildren(QSpinBox)
    cards=(window.server_card,window.ports_card,window.certificate_card)
    assert all(not c.isExpanded() and not c.body.isVisible() for c in cards)
    for c in cards:
        QTest.mouseClick(c.header,Qt.LeftButton);app.processEvents();assert c.isExpanded() and c.body.isVisible()
        QTest.mouseClick(c.header,Qt.LeftButton);app.processEvents();assert not c.isExpanded()
    ports=[window.inputs[key].value() for key in ('panel_port','vless_port','hy2_port')]
    assert len(set(ports))==3 and all(10000<=p<=30000 for p in ports)
    window.ports_card.header.click();app.processEvents()
    window.inputs['ssh_port'].setValue(ports[1])
    old=window.inputs['panel_port'].value();window.port_random_buttons['panel_port'].click()
    assert window.inputs['panel_port'].value() not in {old,ports[1],ports[2]}
    assert window.logs.isVisible()
    window.close()

def test_certificate_choices_push_fields_down_without_popup(monkeypatch):
    from pathlib import Path
    import uuid
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    tmp=Path('test-artifacts')/('inline-'+uuid.uuid4().hex);tmp.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp))
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.show();window.certificate_card.header.click();app.processEvents()
    original=window.inputs['domain'].mapTo(window.certificate_card,window.inputs['domain'].rect().topLeft()).y()
    QTest.mouseClick(window.tls.opener,Qt.LeftButton);app.processEvents()
    moved=window.inputs['domain'].mapTo(window.certificate_card,window.inputs['domain'].rect().topLeft()).y()
    assert moved>original and window.tls.choices.isVisible()
    assert QApplication.activePopupWidget() is None
    QTest.mouseClick(window.tls.buttons[1],Qt.LeftButton);app.processEvents()
    assert window.tls.currentData()=='selfsigned' and not window.tls.choices.isVisible()
    QTest.qWait(20)
    assert window.inputs['domain'].mapTo(window.certificate_card,window.inputs['domain'].rect().topLeft()).y()==original
    window.close()

def test_explicit_server_entry_restores_original_node_ports(monkeypatch):
    from pathlib import Path
    import uuid
    import deployer.gui as gui
    tmp=Path('test-artifacts')/('resume-'+uuid.uuid4().hex);tmp.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp))
    record={'ports':{'panel':15001,'vless':15002,'hy2':15003},'settings':{'host':'192.0.2.31'},'identity':{'panel_user':'test','panel_password':'test'},'links':{},'rules':[]}
    monkeypatch.setattr(gui,'load_secret',lambda name,default=None:record if name=='192.0.2.31_2222' else default)
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();assert window.record is None
    window.inputs['host'].setText('192.0.2.31');window.inputs['ssh_port'].setValue(2222);window.inputs['ssh_port'].editingFinished.emit()
    assert window.record==record and window.settings(False).hy2_port==15003
    window.inputs['host'].clear();window.inputs['host'].editingFinished.emit()
    assert window.record is None and not window.linkbox.toPlainText() and not window.credentials.text()
    window.close()
