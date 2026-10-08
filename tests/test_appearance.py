import os
os.environ['QT_QPA_PLATFORM']='offscreen'
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication,QPushButton
from deployer.gui import Window,HostIdentityDialog,configure
from deployer.storage import load_public,save_public


def test_theme_switch_preserves_current_form_log_and_navigation_and_survives_restart(tmp_path,monkeypatch):
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    app=QApplication.instance() or QApplication([]);configure(app)
    window=Window();window.show();window.server_card.setExpanded(True)
    window.inputs['host'].setText('192.0.2.10');window.inputs['ssh_port'].setValue(2222)
    window.append_log('主题切换测试：保留当前任务输出');window.nav.setCurrentIndex(2)
    window.security_card.setExpanded(True)
    state=(window.inputs['host'].text(),window.inputs['ssh_port'].value(),window.logs.toPlainText(),window.nav.currentIndex())
    QTest.mouseClick(window.findChild(QPushButton,'darkTheme'),Qt.LeftButton);app.processEvents()
    assert app.property('appearance')=='dark' and load_public('appearance')=={'mode':'dark'}
    assert state==(window.inputs['host'].text(),window.inputs['ssh_port'].value(),window.logs.toPlainText(),window.nav.currentIndex())
    assert window.server_card.isExpanded() and window.security_card.isExpanded()
    assert window.logs.isVisible() and not window.windowIcon().isNull()
    window.close();configure(app);reopened=Window()
    assert app.property('appearance')=='dark' and reopened.findChild(QPushButton,'darkTheme').isChecked()
    QTest.mouseClick(reopened.findChild(QPushButton,'lightTheme'),Qt.LeftButton)
    assert app.property('appearance')=='light' and load_public('appearance')=={'mode':'light'}
    reopened.close()


def test_dark_theme_dialogs_and_controls_use_readable_palette(tmp_path,monkeypatch):
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path));save_public('appearance',{'mode':'dark'})
    app=QApplication.instance() or QApplication([]);configure(app);window=Window();window.show()
    dialog=HostIdentityDialog(window,'192.0.2.10','SHA256:example');dialog.show();app.processEvents()
    assert not dialog.styleSheet()  # no local white background overriding the app theme
    for widget in (window.logs,window.inputs['host'],dialog):
        background=widget.palette().color(QPalette.Base if widget is not dialog else QPalette.Window)
        text=widget.palette().color(QPalette.Text if widget is not dialog else QPalette.WindowText)
        assert background.lightnessF()<0.3 and text.lightnessF()>0.7
    window.certificate_card.setExpanded(True);window.tls.showPopup();app.processEvents()
    assert window.tls.choices.isVisible() and window.tls.opener.isChecked()
    window.set_appearance('light');app.processEvents()
    assert window.tls.choices.isVisible() and window.tls.opener.isChecked()
    dialog.close();window.close()


def test_unknown_or_malformed_preference_falls_back_to_light(tmp_path,monkeypatch):
    monkeypatch.setenv('NODEPILOT_HOME',str(tmp_path))
    app=QApplication.instance() or QApplication([])
    for value in ({'mode':'unsupported'},['dark'],None):
        save_public('appearance',value);configure(app)
        assert app.property('appearance')=='light'
