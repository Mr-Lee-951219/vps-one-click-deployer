"""Render both appearances with only synthetic input, without any SSH calls."""
import os,sys,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deployer import __version__
tag='v'+__version__.replace('.','')
os.environ['QT_QPA_PLATFORM']='offscreen'
os.environ['NODEPILOT_HOME']=str(Path('test-artifacts')/('appearance-preview-'+uuid.uuid4().hex))
from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication,QDialog,QPushButton
from deployer.gui import Window,HostIdentityDialog,configure
app=QApplication([]);configure(app);window=Window();window.resize(1260,860);window.show()
window.server_card.setExpanded(True);window.node_card.setExpanded(True) if hasattr(window,'node_card') else None
window.append_log('准备就绪。填写左侧参数后，可以测试连接并开始部署。')
for mode in ('light','dark'):
    window.set_appearance(mode);QTest.qWait(70)
    window.grab().save('test-artifacts/ui-'+tag+'-'+mode+'.png')
    window.certificate_card.setExpanded(True);window.tls.showPopup()
    QTest.qWait(60);window.stack.widget(0).ensureWidgetVisible(window.tls);QTest.qWait(60)
    window.grab().save('test-artifacts/ui-'+tag+'-'+mode+'-certificate.png')
    window.tls.hidePopup();window.certificate_card.setExpanded(False)
    window.stack.widget(0).verticalScrollBar().setValue(0)
    prompt=HostIdentityDialog(window,'192.0.2.10','SHA256:example');prompt.show();QTest.qWait(30)
    prompt.grab().save('test-artifacts/ui-'+tag+'-'+mode+'-dialog.png');prompt.close()
    def close_startup():
        dialog=next(w for w in app.topLevelWidgets() if isinstance(w,QDialog) and w.objectName()=='systemPrompt' and w.isVisible())
        dialog.grab().save('test-artifacts/ui-'+tag+'-'+mode+'-startup.png')
        next(b for b in dialog.findChildren(QPushButton) if b.text()=='已确认，继续').click()
    QTimer.singleShot(150,close_startup);assert window.system_notice()
window.close();print('Both appearances, inline certificate choices and dialogs rendered.')
