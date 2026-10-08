"""Render current release UI with synthetic security data."""
import os,sys,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deployer import __version__
tag='v'+__version__.replace('.','')
os.environ['QT_QPA_PLATFORM']='offscreen'
os.environ['NODEPILOT_HOME']=str(Path('test-artifacts')/('preview-'+uuid.uuid4().hex))
from PySide6.QtWidgets import QApplication
from PySide6.QtTest import QTest
from deployer.gui import Window,configure
app=QApplication([]);configure(app)
w=Window();w.resize(1260,860);w.show();QTest.qWait(30)
assert not w.inputs['host'].text() and not w.inputs['ssh_port'].value()
w.grab().save('test-artifacts/ui-'+tag+'-main.png')
w.certificate_card.setExpanded(True);w.tls.showPopup();QTest.qWait(30)
w.stack.widget(0).ensureWidgetVisible(w.tls,0,24);QTest.qWait(30)
w.grab().save('test-artifacts/ui-'+tag+'-certificate.png')
w.nav.setCurrentIndex(2);w.security_card.setExpanded(True)
w.append_log('界面示例：未连接服务器，下面仅展示统计布局。')
w.render_security({'enabled':True,'installed':True,'note':'界面示例数据；没有读取或改动 VPS。','metrics':{'failed_ips':12,'failures':78,'currently_banned':3,'bans':9},'rows':[{'ip':'198.51.100.7','failures':18,'bans':2,'last':1791417600,'banned':True},{'ip':'2001:db8::7','failures':8,'bans':1,'last':1791414000,'banned':False}],'collector':'active'})
QTest.qWait(30);scroll=w.stack.widget(2);scroll.verticalScrollBar().setValue(w.security_card.mapTo(scroll.widget(),w.security_card.rect().topLeft()).y());QTest.qWait(30)
w.grab().save('test-artifacts/ui-'+tag+'-security-rules.png')
w.stack.widget(2).ensureWidgetVisible(w.security_metrics,0,25);QTest.qWait(30)
w.grab().save('test-artifacts/ui-'+tag+'-security-stats.png')
for size in ((960,650),(853,520),(760,480)):
    w.resize(*size);QTest.qWait(30)
    assert w.logs.isVisible() and w.security_card.isExpanded()
    w.stack.widget(2).ensureWidgetVisible(w.security_metrics,0,0);QTest.qWait(30)
    w.grab().save('test-artifacts/ui-'+tag+'-'+str(size[0])+'.png')
w.close()
print('Current release UI rendered at full and compact window sizes')
