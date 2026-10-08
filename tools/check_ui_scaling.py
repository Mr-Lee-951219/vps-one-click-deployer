"""Exercise the real UI at 125% / 150% on a simulated 1280x768 desktop."""
import json,os,sys,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deployer import __version__
scale=float(sys.argv[1]);tag='v'+__version__.replace('.','')+'-'+str(int(scale*100))
appearance=sys.argv[2] if len(sys.argv)>2 else 'light';tag+='-'+appearance
root=Path('test-artifacts')/('scale-'+uuid.uuid4().hex);root.mkdir(parents=True)
config=root/'screen.json';config.write_text(json.dumps({'screens':[{'name':'desktop','width':1280,'height':768,'logicalDpi':96,'logicalBaseDpi':96,'dpr':1,'availableGeometry':{'width':1280,'height':728}}]}))
os.environ['QT_QPA_PLATFORM']='offscreen:configfile='+config.as_posix()
os.environ['QT_SCALE_FACTOR']=str(scale)
os.environ['NODEPILOT_HOME']=str(root/'home')
from PySide6.QtWidgets import QApplication
from PySide6.QtTest import QTest
from deployer.gui import Window,configure
app=QApplication([]);configure(app);w=Window();w.show();QTest.qWait(30)
w.set_appearance(appearance);QTest.qWait(30)
available=app.primaryScreen().availableGeometry()
assert w.width()<=available.width() and w.height()+30<=available.height(),(w.size(),available)
for index in (0,2):
    w.nav.setCurrentIndex(index);QTest.qWait(30)
    assert w.logs.isVisible() and w.saved_btn.isVisible()
    assert w.theme_switcher.isVisible() and w.theme_switcher.geometry().right()<w.saved_btn.geometry().left()
    assert w.config_panel.width()>=300 and w.logs.width()>=300
    if index==0:
        w.server_card.setExpanded(True);w.stack.widget(index).ensureWidgetVisible(w.inputs['password']);QTest.qWait(30)
    else:
        w.security_card.setExpanded(True);QTest.qWait(30);w.stack.widget(index).ensureWidgetVisible(w.security_metrics);QTest.qWait(30)
    w.grab().save('test-artifacts/ui-'+tag+'-'+str(index)+'.png')
print('UI scale verified:',scale,'window',w.width(),w.height(),'available',available.width(),available.height())
w.close()
