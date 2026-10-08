"""Read-only acceptance probe: exercise the actual worker and real SSH connection."""
import sys,getpass,json,time,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ['QT_QPA_PLATFORM']='offscreen'
os.environ['NODEPILOT_HOME']=str(Path('test-artifacts/live-window-home').resolve())
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from deployer.gui import Window,configure
from live_settings import connection_settings
s, expected = connection_settings()
password=s.password
app=QApplication([]);configure(app);window=Window();window.show()
window.inputs['host'].setText(s.host);window.inputs['ssh_port'].setValue(s.ssh_port);window.inputs['password'].setText(password)
def verify(host,fp,reply):
    reply['accepted']=fp==expected;reply['event'].set()
window.verify_host=verify
streaming=[];complete=[False]
def check_stream():
    text=window.logs.toPlainText()
    if '连接已建立' in text and window.active and window.active.isRunning() and not streaming:
        window.inputs['password'].clear();streaming.append(True)
        window.grab().save('test-artifacts/ui-live-window.png')
    if complete[0]:
        assert streaming,'No live log event before completion'
        assert 'x-ui' in text and password not in text
        window.grab().save('test-artifacts/ui-live-window-complete.png')
        Path('test-artifacts/live-window.json').write_text(json.dumps({'real_ssh_streaming':True,'password_hidden':True,'diagnose_completed':True},indent=2),encoding='utf-8')
        print('Real SSH live window verified',flush=True);timer.stop();window.close();app.quit()
timer=QTimer();timer.setInterval(100);timer.timeout.connect(check_stream);timer.start()
window.start('diagnose');window.active.finished.connect(lambda:complete.__setitem__(0,True))
QTimer.singleShot(60000,app.quit)
app.exec()
if not complete[0]:raise RuntimeError('Live window probe timed out')
