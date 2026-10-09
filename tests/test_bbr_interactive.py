import os
os.environ['QT_QPA_PLATFORM']='offscreen'
import hashlib
import queue
import threading
import time
import uuid
from pathlib import Path
import pytest
from PySide6.QtWidgets import QApplication,QDialog,QMessageBox

from deployer import bbr_interactive as module
from deployer.bbr_interactive import BbrSession,TerminalFilter,input_line
from deployer.bbr_ui import BbrDialog
from deployer.models import Settings


@pytest.fixture
def app(monkeypatch):
    root=Path('test-artifacts')/('bbr-ui-'+uuid.uuid4().hex);root.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME',str(root.resolve()))
    app=QApplication.instance() or QApplication([])
    from deployer.gui import configure
    configure(app)
    return app


def test_bundled_menu_is_pinned_and_tampering_fails(monkeypatch):
    raw=module.script_bytes()
    assert hashlib.sha256(raw).hexdigest()==module.SCRIPT_HASH
    for number in range(1,13):assert ('    '+str(number)+')').encode() in raw
    monkeypatch.setattr(Path,'read_bytes',lambda _:raw+b'changed')
    with pytest.raises(RuntimeError,match='校验失败'):module.script_bytes()


@pytest.mark.parametrize('value',['1\n9','y\r','\x03','a\x1b[31m','x'*1025])
def test_input_rejects_multiline_and_terminal_control(value):
    with pytest.raises(ValueError):input_line(value)


def test_empty_default_and_shell_characters_are_sent_as_data():
    assert input_line('')==b'\n'
    assert input_line('$(touch /tmp/test); 3')==b'$(touch /tmp/test); 3\n'
    worker=BbrSession(Settings());worker.accepting=True
    worker.submit('2');worker.submit('y')
    assert worker.inputs.get()==b'2\n' and worker.inputs.get()==b'y\n'
    worker.accepting=False
    with pytest.raises(ValueError):worker.submit('1')


def test_terminal_filter_handles_split_color_title_and_non_newline_prompt():
    f=TerminalFilter()
    chunks=['\x1b[','31m请选择','一个操作：\x1b[0','m','\x1b]0;private-title','\x07','1\r\n','\x1b[2J']
    assert ''.join(f.feed(c) for c in chunks)=='请选择一个操作：1\r\n'


class Channel:
    def __init__(self,chunks=(),code=0):
        self.chunks=list(chunks);self.code=code;self.closed=False;self.sent=[];self.commands=[];self.pty=None
    def recv_ready(self):return bool(self.chunks)
    def recv(self,n):return self.chunks.pop(0)
    def exit_status_ready(self):return not self.chunks
    def recv_exit_status(self):return self.code
    def sendall(self,data):self.sent.append(data)
    def get_pty(self,**kwargs):self.pty=kwargs
    def settimeout(self,value):pass
    def exec_command(self,command):self.commands.append(command)
    def close(self):self.closed=True


def test_real_stream_decodes_split_utf8_and_writes_stdin_only(monkeypatch):
    raw='请选择一个操作：'.encode()
    channel=Channel([b'\x1b[31m'+raw[:5],raw[5:]+b'\x1b[0m'])
    worker=BbrSession(Settings());worker.accepting=True;worker.submit('3');output=[]
    code,message=worker.stream(channel,output.append)
    assert ''.join(output)=='请选择一个操作：'
    assert channel.sent==[b'3\n'] and not channel.commands
    assert code==0 and '刷新' in message and '安装成功' not in message


@pytest.mark.parametrize('code',[73,-1,1])
def test_session_does_not_claim_success_on_lock_or_disconnect(code):
    worker=BbrSession(Settings());result=worker.stream(Channel(code=code),lambda _:None)
    assert result[0]==code and '安装成功' not in result[1]
    assert ('另一项' if code==73 else '尚未确认' if code==-1 else '退出代码') in result[1]


def test_session_cancel_sends_ctrl_c_once_and_discards_queued_answers():
    worker=BbrSession(Settings());worker.accepting=True;worker.submit('9')
    worker.isInterruptionRequested=lambda:True
    channel=Channel([b'ready'])
    code,_=worker.stream(channel,lambda _:None)
    assert code==-2 and channel.sent==[b'\x03']


def test_session_checks_local_hash_before_connecting(monkeypatch):
    calls=[]
    monkeypatch.setattr(module,'script_bytes',lambda:(_ for _ in ()).throw(RuntimeError('校验失败')))
    monkeypatch.setattr(module,'SSH',lambda *args:calls.append(args))
    worker=BbrSession(Settings(password='test-secret'));results=[];worker.ended.connect(lambda *args:results.append(args))
    worker.run()
    assert not calls and results[0][0]==-1 and not worker.settings.password


def test_worker_uses_verified_file_pty_and_both_operation_locks(monkeypatch):
    channel=Channel([b'menu']);commands=[];writes=[];closed=[]
    class FakeSSH:
        def __init__(self,*args):self.client=self
        def connect(self):commands.append('connect')
        def run(self,command,**kwargs):commands.append(command);return ''
        def lock(self):commands.append('desktop-lock')
        def write(self,path,data,mode):writes.append((path,data,mode))
        def get_transport(self):return self
        def open_session(self,**kwargs):return channel
        def close(self):closed.append(True)
    monkeypatch.setattr(module,'SSH',FakeSSH)
    worker=BbrSession(Settings(password='test-secret'));results=[];worker.ended.connect(lambda *args:results.append(args))
    worker.run()
    assert channel.pty['term']=='xterm' and 'flock -n -E 73' in channel.commands[0]
    assert 'server-job.lock' in channel.commands[0] and 'desktop-lock' in commands
    assert any('sha256sum -c -' in c for c in commands)
    assert writes[0][1]==module.script_bytes() and writes[0][2]==0o700
    assert channel.closed and closed and any(c.startswith('rm -f -- ') for c in commands)
    assert results[0][0]==0 and not worker.settings.password


def dialog(app):
    parent=QDialog();parent.verify_host=lambda *args:None
    d=BbrDialog(parent,Settings(host='192.0.2.1',ssh_port=2222,password='fixture-secret'))
    d._keep_parent=parent
    return d


def test_menu_choice_and_blank_default_send_real_answers(app):
    d=dialog(app);answers=[]
    d.worker=type('Worker',(),{'submit':lambda _,v:answers.append(v)})()
    d.ready();assert not d.input.isEnabled()
    d.append_output('请选择一');d.append_output('个操作 (1-12)：')
    assert d.input.isEnabled() and d.at_menu
    d.choices.setCurrentRow(1);assert d.input.text()=='2'
    d.send();d.input.setText('y');d.send();d.send()
    assert answers==['2','y','']
    d.ended(0,'脚本已退出')
    assert not d.input.isEnabled() and not d.send_button.isEnabled()
    d.worker=None;d.reject()


def test_dangerous_choice_requires_confirmation_after_split_menu_prompt(app,monkeypatch):
    d=dialog(app);answers=[]
    d.worker=type('Worker',(),{'submit':lambda _,v:answers.append(v)})()
    d.ready();d.append_output('请选择一');d.append_output('个操作 (1-12)：')
    monkeypatch.setattr(QMessageBox,'question',lambda *args:QMessageBox.No)
    d.input.setText('9');d.send();assert not answers
    monkeypatch.setattr(QMessageBox,'question',lambda *args:QMessageBox.Yes)
    d.send();assert answers==['9']
    d.worker=None;d.reject()


def test_partial_prompts_crlf_and_progress_updates_remain_readable(app):
    d=dialog(app)
    d.append_output('菜单\r');d.append_output('\n选择版本：')
    assert d.console.toPlainText()=='菜单\n选择版本：'
    d.append_output('\n下载 10%\r');d.append_output('下载 100%\r\n完成')
    assert d.console.toPlainText()=='菜单\n选择版本：\n下载 100%\n完成'
    d.reject()


def test_modal_defers_close_until_worker_has_finished(app):
    d=dialog(app);d.show();app.processEvents()
    d.worker=type('Worker',(),{'isRunning':lambda _:True})()
    d.reject();assert d.isVisible() and d.settings.password
    d.close();assert d.isVisible()
    d.worker=None;d.reject();assert not d.isVisible() and not d.settings.password
