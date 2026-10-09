"""PTY session for the reviewed byJoey menu; input is data, never shell code."""
import codecs
import hashlib
from pathlib import Path
import queue
import shlex
import threading
import time
import uuid

from PySide6.QtCore import QThread, Signal

from .errors import friendly_error
from .ssh import SSH, REMOTE_ROOT, ConnectionCancelled
from .storage import Redactor

SCRIPT_HASH = 'b49b5fe5cd21a41d7c465163ef52deafd781b0db70a0ffec180f915dfd14287e'
SCRIPT_COMMIT = '5f10347280095b41f8597d974b9d7ad3ffa4fe2a'
MENU = (
    '安装或更新 BBRv3（最新版）', '指定版本安装', '检查 BBRv3 状态',
    '启用 BBR + FQ', '启用 BBR + FQ_CODEL', '启用 BBR + FQ_PIE',
    '启用 BBR + CAKE', '亚太机器 TCP 调优', '卸载 BBR 内核',
    'BBRv3 智能带宽优化', '清空网络优化配置', 'BBRv3 极限测速模式',
)


def script_bytes():
    path = Path(__file__).resolve().parent.parent / 'assets/joey-bbr-install.sh'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCRIPT_HASH:
        raise RuntimeError('byJoey 交互脚本校验失败，请重新解压完整软件包')
    return raw


def input_line(value):
    if len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('请只输入一行编号或回答，不要粘贴多行内容')
    return (value + '\n').encode('utf-8')


class TerminalFilter:
    """Strip split ANSI/OSC sequences, preserving prompts without a newline."""
    def __init__(self):
        self.state = 'text'

    def feed(self, text):
        output = []
        for char in text:
            if self.state == 'text':
                if char == '\x1b':self.state = 'escape'
                elif char in '\n\r\t\b' or ord(char) >= 32:output.append(char)
            elif self.state == 'escape':
                self.state = {'[':'csi', ']':'osc', '(':'charset', ')':'charset'}.get(char, 'text')
            elif self.state == 'csi':
                if '@' <= char <= '~':self.state = 'text'
            elif self.state == 'osc':
                if char == '\a':self.state = 'text'
                elif char == '\x1b':self.state = 'osc_escape'
            elif self.state == 'osc_escape':
                self.state = 'text' if char == '\\' else 'osc'
            else:self.state = 'text'
        return ''.join(output)


class BbrSession(QThread):
    output = Signal(str)
    ready = Signal()
    ended = Signal(int, str)
    verify = Signal(str, str, object)

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.inputs = queue.Queue(maxsize=32)
        self.accepting = False
        self.redactor = Redactor([settings.password, settings.panel_password, settings.cf_token])

    def submit(self, value):
        data = input_line(value)
        if not self.accepting or self.isInterruptionRequested():
            raise ValueError('请先连接并打开菜单，再发送输入')
        try:self.inputs.put_nowait(data)
        except queue.Full:raise ValueError('输入正在发送，请稍后再试') from None

    def ask_trust(self, host, fingerprint, previous=''):
        reply = {'event':threading.Event(), 'accepted':False, 'previous':previous}
        self.verify.emit(host, fingerprint, reply)
        while not reply['event'].wait(.1):
            if self.isInterruptionRequested():return False
        return reply['accepted']

    def run(self):
        ssh = None; channel = None; remote = None
        emit = lambda text:self.output.emit(self.redactor(text))
        try:
            raw = script_bytes()  # Verify locally before any server mutation.
            ssh = SSH(self.settings, lambda text:emit(text+'\n'), self.ask_trust,
                      lambda host,old,new:self.ask_trust(host,new,old))
            ssh.connect()
            if self.isInterruptionRequested():raise ConnectionCancelled('已取消打开菜单')
            ssh.run("test \"$(id -u)\" = 0 && . /etc/os-release && test \"$ID\" = debian && test \"$VERSION_ID\" = 12 && test \"$(uname -m)\" = x86_64")
            ssh.run('install -d -m 700 '+REMOTE_ROOT+' '+REMOTE_ROOT+'/interactive-bbr')
            ssh.lock()
            remote = REMOTE_ROOT+'/interactive-bbr/'+uuid.uuid4().hex+'.sh'
            ssh.write(remote, raw, 0o700)
            ssh.run('printf '+shlex.quote(SCRIPT_HASH+'  '+remote+'\n')+' | sha256sum -c -')
            if self.isInterruptionRequested():raise ConnectionCancelled('已取消打开菜单')
            channel = ssh.client.get_transport().open_session(timeout=15)
            channel.get_pty(term='xterm', width=110, height=36)
            channel.settimeout(1)
            channel.exec_command('env TERM=xterm LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive '
                                 'flock -n -E 73 '+REMOTE_ROOT+'/server-job.lock bash '+shlex.quote(remote))
            self.accepting = True;self.ready.emit()
            code, message = self.stream(channel, emit)
            self.ended.emit(code, message)
        except ConnectionCancelled as ex:
            self.ended.emit(-2,str(ex))
        except Exception as ex:
            self.ended.emit(-1,self.redactor(friendly_error(ex)))
        finally:
            self.accepting = False
            if channel is not None:channel.close()
            if ssh is not None:
                try:
                    if remote:ssh.run('rm -f -- '+shlex.quote(remote),timeout=8)
                except Exception:pass
                ssh.close()
            self.settings.password = ''

    def stream(self, channel, emit):
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        terminal = TerminalFilter();interrupted_at = None
        while True:
            if self.isInterruptionRequested() and interrupted_at is None:
                interrupted_at = time.monotonic()
                try:channel.sendall(b'\x03')
                except (OSError, EOFError):pass
            if interrupted_at is None:
                try:
                    while True:channel.sendall(self.inputs.get_nowait())
                except queue.Empty:pass
            if channel.recv_ready():
                data = channel.recv(32768)
                if data:emit(terminal.feed(decoder.decode(data)))
            if channel.exit_status_ready() and not channel.recv_ready():
                code = channel.recv_exit_status()
                tail = terminal.feed(decoder.decode(b'',final=True))
                if tail:emit(tail)
                if interrupted_at is not None:return -2,'脚本已中断；请刷新实际状态，正在安装的软件包可能需要修复'
                if code == 73:return code,'另一项服务器后台任务正在执行，请结束后重试'
                if code == -1:return code,'SSH 连接中断或服务器已重启，操作结果尚未确认，请重新连接后刷新状态'
                return code,'脚本已退出；请返回维护页刷新当前 BBR 状态' if code == 0 else '脚本退出代码 '+str(code)+'；请查看上方输出并刷新状态'
            if channel.closed:
                return -1,'SSH 连接已断开，操作结果尚未确认，请重新连接后刷新状态'
            if interrupted_at is not None and time.monotonic()-interrupted_at > 10:
                return -2,'已关闭交互连接，操作结果尚未确认；请重新连接检查服务器'
            time.sleep(.03)
