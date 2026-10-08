import base64
import hashlib
import io
import json
import select
import shlex
import socketserver
import threading
import time
import uuid

import paramiko
from .storage import home, remember_server, save_authenticated_password

REMOTE_ROOT = "/var/lib/nodepilot"

def key_fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")

class ConnectionCancelled(Exception):
    pass

class SSH:
    def cancel_requested(self):
        return False

    def __init__(self, settings, log=lambda _: None, trust=None, trust_changed=None):
        self.settings = settings
        self.log = log
        self.trust = trust
        self.trust_changed = trust_changed
        self.lease = None
        self.host_file = home() / "known_hosts"
        self.client = self.new_client()

    def remember_key(self, hostname, key):
        # Reload before saving to preserve other servers' identity records.
        keys = paramiko.HostKeys()
        if self.host_file.exists():
            keys.load(str(self.host_file))
        keys.add(hostname, key.get_name(), key)
        temporary = self.host_file.with_name('known_hosts.' + uuid.uuid4().hex + '.tmp')
        try:
            keys.save(str(temporary))
            temporary.replace(self.host_file)
        finally:
            temporary.unlink(missing_ok=True)

    def new_client(self):
        client = paramiko.SSHClient()
        # NodePilot owns these pins independently of other SSH applications.
        if self.host_file.exists():
            client.load_host_keys(str(self.host_file))
        outer = self
        class Policy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                fingerprint = key_fingerprint(key)
                if outer.settings.strict_host_key and (not outer.trust or not outer.trust(hostname, fingerprint)):
                    raise ConnectionCancelled("已取消连接，尚未发送登录密码。")
                outer.remember_key(hostname, key)
                client.get_host_keys().add(hostname, key.get_name(), key)
                outer.log('已记录这台服务器的身份，继续登录。')
        client.set_missing_host_key_policy(Policy())
        return client

    def connect(self):
        transport = self.client.get_transport()
        if transport and transport.is_active() and transport.is_authenticated():
            return self
        s = self.settings
        self.log('正在建立 SSH 连接…')
        for attempt in range(2):
            try:
                self.client.connect(s.host, port=s.ssh_port, username=s.username,
                                    password=s.password or None, key_filename=s.private_key or None,
                                    timeout=18, banner_timeout=18, auth_timeout=18,
                                    allow_agent=False, look_for_keys=False)
                break
            except paramiko.BadHostKeyException as ex:
                self.client.close()
                old_fp, new_fp = key_fingerprint(ex.expected_key), key_fingerprint(ex.key)
                hostname = s.host if s.ssh_port == 22 else f'[{s.host}]:{s.ssh_port}'
                if attempt or (s.strict_host_key and not self.trust_changed):
                    raise RuntimeError(
                        f'服务器身份指纹发生变化，连接已停止。\n服务器：{s.host}:{s.ssh_port}\n\n'
                        f'原指纹：{old_fp}\n新指纹：{new_fp}\n\n'
                        '此时尚未发送登录密码。请核对服务器身份后重新连接。'
                    ) from None
                if s.strict_host_key and not self.trust_changed(hostname, old_fp, new_fp):
                    raise ConnectionCancelled('已取消连接，原服务器指纹仍保留，尚未发送登录密码。') from None
                self.remember_key(hostname, ex.key)
                self.client = self.new_client()
                self.log('服务器指纹变化：'+old_fp+' → '+new_fp)
                self.log('已更新这台服务器的身份记录，正在继续连接…')
        self.client.get_transport().set_keepalive(20)
        self.log('SSH 身份验证成功，连接已建立。')
        try:
            save_authenticated_password(s)
        except (OSError, RuntimeError) as ex:
            self.log('连接成功，但密码保存未完成：' + str(ex))
        remember_server(s)
        return self

    def close(self):
        if self.lease:
            self.lease.close()
        self.client.close()

    def lock(self):
        """Advisory lock held by this SSH channel; released even on abrupt disconnect."""
        self.lease = self.client.get_transport().open_session()
        self.lease.settimeout(15)
        self.lease.exec_command('flock -n /var/lib/nodepilot/desktop.lock bash -c \'echo LOCKED; cat >/dev/null\'')
        reply = self.lease.recv(100).decode()
        if 'LOCKED' not in reply:
            raise RuntimeError('另一台电脑正在管理这台服务器，请稍后重试')

    def run(self, command, timeout=60, check=True):
        _, out, err = self.client.exec_command(command, timeout=timeout)
        stdout, stderr = out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace")
        code = out.channel.recv_exit_status()
        if check and code:
            raise RuntimeError(f"服务器操作失败（{code}）：{stderr[-1500:] or stdout[-1500:]}")
        return stdout

    def write(self, path, data, mode=0o600):
        sftp = self.client.open_sftp()
        try:
            with sftp.file(path, "wb") as f:
                f.write(data.encode() if isinstance(data, str) else data)
            sftp.chmod(path, mode)
        finally:
            sftp.close()

    def read(self, path):
        sftp = self.client.open_sftp()
        try:
            with sftp.file(path, "rb") as f:
                return f.read()
        finally:
            sftp.close()

    def exists(self, path):
        return self.run("test -e " + shlex.quote(path) + " && echo yes || true").strip() == "yes"

    def json(self, path, default=None):
        return json.loads(self.read(path)) if self.exists(path) else default

    def write_json(self, path, value):
        self.write(path + ".tmp", json.dumps(value, ensure_ascii=False, indent=2))
        self.run("mv -- " + shlex.quote(path + ".tmp") + " " + shlex.quote(path))

    def job(self, name, script, timeout=900):
        """Detached per-step job. It survives loss of the desktop SSH session."""
        if self.cancel_requested():
            raise ConnectionCancelled('已停止等待，未启动新的服务器任务。')
        self.run(f"install -d -m 700 {REMOTE_ROOT}/jobs")
        root = f"{REMOTE_ROOT}/jobs/{name}"
        existing = self.json(root + ".status", {})
        if existing.get("code") == 0:
            return
        if not self.exists(root + ".pid") or not self.run(f"kill -0 $(cat {root}.pid) 2>/dev/null && echo alive || true").strip():
            self.write(root + ".sh", "#!/bin/bash\nset -Eeuo pipefail\numask 077\n" + script + "\n", 0o700)
            wrapper = (f"#!/bin/bash\numask 077\nflock -n {REMOTE_ROOT}/server-job.lock bash {root}.sh > {root}.log 2>&1\n"
                       f"rc=$?\nprintf '{{\"code\":%s}}' \"$rc\" > {root}.status.tmp\n"
                       f"mv {root}.status.tmp {root}.status\nexit $rc\n")
            self.write(root + ".wrapper", wrapper, 0o700)
            self.run(f"rm -f {root}.status; nohup bash {root}.wrapper </dev/null >/dev/null 2>&1 & echo $! > {root}.pid")
        start, offset, pending = time.monotonic(), 0, b''
        while time.monotonic() - start < timeout:
            if self.cancel_requested():
                raise ConnectionCancelled('已停止等待。已经启动的服务器任务继续运行；请查看后台任务，再继续未完成部署。')
            data = self.read(root + ".log") if self.exists(root + ".log") else b""
            if len(data) > offset:
                pending += data[offset:]
                offset = len(data)
                if b'\n' in pending:
                    complete, pending = pending.rsplit(b'\n', 1)
                    self.log(complete.decode('utf-8', 'replace'))
            status = self.json(root + ".status", None)
            if status is not None:
                if pending:
                    self.log(pending.decode('utf-8', 'replace'))
                if status["code"]:
                    raise RuntimeError(f"{name} 未完成，修复后可重试。\n" + data[-2500:].decode("utf-8", "replace"))
                return
            time.sleep(2)
        raise TimeoutError("服务器任务仍在运行；重新连接后可继续检查任务结果")

class Tunnel:
    def __init__(self, ssh, remote_port):
        transport = ssh.client.get_transport()
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                channel = transport.open_channel("direct-tcpip", ("127.0.0.1", remote_port), self.request.getpeername())
                if channel is None:
                    return
                try:
                    while True:
                        ready, _, _ = select.select([self.request, channel], [], [], 30)
                        if self.request in ready:
                            chunk = self.request.recv(32768)
                            if not chunk:
                                break
                            channel.sendall(chunk)
                        if channel in ready:
                            chunk = channel.recv(32768)
                            if not chunk:
                                break
                            self.request.sendall(chunk)
                finally:
                    channel.close()
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True
        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
