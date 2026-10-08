from contextlib import contextmanager
from pathlib import Path
import socket
import threading
import uuid

import paramiko
import pytest

from deployer.models import Settings
from deployer.ssh import SSH, ConnectionCancelled, key_fingerprint


@pytest.fixture
def ssh_home(monkeypatch):
    root = Path('test-artifacts') / ('reconnect-' + uuid.uuid4().hex)
    root.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME', str(root.resolve()))
    return root


@contextmanager
def server(keys, auth_result=paramiko.AUTH_SUCCESSFUL):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    listener.settimeout(4)
    port = listener.getsockname()[1]
    transports, attempts, errors = [], [], []

    class Auth(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            attempts.append((username, password))
            return auth_result

    def serve():
        for key in keys:
            try:
                peer, _ = listener.accept()
                transport = paramiko.Transport(peer)
                transports.append(transport)
                transport.add_server_key(key)
                transport.start_server(server=Auth())
            except (EOFError, ConnectionResetError):
                pass
            except OSError:
                if listener.fileno() != -1:
                    errors.append('listener failed')
                return
            except Exception as ex:
                errors.append(str(ex))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, attempts
    finally:
        listener.close()
        for transport in transports:
            transport.close()
        thread.join(5)
    assert not thread.is_alive() and not errors


def store_key(root, port, key):
    keys = paramiko.HostKeys()
    keys.add(f'[127.0.0.1]:{port}', key.get_name(), key)
    keys.add('[192.0.2.20]:2222', key.get_name(), key)
    keys.add('[127.0.0.1]:2222', key.get_name(), key)
    keys.add('127.0.0.1', key.get_name(), key)
    keys.save(str(root / 'known_hosts'))


def test_first_connection_reinstall_and_next_connection_need_no_prompt(ssh_home):
    old_key, new_key = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    prompts, logs = [], []
    with server([old_key, new_key, new_key, new_key]) as (port, attempts):
        settings = Settings(host='127.0.0.1', ssh_port=port, password='test-login')
        for _ in range(3):
            ssh = SSH(settings, logs.append,
                      trust=lambda *args: prompts.append(args) or False,
                      trust_changed=lambda *args: prompts.append(args) or False)
            try:
                ssh.connect()
            finally:
                ssh.close()
        assert attempts == [('root', 'test-login')] * 3
    assert prompts == []
    assert any('正在继续连接' in text for text in logs)
    assert any(key_fingerprint(old_key) in text and key_fingerprint(new_key) in text for text in logs)
    assert paramiko.HostKeys(str(ssh_home / 'known_hosts'))[f'[127.0.0.1]:{port}']['ssh-rsa'] == new_key


def test_strict_mode_updates_only_selected_server_after_confirmation(ssh_home):
    old_key, new_key = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    prompts = []
    with server([new_key, new_key]) as (port, attempts):
        store_key(ssh_home, port, old_key)
        ssh = SSH(Settings(host='127.0.0.1', ssh_port=port, password='confirmed-login', strict_host_key=True),
                  trust_changed=lambda *args: prompts.append(args) or True)
        try:
            ssh.connect()
        finally:
            ssh.close()
        assert attempts == [('root', 'confirmed-login')]
    assert prompts == [(f'[127.0.0.1]:{port}', key_fingerprint(old_key), key_fingerprint(new_key))]
    keys = paramiko.HostKeys(str(ssh_home / 'known_hosts'))
    assert keys[f'[127.0.0.1]:{port}']['ssh-rsa'] == new_key
    assert keys['[192.0.2.20]:2222']['ssh-rsa'] == old_key
    assert keys['[127.0.0.1]:2222']['ssh-rsa'] == old_key
    assert keys['127.0.0.1']['ssh-rsa'] == old_key


def test_strict_mode_cancel_sends_no_password_and_keeps_old_identity(ssh_home):
    old_key, new_key = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    with server([new_key]) as (port, attempts):
        store_key(ssh_home, port, old_key)
        original = (ssh_home / 'known_hosts').read_bytes()
        ssh = SSH(Settings(host='127.0.0.1', ssh_port=port, password='never-send', strict_host_key=True),
                  trust_changed=lambda *args: False)
        try:
            with pytest.raises(ConnectionCancelled):
                ssh.connect()
        finally:
            ssh.close()
        assert attempts == [] and (ssh_home / 'known_hosts').read_bytes() == original


def test_second_identity_change_does_not_repeat_retry_or_send_password(ssh_home):
    old, first, second = (paramiko.RSAKey.generate(1024) for _ in range(3))
    with server([first, second]) as (port, attempts):
        store_key(ssh_home, port, old)
        ssh = SSH(Settings(host='127.0.0.1', ssh_port=port, password='never-send'))
        try:
            with pytest.raises(RuntimeError, match='服务器身份指纹发生变化'):
                ssh.connect()
        finally:
            ssh.close()
        assert attempts == []
    assert paramiko.HostKeys(str(ssh_home / 'known_hosts'))[f'[127.0.0.1]:{port}']['ssh-rsa'] == first


def test_wrong_password_after_reinstall_remains_an_authentication_error(ssh_home):
    old, new = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    with server([new, new], paramiko.AUTH_FAILED) as (port, attempts):
        store_key(ssh_home, port, old)
        ssh = SSH(Settings(host='127.0.0.1', ssh_port=port, password='incorrect'))
        try:
            with pytest.raises(paramiko.AuthenticationException):
                ssh.connect()
        finally:
            ssh.close()
        assert attempts == [('root', 'incorrect')]


def test_gui_defaults_to_automatic_mode_and_optional_strict_prompt(ssh_home, monkeypatch):
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QPushButton, QLineEdit
    import deployer.gui as gui
    app = QApplication.instance() or QApplication([])
    gui.configure(app)
    window = gui.Window()
    assert not window.inputs['strict_host_key'].isChecked() and not window.settings(False).strict_host_key
    window.inputs['strict_host_key'].setChecked(True)
    assert window.settings(False).strict_host_key
    new, old = 'SHA256:' + 'B' * 43, 'SHA256:' + 'A' * 43
    captured = []

    def confirm():
        dialog = next(w for w in app.topLevelWidgets() if isinstance(w, gui.HostIdentityDialog) and w.isVisible())
        fields = [field.text() for field in dialog.findChildren(QLineEdit)]
        captured.append(fields)
        next(b for b in dialog.findChildren(QPushButton) if b.text() == '如何核对？').click()
        dialog.grab().save('test-artifacts/ui-host-identity-v132.png')
        next(b for b in dialog.findChildren(QPushButton) if b.text() == '信任并继续').click()

    reply = {'event': threading.Event(), 'accepted': False, 'previous': old}
    QTimer.singleShot(50, confirm)
    window.verify_host('[192.0.2.10]:2222', new, reply)
    assert reply['accepted'] and reply['event'].is_set()
    assert old in captured[0] and new in captured[0]
    errors = []
    monkeypatch.setattr(gui.QMessageBox, 'warning', lambda *args: errors.append(args))
    window.connection_cancelled('已取消连接')
    assert window.state.text() == '已取消连接' and not errors
    window.close()
