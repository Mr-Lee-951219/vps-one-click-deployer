import socket
import threading
import uuid
from pathlib import Path

import paramiko
import pytest

from deployer.models import Settings
from deployer.ssh import SSH, key_fingerprint
from deployer.storage import clear_saved_ssh_credentials, load_public, save_public, save_secret


def local_home(monkeypatch):
    root = Path('test-artifacts') / ('privacy-' + uuid.uuid4().hex)
    root.mkdir(parents=True)
    monkeypatch.setenv('NODEPILOT_HOME', str(root.resolve()))
    return root


def test_connection_defaults_have_no_personal_address_or_login_secret():
    settings = Settings()
    assert settings.host == '' and settings.ssh_port == 0
    assert settings.password == '' and settings.private_key == ''
    assert 'password' not in settings.public_dict()


def test_legacy_login_cleanup_keeps_node_results_and_server_identity(monkeypatch):
    root = local_home(monkeypatch)
    save_secret('ssh-192.0.2.10_2222', {'password': 'old-login-secret'})
    save_secret('192.0.2.10_2222', {'identity': {'panel_password': 'node-result-secret'}})
    node_record = (root / '192_0_2_10_2222.protected').read_bytes()
    (root / 'known_hosts').write_text('keep-server-identity', encoding='utf-8')
    (root / 'ssh-old.tmp').write_bytes(b'legacy-partial-cache')
    save_public('last-server', {'host': '192.0.2.10', 'ssh_port': 2222,
                              'password': 'legacy-plain-secret', 'private_key': 'old-key',
                              'cf_token': 'old-token', 'hy2': True})
    assert clear_saved_ssh_credentials() == 2
    assert not list(root.glob('ssh-*'))
    assert (root / '192_0_2_10_2222.protected').read_bytes() == node_record
    assert (root / 'known_hosts').read_text() == 'keep-server-identity'
    assert load_public('last-server') == {'hy2': True}
    assert clear_saved_ssh_credentials() == 0


def test_ui_requires_entered_authentication_even_when_legacy_cache_exists(monkeypatch):
    import deployer.gui as gui
    from PySide6.QtWidgets import QApplication
    root = local_home(monkeypatch)
    app = QApplication.instance() or QApplication([])
    gui.configure(app)
    save_public('last-server', {'password': 'legacy-plain-secret', 'private_key': 'old-key'})
    window = gui.Window()
    assert window.inputs['password'].text() == '' and window.inputs['private_key'].text() == ''
    window.inputs['host'].setText('192.0.2.10')
    window.inputs['ssh_port'].setValue(2222)
    save_secret('ssh-192.0.2.10_2222', {'password': 'cached-login-secret'})
    started = []
    notices = []
    monkeypatch.setattr(gui.Worker, 'start', lambda worker: started.append(worker.settings))
    monkeypatch.setattr(gui.QMessageBox, 'warning', lambda parent, title, text: notices.append(text))
    window.start('inspect')
    assert not started and 'SSH 密码或私钥' in notices[0]
    window.inputs['password'].setText('session-only-secret')
    window.inputs['private_key'].setText('session-key')
    window.clear_connection_btn.click()
    assert all(not window.inputs[k].text() for k in ('host', 'ssh_port', 'password', 'private_key'))
    assert not list(root.glob('ssh-*'))
    window.close()


def test_changed_server_key_is_rejected_before_password_authentication(monkeypatch):
    root = local_home(monkeypatch)
    old_key = paramiko.RSAKey.generate(1024)
    new_key = paramiko.RSAKey.generate(1024)
    auth_attempts = []
    errors = []
    transport_holder = []

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            auth_attempts.append((username, password))
            return paramiko.AUTH_SUCCESSFUL

    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    host_keys = paramiko.HostKeys()
    host_keys.add(f'[127.0.0.1]:{port}', old_key.get_name(), old_key)
    host_keys.save(str(root / 'known_hosts'))
    original = (root / 'known_hosts').read_bytes()

    def serve():
        try:
            peer, _ = listener.accept()
            transport = paramiko.Transport(peer)
            transport_holder.append(transport)
            transport.add_server_key(new_key)
            transport.start_server(server=Server())
        except (EOFError, ConnectionResetError):
            # The client closes the connection immediately after key rejection.
            pass
        except Exception as ex:
            errors.append(ex)

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    trust_requests = []
    ssh = SSH(Settings(host='127.0.0.1', ssh_port=port, password='must-not-be-sent',strict_host_key=True),
              trust=lambda *args: trust_requests.append(args) or True)
    try:
        with pytest.raises(RuntimeError) as failure:
            ssh.connect()
        message = str(failure.value)
        assert '服务器身份指纹发生变化' in message and '尚未发送登录密码' in message
        assert key_fingerprint(old_key) in message and key_fingerprint(new_key) in message
        assert not auth_attempts and not trust_requests
        assert (root / 'known_hosts').read_bytes() == original
    finally:
        ssh.close()
        listener.close()
        server_thread.join(5)
        for transport in transport_holder:
            transport.close()
    assert not server_thread.is_alive() and not errors
