import copy
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import requests

from deployer.connectivity import verify_connectivity, summary
from deployer.models import Settings
from deployer.ssh import ConnectionCancelled


def record():
    return {'settings': {'host': '192.0.2.7', 'ssh_port': 2222, 'firewall': False},
            'ports': {'panel': 25000, 'vless': 25001, 'hy2': 25002},
            'identity': {'panel_path': '/test-only/', 'panel_user': 'test-user', 'panel_password': 'test-secret'},
            'panel_access': {'public': True, 'scheme': 'https', 'domain': 'node.example.com'},
            'links': {'VLESS': 'test-vless', 'HY2': 'test-hy2'},
            'rules': [{'service': '管理面板', 'port': 25000, 'protocol': 'TCP', 'source': '0.0.0.0/0'},
                      {'service': 'VLESS', 'port': 25001, 'protocol': 'TCP', 'source': '0.0.0.0/0'},
                      {'service': 'HY2', 'port': 25002, 'protocol': 'UDP', 'source': '0.0.0.0/0'},
                      {'service': '证书验证与续期', 'port': 80, 'protocol': 'TCP', 'source': '0.0.0.0/0'}]}


@pytest.fixture
def probes(monkeypatch):
    seen = []
    def nodes(settings, r, log, **kwargs):
        seen.append(('nodes', settings.host, tuple(r['links'])))
        return {p: {'status': '实际 HTTPS 流量通过'} for p in r['links']}
    monkeypatch.setattr('deployer.testing.test_nodes', nodes)
    class Response:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Session:
        trust_env = True
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kwargs):
            seen.append(('panel', self.trust_env, url, kwargs))
            return Response()
    monkeypatch.setattr('deployer.connectivity.requests.Session', Session)
    return seen


def test_actual_protocol_and_panel_probes_do_not_touch_firewall_or_credentials(probes, monkeypatch):
    r = record(); original = copy.deepcopy(r)
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('No raw socket proof for HY2 or idle ACME port'))
    report = verify_connectivity(Settings(host='192.0.2.9'), r)
    assert report['all_passed'] and len(report['rows']) == 3 and r == original
    assert probes[0] == ('nodes', '192.0.2.9', ('VLESS', 'HY2'))
    assert probes[1][1] is False and probes[1][2].startswith('https://node.example.com:25000/')
    assert probes[1][3] == {'timeout': (4, 8), 'allow_redirects': False, 'stream': True}
    assert 'test-secret' not in str(probes) and '当前电脑' in summary(report)


@pytest.mark.parametrize('kind', ['timeout', 'certificate', 'node-failure', 'core-missing'])
def test_failures_preserve_record_and_never_diagnose_cloud_firewall(kind, probes, monkeypatch):
    r = record(); original = copy.deepcopy(r); logs = []
    if kind in ('timeout', 'certificate'):
        def fail(*args, **kwargs):
            raise (requests.exceptions.SSLError if kind == 'certificate' else requests.exceptions.ConnectTimeout)('test-secret')
        monkeypatch.setattr(requests.Session, 'get', fail)
    elif kind == 'node-failure':
        monkeypatch.setattr('deployer.testing.test_nodes', lambda *a, **k: {'VLESS': {'status': '未通过'}})
    else:
        def missing(*args, **kwargs): raise RuntimeError('test-secret')
        monkeypatch.setattr('deployer.testing.test_nodes', missing)
    report = verify_connectivity(Settings(host='192.0.2.9'), r, logs.append)
    assert not report['all_passed'] and r == original
    assert '超时本身不能确定原因' in logs[-1] and 'test-secret' not in str(report) + str(logs)
    assert any(row['state'] == 'failed' for row in report['rows'])


def test_unknown_udp_remains_unverified_and_tcp_is_only_connection_evidence(probes, monkeypatch):
    r = record()
    r['rules'] += [dict(service='其他 UDP', port=25100, protocol='UDP'),
                   dict(service='其他 TCP', port=25101, protocol='TCP')]
    calls = []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    monkeypatch.setattr(socket, 'create_connection', lambda target, **k: (calls.append(target), Connection())[1])
    report = verify_connectivity(Settings(host='192.0.2.9'), r)
    assert calls == [('192.0.2.9', 25101)] and not report['all_passed']
    assert report['rows'][-2]['state'] == 'unverified'
    assert '应用协议仍需' in report['rows'][-1]['detail']


def test_empty_record_cannot_be_reported_as_success(probes):
    r = record(); r['links'] = {}; r['rules'] = []; r['panel_access'] = {}
    assert not verify_connectivity(Settings(host='192.0.2.9'), r)['all_passed']


def test_cancel_does_not_start_probes(probes):
    with pytest.raises(ConnectionCancelled):
        verify_connectivity(Settings(host='192.0.2.9'), record(), cancelled=lambda: True)
    assert not probes


@pytest.mark.parametrize('status,passed', [(200, True), (302, True), (404, False), (503, False)])
def test_real_http_listener_and_current_target_without_following_redirects(monkeypatch, status, passed):
    requests_seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests_seen.append((self.path, self.headers.get('Authorization'), self.headers.get('Cookie')))
            self.send_response(status)
            if status == 302: self.send_header('Location', 'https://must-not-follow.invalid/')
            self.end_headers()
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        r = record(); r['links'] = {}; r['rules'] = []
        r['panel_access'] = {'public': True, 'scheme': 'http'}
        r['ports']['panel'] = server.server_port
        monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:1')
        report = verify_connectivity(Settings(host='127.0.0.1'), r)
        assert report['all_passed'] is passed
        assert requests_seen == [('/test-only/', None, None)]
        assert 'HTTP ' + str(status) in report['rows'][0]['detail']
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


@pytest.mark.parametrize('action', ['deploy','resume_deploy','sync','apply_certificate','verify_connectivity','open'])
def test_worker_verifies_after_configuration_and_saves_report(monkeypatch, tmp_path, probes, action):
    import deployer.gui as gui
    from deployer.storage import load_secret, Redactor
    monkeypatch.setenv('NODEPILOT_HOME', str(tmp_path))
    r = record(); events = []
    class Engine:
        def __init__(self, settings, log, progress, *args):
            self.settings = settings; self.log = log; self.progress = progress
            self.redact = Redactor([]); self.ssh = SimpleNamespace()
        def load_remote(self):
            events.append('load')
            return {**r, 'panel_access': {}} if action == 'open' else r
        def enable_automatic_panel(self): events.append('configure'); return r
        def deploy(self): events.append('configure'); return r
        resume_deploy = sync = apply_certificate = deploy
        def record_name(self): return 'test-connectivity'
        def close(self): events.append('close')
    monkeypatch.setattr(gui, 'Engine', Engine)
    worker = gui.Worker(Settings(host='192.0.2.9'), action); results = []; errors = []
    worker.result.connect(results.append); worker.failed.connect(errors.append); worker.run()
    assert not errors and len(results) == 1
    assert load_secret('test-connectivity')['connectivity']['all_passed']
    assert events[-1] == 'close' and len(probes) == 2


def test_success_does_not_open_security_group_dialog(monkeypatch, tmp_path):
    import deployer.gui as gui
    from PySide6.QtWidgets import QApplication
    monkeypatch.setenv('NODEPILOT_HOME', str(tmp_path))
    app = QApplication.instance() or QApplication([]); gui.configure(app)
    window = gui.Window(); r = record()
    r['connectivity'] = {'all_passed': True, 'checked_at': 'test', 'rows': []}
    monkeypatch.setattr(gui.QDialog, 'exec', lambda self: pytest.fail('A passing deployment must not demand security group settings'))
    window.record = r; window.show_record(r); window.security_group_notice()
    assert '全部通过' in window.connectivity_summary.text()
    window.inputs['host'].clear(); window.inputs['host'].editingFinished.emit()
    assert '尚未验证' in window.connectivity_summary.text()
    window.close()


def test_tutorials_describe_verification_first_without_fixed_provider():
    from pathlib import Path
    from deployer.guide import STEPS
    text = '\n'.join(str(step) for step in STEPS)
    for filename in ('README.md', 'docs/user-guide.md'):
        content = Path(filename).read_text(encoding='utf-8')
        assert 'RakSmart' not in content and '重新验证节点与面板' in content
    assert 'RakSmart' not in text and '超时不能证明' in text and 'TCP 80' in text
