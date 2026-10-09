"""Verify from the desktop network; never infer a provider firewall from a timeout."""
from datetime import datetime, timezone
import socket

import requests

from .models import Settings
from .public_panel import public_url
from .ssh import ConnectionCancelled


def summary(report):
    if not report:
        return '尚未验证；点击“重新验证节点与面板”。'
    rows = report.get('rows', [])
    lines = ['连接验证全部通过' if report.get('all_passed') else '服务器配置已完成，部分连接尚未通过验证']
    lines.extend(f"{r['service']} · {r['protocol']} {r['port']}：{r['detail']}" for r in rows)
    lines.append('验证时间：' + report.get('checked_at', '未记录'))
    lines.append('结果仅代表当前电脑的网络；其他电脑或网络请另行测试。')
    return '\n'.join(lines)


def verify_connectivity(settings, record, log=lambda _: None, cancelled=lambda: False):
    def checkpoint():
        if cancelled():
            raise ConnectionCancelled('服务器配置已保留，已停止连接验证；稍后可重新验证。')

    rows = []
    covered = set()
    ports = record.get('ports', {})

    def add(service, port, protocol, state, detail):
        rows.append(dict(service=service, port=port, protocol=protocol, state=state, detail=detail))
        covered.add((int(port), protocol))
        log(f'{service} · {protocol} {port}：{detail}')

    checkpoint()
    actual = Settings(**record['settings'])
    actual.host = settings.host
    supported = {p: link for p, link in record.get('links', {}).items() if p in ('VLESS', 'HY2')}
    if supported:
        from .testing import test_nodes
        try:
            checks = test_nodes(actual, {**record, 'links': supported}, log, cancelled=cancelled)
        except ConnectionCancelled:
            raise
        except Exception:
            checks = {}
            log('节点测试未能完成；配置仍已保留，请检查测试核心及运行日志后重试。')
        for protocol in supported:
            key, transport = ('vless', 'TCP') if protocol == 'VLESS' else ('hy2', 'UDP')
            item = checks.get(protocol, {})
            passed = item.get('status') == '实际 HTTPS 流量通过'
            add(protocol, ports[key], transport, 'passed' if passed else 'failed',
                '实际 HTTPS 流量通过' if passed else '实际流量未通过；检查服务、节点配置、本机防火墙及外部网络')

    checkpoint()
    # Use the current SSH target, including when a saved record has an older address.
    url = public_url({**record, 'settings': {**record['settings'], 'host': settings.host}})
    if url:
        try:
            # Never send login data or borrow an environment proxy/certificate exception.
            with requests.Session() as session:
                session.trust_env = False
                with session.get(url, timeout=(4, 8), allow_redirects=False, stream=True) as response:
                    passed = 200 <= response.status_code < 400
                    detail = ('公网入口已响应' if passed else '公网入口返回异常') + f'（HTTP {response.status_code}）'
        except requests.exceptions.SSLError:
            passed, detail = False, 'HTTPS 证书验证未通过；检查域名、证书有效期和服务器时间'
        except requests.exceptions.RequestException:
            passed, detail = False, '公网入口未响应；检查面板监听、本机防火墙、解析及外部网络'
        add('管理面板', ports['panel'], 'TCP', 'passed' if passed else 'failed', detail)

    # Additional panel nodes have no exported protocol credentials. TCP reachability
    # is useful evidence but cannot establish that their application traffic works.
    extra_count = 0
    for rule in record.get('rules', []):
        checkpoint()
        port, protocol = int(rule['port']), rule['protocol'].upper()
        if (port, protocol) in covered or rule['service'] == '证书验证与续期':
            continue  # HTTP-01 listens temporarily; do not misreport its idle port as blocked.
        extra_count += 1
        if protocol != 'TCP':
            add(rule['service'], port, protocol, 'unverified', '需使用对应客户端测试；发送 UDP 数据不能证明连通')
        elif extra_count > 12:
            add(rule['service'], port, protocol, 'unverified', '额外端口超过本次探测上限，请用对应客户端验证')
        else:
            try:
                with socket.create_connection((settings.host, port), timeout=4):
                    pass
                add(rule['service'], port, protocol, 'passed', 'TCP 连接通过；应用协议仍需对应客户端测试')
            except OSError:
                add(rule['service'], port, protocol, 'failed', 'TCP 未连通；检查服务监听、本机防火墙及外部网络')
    checkpoint()
    report = {'checked_at': datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds'),
              'target': settings.host, 'rows': rows,
              'all_passed': bool(rows) and all(r['state'] == 'passed' for r in rows)}
    log('连接验证全部通过，无需额外设置安全组。' if report['all_passed'] else
        '配置已保留。请先核对服务和本机规则；若服务商外部防火墙阻拦，再到对应后台放行。超时本身不能确定原因。')
    return report
