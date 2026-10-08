"""Small, explicitly requested speed comparisons; no tuning or system proxy changes."""
import hashlib
import json
import shlex
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
import requests
from .models import Settings
from .panel import client_config

LIMIT = 4 * 1024**2
URL = 'https://speed.cloudflare.com/__down?bytes=' + str(LIMIT)


def download(proxies=None, url=URL, limit=LIMIT):
    start = time.monotonic()
    size = 0
    with requests.Session() as session:
        session.trust_env = False
        with session.get(url, proxies=proxies, timeout=(12,20), stream=True) as response:
            response.raise_for_status()
            for chunk in response.iter_content(65536):
                size += min(len(chunk), limit-size)
                if size >= limit:
                    break
                if time.monotonic()-start > 60:
                    raise TimeoutError('下载测试超时')
    elapsed = max(time.monotonic()-start, 0.001)
    return {'bytes':size,'seconds':round(elapsed,3),'mbps':round(size*8/elapsed/1e6,2),'MBps':round(size/elapsed/1e6,2)}


@contextmanager
def local_client(assets, settings, record, protocol):
    core = assets / 'core' / 'xray.exe'
    provenance = json.loads((core.parent/'provenance.json').read_text())
    if hashlib.sha256(core.read_bytes()).hexdigest() != provenance['xray_sha256']:
        raise RuntimeError('测试核心校验失败')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='nodepilot-speed-') as folder:
        path = Path(folder) / 'client.json'
        path.write_text(json.dumps(client_config(settings,record['ports'],record['identity'],record.get('certificate'),protocol,port)),encoding='utf-8')
        process = subprocess.Popen([str(core),'run','-c',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            for _ in range(30):
                if process.poll() is not None:
                    raise RuntimeError('测速核心启动失败')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.15):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('测速核心未能监听本机端口')
            yield {'https':'socks5h://127.0.0.1:' + str(port)}
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()


TCP_PROBE = """python3 - <<'PY'
import json
lines=open('/proc/net/snmp').read().splitlines()
data={}
for a,b in zip(lines,lines[1:]):
 if a.startswith('Tcp:') and b.startswith('Tcp:'):
  data=dict(zip(a.split()[1:],map(int,b.split()[1:])));break
print(json.dumps({'out_segments':data.get('OutSegs',0),'retransmissions':data.get('RetransSegs',0)}))
PY"""


def diagnose_speed(ssh, settings, record, log):
    from .engine import ASSETS
    rows = []
    traffic = 0
    before = json.loads(ssh.run(TCP_PROBE))
    def add(name, operation):
        nonlocal traffic
        log('正在测试：' + name + '，最多下载 4 MiB。')
        try:
            result = operation()
            traffic += result['bytes']
            rows.append({'path':name,**result})
            log(name + '：' + str(result['mbps']) + ' Mbps / ' + str(result['MBps']) + ' MB/s')
        except Exception:
            rows.append({'path':name,'error':'未完成，请核对服务、对应端口和网络。'})
            # Failed requests may still have transferred their full allowance.
            traffic += LIMIT
            log(name + '：测试未完成。')
    add('本机直连', download)
    def server_download():
        raw=ssh.run('curl --noproxy "*" --max-time 45 --max-filesize '+str(LIMIT)+' --silent --show-error --fail -o /dev/null -w "%{size_download}|%{time_total}" '+shlex.quote(URL),timeout=55).strip()
        size, elapsed=raw.split('|');size=int(float(size));elapsed=max(float(elapsed),.001)
        return {'bytes':size,'seconds':round(elapsed,3),'mbps':round(size*8/elapsed/1e6,2),'MBps':round(size/elapsed/1e6,2)}
    add('VPS 直连',server_download)
    original=Settings(**record['settings']);original.host=settings.host
    for protocol in record.get('links',{}):
        def node_download(protocol=protocol):
            with local_client(ASSETS,original,record,protocol) as proxies:
                return download(proxies)
        add(protocol.upper()+' 节点',node_download)
    after=json.loads(ssh.run(TCP_PROBE))
    rtts=ssh.run('ss -Htin state established',check=False)
    import re
    values=[float(x) for x in re.findall(r'rtt:(\d+(?:\.\d+)?)',rtts)]
    retrans=max(0,after['retransmissions']-before['retransmissions'])
    note='单连接短测，包含连接启动开销，不代表最高带宽。RTT 来自服务器当前全部 TCP 连接；重传是全部 TCP 连接的增量，不是精确丢包率。'
    log('测速流量上限记录：%.1f MiB；服务器 TCP 重传增量：%d'%(traffic/1024**2,retrans))
    log(note)
    if values:log('当前服务器 TCP 连接 RTT：%.1f–%.1f ms'%(min(values),max(values)))
    return {'rows':rows,'traffic_bytes':traffic,'tcp_retransmissions_delta':retrans,'rtt_ms_range':[min(values),max(values)] if values else [],'note':note}
