import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import requests
from .engine import ASSETS
from .panel import client_config

def test_nodes(settings, record, log=lambda _:None):
    core=ASSETS/'core'/'xray.exe'
    if not core.exists():raise RuntimeError('测试核心未包含在当前安装包中')
    provenance=json.loads((core.parent/'provenance.json').read_text())
    if hashlib.sha256(core.read_bytes()).hexdigest()!=provenance['xray_sha256']:raise RuntimeError('测试核心校验失败')
    results={}
    for protocol in record.get('links',{}):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='nodepilot-test-') as directory:
            cfg=Path(directory)/'client.json'
            cfg.write_text(json.dumps(client_config(settings,record['ports'],record['identity'],record.get('certificate'),protocol,port)),encoding='utf-8')
            output=Path(directory)/'core.log'
            with output.open('wb') as stream:
                process=subprocess.Popen([str(core),'run','-c',str(cfg)],stdout=stream,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                try:
                    time.sleep(1)
                    if process.poll() is not None:raise RuntimeError('客户端核心启动失败')
                    session=requests.Session(); session.trust_env=False
                    response=session.get('https://www.cloudflare.com/cdn-cgi/trace',proxies={'https':f'socks5h://127.0.0.1:{port}'},timeout=25)
                    response.raise_for_status()
                    lines=dict(line.split('=',1) for line in response.text.splitlines() if '=' in line)
                    if not lines.get('ip'):raise RuntimeError('返回内容未包含出口地址')
                    results[protocol]={'status':'实际 HTTPS 流量通过','exit_ip':lines['ip'],'matches_server':lines['ip']==settings.host}
                    log(protocol+'：实际 HTTPS 流量通过，出口 '+lines['ip'])
                except Exception as ex:
                    # Avoid copying core logs containing node credentials into the UI.
                    results[protocol]={'status':'未通过','reason':str(ex)}
                    log(protocol+'：未通过，请检查服务状态和 RakSmart 对应协议端口')
                    from .storage import Redactor
                    log(Redactor(record['identity'].values())(output.read_text(errors='replace')[-2200:]))
                finally:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
    return results
