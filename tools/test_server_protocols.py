import sys,getpass,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from live_settings import connection_settings
from deployer.engine import Engine
from deployer.panel import client_config
s, expected = connection_settings()
e=Engine(s,print,trust=lambda h,fp:fp==expected)
try:
    record=e.load_remote();s.host='127.0.0.1';results={}
    for proto in record['links']:
        e.ssh.write_json('/var/lib/nodepilot/client-test/config.json',client_config(s,record['ports'],record['identity'],record['certificate'],proto,31091))
        output=e.ssh.run("""python3 - <<'PY'
import subprocess,time,json,pathlib
path='/var/lib/nodepilot/client-test/'
with open(path+'core.log','wb') as log:
 p=subprocess.Popen(['/usr/local/x-ui/bin/xray-linux-amd64','run','-c',path+'config.json'],stdout=log,stderr=log)
 try:
  time.sleep(1)
  value=subprocess.run(['curl','-fsS','--max-time','25','--socks5-hostname','127.0.0.1:31091','https://www.cloudflare.com/cdn-cgi/trace'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  print(json.dumps({'code':value.returncode,'trace':value.stdout,'error':value.stderr,'core':pathlib.Path(path+'core.log').read_text()[-2200:]}))
 finally:
  p.terminate();p.wait(timeout=5);pathlib.Path(path+'config.json').unlink(missing_ok=True)
PY""",timeout=45)
        value=json.loads(output);print(proto, e.redact(json.dumps(value,ensure_ascii=False)),flush=True);results[proto]=value
    Path('test-artifacts/server-protocols.json').write_text(e.redact(json.dumps(results,ensure_ascii=False,indent=2)),encoding='utf-8')
finally:e.close()
