import sys,getpass,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from live_settings import connection_settings
from deployer.engine import Engine
from deployer.testing import test_nodes
s, expected = connection_settings()
e=Engine(s,print,trust=lambda h,fp:fp==expected)
try:
    record=e.load_remote()
    e.ssh.run("sqlite3 /etc/x-ui/x-ui.db \"DELETE FROM api_tokens WHERE name='install';\"")
    print(e.ssh.run('/usr/local/x-ui/bin/xray-linux-amd64 version').splitlines()[0])
    result=test_nodes(s,record,e.log)
    Path('test-artifacts/connectivity.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))
finally:e.close()
