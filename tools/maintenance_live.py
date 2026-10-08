import sys,getpass,json,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from live_settings import connection_settings
from deployer.engine import Engine
s, expected = connection_settings()
def make():return Engine(s,print,lambda p,t:print(p,t,flush=True),lambda h,fp:fp==expected)
e=make()
try:
    backup=e.backup();print('Backup:',backup,flush=True)
finally:e.close()
e=make()
try:
    record=e.restore(backup.split('/')[-1]);original_ports=dict(record['ports']);time.sleep(2)
    assert len(e.panel(record).list())==2
    print('Restore and API verified',flush=True)
finally:e.close()
e=make()
try:
    record=e.deploy()
    assert record['ports']==original_ports
    print('Retry kept all existing ports',flush=True)
finally:e.close()
Path('test-artifacts/maintenance.json').write_text(json.dumps({'backup':backup,'restore':'verified API and two nodes','retry':'same ports and identities retained'},indent=2),encoding='utf-8')
