import sys, getpass, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from live_settings import connection_settings
from deployer.engine import Engine

s, expected = connection_settings()
engine = Engine(s, print, lambda p,t: print(f'{p}% {t}',flush=True), lambda host,fp: fp == expected)
try:
    record = engine.deploy()
    public = {k:record[k] for k in ('ports','bbr','rules','stage','firewall') if k in record}
    Path('test-artifacts/deployment-public.json').write_text(json.dumps(public,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(public,ensure_ascii=False))
finally:
    engine.close()
