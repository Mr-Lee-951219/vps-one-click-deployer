import json,sys,hashlib,zipfile,io
from pathlib import Path
import requests
root=Path(__file__).resolve().parents[1]
session=requests.Session(); session.trust_env=False
response=session.get('https://api.github.com/repos/MHSanaei/3x-ui/releases/tags/v3.9.0',timeout=(10,30)); response.raise_for_status()
assets=response.json()['assets']
print([a['name'] for a in assets])
name='x-ui-windows-amd64.zip'
asset=next(a for a in assets if a['name']==name)
check=next(a for a in assets if a['name']==name+'.sha256')
raw=session.get(asset['browser_download_url'],timeout=(10,30),stream=True); raw.raise_for_status()
chunks=[]; total=0
for chunk in raw.iter_content(1024*1024):
    chunks.append(chunk); total+=len(chunk); print('downloaded',round(total/1024**2,1),'MB',flush=True)
content=b''.join(chunks)
digest=session.get(check['browser_download_url'],timeout=30); digest.raise_for_status()
expected=digest.text.split()[0]
assert hashlib.sha256(content).hexdigest()==expected,'checksum mismatch'
archive=zipfile.ZipFile(io.BytesIO(content))
print([n for n in archive.namelist() if n.endswith('.exe')])
dest=root/'assets'/'core'; dest.mkdir(exist_ok=True)
names=[n for n in archive.namelist() if 'xray' in n.lower() and n.lower().endswith('.exe')]
assert len(names)==1,archive.namelist()
(dest/'xray.exe').write_bytes(archive.read(names[0]))
(dest/'provenance.json').write_text(json.dumps({'source':asset['browser_download_url'],'archive_sha256':expected,'xray_sha256':hashlib.sha256((dest/'xray.exe').read_bytes()).hexdigest()},indent=2))
print('verified core ready')
