import sys,getpass,hashlib,json,shlex
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from live_settings import connection_settings
from deployer.ssh import SSH
root=Path(__file__).resolve().parents[1]
s, expected = connection_settings()
ssh=SSH(s,trust=lambda h,fp:fp==expected).connect()
try:
    cmd="""python3 - <<'PY'
import urllib.request,json,hashlib,zipfile,pathlib
url='https://github.com/MHSanaei/3x-ui/releases/download/v3.9.0/x-ui-windows-amd64.zip'
base=pathlib.Path('/var/lib/nodepilot/client-test');base.mkdir(mode=0o700,exist_ok=True)
path=base/'package.zip'
if not path.exists(): urllib.request.urlretrieve(url,path)
digest=urllib.request.urlopen(url+'.sha256').read().decode().split()[0]
assert hashlib.sha256(path.read_bytes()).hexdigest()==digest
archive=zipfile.ZipFile(path)
names=[n for n in archive.namelist() if 'xray' in n.lower() and n.lower().endswith('.exe')]
assert len(names)==1,archive.namelist()
data=archive.read(names[0]);(base/'xray.exe').write_bytes(data)
(base/'provenance.json').write_text(json.dumps({'source':url,'archive_sha256':digest,'xray_sha256':hashlib.sha256(data).hexdigest()}))
print(len(data))
PY"""
    print('Downloading verified package on server',flush=True)
    print(ssh.run(cmd,timeout=180),flush=True)
    dest=root/'assets'/'core';dest.mkdir(exist_ok=True)
    sftp=ssh.client.open_sftp()
    def progress(done,total):
        if done%1048576==0 or done==total:print(round(done/1048576,1),'/',round(total/1048576,1),'MB',flush=True)
    sftp.get('/var/lib/nodepilot/client-test/xray.exe',str(dest/'xray.exe'),callback=progress)
    sftp.get('/var/lib/nodepilot/client-test/provenance.json',str(dest/'provenance.json'))
    provenance=json.loads((dest/'provenance.json').read_text());assert hashlib.sha256((dest/'xray.exe').read_bytes()).hexdigest()==provenance['xray_sha256']
    print('Verified core ready')
finally:ssh.close()
