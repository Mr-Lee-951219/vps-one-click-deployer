"""Portable AES-GCM backups, independently protected and path checked."""
import base64
import hashlib
import json
import os
import re
import shlex
import sqlite3
import tempfile
import time
from pathlib import Path, PurePosixPath
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .models import Settings, PANEL_VERSION
from .panel import node_links
from .ssh import REMOTE_ROOT
from . import scripts

MAGIC = b'NODEPILOT-BACKUP-1\x00'
MAX_BYTES = 128 * 1024**2
FIXED = {'x-ui.db', 'deployment.json', 'cloudflare.env', 'cloudflare-panel.env', 'renew-certificates.py', 'rules.json', 'manifest.json',
         'nodepilot-cert-renew.service', 'nodepilot-cert-renew.timer',
         '90-nodepilot-bbr.conf', 'nodepilot-bbr.conf', 'firewall.py'}

def valid_name(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and '\\' not in name and '\x00' not in name
            and all(x not in ('', '.', '..') for x in name.split('/'))
            and (name in FIXED or len(path.parts)>1 and path.parts[0] in {'certs','acme'}))

def validate_bundle(bundle):
    if bundle.get('format') != 1 or bundle.get('panel_version') != PANEL_VERSION:
        raise ValueError('备份格式或面板版本不兼容')
    files = bundle.get('files', {})
    if not {'x-ui.db','deployment.json'} <= files.keys() or len(files)>5000:
        raise ValueError('备份缺少数据库或部署记录')
    raw_files={};size=0
    for name,entry in files.items():
        if not valid_name(name):raise ValueError('备份包含不允许的文件路径')
        raw=base64.b64decode(entry['data'],validate=True);size+=len(raw)
        if size>MAX_BYTES or hashlib.sha256(raw).hexdigest()!=entry['sha256']:
            raise ValueError('备份大小或完整性校验失败')
        raw_files[name]=raw
    record=json.loads(raw_files['deployment.json'])
    Settings(**record['settings']).validate_limits()
    ports=list(record['ports'].values())
    if not ports or len(set(ports))!=len(ports) or any(type(p)!=int or not 1<=p<=65535 for p in ports):
        raise ValueError('备份端口设置无效')
    for key in ('panel_user','panel_password','panel_path','api_token'):
        if not isinstance(record['identity'].get(key),str) or not record['identity'][key]:
            raise ValueError('备份身份信息不完整')
    if record.get('certificate'):
        for key in ('cert','key'):
            path=record['certificate'][key]
            if not path.startswith(REMOTE_ROOT+'/certs/') or not valid_name(path[len(REMOTE_ROOT)+1:]):
                raise ValueError('证书路径无效')
    access=record.get('panel_access',{})
    if access.get('public') and access.get('scheme','https')=='https':
        from .models import validate_domain
        validate_domain(access.get('domain',''))
        for key in ('cert','key'):
            path=access.get(key,'')
            if not path.startswith(REMOTE_ROOT+'/certs/') or not valid_name(path[len(REMOTE_ROOT)+1:]):
                raise ValueError('公网面板证书路径无效')
    with sqlite3.connect(':memory:') as db:
        db.deserialize(raw_files['x-ui.db'])
        if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
            raise ValueError('备份数据库完整性校验失败')
        tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'settings','users','inbounds','api_tokens'} <= tables:
            raise ValueError('备份缺少必要的 3x-ui 数据表')
    return record,raw_files

def seal(bundle,password):
    if len(password)<8:raise ValueError('备份密码至少 8 位，请妥善保存')
    validate_bundle(bundle)
    salt,nonce=os.urandom(16),os.urandom(12)
    key=Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(password.encode())
    return MAGIC+salt+nonce+AESGCM(key).encrypt(nonce,json.dumps(bundle).encode(),MAGIC)

def unseal(raw,password):
    if not raw.startswith(MAGIC) or len(raw)>MAX_BYTES*2:raise ValueError('不是有效的 NodePilot 加密备份')
    n=len(MAGIC);salt,nonce=raw[n:n+16],raw[n+16:n+28]
    try:
        key=Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(password.encode())
        bundle=json.loads(AESGCM(key).decrypt(nonce,raw[n+28:],MAGIC))
    except Exception:raise ValueError('备份密码不正确，或文件已损坏') from None
    validate_bundle(bundle)
    return bundle

class BackupMixin:
    def make_backup_connected(self):
        version=self.ssh.run('/usr/local/x-ui/x-ui -v').strip().lstrip('v')
        if version!=PANEL_VERSION.lstrip('v'):raise RuntimeError('当前面板版本与软件不匹配，未创建可能不兼容的备份')
        stamp=time.strftime('%Y%m%d-%H%M%S')
        base=REMOTE_ROOT+'/backups/'+stamp
        if self.ssh.exists(base):
            time.sleep(1);stamp=time.strftime('%Y%m%d-%H%M%S');base=REMOTE_ROOT+'/backups/'+stamp
        self.ssh.run(f'''set -e
test ! -e {base}
install -d -m 700 {base}
sqlite3 /etc/x-ui/x-ui.db ".backup '{base}/x-ui.db'"
cp {REMOTE_ROOT}/deployment.json {base}/
for name in certs acme cloudflare.env cloudflare-panel.env renew-certificates.py rules.json firewall.py; do
 if [ -e {REMOTE_ROOT}/$name ]; then cp -a {REMOTE_ROOT}/$name {base}/; fi
done
for name in nodepilot-cert-renew.service nodepilot-cert-renew.timer; do
 if [ -e /etc/systemd/system/$name ]; then cp /etc/systemd/system/$name {base}/; fi
done
if [ -f /etc/sysctl.d/90-nodepilot-bbr.conf ]; then cp /etc/sysctl.d/90-nodepilot-bbr.conf {base}/; fi
if [ -f /etc/modules-load.d/nodepilot-bbr.conf ]; then cp /etc/modules-load.d/nodepilot-bbr.conf {base}/; fi
chmod -R go-rwx {base}
sqlite3 {base}/x-ui.db 'PRAGMA integrity_check;' | grep -qx ok''',timeout=120)
        self.log('已创建完整备份：'+base)
        self.ssh.write_json(base+'/manifest.json',{'format':1,'panel_version':PANEL_VERSION,'created':stamp})
        return base

    def backup(self):
        self.load_remote();self.ssh.lock()
        return self.make_backup_connected()

    def backups(self):
        self.load_remote()
        command="""import pathlib,json,re
p=pathlib.Path('/var/lib/nodepilot/backups')
print(json.dumps([{'id':d.name,'bytes':sum(f.stat().st_size for f in d.rglob('*') if f.is_file() and not f.is_symlink())} for d in sorted(p.iterdir(),reverse=True) if d.is_dir() and re.fullmatch(r'\\d{8}-\\d{6}',d.name) and (d/'deployment.json').exists()]))"""
        return json.loads(self.ssh.run("python3 - <<'PY'\n"+command+'\nPY'))

    def download_backup(self,payload):
        self.load_remote()
        stamp=payload['id']
        if not re.fullmatch(r'\d{8}-\d{6}',stamp):raise ValueError('备份编号无效')
        base=REMOTE_ROOT+'/backups/'+stamp
        import stat
        sftp=self.ssh.client.open_sftp();files={};total=0
        def walk(folder,prefix=''):
            nonlocal total
            for entry in sftp.listdir_attr(folder):
                name=prefix+entry.filename
                if stat.S_ISDIR(entry.st_mode):
                    if name in ('certs','acme') or name.startswith(('certs/','acme/')):
                        walk(folder+'/'+entry.filename,name+'/')
                elif stat.S_ISREG(entry.st_mode) and valid_name(name):
                    total+=entry.st_size
                    if total>MAX_BYTES:raise ValueError('备份超过 128 MB，请检查 ACME 缓存')
                    with sftp.file(folder+'/'+entry.filename,'rb') as f:raw=f.read()
                    files[name]={'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
        try:walk(base)
        finally:sftp.close()
        metadata=json.loads(base64.b64decode(files['manifest.json']['data'])) if 'manifest.json' in files else {'format':1,'panel_version':PANEL_VERSION,'created':stamp}
        bundle={**metadata,'files':files}
        raw=seal(bundle,payload['password'])
        target=Path(payload['path']);temp=target.with_suffix('.tmp');temp.write_bytes(raw);temp.replace(target)
        unseal(target.read_bytes(),payload['password'])
        return '加密备份已下载并校验：'+str(target)

    def import_backup(self,payload):
        bundle=unseal(Path(payload['path']).read_bytes(),payload['password'])
        backup,files=validate_bundle(bundle)
        info=self.inspect()
        if not info['root'] or 'ID=debian' not in info['os'] or 'VERSION_ID="12"' not in info['os'] or info['arch']!='x86_64':
            raise RuntimeError('恢复需要 Debian 12 x86_64 / root')
        current=self.ssh.json(REMOTE_ROOT+'/deployment.json')
        if info['panel_installed'] and not current:raise RuntimeError('已有非本软件管理的面板，未覆盖')
        if current and info['panel_installed'] and self.ssh.run('/usr/local/x-ui/x-ui -v').strip().lstrip('v')!=PANEL_VERSION.lstrip('v'):
            raise RuntimeError('目标面板版本与备份不兼容，未覆盖配置')
        occupied=set(map(int,re.findall(r':(\d+)\s',info['listeners'])))
        owned=set(current['ports'].values()) if current else set()
        requested=set(backup['ports'].values())
        if requested & (occupied-owned) or self.settings.ssh_port in requested:raise RuntimeError('备份端口与 SSH 或其他服务冲突')
        if backup.get('certificate') and not backup['certificate']['selfsigned'] and backup['settings']['host']!=self.settings.host:
            raise RuntimeError('域名证书备份仅直接恢复原服务器地址；迁移请先调整域名解析')
        if backup.get('panel_access',{}).get('public') and backup.get('panel_access',{}).get('scheme','https')=='https' and backup['settings']['host']!=self.settings.host:
            raise RuntimeError('公网面板备份仅直接恢复原服务器地址；迁移请先调整域名解析')
        self.ssh.run('install -d -m 700 '+REMOTE_ROOT+' '+REMOTE_ROOT+'/backups');self.ssh.lock()
        if current and info['panel_installed']:self.make_backup_connected()
        elif current:
            self.ssh.write_json(REMOTE_ROOT+'/backups/before-restore-partial.json',current)
        self.redact.add(*backup['identity'].values())
        backup['settings'].update(host=self.settings.host,ssh_port=self.settings.ssh_port,username=self.settings.username)
        stage=REMOTE_ROOT+'/restore-'+str(int(time.time()))
        self.ssh.run('install -d -m 700 '+stage)
        if not info['panel_installed']:
            self.ssh.run('export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq sqlite3',timeout=300)
        for name,raw in files.items():
            path=stage+'/'+name
            self.ssh.run('install -d -m 700 '+shlex.quote(str(PurePosixPath(path).parent)))
            self.ssh.write(path,raw,0o700 if name=='acme/acme.sh' else 0o600)
        self.ssh.run('sqlite3 '+stage+"/x-ui.db 'PRAGMA integrity_check;' | grep -qx ok")
        if not info['panel_installed']:
            installer=(self.assets/'official-install.sh').read_bytes()
            if hashlib.sha256(installer).hexdigest()!=self.install_hash:raise RuntimeError('安装脚本校验失败')
            self.ssh.write(REMOTE_ROOT+'/official-install.sh',installer,0o700)
            self.ssh.job('restore-install-'+str(int(time.time())),scripts.install_script(backup['identity'],backup['ports'],self.settings.host),1200)
        self.ssh.run(f'''set -e
systemctl stop x-ui
trap 'systemctl start x-ui' EXIT
rm -f /etc/x-ui/x-ui.db-wal /etc/x-ui/x-ui.db-shm
cp {stage}/x-ui.db /etc/x-ui/x-ui.db
chmod 600 /etc/x-ui/x-ui.db
for name in certs acme cloudflare.env cloudflare-panel.env renew-certificates.py rules.json firewall.py; do
 if [ -e {stage}/$name ]; then cp -a {stage}/$name {REMOTE_ROOT}/; fi
done
for name in nodepilot-cert-renew.service nodepilot-cert-renew.timer; do
 if [ -e {stage}/$name ]; then cp {stage}/$name /etc/systemd/system/; fi
done
systemctl daemon-reload
if [ -e /etc/systemd/system/nodepilot-cert-renew.timer ]; then systemctl enable --now nodepilot-cert-renew.timer; fi
systemctl start x-ui
systemctl is-active --quiet x-ui''',timeout=120)
        backup['links']=node_links(Settings(**backup['settings']),backup['ports'],backup['identity'],backup.get('certificate'))
        self.persist(backup)
        restored_nodes=self.panel(backup).list()
        listeners=self.ssh.run('ss -H -lntup')
        ports={'panel':backup['ports']['panel']}
        ports.update({node.get('remark',str(node['id'])):node['port'] for node in restored_nodes if node.get('enable')})
        for key,port in ports.items():
            if not re.search(':'+str(port)+r'\s',listeners):raise RuntimeError('配置已恢复，但 '+key+' 端口尚未监听，请查看服务日志')
        if backup.get('certificate'):
            self.ssh.run('openssl x509 -in '+shlex.quote(backup['certificate']['cert'])+' -noout -dates')
        if self.settings.firewall:
            self.ssh.write_json(REMOTE_ROOT+'/rules.json',backup.get('rules',[]))
            self.ssh.write(REMOTE_ROOT+'/firewall.py',scripts.FIREWALL_PY)
            self.ssh.run('python3 '+REMOTE_ROOT+'/firewall.py')
        self.log('配置、证书与续期任务已恢复。BBRv3 内核需单独安装并重启验证。')
        from . import bbr
        backup['bbr']=self.ssh.run('sysctl -n net.ipv4.tcp_congestion_control').strip()
        if backup.get('bbrv3'):backup['bbrv3']=bbr.describe_status(json.loads(self.ssh.run(bbr.status_command())))
        from .testing import test_nodes
        self.log('正在用恢复后的链接测试节点…')
        backup['restore_test']=test_nodes(Settings(**backup['settings']),backup,self.log)
        if any(v.get('status')=='未通过' for v in backup['restore_test'].values()):
            self.log('配置已恢复；部分节点未连通，请检查云安全组和证书状态。')
        self.persist(backup)
        return backup

