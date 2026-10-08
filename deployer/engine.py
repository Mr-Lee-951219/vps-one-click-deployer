import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from .models import Settings, allocate_ports, new_identity, port_rules
from .ssh import SSH, Tunnel, REMOTE_ROOT, ConnectionCancelled
from .panel import Panel, build_inbounds, node_links
from .cloudflare import Cloudflare
from .domain_certificate import check_domain
from .storage import Redactor, save_secret, load_secret, save_public
from . import scripts
from . import bbr
from .maintenance import MaintenanceMixin
from .portable_backup import BackupMixin
from .public_panel import PublicPanelMixin, panel_rules
from .security import SecurityMixin

ASSETS = Path(__file__).resolve().parent.parent / "assets"
INSTALL_HASH = "18616fe26c8f6c92db6daa2dcd7cd53c5143ee69ecfd26d8ea6dc9b2c78607a6"

class Engine(MaintenanceMixin, BackupMixin, PublicPanelMixin, SecurityMixin):
    assets = ASSETS
    install_hash = INSTALL_HASH
    def __init__(self, settings, log=lambda _: None, progress=lambda *_: None, trust=None, trust_changed=None):
        self.settings = settings
        self.redact = Redactor([settings.password, settings.panel_password, settings.cf_token])
        self.log = lambda x: log(self.redact(x))
        self.progress = progress
        self.ssh = SSH(settings, self.log, trust, trust_changed)
        self.tunnel = None

    def close(self):
        if self.tunnel:
            self.tunnel.close()
        self.ssh.close()

    def inspect(self):
        self.ssh.connect()
        value = self.ssh.run("python3 - <<'PY'\nimport json,platform,os,shutil,subprocess\nprint(json.dumps({'os':open('/etc/os-release').read(),'arch':platform.machine(),'root':os.geteuid()==0,'free_gb':round(shutil.disk_usage('/').free/1024**3,1),'listeners':subprocess.getoutput('ss -H -lntu'),'bbr':subprocess.getoutput('sysctl -n net.ipv4.tcp_congestion_control'),'panel_installed':os.path.exists('/usr/local/x-ui/x-ui')}))\nPY")
        return json.loads(value)

    def record_name(self):
        return self.settings.host.replace(':', '_') + '_' + str(self.settings.ssh_port)

    def panel(self, record):
        if not self.tunnel:
            self.tunnel = Tunnel(self.ssh, record['ports']['panel'])
        access=record.get('panel_access',{})
        scheme=access.get('scheme','https') if access.get('public') else 'http'
        fingerprint=self.panel_fingerprint(record) if scheme=='https' else None
        return Panel(f"{scheme}://127.0.0.1:{self.tunnel.port}{record['identity']['panel_path']}", record['identity']['api_token'],fingerprint)

    def deploy(self):
        s = self.settings
        s.validate()
        if s.tls_mode in ('domain','cloudflare'):check_domain(s.domain,s.host)
        self.progress(5, '检查服务器')
        info = self.inspect()
        if not info['root'] or 'ID=debian' not in info['os'] or 'VERSION_ID="12"' not in info['os'] or info['arch'] != 'x86_64':
            raise RuntimeError('此安装包已按 Debian 12 / x86_64 测试，请使用该系统')
        if info['free_gb'] < 2:
            raise RuntimeError('至少需要 2GB 可用磁盘')
        self.ssh.run(f'install -d -m 700 {REMOTE_ROOT} {REMOTE_ROOT}/backups')
        self.ssh.lock()
        record = self.ssh.json(REMOTE_ROOT + '/deployment.json')
        if not record:
            if info['panel_installed']:
                raise RuntimeError('检测到已有 3x-ui。为保护原配置，本软件不会覆盖安装，请先备份并使用原面板管理')
            occupied = set(int(p) for p in re.findall(r':(\d+)\s', info['listeners']))
            ports = allocate_ports(s, occupied)
            identity = new_identity(s)
            key = X25519PrivateKey.generate()
            enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
            identity.update(reality_private=enc(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())), reality_public=enc(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
            record = {'version': 1, 'ports': ports, 'identity': identity, 'settings': s.public_dict(), 'stage': 'prepared'}
            self.ssh.write_json(REMOTE_ROOT + '/deployment.json', record)
        else:
            original = record['settings']
            immutable = ('vless', 'hy2', 'tls_mode', 'reality_sni', 'reality_target')
            if s.tls_mode in ('domain','cloudflare'):immutable+=('domain',)
            normalize=lambda key,value:('domain' if value=='cloudflare' else value) if key=='tls_mode' else value
            if any(normalize(k,original.get(k)) != normalize(k,getattr(s, k)) for k in immutable):
                raise RuntimeError('服务器已有部署记录；重试请使用原协议和域名。修改节点请从管理面板操作后同步端口')
            for key in record['ports']:
                requested = getattr(s, key + '_port')
                if requested and requested != record['ports'][key]:
                    raise RuntimeError('重试保留原端口；请恢复随机选项或填写部署记录中的端口')
        ports, identity = record['ports'], record['identity']
        if s.panel_user and (s.panel_user != identity['panel_user'] or (s.panel_password and s.panel_password != identity['panel_password'])):
            raise RuntimeError('已有部署将保留原面板账号密码；请在服务器维护中使用“修改面板账号与密码”')
        self.redact.add(*identity.values(), identity['panel_path'].strip('/'))
        save_secret(self.record_name(), record)
        self.log('本次端口：' + json.dumps(ports))
        self.progress(15, '安装 3x-ui')
        installer = (ASSETS / 'official-install.sh').read_bytes()
        if hashlib.sha256(installer).hexdigest() != INSTALL_HASH:
            raise RuntimeError('安装脚本校验失败')
        self.ssh.write(REMOTE_ROOT + '/official-install.sh', installer, 0o700)
        self.ssh.job('install', scripts.install_script(identity, ports, s.host,record.get('panel_access')), 1200)
        # Disable the unrelated public subscription listener before opening any nodes.
        self.ssh.run("set -e; systemctl stop x-ui; sqlite3 /etc/x-ui/x-ui.db \"UPDATE settings SET value='false' WHERE key='subEnable'; DELETE FROM api_tokens WHERE name='install';\"; systemctl start x-ui")
        if 'api_token' not in identity:
            output = self.ssh.run('/usr/local/x-ui/x-ui setting -getApiToken -tokenName nodepilot -tokenScope admin')
            match = re.search(r'apiToken:\s*(\S+)', output)
            if not match:
                raise RuntimeError('无法获取面板接口凭据')
            identity['api_token'] = match.group(1)
            self.redact.add(identity['api_token'])
            self.ssh.write_json(REMOTE_ROOT + '/deployment.json', record)
        self.progress(35, '准备证书')
        certificate = record.get('certificate')
        if (s.hy2 or s.tls_mode in ('domain','cloudflare')) and not certificate:
            if s.tls_mode in ('domain','cloudflare'):
                self.prepare_domain_certificate(record)
                domain = s.domain
                base = REMOTE_ROOT + '/certs/' + domain
            else:
                self.ssh.job('self-certificate', scripts.SELF_CERT)
                domain, base = 'nodepilot.local', REMOTE_ROOT + '/certs/hy2'
            der = self.ssh.run('openssl x509 -in ' + shlex.quote(base + '/fullchain.pem') + ' -outform DER | base64 -w0')
            digest = hashlib.sha256(base64.b64decode(der)).digest()
            certificate = {'domain': domain, 'cert': base + '/fullchain.pem', 'key': base + '/key.pem', 'selfsigned': s.tls_mode not in ('domain','cloudflare'), 'fingerprint': digest.hex(), 'fingerprint_b64': base64.b64encode(digest).decode()}
            if not certificate['selfsigned']:certificate['method']='http'
            record['certificate'] = certificate
            self.ssh.write_json(REMOTE_ROOT + '/deployment.json', record)
        if certificate and not certificate.get('selfsigned'):self.ssh.job('renewal-v3',scripts.ACME_TIMER)
        self.progress(45, '生成面板访问入口')
        if not record.get('panel_access',{}).get('public'):
            self.ssh.run("sqlite3 /etc/x-ui/x-ui.db \".backup '/var/lib/nodepilot/backups/before-public-panel.db'\"")
            record=self.apply_automatic_panel(record)
            self.ssh.write_json(REMOTE_ROOT+'/deployment.json',record)
        self.progress(50, '检查 TCP 拥塞控制')
        if s.bbr_mode == 'native':
            self.ssh.run("bash -se <<'NP'\n" + scripts.BBR + '\nNP', timeout=120)
            if self.ssh.run('sysctl -n net.ipv4.tcp_congestion_control').strip() != 'bbr':
                raise RuntimeError('当前内核未能启用 BBR，请选择保持当前设置或核对内核')
        record['bbr'] = self.ssh.run('sysctl -n net.ipv4.tcp_congestion_control').strip()
        self.progress(65, '创建节点')
        self.ssh.run("test -f /var/lib/nodepilot/backups/before-nodes.db || sqlite3 /etc/x-ui/x-ui.db \".backup '/var/lib/nodepilot/backups/before-nodes.db'\"")
        time.sleep(2)
        api = self.panel(record)
        for inbound in build_inbounds(s, ports, identity, certificate):
            api.ensure(inbound)
        api.call('POST', 'panel/api/server/restartXrayService')
        rules = panel_rules(record,port_rules(s, ports))
        self.ssh.write_json(REMOTE_ROOT + '/rules.json', rules)
        self.progress(80, '配置服务器端口')
        if s.firewall:
            self.ssh.write(REMOTE_ROOT + '/firewall.py', scripts.FIREWALL_PY)
            self.ssh.job('firewall-' + hashlib.sha256(json.dumps(rules).encode()).hexdigest()[:10], scripts.FIREWALL)
            record['firewall'] = self.ssh.json(REMOTE_ROOT + '/firewall-result.json')
        time.sleep(2)
        listeners = self.ssh.run('ss -H -lntup')
        for key in ('vless', 'hy2'):
            if key in ports and not re.search(r':' + str(ports[key]) + r'\s', listeners):
                raise RuntimeError(f'{key} 未监听预定端口，请查看诊断日志')
        if s.bbr_mode == 'v3':
            self.progress(90, '安装 byJoey BBRv3 标准内核')
            self.ssh.job('bbrv3-'+bbr.MANIFEST['tag'],bbr.install_script(),2400)
            record['bbrv3']=bbr.describe_status(json.loads(self.ssh.run(bbr.status_command())))
            if record['bbrv3']['active']:self.log('byJoey BBRv3 已验证生效；实际队列：'+(record['bbrv3'].get('actual_qdisc') or '未确认'))
            else:self.log('节点已配置；BBRv3 尚未确认生效，请重启服务器后验证。')
            record['bbr']=self.ssh.run('sysctl -n net.ipv4.tcp_congestion_control').strip()
        record.update(stage='installed', links=node_links(s, ports, identity, certificate), rules=rules)
        record['bbr_status']=self.current_bbr()
        self.ssh.write_json(REMOTE_ROOT + '/deployment.json', record)
        save_secret(self.record_name(), record)
        save_public('last-server', s.public_dict())
        self.progress(100, '部署完成，等待节点连通性验证')
        return record

    def load_remote(self):
        self.ssh.connect()
        result = self.ssh.json(REMOTE_ROOT + '/deployment.json')
        if not result:
            raise RuntimeError('该服务器没有本软件的部署记录')
        self.redact.add(*result['identity'].values())
        return result

    def resume_deploy(self):
        record = self.load_remote()
        if record.get('stage') == 'installed':
            self.log('这台服务器已有完成的部署记录，无需重复部署。')
            return record
        current = self.settings
        settings = Settings(**record['settings'])
        for key in ('host','ssh_port','username','password','private_key','strict_host_key','remember_password','name'):
            setattr(settings, key, getattr(current, key))
        for key, port in record['ports'].items():
            setattr(settings, key + '_port', port)
        settings.panel_user = record['identity']['panel_user']
        settings.panel_password = record['identity']['panel_password']
        self.settings = self.ssh.settings = settings
        self.redact.add(*record['identity'].values())
        self.log('已读取原协议、端口和节点身份，继续检查未完成步骤。')
        return self.deploy()

    def network_diagnosis(self):
        from .network import diagnose_speed
        record = self.load_remote()
        return diagnose_speed(self.ssh, self.settings, record, self.log)

    def verify_bbr(self):
        record=self.load_remote()
        self.ssh.lock()
        record=self.ssh.json(REMOTE_ROOT+'/deployment.json')
        if not record.get('bbrv3'):raise RuntimeError('尚未通过本软件安装 byJoey BBRv3，请先勾选“安装 BBRv3”完成部署')
        status=bbr.describe_status(json.loads(self.ssh.run(bbr.status_command())))
        record['bbrv3']=status;record['bbr']=status['algorithm']
        self.ssh.write_json(REMOTE_ROOT+'/deployment.json',record);save_secret(self.record_name(),record)
        return record

    def reboot_bbr(self):
        record=self.load_remote()
        if not record.get('bbrv3'):raise RuntimeError('没有本软件安装的 BBRv3 记录，请先部署并安装内核')
        if not self.ssh.exists('/boot/vmlinuz-'+bbr.MANIFEST['kernel']):raise RuntimeError('目标 BBRv3 内核尚未安装，请先安装再安排重启')
        self.log('服务器将在 5 秒后重启，SSH 和节点会短暂断开。')
        self.ssh.run('systemd-run --unit=nodepilot-bbr-reboot-'+str(int(time.time()))+' --on-active=5s /usr/bin/systemctl reboot')
        return '已安排服务器重启。稍后点击“验证 BBRv3 状态”，确认新内核及 BBRv3 已生效。'

    def sync(self):
        record = self.load_remote()
        self.ssh.lock()
        nodes = self.panel(record).list()
        rules = []
        for node in nodes:
            if not node.get('enable'):
                continue
            stream = json.loads(node.get('streamSettings') or '{}')
            network = stream.get('network', 'tcp')
            proto = 'UDP' if node['protocol'] == 'hysteria' or network in ('kcp', 'quic') else 'TCP'
            rules.append({'service': node['remark'], 'port': node['port'], 'protocol': proto, 'source': '0.0.0.0/0'})
        rules=panel_rules(record,rules)
        self.ssh.write_json(REMOTE_ROOT + '/rules.json', rules)
        self.ssh.write(REMOTE_ROOT + '/firewall.py', scripts.FIREWALL_PY)
        self.ssh.run('python3 ' + REMOTE_ROOT + '/firewall.py')
        record['rules'] = rules
        original=Settings(**record['settings'])
        for node in nodes:
            key='vless' if node['remark']=='NodePilot · VLESS' else 'hy2' if node['remark']=='NodePilot · HY2' else None
            if key:
                record['ports'][key]=node['port']
                config=json.loads(node['settings'])
                clients=config.get('clients',[])
                if clients:
                    record['identity']['uuid' if key=='vless' else 'hy2_password']=clients[0].get('id' if key=='vless' else 'auth',record['identity']['uuid' if key=='vless' else 'hy2_password'])
        record['links']=node_links(original,record['ports'],record['identity'],record.get('certificate'))
        self.ssh.write_json(REMOTE_ROOT + '/deployment.json', record)
        save_secret(self.record_name(), record)
        return record

    def restore_bbr(self):
        self.ssh.connect()
        self.ssh.lock()
        self.ssh.run("python3 - <<'PY'\nimport json,subprocess,pathlib\np=pathlib.Path('/var/lib/nodepilot/backups/bbr-original.json')\nif not p.exists(): raise RuntimeError('没有原参数备份')\nfor k,v in json.loads(p.read_text()).items(): subprocess.run(['sysctl','-w',k+'='+v],check=True)\nfor p in ['/etc/sysctl.d/90-nodepilot-bbr.conf','/etc/modules-load.d/nodepilot-bbr.conf']: pathlib.Path(p).unlink(missing_ok=True)\nPY")
        self.ssh.run('rm -f /var/lib/nodepilot/jobs/bbr.status')
        self.ssh.run('rm -f /var/lib/nodepilot/jobs/bbrv3-'+bbr.MANIFEST['tag']+'.status')
        expected=self.ssh.json('/var/lib/nodepilot/backups/bbr-original.json')
        actual={key:self.ssh.run('sysctl -n '+shlex.quote(key)).strip() for key in expected}
        if actual!=expected:raise RuntimeError('恢复参数的回读值不同，请查看当前 BBR 状态')
        return '已回读确认恢复原参数：'+json.dumps(actual,ensure_ascii=False)+'。当前运行内核保持。'

    def prepare_domain_certificate(self,record):
        s=self.settings;check_domain(s.domain,s.host)
        if 80 in record['ports'].values() or s.ssh_port==80:
            raise ValueError('TCP 80 与现有面板、节点或 SSH 冲突，未更改已有服务')
        if re.search(r':80\s',self.ssh.run('ss -H -lnt')):
            raise ValueError('TCP 80 已被其他服务占用，未停止该服务。请释放验证端口后重试')
        record['acme_http']=True
        record['rules']=panel_rules(record,record.get('rules',[]))
        self.ssh.write_json(REMOTE_ROOT+'/deployment.json',record)
        self.ssh.write_json(REMOTE_ROOT+'/rules.json',record['rules'])
        self.ssh.write(REMOTE_ROOT+'/firewall.py',scripts.FIREWALL_PY)
        if s.firewall:self.log(self.ssh.run('python3 '+REMOTE_ROOT+'/firewall.py'))
        self.log('域名证书通过 TCP 80 验证；请确保 RakSmart 入站 TCP 80 已放行并保持开放以自动续期。')
        name='certificate-http-'+hashlib.sha256(s.domain.encode()).hexdigest()[:20]
        base=REMOTE_ROOT+'/certs/'+s.domain
        if not (self.ssh.exists(base+'/fullchain.pem') and self.ssh.exists(base+'/key.pem')):
            self.ssh.run('rm -f '+shlex.quote(REMOTE_ROOT+'/jobs/'+name+'.status'))
        try:self.ssh.job(name,scripts.http_certificate_script(s.domain),1200)
        except ConnectionCancelled:
            raise
        except Exception as ex:
            raise RuntimeError('域名证书申请未完成。请核对灰云 A 记录、RakSmart TCP 80 入站规则、服务器防火墙及 CAA 设置后重试。\n'+str(ex)) from ex
        self.ssh.run('openssl x509 -in '+shlex.quote(base+'/fullchain.pem')+' -checkend 86400 -checkhost '+shlex.quote(s.domain)+' -noout')

    def apply_certificate(self):
        s=self.settings
        if s.tls_mode not in ('domain','cloudflare'):raise ValueError('请先选择域名证书')
        s.validate()
        record=self.load_remote(); self.ssh.lock()
        self.make_backup_connected()
        self.prepare_domain_certificate(record)
        base=REMOTE_ROOT+'/certs/'+s.domain
        der=self.ssh.run('openssl x509 -in '+shlex.quote(base+'/fullchain.pem')+' -outform DER | base64 -w0')
        digest=hashlib.sha256(base64.b64decode(der)).digest()
        cert={'domain':s.domain,'cert':base+'/fullchain.pem','key':base+'/key.pem','selfsigned':False,'method':'http','fingerprint':digest.hex(),'fingerprint_b64':base64.b64encode(digest).decode()}
        api=self.panel(record)
        for node in api.list():
            if node['remark']=='NodePilot · HY2':
                stream=json.loads(node['streamSettings'])
                stream['tlsSettings']['serverName']=s.domain
                stream['tlsSettings']['certificates']=[{'certificateFile':cert['cert'],'keyFile':cert['key'],'oneTimeLoading':False}]
                stream['tlsSettings'].setdefault('settings',{})['pinnedPeerCertSha256']=[]
                node['streamSettings']=json.dumps(stream);api.update(node)
        record['certificate']=cert
        for key in ('tls_mode','domain'):record['settings'][key]=getattr(s,key)
        record=self.apply_automatic_panel(record)
        original=Settings(**record['settings'])
        record['links']=node_links(original,record['ports'],record['identity'],cert)
        self.ssh.write_json(REMOTE_ROOT+'/deployment.json',record);save_secret(self.record_name(),record)
        self.ssh.job('renewal-v3',scripts.ACME_TIMER)
        save_public('last-server',record['settings'])
        return record

    def restore(self, backup_id):
        import tempfile
        import secrets
        if not re.fullmatch(r'\d{8}-\d{6}',backup_id):raise ValueError('请选择有效的备份时间编号')
        with tempfile.TemporaryDirectory(prefix='nodepilot-restore-') as folder:
            payload={'id':backup_id,'path':str(Path(folder)/'backup.npbackup'),'password':secrets.token_urlsafe(32)}
            self.download_backup(payload)
            return self.import_backup(payload)
