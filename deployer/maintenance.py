"""SSH maintenance operations; every mutation reads back its result."""
import base64
import copy
import hashlib
import json
import re
import shlex
import time
from datetime import datetime, timezone, timedelta
from .models import Settings, validate_panel_login
from .panel import node_links
from .ssh import REMOTE_ROOT
from .storage import save_secret
from . import scripts, bbr

BEIJING = timezone(timedelta(hours=8))

def date_text(value):
    if value < 0:return '首次使用后 %.1f 天' % (-value/86400000)
    return datetime.fromtimestamp(value / 1000, BEIJING).strftime('%Y-%m-%d %H:%M') if value > 0 else '不限期'

def json_object(value):
    return json.loads(value or '{}') if isinstance(value, str) else value or {}

def client_rows(nodes):
    rows = []
    for node in nodes:
        stats = {s['email']: s for s in node.get('clientStats', [])}
        for client in json_object(node.get('settings')).get('clients', []):
            email = client.get('email', '')
            if not email:
                continue
            stat = stats.get(email, {})
            rows.append({'inbound_id': node['id'], 'remark': node.get('remark', ''), 'email': email,
                         'protocol': node.get('protocol'), 'port': node.get('port'),
                         'used': int(stat.get('up', 0)) + int(stat.get('down', 0)),
                         'total': int(client.get('totalGB', 0)), 'expiry': int(client.get('expiryTime', 0)),
                         'enable': bool(client.get('enable', True)), 'client': client})
            rows[-1]['effective_enable'] = bool(stat.get('enable', client.get('enable', True)))
    return rows

def bbr_label(status):
    if status.get('algorithm') != 'bbr':
        return '当前未使用 BBR（' + status.get('algorithm', '未知') + '）'
    version = status.get('bbr_version', status.get('module_version', ''))
    if status.get('active'):
        return 'byJoey BBRv3 · 已生效'
    if version in ('1', '2', '3'):
        if version == '1' and status.get('native_verified'):
            return '原版内核 BBRv1 · 已启用'
        return 'BBRv' + version + '（当前运行内核）'
    return '内核 BBR · 版本未确认'

OVERVIEW = r'''python3 - <<'PY'
import json,os,platform,shutil,subprocess,time,pathlib
def cmd(args):
 try:
  r=subprocess.run(args,capture_output=True,text=True);return r.stdout.strip() or r.stderr.strip()
 except FileNotFoundError:return '命令未安装：'+args[0]
mem={l.split(':')[0]:int(l.split()[1])*1024 for l in open('/proc/meminfo') if ':' in l}
disk=shutil.disk_usage('/')
jobs=[]
for p in pathlib.Path('/var/lib/nodepilot/jobs').glob('*.status'):
 try: jobs.append({'name':p.stem,'result':json.loads(p.read_text())})
 except (ValueError,OSError): pass
for p in pathlib.Path('/var/lib/nodepilot/jobs').glob('*.pid'):
 if p.with_suffix('.status').exists():continue
 try:
  pid=int(p.read_text());os.kill(pid,0);jobs.append({'name':p.stem,'result':'运行中'})
 except (ValueError,OSError):jobs.append({'name':p.stem,'result':'任务中断，需检查日志'})
print(json.dumps({'time':time.strftime('%Y-%m-%d %H:%M:%S %Z'),'uptime':int(float(open('/proc/uptime').read().split()[0])),
'cpu_count':os.cpu_count(),'load':os.getloadavg(),'memory_total':mem.get('MemTotal',0),'memory_available':mem.get('MemAvailable',0),
'disk_total':disk.total,'disk_free':disk.free,'os':open('/etc/os-release').read(),'kernel':platform.release(),
'panel':cmd(['systemctl','is-active','x-ui']),'listeners':cmd(['ss','-H','-lntup']),
'firewall':cmd(['nft','list','ruleset']),'renewal':cmd(['systemctl','list-timers','nodepilot-cert-renew.timer','--no-pager']),
'jobs':jobs}))
PY'''

class MaintenanceMixin:
    def overview(self):
        self.ssh.connect()
        info = json.loads(self.ssh.run(OVERVIEW))
        self.log('服务器时间：' + info['time'] + '；在线 ' + str(info['uptime'] // 3600) + ' 小时')
        self.log('CPU 核数：' + str(info['cpu_count']) + '；负载：' + str(info['load']))
        self.log('内存可用 / 总量：%.2f / %.2f GB；磁盘可用：%.2f GB' %
                 (info['memory_available']/1024**3, info['memory_total']/1024**3, info['disk_free']/1024**3))
        self.log('3x-ui 服务：' + info['panel'] + '；内核：' + info['kernel'])
        self.log('实际监听：\n' + info['listeners'])
        self.log('证书续期任务：\n' + (info['renewal'] or '未安装'))
        self.log('后台任务：' + json.dumps(info['jobs'], ensure_ascii=False))
        return info

    def current_bbr(self):
        self.ssh.connect()
        status = bbr.describe_status(json.loads(self.ssh.run(bbr.status_command())))
        status['installed'] = self.ssh.run('test -s ' + shlex.quote('/boot/vmlinuz-' + bbr.MANIFEST['kernel']) + ' && echo yes || true').strip() == 'yes'
        status['label'] = bbr_label(status)
        status['reboot_required'] = status['installed'] and status['kernel'] != status['target_kernel']
        record = self.ssh.json(REMOTE_ROOT + '/deployment.json', {})
        status['hy2'] = []
        if record:
            self.redact.add(*record['identity'].values())
            try:
                for node in self.panel(record).list():
                    if node.get('protocol') == 'hysteria':
                        quic = json_object(node.get('streamSettings')).get('finalmask', {}).get('quicParams', {})
                        status['hy2'].append({'node': node.get('remark'), 'congestion': quic.get('congestion', '核心默认'), 'profile': quic.get('bbrProfile', '默认')})
            except Exception as ex:
                self.log('TCP 状态已读取；HY2 配置暂无法读取：' + self.redact(str(ex)))
        self.log(status['label'] + '\n运行内核：' + status['kernel'] + '\nTCP 算法：' + status['algorithm'] + '；默认队列：' + status['qdisc'] + '\n实际网卡：' + status.get('interface','未读取') + '；实际队列：' + (status.get('actual_qdisc') or '未确认'))
        self.log('BBR 版本：'+('BBRv'+status['bbr_version'] if status['bbr_version'] else '未确认')+'\n识别依据：'+status['version_evidence'])
        self.log('软件指定的 byJoey 内核（' + status['target_kernel'] + '）已安装：' + ('是' if status['installed'] else '否') + '；此版本待重启：' + ('是' if status['reboot_required'] else '否'))
        if not status['installed']:
            self.log('未检测到指定版本，不代表没有安装其他 BBRv3 内核；当前生效版本以运行内核和模块检查为准。')
        self.log('HY2 QUIC：' + json.dumps(status['hy2'], ensure_ascii=False))
        return status

    def native_bbr(self):
        self.ssh.connect(); self.ssh.run('install -d -m 700 ' + REMOTE_ROOT); self.ssh.lock()
        self.ssh.run('bash -se <<\'NP\'\n' + scripts.BBR + '\nNP', timeout=120)
        status = bbr.describe_status(json.loads(self.ssh.run(bbr.status_command())))
        if status['algorithm'] != 'bbr' or status['qdisc'] != 'fq':
            raise RuntimeError('当前内核 BBR 或默认队列未通过回读验证，请刷新当前状态检查')
        return self.current_bbr()

    def change_panel_login(self, payload):
        if payload.get('endpoint') != self.settings.host + ':' + str(self.settings.ssh_port):
            raise RuntimeError('目标服务器已变化，请重新选择服务器')
        username, password = payload.get('username',''), payload.get('password','')
        validate_panel_login(username,password)
        self.redact.add(password)
        record=self.load_remote();self.ssh.lock()
        self.ssh.run("sqlite3 /etc/x-ui/x-ui.db \".backup '/var/lib/nodepilot/backups/before-panel-login.db'\"")
        command='/usr/local/x-ui/x-ui setting -username '+shlex.quote(username)+' -password '+shlex.quote(password)
        self.ssh.run(command)
        # The CLI prints success even for some failures; verify actual panel login.
        import bcrypt
        actual=json.loads(self.ssh.run('sqlite3 -json /etc/x-ui/x-ui.db '+shlex.quote('SELECT username,password FROM users ORDER BY id LIMIT 1;')))
        if actual:self.redact.add(actual[0].get('password',''))
        if not actual or actual[0]['username']!=username or not bcrypt.checkpw(password.encode('utf-8'),actual[0]['password'].encode('utf-8')):
            raise RuntimeError('新面板账号密码未通过数据库回读验证，请查看面板或备份')
        record['identity'].update(panel_user=username,panel_password=password)
        record['settings']['panel_user']=username
        self.persist(record)
        self.log('面板账号密码已修改，已回读核对账号和密码哈希。')
        return record

    def install_bbr(self):
        record = self.load_remote(); self.ssh.lock()
        self.ssh.job('bbrv3-' + bbr.MANIFEST['tag'], bbr.install_script(), 2400)
        record['bbrv3'] = bbr.describe_status(json.loads(self.ssh.run(bbr.status_command())))
        record['bbr'] = record['bbrv3']['algorithm']
        self.persist(record)
        return record

    def persist(self, record):
        self.ssh.write_json(REMOTE_ROOT + '/deployment.json', record)
        save_secret(self.record_name(), record)

    def clients(self):
        record = self.load_remote()
        return client_rows(self.panel(record).list())

    def change_client(self, payload):
        if payload.get('endpoint') != self.settings.host + ':' + str(self.settings.ssh_port):
            raise RuntimeError('目标服务器已变化，请刷新节点用户后操作')
        record = self.load_remote(); self.ssh.lock()
        api = self.panel(record)
        rows = client_rows(api.list())
        target = next((r for r in rows if r['inbound_id'] == payload['inbound_id'] and r['email'] == payload['email']), None)
        if not target:
            raise RuntimeError('用户已经变化，请刷新列表后操作')
        if any(target[k] != payload['before'][k] for k in ('total', 'expiry', 'enable')):
            raise RuntimeError('面板数据已被修改，请刷新后重新预览')
        client = copy.deepcopy(target['client'])
        mode = payload['mode']
        changes = payload.get('changes', {})
        allowed = {'limits': {'totalGB', 'expiryTime'}, 'enable': {'enable'}, 'reset': set()}
        if mode not in allowed or not set(changes) <= allowed[mode]:
            raise ValueError('修改范围无效')
        if any(k in changes and (not isinstance(changes[k], int) or changes[k] < 0) for k in ('totalGB', 'expiryTime')):
            raise ValueError('流量或日期无效')
        if mode == 'reset':
            # Reset is email-wide in this panel version; never reset shared users silently.
            if sum(r['email'] == target['email'] for r in rows) > 1:
                raise RuntimeError('该用户同时用于多个入站，请在 3x-ui 面板核对范围后重置')
            api.reset_client(target['email'])
        else:
            client.update(changes)
            api.update_client(target['inbound_id'], client)
        refreshed = client_rows(api.list())
        actual = next(r for r in refreshed if r['inbound_id'] == target['inbound_id'] and r['email'] == target['email'])
        if mode != 'reset':
            names = {'totalGB': 'total', 'expiryTime': 'expiry', 'enable': 'enable'}
            if any(actual[names[k]] != v for k, v in changes.items()):
                raise RuntimeError('面板回读结果与预期不同，请刷新核对')
        elif actual['used'] > target['used'] and target['used']:
            self.log('重置请求已提交；有活跃流量，请再次刷新查看新统计。')
        self.log('已回读用户 ' + target['email'] + '：流量 %.2f GB，到期 %s，启用 %s' % (actual['total']/1024**3, date_text(actual['expiry']), actual['enable']))
        return refreshed

    def service_action(self, action):
        record = self.load_remote(); self.ssh.lock()
        if action == 'restart_core':
            self.panel(record).call('POST', 'panel/api/server/restartXrayService')
            time.sleep(2)
        elif action == 'restart_panel':
            self.ssh.run('systemctl restart x-ui'); time.sleep(2)
        elif action == 'reboot':
            self.ssh.run('systemd-run --unit=nodepilot-reboot-' + str(int(time.time())) + ' --on-active=5s /usr/bin/systemctl reboot')
            return '已安排 5 秒后重启；稍后重新连接并刷新服务与 BBR 状态。'
        else:
            raise ValueError('无效服务操作')
        self.ssh.run('systemctl is-active --quiet x-ui')
        nodes = self.panel(record).list()
        listeners = self.ssh.run('ss -H -lntup')
        for node in nodes:
            if node.get('enable') and not re.search(':' + str(node['port']) + r'\s', listeners):
                raise RuntimeError('服务已启动，但节点 ' + node.get('remark', '') + ' 未监听，请查看日志')
        return '服务已启动，启用节点的监听端口已回读。'

    def service_logs(self):
        self.ssh.connect()
        return self.ssh.run('journalctl -u x-ui -u nodepilot-cert-renew.service -n 100 --no-pager', check=False)

    def certificate_status(self):
        record = self.load_remote()
        cert = record.get('certificate')
        if not cert:
            return '当前服务器未配置域名 / HY2 证书。可在“域名与证书”给现有面板添加 HTTPS。'
        path = shlex.quote(cert['cert'])
        raw = self.ssh.run('openssl x509 -in ' + path + ' -noout -enddate').strip().partition('=')[2]
        expires = datetime.strptime(raw, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        remaining = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
        health = '已过期，请立即更新' if remaining < 0 else '即将到期，请核对续期任务' if remaining < 14 else '有效'
        return ('证书状态：' + health + '；剩余 ' + str(max(0,remaining)) + ' 天\n到期时间（北京）：' + expires.astimezone(BEIJING).strftime('%Y-%m-%d %H:%M') + '\n证书类型：' + ('自签证书' if cert['selfsigned'] else '域名证书 · TCP 80 验证' if cert.get('method')=='http' else '域名证书 · 原 DNS 验证') + '\n' +
                self.ssh.run('openssl x509 -in ' + path + ' -noout -subject -issuer; systemctl list-timers nodepilot-cert-renew.timer --no-pager; systemctl show nodepilot-cert-renew.service -p Result -p ExecMainStatus -p ExecMainExitTimestamp; journalctl -u nodepilot-cert-renew.service -n 12 --no-pager', check=False))

    def renew_certificate(self):
        record = self.load_remote(); self.ssh.lock()
        cert = record.get('certificate')
        if not cert:
            raise RuntimeError('没有 HY2 证书可续期')
        if cert['selfsigned']:
            # Keep a rollback copy until the updated panel config is applied.
            base = REMOTE_ROOT + '/certs/hy2'
            self.ssh.run('cp ' + base + '/fullchain.pem ' + base + '/fullchain.previous.pem; cp ' + base + '/key.pem ' + base + '/key.previous.pem')
            command = scripts.SELF_CERT.replace('if [ ! -s /var/lib/nodepilot/certs/hy2/fullchain.pem ]; then', 'if true; then')
            self.ssh.run("bash -se <<'NP'\n" + command + '\nNP')
        else:
            from .public_panel import renew_script
            self.ssh.run(renew_script(cert['domain'],'cloudflare.env',cert.get('method','dns')),timeout=1200)
        der = self.ssh.run('openssl x509 -in ' + shlex.quote(cert['cert']) + ' -outform DER | base64 -w0')
        digest = hashlib.sha256(base64.b64decode(der)).digest()
        cert.update(fingerprint=digest.hex(), fingerprint_b64=base64.b64encode(digest).decode())
        api = self.panel(record)
        for node in api.list():
            if node.get('remark') == 'NodePilot · HY2':
                stream = json_object(node['streamSettings'])
                stream['tlsSettings'].setdefault('settings', {})['pinnedPeerCertSha256'] = [cert['fingerprint']] if cert['selfsigned'] else []
                node['streamSettings'] = json.dumps(stream); api.update(node)
        api.call('POST', 'panel/api/server/restartXrayService')
        self.ssh.run('openssl x509 -in ' + shlex.quote(cert['cert']) + ' -checkend 86400 -noout')
        record['links'] = node_links(Settings(**record['settings']), record['ports'], record['identity'], cert)
        self.persist(record)
        self.log('证书已更新；自签证书用户请重新导入 HY2 链接。' if cert['selfsigned'] else '证书续期后已回读有效期。')
        return record

    def cleanup_preview(self):
        record = self.load_remote()
        # Exact installer cache allowlist: no backup, certificate or job log deletion.
        paths = [REMOTE_ROOT + '/acme-source.tar.gz']
        paths += [REMOTE_ROOT + '/bbrv3/' + bbr.MANIFEST['asset']['name'] + suffix for suffix in ('', '.part')]
        result = []
        for path in paths:
            if self.ssh.exists(path):
                size = int(self.ssh.run('stat -c %s -- ' + shlex.quote(path)).strip())
                result.append({'path': path, 'size': size})
        return result

    def cleanup(self, expected):
        current = self.cleanup_preview(); self.ssh.lock()
        if current != expected:
            raise RuntimeError('清理文件已变化，请重新预览')
        for item in current:
            self.ssh.run('rm -- ' + shlex.quote(item['path']))
            if self.ssh.exists(item['path']):
                raise RuntimeError('文件仍存在：' + item['path'])
        return '安装缓存清理完成，释放 %.2f MB。' % (sum(x['size'] for x in current) / 1024**2)

    def clean_old_logs(self):
        self.ssh.connect(); self.ssh.run('journalctl --rotate; journalctl --vacuum-time=14d', timeout=120)
        return self.ssh.run('journalctl --disk-usage')

    def diagnose(self):
        self.ssh.connect()
        info = json.loads(self.ssh.run(OVERVIEW))
        report = ['SSH：连接与身份验证通过', '3x-ui 服务：' + info['panel'], '运行内核：' + info['kernel']]
        record = self.ssh.json(REMOTE_ROOT + '/deployment.json')
        if not record:
            report.append('部署记录：不存在；请先部署或恢复完整备份')
        else:
            self.redact.add(*record['identity'].values())
            try:
                nodes = self.panel(record).list()
                report.append('面板接口：通过')
                for node in nodes:
                    listen = bool(re.search(':' + str(node['port']) + r'\s', info['listeners']))
                    report.append(node.get('remark', '') + ' 端口 ' + str(node['port']) + '：' + ('正在监听' if listen else '未监听，请检查服务日志'))
                now = int(time.time()*1000)
                for row in client_rows(nodes):
                    problems = []
                    if not row['enable']: problems.append('已停用')
                    if row['expiry'] and row['expiry'] <= now: problems.append('已到期')
                    if row['total'] and row['used'] >= row['total']: problems.append('已用流量达到配额')
                    report.append(row['email'] + '：' + ('、'.join(problems) or '日期与配额检查通过'))
            except Exception as ex:
                report.append('面板接口未通过：' + self.redact(str(ex)))
            cert = record.get('certificate')
            if cert:
                path = shlex.quote(cert['cert'])
                valid = self.ssh.run('openssl x509 -in ' + path + ' -checkend 0 -noout >/dev/null 2>&1 && echo yes || true').strip() == 'yes'
                report.append('HY2 证书：' + ('尚在有效期内' if valid else '已失效或无法读取，请检查证书'))
        report.append('本机防火墙（请核对实际端口与规则）：\n' + (info['firewall'] or '未读取到 nftables 规则；请确认是否由 UFW 或其他防火墙管理'))
        report.append('外部网络：SSH 连接不能证明节点端口畅通；请使用“测试现有节点”。外部超时可能涉及安全组、路由或网络，不能仅凭超时确定原因。')
        report.append('最近日志：\n' + self.ssh.run('journalctl -u x-ui -n 35 --no-pager', check=False))
        return '\n'.join(report)
