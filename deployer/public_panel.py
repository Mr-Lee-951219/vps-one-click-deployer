"""Public HTTPS access for the existing panel; keep SSH administration available."""
import base64
import copy
import hashlib
import ipaddress
import re
import shlex
import time
from .models import validate_domain
from .cloudflare import Cloudflare
from .ssh import REMOTE_ROOT
from . import scripts


def public_url(record):
    access=record.get('panel_access',{})
    if not access.get('public'):return ''
    port=record['ports']['panel']
    scheme=access.get('scheme','https')
    host=access.get('domain') or record['settings']['host']
    if ':' in host and not host.startswith('['):host='['+host+']'
    suffix='' if port==({'http':80,'https':443}[scheme]) else ':'+str(port)
    return scheme+'://'+host+suffix+record['identity']['panel_path']


def deployment_access(record):
    """Reuse an issued domain certificate; otherwise expose the server address."""
    cert=record.get('certificate',{})
    if cert and not cert.get('selfsigned'):
        return {'public':True,'scheme':'https','domain':cert['domain'],
                'cert':cert['cert'],'key':cert['key'],'method':cert.get('method','dns'),'credential_file':'cloudflare.env'}
    return {'public':True,'scheme':'http'}


def panel_rules(record,rules):
    result=[dict(r) for r in rules if r.get('service') not in ('管理面板','证书验证与续期')]
    if record.get('acme_http') or record.get('certificate',{}).get('method')=='http' or record.get('panel_access',{}).get('method')=='http':
        result.append({'service':'证书验证与续期','port':80,'protocol':'TCP','source':'0.0.0.0/0'})
    if record.get('panel_access',{}).get('public'):
        result.insert(0,{'service':'管理面板','port':record['ports']['panel'],'protocol':'TCP','source':'0.0.0.0/0'})
    return result


def validate_public(payload,settings):
    if payload.get('endpoint') != settings.host+':'+str(settings.ssh_port):
        raise ValueError('目标服务器已变化，请重新设置公网面板')
    domain=payload.get('domain','').strip().lower();validate_domain(domain)
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',payload.get('email','')):
        raise ValueError('请填写有效的证书联系邮箱')
    if not payload.get('cf_token','').strip():raise ValueError('请填写 Cloudflare API Token')
    port=payload.get('port')
    if type(port)!=int or not 1<=port<=65535 or port==settings.ssh_port:
        raise ValueError('面板公网端口应在 1–65535，且不能与 SSH 端口相同')
    try:address=ipaddress.ip_address(settings.host)
    except ValueError:raise ValueError('请在服务器地址中填写 VPS 的公网 IPv4 地址') from None
    if address.version!=4:raise ValueError('当前公网面板支持 IPv4 服务器')
    return domain


def panel_configure_script(record):
    access=record.get('panel_access',{})
    command='/usr/local/x-ui/x-ui'
    if access.get('public') and access.get('scheme','https')=='https':
        configure=(command+' setting -listenIP 0.0.0.0 -port '+str(record['ports']['panel'])+
                   ' -webCert '+shlex.quote(access['cert'])+' -webCertKey '+shlex.quote(access['key']))
    else:
        listen='0.0.0.0' if access.get('public') else '127.0.0.1'
        configure=command+' cert -reset\n'+command+' setting -listenIP '+listen+' -port '+str(record['ports']['panel'])
    return 'set -e\n'+configure+'\nsystemctl restart x-ui\nsystemctl is-active --quiet x-ui'


class PublicPanelMixin:
    def apply_automatic_panel(self,record):
        candidate=copy.deepcopy(record)
        candidate['panel_access']=deployment_access(record)
        candidate['rules']=panel_rules(candidate,record.get('rules',[]))
        candidate['settings'].update(panel_public=True,panel_domain=candidate['panel_access'].get('domain',''),management_cidr='0.0.0.0/0')
        try:
            self.ssh.run(panel_configure_script(candidate),timeout=120)
            if self.tunnel:self.tunnel.close();self.tunnel=None
            time.sleep(2);self.panel(candidate).list()
            listeners=self.ssh.run('ss -H -lnt')
            if not re.search(r'(?:0\.0\.0\.0|\*|\[::\]|::):'+str(candidate['ports']['panel'])+r'\s',listeners):
                raise RuntimeError('面板未监听公网端口')
        except Exception:
            if self.tunnel:self.tunnel.close();self.tunnel=None
            self.ssh.run(panel_configure_script(record),timeout=120)
            raise
        return candidate

    def enable_automatic_panel(self):
        record=self.load_remote();self.ssh.lock();self.make_backup_connected()
        candidate=self.apply_automatic_panel(record)
        self.ssh.write_json(REMOTE_ROOT+'/rules.json',candidate['rules'])
        self.ssh.write(REMOTE_ROOT+'/firewall.py',scripts.FIREWALL_PY)
        self.log(self.ssh.run('python3 '+REMOTE_ROOT+'/firewall.py'))
        self.persist(candidate)
        self.log('公网面板入口已生成，管理面板 TCP '+str(candidate['ports']['panel'])+'；实际外部连接仍需验证。')
        return candidate

    def configure_public_panel(self,payload):
        domain=validate_public(payload,self.settings)
        self.redact.add(payload['cf_token'])
        record=self.load_remote();self.ssh.lock()
        port=payload['port']
        if port!=record['ports']['panel']:
            occupied=self.ssh.run('ss -H -lntu')
            if re.search(r':'+str(port)+r'\s',occupied) or port in [v for k,v in record['ports'].items() if k!='panel']:
                raise ValueError('公网面板端口已被使用，请换一个端口')
        # Preserve the current database, records and certificates before changing access.
        self.make_backup_connected()
        dns=Cloudflare(payload['cf_token']).ensure_address(domain,self.settings.host)
        self.ssh.write(REMOTE_ROOT+'/cloudflare-panel.env','CF_Token='+shlex.quote(payload['cf_token'])+'\n')
        base=REMOTE_ROOT+'/certs/'+domain
        if not (self.ssh.exists(base+'/fullchain.pem') and self.ssh.exists(base+'/key.pem')):
            script=scripts.certificate_script(domain,payload['email'],dns['zone_id'],credential_file='cloudflare-panel.env')
            name='panel-certificate-'+hashlib.sha256(domain.encode()).hexdigest()[:20]
            self.ssh.run('rm -f '+shlex.quote(REMOTE_ROOT+'/jobs/'+name+'.status'))
            self.ssh.job(name,script,1200)
        valid=self.ssh.run('openssl x509 -in '+shlex.quote(base+'/fullchain.pem')+' -checkend 86400 -noout >/dev/null 2>&1 && echo valid || true').strip()
        if valid!='valid':
            self.ssh.run(renew_script(domain),timeout=1200)
        self.ssh.run('openssl x509 -in '+shlex.quote(base+'/fullchain.pem')+' -checkend 86400 -noout')
        self.ssh.run('openssl x509 -in '+shlex.quote(base+'/fullchain.pem')+' -checkhost '+shlex.quote(domain)+' -noout')
        self.ssh.job('renewal-v2',scripts.ACME_TIMER)
        candidate=copy.deepcopy(record)
        candidate['ports']['panel']=port
        candidate['panel_access']={'public':True,'domain':domain,'email':payload['email'],'cert':base+'/fullchain.pem','key':base+'/key.pem'}
        candidate['rules']=panel_rules(candidate,record.get('rules',[]))
        self.ssh.run('install -d -m 700 '+REMOTE_ROOT)
        self.ssh.write_json(REMOTE_ROOT+'/rules.json',candidate['rules'])
        self.ssh.write(REMOTE_ROOT+'/firewall.py',scripts.FIREWALL_PY)
        self.log(self.ssh.run('python3 '+REMOTE_ROOT+'/firewall.py'))
        try:
            self.ssh.run(panel_configure_script(candidate),timeout=120)
            if self.tunnel:self.tunnel.close();self.tunnel=None
            time.sleep(2)
            self.panel(candidate).list()  # TLS + panel API verification over the authenticated SSH tunnel.
            listeners=self.ssh.run('ss -H -lnt')
            if not re.search(r'(?:0\.0\.0\.0|\*|\[::\]|::):'+str(port)+r'\s',listeners):
                raise RuntimeError('面板没有监听公网端口，未确认公网访问配置')
        except Exception:
            self.log('公网配置未通过检查，正在恢复原面板入口。')
            if self.tunnel:self.tunnel.close();self.tunnel=None
            self.ssh.run(panel_configure_script(record),timeout=120)
            self.ssh.write_json(REMOTE_ROOT+'/rules.json',record.get('rules',[]))
            raise
        candidate['settings'].update(panel_port=port,panel_public=True,panel_domain=domain,management_cidr='0.0.0.0/0')
        self.persist(candidate)
        self.log('服务器已配置公网 HTTPS 面板，TCP '+str(port)+'；随后验证公网入口，若服务商外部防火墙阻拦再到对应后台放行。')
        return candidate

    def disable_public_panel(self,payload):
        if payload.get('endpoint')!=self.settings.host+':'+str(self.settings.ssh_port):
            raise ValueError('目标服务器已变化，请重新选择服务器')
        record=self.load_remote();self.ssh.lock();self.make_backup_connected()
        candidate=copy.deepcopy(record);candidate['panel_access']={'public':False}
        candidate['settings'].update(panel_public=False,panel_domain='',management_cidr='')
        candidate['rules']=panel_rules(candidate,record.get('rules',[]))
        try:
            self.ssh.run(panel_configure_script(candidate),timeout=120)
            if self.tunnel:self.tunnel.close();self.tunnel=None
            time.sleep(2);self.panel(candidate).list()
        except Exception:
            if self.tunnel:self.tunnel.close();self.tunnel=None
            self.ssh.run(panel_configure_script(record),timeout=120)
            raise
        self.ssh.write_json(REMOTE_ROOT+'/rules.json',candidate['rules']);self.persist(candidate)
        self.log('面板已恢复为本机监听。公网链接停止提供面板访问；仍可通过软件的 SSH 隧道打开。')
        return candidate

    def panel_fingerprint(self,record):
        access=record['panel_access']
        der=self.ssh.run('openssl x509 -in '+shlex.quote(access['cert'])+' -outform DER | base64 -w0')
        return hashlib.sha256(base64.b64decode(der,validate=True)).hexdigest()

    def renew_public_panel_certificate(self):
        record=self.load_remote();self.ssh.lock();access=record.get('panel_access',{})
        if not access.get('public') or access.get('scheme','https')!='https':raise ValueError('IP HTTP 面板没有域名证书，无需续期')
        validate_domain(access['domain'])
        self.ssh.run(renew_script(access['domain'],access.get('credential_file','cloudflare-panel.env'),access.get('method','dns')),timeout=1200)
        self.panel(record).list()
        self.log('公网面板证书已更新，HTTPS 面板接口已验证。')
        return record


def renew_script(domain,credential_file='cloudflare-panel.env',method='dns'):
    validate_domain(domain)
    if credential_file not in ('cloudflare.env','cloudflare-panel.env'):raise ValueError('证书凭据路径无效')
    environment='' if method=='http' else 'set -a\n. /var/lib/nodepilot/'+credential_file+'\nset +a\n'
    return "bash -se <<'NP_PANEL_RENEW'\n"+environment+"/var/lib/nodepilot/acme/acme.sh --home /var/lib/nodepilot/acme --renew -d "+shlex.quote(domain)+" --ecc --force\nNP_PANEL_RENEW"
