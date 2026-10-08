import json
import shlex

q = shlex.quote

BBR = r'''
mkdir -p /var/lib/nodepilot/backups
if [ ! -e /var/lib/nodepilot/backups/bbr-original.json ]; then
python3 - <<'PY'
import json, subprocess
keys=['net.ipv4.tcp_congestion_control','net.core.default_qdisc']
d={k:subprocess.check_output(['sysctl','-n',k],text=True).strip() for k in keys}
open('/var/lib/nodepilot/backups/bbr-original.json','w').write(json.dumps(d))
PY
fi
modprobe tcp_bbr 2>/dev/null || true
if sysctl -n net.ipv4.tcp_available_congestion_control | grep -qw bbr; then
printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > /etc/sysctl.d/90-nodepilot-bbr.conf
sysctl -p /etc/sysctl.d/90-nodepilot-bbr.conf
printf 'tcp_bbr\n' > /etc/modules-load.d/nodepilot-bbr.conf
else
echo '当前内核未提供 BBR，保持原参数，继续部署'
fi
'''

def install_script(identity, ports, host, panel_access=None):
    env = {"XUI_NONINTERACTIVE": "1", "XUI_SSL_MODE": "none", "XUI_DB_TYPE": "sqlite", "XUI_ENABLE_FAIL2BAN": "false",
           "XUI_USERNAME": identity["panel_user"], "XUI_PASSWORD": identity["panel_password"],
           "XUI_WEB_BASE_PATH": identity["panel_path"].strip("/"), "XUI_PANEL_PORT": str(ports["panel"]), "XUI_SERVER_IP": host}
    exports = "\n".join("export " + k + "=" + q(v) for k, v in env.items())
    from .public_panel import panel_configure_script
    configure=panel_configure_script({'ports':ports,'panel_access':panel_access or {}})
    return f'''export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates openssl python3 sqlite3 nftables
{exports}
bash /var/lib/nodepilot/official-install.sh v3.9.0
{configure}
echo '面板安装完成'
'''

SELF_CERT = r'''
mkdir -p /var/lib/nodepilot/certs/hy2
if [ ! -s /var/lib/nodepilot/certs/hy2/fullchain.pem ]; then
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
 -keyout /var/lib/nodepilot/certs/hy2/key.pem -out /var/lib/nodepilot/certs/hy2/fullchain.pem \
 -subj '/CN=nodepilot.local' -addext 'subjectAltName=DNS:nodepilot.local' >/dev/null 2>&1
fi
chmod 600 /var/lib/nodepilot/certs/hy2/key.pem
echo '自签证书已准备，客户端将固定证书指纹'
'''

def certificate_script(domain, email, zone_id, tag="3.1.6", credential_file='cloudflare.env'):
    if credential_file not in ('cloudflare.env','cloudflare-panel.env'):raise ValueError('证书凭据文件无效')
    return f'''
mkdir -p /var/lib/nodepilot/certs/{q(domain)} /var/lib/nodepilot/acme
if [ ! -x /var/lib/nodepilot/acme/acme.sh ]; then
curl -fL --retry 3 https://github.com/acmesh-official/acme.sh/archive/refs/tags/{tag}.tar.gz -o /var/lib/nodepilot/acme-source.tar.gz
mkdir -p /var/lib/nodepilot/acme-source
tar -xzf /var/lib/nodepilot/acme-source.tar.gz -C /var/lib/nodepilot/acme-source --strip-components=1
cd /var/lib/nodepilot/acme-source
./acme.sh --install --home /var/lib/nodepilot/acme --accountemail {q(email)} --nocron
fi
set -a
. /var/lib/nodepilot/{credential_file}
set +a
export CF_Zone_ID={q(zone_id)}
ACME=/var/lib/nodepilot/acme/acme.sh
rc=0
"$ACME" --home /var/lib/nodepilot/acme --issue --server letsencrypt --dns dns_cf -d {q(domain)} --keylength ec-256 || rc=$?
[ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]
"$ACME" --home /var/lib/nodepilot/acme --install-cert -d {q(domain)} --ecc \
 --key-file /var/lib/nodepilot/certs/{q(domain)}/key.pem \
 --fullchain-file /var/lib/nodepilot/certs/{q(domain)}/fullchain.pem \
 --reloadcmd 'systemctl restart x-ui'
chmod 600 /var/lib/nodepilot/certs/{q(domain)}/key.pem
echo '域名证书已安装'
'''


def http_certificate_script(domain,tag='3.1.6'):
    from .models import validate_domain
    validate_domain(domain)
    return f'''set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq socat
mkdir -p /var/lib/nodepilot/certs/{q(domain)} /var/lib/nodepilot/acme
if [ ! -x /var/lib/nodepilot/acme/acme.sh ]; then
curl -fL --retry 3 https://github.com/acmesh-official/acme.sh/archive/refs/tags/{tag}.tar.gz -o /var/lib/nodepilot/acme-source.tar.gz
mkdir -p /var/lib/nodepilot/acme-source
tar -xzf /var/lib/nodepilot/acme-source.tar.gz -C /var/lib/nodepilot/acme-source --strip-components=1
cd /var/lib/nodepilot/acme-source
./acme.sh --install --home /var/lib/nodepilot/acme --nocron
fi
ACME=/var/lib/nodepilot/acme/acme.sh
rc=0
"$ACME" --home /var/lib/nodepilot/acme --issue --server letsencrypt --standalone -d {q(domain)} --keylength ec-256 --force || rc=$?
[ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]
"$ACME" --home /var/lib/nodepilot/acme --install-cert -d {q(domain)} --ecc \\
 --key-file /var/lib/nodepilot/certs/{q(domain)}/key.pem \\
 --fullchain-file /var/lib/nodepilot/certs/{q(domain)}/fullchain.pem \\
 --reloadcmd 'systemctl restart x-ui'
chmod 600 /var/lib/nodepilot/certs/{q(domain)}/key.pem
openssl x509 -in /var/lib/nodepilot/certs/{q(domain)}/fullchain.pem -checkend 86400 -checkhost {q(domain)} -noout
echo '域名证书已通过 TCP 80 验证并安装'
'''

RENEW_CERTIFICATES = r'''import json,re,shlex,subprocess
from pathlib import Path
root=Path('/var/lib/nodepilot')
record=json.loads((root/'deployment.json').read_text())
pairs={}
cert=record.get('certificate',{})
if cert and not cert.get('selfsigned'):pairs[cert['domain']]=None if cert.get('method')=='http' else 'cloudflare.env'
access=record.get('panel_access',{})
if access.get('public') and access.get('scheme','https')=='https':pairs[access['domain']]=None if access.get('method')=='http' else access.get('credential_file','cloudflare-panel.env')
failed=False
for domain,credential in pairs.items():
 if not re.fullmatch(r'[a-zA-Z0-9.-]+',domain):raise ValueError('Invalid certificate domain')
 if credential not in (None,'cloudflare.env','cloudflare-panel.env'):raise ValueError('Invalid credential file')
 environment='' if credential is None else 'set -a\n. '+shlex.quote(str(root/credential))+'\nset +a\n'
 command=environment+shlex.quote(str(root/'acme/acme.sh'))+' --home '+shlex.quote(str(root/'acme'))+' --renew -d '+shlex.quote(domain)+' --ecc'
 result=subprocess.run(['bash','-se'],input=command,text=True)
 # acme.sh returns 2 when the certificate does not yet need renewal.
 if result.returncode not in (0,2):failed=True
raise SystemExit(1 if failed else 0)
'''

ACME_TIMER = '''cat > /var/lib/nodepilot/renew-certificates.py <<'NP_RENEW'
'''+RENEW_CERTIFICATES+'''NP_RENEW
chmod 700 /var/lib/nodepilot/renew-certificates.py
cat > /etc/systemd/system/nodepilot-cert-renew.service <<'EOF'
[Unit]
Description=NodePilot certificate renewal
[Service]
Type=oneshot
UMask=0077
ExecStart=/usr/bin/python3 /var/lib/nodepilot/renew-certificates.py
EOF
cat > /etc/systemd/system/nodepilot-cert-renew.timer <<'EOF'
[Unit]
Description=Daily NodePilot certificate renewal
[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now nodepilot-cert-renew.timer
'''

# Detect the existing manager. Never flush an existing firewall or change its default policy.
FIREWALL = r'''
python3 /var/lib/nodepilot/firewall.py
'''

FIREWALL_PY = r'''
import json, subprocess, pathlib, ipaddress, shutil
root=pathlib.Path('/var/lib/nodepilot')
rules=json.loads((root/'rules.json').read_text())
run=lambda args:subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
changes=[]
ufw=shutil.which('ufw')
if ufw and 'Status: active' in run([ufw,'status']).stdout:
    for r in rules:
        args=[ufw,'allow','from',r['source'],'to','any','port',str(r['port']),'proto',r['protocol'].lower(),'comment','NodePilot']
        value=run(args)
        if value.returncode: raise RuntimeError(value.stderr)
        changes.append({'manager':'ufw','rule':r})
    status='UFW 已按实际端口配置'
else:
    nft=shutil.which('nft')
    current=run([nft,'-j','list','ruleset'])
    if current.returncode: raise RuntimeError(current.stderr)
    data=json.loads(current.stdout)
    chains=[x['chain'] for x in data.get('nftables',[]) if 'chain' in x and x['chain'].get('hook')=='input' and x['chain'].get('type')=='filter']
    external=[c for c in chains if c['table']!='nodepilot']
    if external:
        status='检测到已有 nftables 输入规则；保留原规则。请按生成的放行清单配置现有防火墙后重新测试'
    else:
        lines=['table inet nodepilot {',' chain input {',' type filter hook input priority 0; policy accept;']
        for r in rules:
            net=ipaddress.ip_network(r['source'],strict=False)
            source=('ip saddr ' if net.version==4 else 'ip6 saddr ')+str(net)+' ' if net.prefixlen else ''
            lines.append(f'  {source}{r["protocol"].lower()} dport {r["port"]} counter accept comment "NodePilot"')
            if net.prefixlen:
                lines.append(f'  {r["protocol"].lower()} dport {r["port"]} counter reject comment "NodePilot restricted management"')
            changes.append({'manager':'nftables','rule':r})
        lines.extend([' }','}'])
        content='\n'.join(lines)+'\n'
        path=pathlib.Path('/etc/nodepilot-firewall.nft')
        path.write_text(content)
        check=run([nft,'-c','-f',str(path)])
        # An existing own table is replaced atomically by the boot helper.
        helper=pathlib.Path('/var/lib/nodepilot/apply-firewall.sh')
        helper.write_text('#!/bin/bash\nset -e\n/usr/sbin/nft list table inet nodepilot >/dev/null 2>&1 && /usr/sbin/nft delete table inet nodepilot || true\n/usr/sbin/nft -f /etc/nodepilot-firewall.nft\n')
        helper.chmod(0o700)
        if run([nft,'list','table','inet','nodepilot']).returncode and check.returncode: raise RuntimeError(check.stderr)
        value=run(['bash',str(helper)])
        if value.returncode: raise RuntimeError(value.stderr)
        unit='[Unit]\nDescription=NodePilot managed firewall rules\nAfter=nftables.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/var/lib/nodepilot/apply-firewall.sh\n[Install]\nWantedBy=multi-user.target\n'
        pathlib.Path('/etc/systemd/system/nodepilot-firewall.service').write_text(unit)
        run(['systemctl','daemon-reload'])
        run(['systemctl','enable','nodepilot-firewall.service'])
        status='本机为允许策略；已记录所需端口并配置开机加载'
(root/'firewall-result.json').write_text(json.dumps({'status':status,'changes':changes},ensure_ascii=False))
print(status)
'''
