"""One-off read-only speed diagnosis. SSH password is read from stdin, never saved."""
import base64
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import paramiko
import requests

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from deployer.models import Settings
from deployer.panel import client_config

parser=argparse.ArgumentParser(description='Read-only VPS speed diagnosis')
parser.add_argument('--host',required=True)
parser.add_argument('--ssh-port',required=True,type=int)
args=parser.parse_args()
HOST=args.host
PORT=args.ssh_port
MAX_BYTES=4*1024*1024
URLS=[('Cloudflare','https://speed.cloudflare.com/__down?bytes=4194304'),
      ('OVH','https://proof.ovh.net/files/10Mb.dat')]
REPORT=ROOT/'test-artifacts'/'vps-speed-diagnosis.json'
REPORT.parent.mkdir(parents=True,exist_ok=True)

REMOTE=r'''import json,os,platform,sqlite3,subprocess,time,shutil
from pathlib import Path
def command(args):
 try:
  result=subprocess.run(args,capture_output=True,text=True,timeout=12)
  return {'code':result.returncode,'output':result.stdout.strip()[:16000]}
 except Exception as e:return {'error':type(e).__name__}
def cpus():return [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
def net():
 result={}
 for p in Path('/sys/class/net').iterdir():
  if p.name=='lo':continue
  result[p.name]={}
  for key in ('rx_bytes','tx_bytes','rx_errors','tx_errors','rx_dropped','tx_dropped'):
   try:result[p.name][key]=int((p/'statistics'/key).read_text())
   except OSError:pass
 return result
a=cpus();na=net();time.sleep(2);b=cpus();nb=net();delta=[y-x for x,y in zip(a,b)];total=sum(delta[:8]) or 1
mem={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())}
disk=shutil.disk_usage('/')
out={'os':Path('/etc/os-release').read_text(),'kernel':platform.release(),'cpu_count':os.cpu_count(),'load':os.getloadavg(),
 'cpu_busy_percent':round(100*(1-(delta[3]+delta[4])/total),2),'cpu_steal_percent':round(100*delta[7]/total,2),
 'memory_total':mem['MemTotal'],'memory_available':mem['MemAvailable'],'swap_used':mem['SwapTotal']-mem['SwapFree'],
 'disk_free':disk.free,'uptime_seconds':int(float(Path('/proc/uptime').read_text().split()[0])),
 'network_totals':nb,'network_two_second_delta':{n:{k:nb[n][k]-v for k,v in fields.items()} for n,fields in na.items() if n in nb},
 'service':command(['systemctl','is-active','x-ui']),
 'core_version':command(['/usr/local/x-ui/bin/xray-linux-amd64','version']),
 'process_load':command(['ps','-C','x-ui,xray-linux-amd64','-o','comm=,pcpu=,pmem=']),
 'tcp_settings':command(['sysctl','net.ipv4.tcp_congestion_control','net.core.default_qdisc','net.ipv4.tcp_available_congestion_control']),
 'qdisc':command(['tc','-s','-j','qdisc','show']),
 'tcp_summary':command(['ss','-s']),
 'net_errors':command(['nstat','-az','TcpRetransSegs','TcpOutSegs','TcpExtTCPSynRetrans','TcpExtTCPTimeouts'])}
try:
 db=sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro',uri=True)
 settings=dict(db.execute('SELECT key,value FROM settings WHERE key IN ("webListen","webPort","webCertFile","webBasePath","subEnable")'))
 settings.pop('webBasePath',None)
 nodes=[]
 for row in db.execute('SELECT id,enable,port,protocol,remark,settings,stream_settings FROM inbounds'):
  identity,enabled,port,protocol,remark,clients,stream=row
  c=json.loads(clients or '{}');st=json.loads(stream or '{}')
  nodes.append({'id':identity,'enabled':bool(enabled),'port':port,'protocol':protocol,'remark':remark,
   'network':st.get('network'),'security':st.get('security'),
   'client_flows':sorted({u.get('flow','') for u in c.get('clients',[])}),
   'total_client_quota_bytes':sum(u.get('totalGB',0) for u in c.get('clients',[])),
   'reality_sni':st.get('realitySettings',{}).get('serverNames',[]),
   'reality_target':st.get('realitySettings',{}).get('target',st.get('realitySettings',{}).get('dest','')),
   'quic':st.get('finalmask',{}).get('quicParams',{})})
 out.update(panel_settings=settings,nodes=nodes);db.close()
except Exception as e:out['db_error']=str(e)
print(json.dumps(out))
'''

REMOTE_SPEED=r'''import json,time,urllib.request
urls=__URLS__
results=[]
for name,url in urls:
 started=time.monotonic();count=0;first=None
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'NodePilot-readonly-diagnostic','Range':'bytes=0-4194303'})
  with urllib.request.urlopen(req,timeout=18) as response:
   status=response.status
   while count<4194304:
    part=response.read(min(65536,4194304-count))
    if not part:break
    if first is None:first=time.monotonic()-started
    count+=len(part)
    if time.monotonic()-started>25:break
  elapsed=time.monotonic()-started
  results.append({'source':name,'bytes':count,'seconds':round(elapsed,3),'first_byte_seconds':round(first or 0,3),'Mbps':round(count*8/elapsed/1e6,2),'status':status})
 except Exception as e:results.append({'source':name,'bytes':count,'error':type(e).__name__+': '+str(e)[:180]})
print(json.dumps(results))
'''


def download(name,url,proxy=None):
    started=time.monotonic();count=0;first=None
    session=requests.Session();session.trust_env=False
    try:
        with session.get(url,headers={'Range':'bytes=0-4194303'},proxies={'http':proxy,'https':proxy} if proxy else None,stream=True,timeout=(12,18)) as response:
            response.raise_for_status()
            for part in response.iter_content(65536):
                if first is None:first=time.monotonic()-started
                count+=len(part)
                if count>=MAX_BYTES or time.monotonic()-started>25:break
        elapsed=time.monotonic()-started
        return {'source':name,'bytes':count,'seconds':round(elapsed,3),'first_byte_seconds':round(first or 0,3),'Mbps':round(count*8/elapsed/1e6,2),'status':response.status_code}
    except Exception as e:
        return {'source':name,'bytes':count,'error':type(e).__name__+': '+str(e)[:180]}
    finally:session.close()


def remote_run(client,code,timeout=60):
    _,out,err=client.exec_command("python3 - <<'NP_READ_ONLY'\n"+code+"\nNP_READ_ONLY",timeout=timeout)
    value=out.read().decode('utf-8','replace');errors=err.read().decode('utf-8','replace')
    if out.channel.recv_exit_status()!=0:raise RuntimeError(errors[:1000])
    return json.loads(value)


def print_report(report):
    REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2),flush=True)


def main():
    print('Waiting for SSH password via standard input; it will not be stored.',flush=True)
    password=os.environ.pop('NODEPILOT_INSPECT_PASSWORD','') or sys.stdin.readline().rstrip('\r\n')
    if not password:raise ValueError('No password supplied')
    report={'host':HOST,'ssh_port':PORT,'read_only':True,'transfer_limit_per_request_bytes':MAX_BYTES}
    client=paramiko.SSHClient()
    known=Path(os.environ.get('LOCALAPPDATA',''))/'NodePilot'/'known_hosts'
    if known.is_file():client.load_host_keys(str(known))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        begin=time.monotonic()
        client.connect(HOST,port=PORT,username='root',password=password,timeout=18,banner_timeout=18,auth_timeout=18,allow_agent=False,look_for_keys=False)
        password=''
        client.get_transport().set_keepalive(15)
        report['ssh_connect_seconds']=round(time.monotonic()-begin,3)
        print('SSH authentication succeeded. Inspecting server, no configuration writes.',flush=True)
        report['server']=remote_run(client,REMOTE)
        probe=(ROOT/'assets/bbr-probe.py').read_text(encoding='utf-8')
        report['bbr']=remote_run(client,probe)
        print_report(report)
        sftp=client.open_sftp()
        try:
            with sftp.file('/var/lib/nodepilot/deployment.json','rb') as f:record=json.loads(f.read())
        finally:sftp.close()
        report['deployment']={'ports':record.get('ports'),'stage':record.get('stage'),
                             'vless':record['settings'].get('vless'),'hy2':record['settings'].get('hy2'),
                             'bbr_mode':record['settings'].get('bbr_mode'),'panel_scheme':record.get('panel_access',{}).get('scheme','legacy')}
        print('Running bounded 4 MiB downloads; comparing local, VPS, and actual node paths.',flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            future=pool.submit(remote_run,client,REMOTE_SPEED.replace('__URLS__',repr(URLS)),70)
            report['local_direct_downloads']=[download(name,url) for name,url in URLS]
            report['vps_direct_downloads']=future.result()
        core=ROOT/'assets/core/xray.exe';provenance=json.loads((core.parent/'provenance.json').read_text())
        if hashlib.sha256(core.read_bytes()).hexdigest()!=provenance['xray_sha256']:raise RuntimeError('Core integrity check failed')
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));local_port=listener.getsockname()[1]
        settings=Settings(**record['settings']);settings.host=HOST
        with tempfile.TemporaryDirectory(prefix='np-readonly-speed-',dir=ROOT/'test-artifacts') as directory:
            cfg=Path(directory)/'client.json';cfg.write_text(json.dumps(client_config(settings,record['ports'],record['identity'],record.get('certificate'),'VLESS',local_port)),encoding='utf-8')
            with (Path(directory)/'core.log').open('wb') as stream:
                process=subprocess.Popen([str(core),'run','-c',str(cfg)],stdout=stream,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                try:
                    time.sleep(1)
                    if process.poll() is not None:raise RuntimeError('Diagnostic client failed to start; logs withheld to protect credentials')
                    proxy='socks5h://127.0.0.1:'+str(local_port)
                    session=requests.Session();session.trust_env=False
                    try:
                        response=session.get('https://www.cloudflare.com/cdn-cgi/trace',proxies={'https':proxy},timeout=18)
                        response.raise_for_status();lines=dict(line.split('=',1) for line in response.text.splitlines() if '=' in line)
                        report['node_exit_matches_vps']=lines.get('ip')==HOST
                    except Exception as ex:report['node_trace_error']=type(ex).__name__+': '+str(ex)[:160]
                    finally:session.close()
                    report['node_downloads']=[download(name,url,proxy) for name,url in URLS]
                    report['connections_during_test']=remote_run(client,"import json,subprocess\np=subprocess.run(['ss','-tinH','sport = :"+str(record['ports']['vless'])+"'],capture_output=True,text=True);lines=p.stdout.splitlines();print(json.dumps([line.strip()[:2000] for line in lines if 'bytes_sent:' in line or 'bbr' in line]))")
                finally:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        report['complete']=True
        print_report(report)
    except Exception as e:
        report['error']=type(e).__name__+': '+str(e)[:1000];print_report(report);raise
    finally:client.close()


if __name__=='__main__':main()
