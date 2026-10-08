"""Install only the SSH security dependencies, with an isolated Debian 12 fallback."""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime,timezone
from pathlib import Path

PACKAGES=['fail2ban','nftables','python3-systemd']
KEYRING=Path('/usr/share/keyrings/debian-archive-keyring.gpg')
APT=['apt-get','-o','APT::Update::Error-Mode=any','-o','Acquire::Retries=1',
     '-o','Acquire::http::Timeout=20','-o','Acquire::https::Timeout=20',
     '-o','Acquire::Check-Valid-Until=true','-o','Acquire::Check-Date=true',
     '-o','Acquire::AllowInsecureRepositories=false','-o','Acquire::AllowDowngradeToInsecureRepositories=false',
     '-o','APT::Get::AllowUnauthenticated=false']
OFFICIAL='''Types: deb
URIs: https://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://security.debian.org/debian-security
Suites: bookworm-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
'''


def command(args,timeout):
    env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',LC_ALL='C')
    try:
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                              text=True,timeout=timeout,env=env)
        return result.returncode,result.stdout
    except subprocess.TimeoutExpired:
        return 124,'软件源或安装操作超时。'
    except OSError as error:
        return 127,str(error)


def ready():
    return bool(shutil.which('fail2ban-client') and shutil.which('nft') and
                command([sys.executable,'-c','import systemd.journal'],20)[0]==0)


def show_clock(reference=None):
    now=time.time()
    print('服务器 UTC 时间：'+datetime.fromtimestamp(now,timezone.utc).isoformat(timespec='seconds'),flush=True)
    if reference is not None and abs(now-reference)>600:
        print('提醒：服务器与电脑时钟相差超过 10 分钟，请核对时间；软件不会自动修改系统时钟。',flush=True)
    code,status=command(['timedatectl','show','-p','NTPSynchronized'],10)
    if code==0:print('时间同步状态：'+status.strip(),flush=True)


def install(run=command,check=ready,temp_parent='/var/tmp'):
    if check():
        print('防护组件已安装，跳过软件源刷新。',flush=True)
        return
    print('正在刷新服务器原软件源，保留签名与有效期检查。',flush=True)
    code,output=run(APT+['update','-qq'],180)
    print(output[-16000:],flush=True)
    if code==0:
        selected=APT
        code,output=run(selected+['install','-y','-qq','--no-install-recommends']+PACKAGES,600)
        print(output[-16000:],flush=True)
        if code!=0:raise RuntimeError('防护组件安装失败，请检查磁盘、软件包锁或安装日志。')
    else:
        print('原软件源刷新失败。改用临时 Debian 12 官方源安装防护组件，服务器原软件源配置保持。',flush=True)
        if not KEYRING.is_file():raise RuntimeError('缺少 Debian 官方签名密钥环，无法使用官方源，请检查 debian-archive-keyring。')
        with tempfile.TemporaryDirectory(prefix='nodepilot-security-apt-',dir=temp_parent) as folder:
            root=Path(folder);root.chmod(0o755)
            source=root/'debian.sources';source.write_text(OFFICIAL,encoding='utf-8');source.chmod(0o644)
            lists=root/'lists';lists.mkdir(mode=0o755)
            selected=APT+['-o','Dir::Etc::sourcelist='+str(source),'-o','Dir::Etc::sourceparts=-',
                          '-o','Dir::State::lists='+str(lists),'-o','Acquire::Check-Valid-Until=true',
                          '-o','Acquire::Check-Date=true']
            code,output=run(selected+['update','-qq'],180)
            print(output[-16000:],flush=True)
            if code!=0:
                raise RuntimeError('官方源也未通过更新检查。请核对服务器时间、DNS 和 HTTPS 网络；没有跳过软件源有效期或签名检查。')
            code,output=run(selected+['install','-y','-qq','--no-install-recommends']+PACKAGES,600)
            print(output[-16000:],flush=True)
            if code!=0:raise RuntimeError('官方源可用，但防护组件安装失败，请检查磁盘、软件包锁或安装日志。')
    if not check():raise RuntimeError('安装结束，但防护组件未通过回读检查，请查看安装日志。')
    print('防护组件已安装并通过回读检查。',flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--reference-utc',type=float)
    args=parser.parse_args();show_clock(args.reference_utc)
    try:install()
    except Exception as error:
        print(str(error),flush=True);return 1
    return 0


if __name__=='__main__':sys.exit(main())
