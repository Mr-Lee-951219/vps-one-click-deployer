"""Install the pinned byJoey standard kernel; never purge or reboot implicitly."""
import json
import re
import shlex
from pathlib import Path

MANIFEST = json.loads((Path(__file__).resolve().parent.parent/'assets'/'bbrv3-release.json').read_text(encoding='utf-8'))

def install_script():
    asset=MANIFEST['asset'];kernel=MANIFEST['kernel']
    if not re.fullmatch(r'[0-9.]+-joeyblog-bbrv3',kernel) or not re.fullmatch(r'[a-f0-9]{64}',asset['sha256']):
        raise ValueError('BBRv3 发布校验信息不正确')
    q=shlex.quote
    return f'''
export DEBIAN_FRONTEND=noninteractive
test "$(id -u)" = 0
. /etc/os-release
if [ "$ID" != debian ] || [ "$VERSION_ID" != 12 ] || [ "$(uname -m)" != x86_64 ]; then echo '需要 Debian 12 x86_64'; exit 1; fi
kind=$(systemd-detect-virt --container 2>/dev/null || true)
if [ -n "$kind" ] && [ "$kind" != none ]; then echo '容器无法更换宿主内核，未安装 BBRv3'; exit 1; fi
test -s /boot/grub/grub.cfg && command -v update-grub >/dev/null || {{ echo '需要可用的 GRUB 引导配置'; exit 1; }}
if [ -d /sys/firmware/efi ]; then
    command -v mokutil >/dev/null || {{ echo 'UEFI 环境请先安装 mokutil 并确认 Secure Boot 状态'; exit 1; }}
    secure_boot=$(mokutil --sb-state 2>/dev/null) || {{ echo '无法确认 Secure Boot 状态'; exit 1; }}
    printf '%s' "$secure_boot" | grep -qi 'SecureBoot disabled' || {{ echo 'Secure Boot 未确认关闭，未安装第三方内核'; exit 1; }}
fi
test "$(df -Pk /boot | awk 'NR==2 {{print $4}}')" -gt 409600 || {{ echo '/boot 至少需要 400MB 可用空间'; exit 1; }}
test "$(df -Pk / | awk 'NR==2 {{print $4}}')" -gt 2097152 || {{ echo '至少需要 2GB 可用磁盘'; exit 1; }}
test -s "/boot/vmlinuz-$(uname -r)" || {{ echo '找不到当前内核的启动文件，未安装新内核'; exit 1; }}
install -d -m 700 /var/lib/nodepilot/backups/bbrv3 /var/lib/nodepilot/bbrv3
if [ ! -e /var/lib/nodepilot/backups/bbrv3/original-kernel ]; then
    uname -r > /var/lib/nodepilot/backups/bbrv3/original-kernel
    cp -a /etc/default/grub /var/lib/nodepilot/backups/bbrv3/grub-default
    cp -a /boot/grub/grub.cfg /var/lib/nodepilot/backups/bbrv3/grub.cfg
fi
if [ ! -e /var/lib/nodepilot/backups/bbr-original.json ]; then
python3 - <<'PY'
import json,subprocess
keys=['net.ipv4.tcp_congestion_control','net.core.default_qdisc']
data={{k:subprocess.check_output(['sysctl','-n',k],text=True).strip() for k in keys}}
open('/var/lib/nodepilot/backups/bbr-original.json','w').write(json.dumps(data))
PY
fi
if ! dpkg-query -W -f='${{Status}}' {q('linux-image-'+kernel)} 2>/dev/null | grep -q 'install ok installed'; then
    apt-get update -qq
    apt-get install -y curl ca-certificates initramfs-tools kmod
    cd /var/lib/nodepilot/bbrv3
    echo '下载 byJoey BBRv3 标准内核：{kernel}'
    curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 20 --max-time 1800 {q(asset['url'])} -o {q(asset['name']+'.part')}
    printf '%s  %s\\n' {q(asset['sha256'])} {q(asset['name']+'.part')} | sha256sum -c -
    mv -- {q(asset['name']+'.part')} {q(asset['name'])}
    apt-get install -y {q('./'+asset['name'])}
fi
test -s {q('/boot/vmlinuz-'+kernel)}
test -s {q('/boot/initrd.img-'+kernel)}
test "$(modinfo -k {q(kernel)} -F version tcp_bbr)" = 3 || {{ echo '新内核 BBR 模块未确认 v3'; exit 1; }}
update-grub
grep -Fq {q(kernel)} /boot/grub/grub.cfg || {{ echo 'GRUB 未找到新内核启动项'; exit 1; }}
printf 'net.core.default_qdisc=fq\\nnet.ipv4.tcp_congestion_control=bbr\\n' > /etc/sysctl.d/90-nodepilot-bbr.conf
printf 'tcp_bbr\\n' > /etc/modules-load.d/nodepilot-bbr.conf
if [ "$(uname -r)" = {q(kernel)} ]; then modprobe tcp_bbr; sysctl -p /etc/sysctl.d/90-nodepilot-bbr.conf; fi
echo 'BBRv3 标准内核已安装，旧内核保留。软件将核对运行内核，确定是否需要重启。'
'''

def status_command():
    source=(Path(__file__).resolve().parent.parent/'assets'/'bbr-probe.py').read_text(encoding='utf-8')
    return "python3 - <<'PY'\n"+source+'\nPY'

def describe_status(status):
    result=dict(status)
    result['target_kernel']=MANIFEST['kernel']
    result['project']=MANIFEST['project']
    version=result.get('module_version','')
    if version in ('1','2','3'):
        result['bbr_version']=version
        result['version_evidence']='运行模块版本信息' if result.get('module_version_source')=='loaded' else '当前内核 tcp_bbr 模块版本信息'
    elif not version and result.get('native_verified'):
        result['bbr_version']='1'
        result['version_evidence']='Debian 12 官方 6.1 内核；内核与 BBR 模块文件和安装包校验一致'
    else:
        result['bbr_version']=''
        result['version_evidence']='缺少可靠版本信息，无法确认；不会按内核名称猜测'
    result['active']=(result.get('kernel')==MANIFEST['kernel'] and result.get('module_version')=='3' and result.get('algorithm')=='bbr')
    result['fq_verified']=result.get('actual_qdisc')=='fq'
    result['reboot_required']=result.get('kernel')!=MANIFEST['kernel']
    return result
