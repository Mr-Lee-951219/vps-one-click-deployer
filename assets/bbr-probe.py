"""Read the running kernel and verify Debian's packaged BBR files; no mutations."""
import hashlib
import json
import platform
import re
import subprocess
from pathlib import Path


def value(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def packaged_file_matches(package, filename):
    try:
        # dpkg may record /lib while usrmerge resolves it to /usr/lib.
        sums = Path('/var/lib/dpkg/info') / (package + '.md5sums')
        if not sums.exists():sums = sums.with_name(package.split(':')[0] + '.md5sums')
        target = Path(filename).resolve()
        for line in sums.read_text().splitlines():
            digest, relative = line.split(None, 1)
            if (Path('/') / relative.lstrip('*')).resolve() == target:
                with target.open('rb') as stream:
                    return hashlib.file_digest(stream, 'md5').hexdigest() == digest
    except (OSError, ValueError):
        pass
    return False


def collect():
    kernel = platform.release()
    module_path = value(['modinfo', '-k', kernel, '-F', 'filename', 'tcp_bbr'])
    disk_version = value(['modinfo', '-k', kernel, '-F', 'version', 'tcp_bbr'])
    try:loaded_version = Path('/sys/module/tcp_bbr/version').read_text().strip()
    except OSError:loaded_version = ''
    package = 'linux-image-' + kernel
    metadata = value(['dpkg-query', '-W', '-f=${Status}\n${source:Package}\n${Maintainer}\n${Version}', package]).splitlines()
    try:os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    except OSError:os_release = {}
    native = (os_release.get('ID', '').strip('"') == 'debian' and os_release.get('VERSION_ID', '').strip('"') == '12'
              and bool(re.fullmatch(r'6\.1\.0-[0-9]+-amd64', kernel)) and len(metadata) == 4
              and metadata[0] == 'install ok installed' and metadata[1] in ('linux', 'linux-signed-amd64')
              and 'Debian Kernel Team' in metadata[2] and metadata[3].startswith('6.1.'))
    native_verified = bool(native and module_path.startswith('/') and
                           packaged_file_matches(package, module_path) and
                           packaged_file_matches(package, '/boot/vmlinuz-' + kernel))
    try:
        routes = json.loads(value(['ip', '-j', 'route', 'get', '1.1.1.1']) or '[]')
        device = routes[0].get('dev', '') if routes else ''
        queues = json.loads(value(['tc', '-j', 'qdisc', 'show', 'dev', device]) or '[]') if device else []
        roots = [x.get('kind', '') for x in queues if x.get('root') or x.get('parent') == 'root']
        leaves = [x.get('kind', '') for x in queues if x.get('kind') not in ('mq', 'noqueue')]
        actual = ', '.join(dict.fromkeys(leaves if roots == ['mq'] else roots))
    except (ValueError, TypeError, IndexError):
        device, actual, queues = '', '', []
    return {'kernel': kernel, 'module_version': loaded_version or disk_version,
            'module_version_source': 'loaded' if loaded_version else 'modinfo',
            'algorithm': value(['sysctl', '-n', 'net.ipv4.tcp_congestion_control']),
            'qdisc': value(['sysctl', '-n', 'net.core.default_qdisc']),
            'interface': device, 'actual_qdisc': actual, 'qdiscs': queues,
            'native_verified': native_verified, 'kernel_package': package if native else '',
            'package_version': metadata[3] if native else ''}


if __name__ == '__main__':
    print(json.dumps(collect()))
