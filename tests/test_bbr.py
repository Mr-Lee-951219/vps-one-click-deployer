from deployer import bbr


def test_native_bbr_requires_verified_running_debian_files():
    from deployer.maintenance import bbr_label
    raw={'kernel':'6.1.0-35-amd64','module_version':'','algorithm':'bbr','qdisc':'fq','native_verified':True}
    result=bbr.describe_status(raw)
    assert result['bbr_version']=='1' and 'BBRv1' in bbr_label(result) and not result['active']
    assert '校验一致' in result['version_evidence']
    raw['native_verified']=False
    assert not bbr.describe_status(raw)['bbr_version']
    raw.update(module_version='3',native_verified=True)
    assert bbr.describe_status(raw)['bbr_version']=='3'  # Actual module takes precedence.


def test_native_probe_checks_running_package_and_both_files(monkeypatch):
    import runpy
    from pathlib import Path
    probe=runpy.run_path('assets/bbr-probe.py',run_name='probe')
    collect=probe['collect'];g=collect.__globals__;files=[]
    monkeypatch.setattr(g['platform'],'release',lambda:'6.1.0-35-amd64')
    read=Path.read_text
    def text(path,*args,**kwargs):
        if path.as_posix()=='/etc/os-release':return 'ID=debian\nVERSION_ID="12"\n'
        if path.as_posix()=='/sys/module/tcp_bbr/version':raise FileNotFoundError()
        return read(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',text)
    def value(args):
        if args[0]=='dpkg-query':return 'install ok installed\nlinux-signed-amd64\nDebian Kernel Team <debian-kernel@lists.debian.org>\n6.1.137+1'
        if args[0]=='modinfo':return '/lib/modules/6.1.0-35-amd64/kernel/net/ipv4/tcp_bbr.ko' if 'filename' in args else ''
        return 'bbr' if 'net.ipv4.tcp_congestion_control' in args else 'fq'
    monkeypatch.setitem(g,'value',value)
    monkeypatch.setitem(g,'packaged_file_matches',lambda package,path:files.append(path) or True)
    assert collect()['native_verified'] and len(files)==2
    monkeypatch.setitem(g,'packaged_file_matches',lambda *args:False)
    assert not collect()['native_verified']
    monkeypatch.setattr(g['platform'],'release',lambda:'6.1.0-35-custom')
    assert not collect()['native_verified']


def test_probe_checksum_detects_modified_module(monkeypatch):
    import runpy,hashlib,uuid
    from pathlib import Path
    probe=runpy.run_path('assets/bbr-probe.py',run_name='probe')
    tmp_path=Path('test-artifacts')/('bbr-checksum-'+uuid.uuid4().hex);tmp_path.mkdir(parents=True)
    module=tmp_path.resolve()/'tcp_bbr.ko';module.write_bytes(b'official-module')
    expected=hashlib.md5(module.read_bytes()).hexdigest()+'  '+str(module).replace('\\','/')
    # The lookup helper supports real Debian paths; intercept only package metadata.
    original_read=Path.read_text;original_exists=Path.exists
    monkeypatch.setattr(Path,'read_text',lambda p,*a,**k:expected if p.suffix=='.md5sums' else original_read(p,*a,**k))
    monkeypatch.setattr(Path,'exists',lambda p:True if p.suffix=='.md5sums' else original_exists(p))
    assert probe['packaged_file_matches']('linux-image-test',str(module))
    module.write_bytes(b'custom-module')
    assert not probe['packaged_file_matches']('linux-image-test',str(module))

def test_bbrv3_status_never_mistakes_native_bbr_or_pending_kernel_for_active():
    value={'kernel':'6.1.0-42-amd64','module_version':'','algorithm':'bbr','qdisc':'fq'}
    assert not bbr.describe_status(value)['active']
    assert bbr.describe_status(value)['reboot_required']
    value['kernel']=bbr.MANIFEST['kernel'];value['module_version']='3'
    assert bbr.describe_status(value)['active']
    for key in ('module_version','algorithm'):
        wrong=dict(value);wrong[key]='unexpected'
        assert not bbr.describe_status(wrong)['active']
    value.update(qdisc='fq',actual_qdisc='fq_codel')
    assert bbr.describe_status(value)['active'] and not bbr.describe_status(value)['fq_verified']

def test_pinned_kernel_install_keeps_boot_recovery_and_checks_package():
    script=bbr.install_script();asset=bbr.MANIFEST['asset']
    assert asset['sha256'] in script and asset['url'] in script and 'sha256sum -c' in script
    assert '/backups/bbrv3/original-kernel' in script and 'update-grub' in script
    assert "modinfo -k" in script and 'SecureBoot disabled' in script
    assert 'systemd-detect-virt --container' in script
    assert 'apt-get remove' not in script and 'purge' not in script and 'systemctl reboot' not in script
    assert 'linux-libc-dev' not in script and '/tmp/linux-' not in script

def test_verify_bbr_saves_measured_state_instead_of_claiming_install_success(monkeypatch):
    import json
    from deployer.engine import Engine
    from deployer.models import Settings
    import deployer.engine as module
    monkeypatch.setattr(module,'save_secret',lambda *args:None)
    e=Engine(Settings());record={'identity':{},'settings':{},'ports':{},'bbrv3':{'target_kernel':bbr.MANIFEST['kernel']}}
    e.load_remote=lambda:record
    stored=[]
    class SSH:
        def lock(self):pass
        def json(self,path):return record
        def run(self,command):return json.dumps({'kernel':'6.1-old','module_version':'','algorithm':'bbr','qdisc':'fq'})
        def write_json(self,path,value):stored.append(value)
    e.ssh=SSH();result=e.verify_bbr()
    assert not result['bbrv3']['active'] and result['bbrv3']['reboot_required']
    assert stored==[result]


def test_native_enable_reports_no_pending_reboot_without_installed_v3():
    import json
    from deployer.engine import Engine
    from deployer.models import Settings
    e=Engine(Settings())
    class SSH:
        def connect(self):pass
        def lock(self):pass
        def json(self,*args):return {}
        def run(self,command,**kwargs):
            if command.startswith("python3 - <<'PY'"):
                return json.dumps({'kernel':'6.1.0-35-amd64','module_version':'','algorithm':'bbr','qdisc':'fq','native_verified':True})
            return ''
    e.ssh=SSH();status=e.native_bbr()
    assert status['bbr_version']=='1' and not status['installed'] and not status['reboot_required']
