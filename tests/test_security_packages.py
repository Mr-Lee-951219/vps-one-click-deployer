import importlib.util
from pathlib import Path
import pytest
from test_security import Manager,payload
from deployer.security import READY_CHECK

spec=importlib.util.spec_from_file_location('security_packages',Path('assets/security-packages.py'))
packages=importlib.util.module_from_spec(spec);spec.loader.exec_module(packages)


def test_existing_components_do_not_refresh_expired_repository():
    commands=[]
    packages.install(run=lambda *args:commands.append(args),check=lambda:True)
    assert not commands
    manager=Manager();manager.security_apply(payload())
    assert not manager.ssh.jobs


def test_good_provider_repository_installs_only_security_dependencies():
    checks=iter([False,True]);commands=[]
    def run(args,timeout):commands.append((args,timeout));return 0,''
    packages.install(run=run,check=lambda:next(checks))
    assert len(commands)==2 and 'update' in commands[0][0]
    assert commands[1][0][-3:]==['fail2ban','nftables','python3-systemd']
    assert all(timeout<=600 for _,timeout in commands)


def test_expired_backports_falls_back_to_isolated_signed_bookworm_sources(tmp_path,monkeypatch):
    key=tmp_path/'keyring.gpg';key.touch();monkeypatch.setattr(packages,'KEYRING',key)
    calls=[];sources=[];locations=[];checks=iter([False,True])
    def run(args,timeout):
        calls.append(args)
        if len(calls)==1:return 100,'E: Release file for provider/bookworm-backports is expired'
        source=next(arg.split('=',1)[1] for arg in args if arg.startswith('Dir::Etc::sourcelist='))
        locations.append(Path(source).parent);sources.append(Path(source).read_text())
        assert 'Dir::Etc::sourceparts=-' in args
        assert any(arg.startswith('Dir::State::lists=') for arg in args)
        assert 'Acquire::Check-Valid-Until=true' in args and 'APT::Get::AllowUnauthenticated=false' in args
        return 0,''
    packages.install(run=run,check=lambda:next(checks),temp_parent=tmp_path)
    assert len(calls)==3 and all('bookworm-backports' not in source and 'trixie' not in source for source in sources)
    assert all('Signed-By:' in source and 'https://deb.debian.org/debian' in source and 'bookworm-security' in source for source in sources)
    assert all(not location.exists() for location in locations)


def test_invalid_official_metadata_stops_before_install_and_cleans_temporary_sources(tmp_path,monkeypatch):
    key=tmp_path/'keyring.gpg';key.touch();monkeypatch.setattr(packages,'KEYRING',key)
    calls=[]
    def run(args,timeout):calls.append(args);return 100,'Release file is not valid yet'
    with pytest.raises(RuntimeError,match='服务器时间'):packages.install(run=run,check=lambda:False,temp_parent=tmp_path)
    assert len(calls)==2 and all('install' not in args for args in calls)
    assert not list(tmp_path.glob('nodepilot-security-apt-*'))


def test_missing_keyring_does_not_disable_signature_checks(tmp_path,monkeypatch):
    monkeypatch.setattr(packages,'KEYRING',tmp_path/'missing');calls=[]
    def run(args,timeout):calls.append(args);return 100,'expired'
    with pytest.raises(RuntimeError,match='签名密钥环'):packages.install(run=run,check=lambda:False,temp_parent=tmp_path)
    assert len(calls)==1


def test_installer_requires_working_components_after_apt_reports_success():
    with pytest.raises(RuntimeError,match='回读检查'):packages.install(run=lambda *args:(0,''),check=lambda:False)


def test_missing_components_replace_failed_job_and_are_verified_after_retry():
    manager=Manager();old=manager.ssh.run;checks=iter(['','ready'])
    manager.ssh.run=lambda command,**kw:next(checks) if command==READY_CHECK else old(command,**kw)
    manager.security_apply(payload())
    assert manager.ssh.jobs[0][0]=='security-dependencies'
    assert 'security-package-setup.py --reference-utc' in manager.ssh.jobs[0][1]
    assert '/var/lib/nodepilot/jobs/security-package-setup.py' in manager.ssh.files
    assert 'rm -f -- /var/lib/nodepilot/jobs/security-dependencies.status' in manager.ssh.commands


def test_failed_component_readback_never_activates_firewall_jail():
    manager=Manager();old=manager.ssh.run
    manager.ssh.run=lambda command,**kw:'' if command==READY_CHECK else old(command,**kw)
    with pytest.raises(RuntimeError,match='回读检查'):manager.security_apply(payload())
    assert not manager.ssh.running


def test_large_clock_difference_is_reported_without_changing_clock(monkeypatch,capsys):
    commands=[];monkeypatch.setattr(packages.time,'time',lambda:1000000)
    monkeypatch.setattr(packages,'command',lambda args,timeout:commands.append(args) or (0,'NTPSynchronized=no'))
    packages.show_clock(1000000-3600)
    assert '相差超过' in capsys.readouterr().out
    assert commands==[['timedatectl','show','-p','NTPSynchronized']]
