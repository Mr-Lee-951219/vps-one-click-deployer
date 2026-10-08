import hashlib
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('journal_check', Path('assets/security-journal-check.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture(tmp):
    (tmp/'jail.d').mkdir();(tmp/'filter.d').mkdir()
    (tmp/'jail.conf').write_text('[DEFAULT]\nbackend = auto\n[sshd]\nlogpath = /var/log/auth.log\n')
    (tmp/'filter.d/sshd.conf').write_text('[Definition]\njournalmatch = _COMM=sshd\n')
    (tmp/'jail.d/defaults-debian.conf').write_text('[sshd]\nenabled = true\n')
    hashes = '\n'.join(str(path)+' '+hashlib.md5(path.read_bytes()).hexdigest()
                       for path in (tmp/'jail.conf',tmp/'filter.d/sshd.conf'))
    return hashes


def test_stock_missing_auth_log_is_compatible_without_writing_files(tmp_path):
    hashes=fixture(tmp_path);before={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert checker.inspect(tmp_path,tmp_path/'absent',hashes)['compatible']
    assert before=={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    (tmp_path/'auth.log').touch()
    assert not checker.inspect(tmp_path,tmp_path/'auth.log',hashes)['compatible']


@pytest.mark.parametrize('text',['[sshd]\nbackend = polling\n','[sshd]\nlogpath = /custom/auth.log\n','[DEFAULT]\nbackend = auto\n'])
def test_custom_configuration_wins_over_automatic_compatibility(tmp_path,text):
    hashes=fixture(tmp_path);(tmp_path/'jail.local').write_text(text)
    assert not checker.inspect(tmp_path,tmp_path/'absent',hashes)['compatible']


@pytest.mark.parametrize('relative',['jail.conf','filter.d/sshd.conf'])
def test_modified_package_configuration_is_not_overwritten(tmp_path,relative):
    hashes=fixture(tmp_path);path=tmp_path/relative;path.write_text(path.read_text()+'# custom\n')
    assert not checker.inspect(tmp_path,tmp_path/'absent',hashes)['compatible']
