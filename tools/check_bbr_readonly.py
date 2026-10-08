"""Check generated shell syntax and current BBR state without executing installation."""
import getpass
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from live_settings import connection_settings
from deployer.ssh import SSH
from deployer import bbr

s, expected = connection_settings()
ssh=SSH(s,trust=lambda host,fp:fp==expected)
try:
    ssh.connect()
    stdin,stdout,stderr=ssh.client.exec_command('bash -n',timeout=30)
    stdin.write(bbr.install_script());stdin.flush();stdin.channel.shutdown_write()
    error=stderr.read().decode();assert stdout.channel.recv_exit_status()==0,error
    status=bbr.describe_status(json.loads(ssh.run(bbr.status_command())))
    Path('test-artifacts/bbr-readonly-check.json').write_text(json.dumps({'shell_syntax_valid':True,'installation_executed':False,'status':status},indent=2),encoding='utf-8')
    print('Debian shell syntax check passed; installation was not executed')
finally:ssh.close();s.password=''
