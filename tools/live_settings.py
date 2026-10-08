"""Explicit connection parameters for optional live development checks."""
import argparse
import getpass
import re
from deployer.models import Settings

def connection_settings():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--ssh-port', required=True, type=int)
    parser.add_argument('--user', default='root')
    parser.add_argument('--fingerprint', required=True,
                        help='SHA256 fingerprint verified in the provider console')
    args = parser.parse_args()
    if not 1 <= args.ssh_port <= 65535:
        parser.error('SSH port must be in 1–65535')
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', args.fingerprint):
        parser.error('Provide the verified SHA256 host key fingerprint')
    return (Settings(host=args.host, ssh_port=args.ssh_port, username=args.user, strict_host_key=True,
                     password=getpass.getpass('SSH password: ')), args.fingerprint)
