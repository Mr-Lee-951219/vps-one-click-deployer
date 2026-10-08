"""Read-only inspection. Credentials are read interactively, never saved."""
import base64
import getpass
import hashlib
import json
import sys
from pathlib import Path

import paramiko

host = sys.argv[1]
port = int(sys.argv[2])
username = sys.argv[3] if len(sys.argv) > 3 else "root"
password = getpass.getpass("SSH password: ")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(host, port=port, username=username, password=password,
                   timeout=15, auth_timeout=15, banner_timeout=15,
                   allow_agent=False, look_for_keys=False)
    key = client.get_transport().get_remote_server_key()
    print("HOST_KEY", key.get_name(), "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("="))
    destination = Path(__file__).resolve().parents[1] / "test-artifacts" / "known_hosts"
    destination.parent.mkdir(exist_ok=True)
    client.save_host_keys(str(destination))
    command = r'''printf '--- OS ---\n'; cat /etc/os-release; uname -m; id -u; printf '\n--- SERVICES ---\n'; systemctl is-active x-ui 2>/dev/null || true; test -x /usr/local/x-ui/x-ui && /usr/local/x-ui/x-ui version; printf '\n--- PORTS ---\n'; ss -lntup; printf '\n--- BBR ---\n'; sysctl net.ipv4.tcp_available_congestion_control net.ipv4.tcp_congestion_control net.core.default_qdisc; printf '\n--- FIREWALL ---\n'; command -v ufw || true; nft list ruleset 2>/dev/null; printf '\n--- DISK ---\n'; df -h /; printf '\n--- DOWNLOAD ---\n'; curl -I -m 12 -s https://api.github.com/repos/MHSanaei/3x-ui/releases/latest | head -n 1'''
    _, stdout, stderr = client.exec_command(command, timeout=40)
    print(stdout.read().decode("utf-8", errors="replace"))
    print(stderr.read().decode("utf-8", errors="replace"))
finally:
    password = ""
    client.close()
