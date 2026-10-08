"""Local persisted secrets use Windows DPAPI, tied to the current user."""
import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re

def home():
    path = Path(os.environ.get("NODEPILOT_HOME", Path(os.environ.get("LOCALAPPDATA", Path.home())) / "NodePilot"))
    path.mkdir(parents=True, exist_ok=True)
    return path

class Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

def protect(raw, decrypt=False):
    if os.name != "nt":
        raise RuntimeError("凭据保护需要 Windows DPAPI")
    buffer = ctypes.create_string_buffer(raw)
    source = Blob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    destination = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(destination)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel.LocalFree(destination.pbData)

def save_secret(name, value):
    data = protect(json.dumps(value, ensure_ascii=False).encode("utf-8"))
    target = home() / (re.sub(r"[^a-zA-Z0-9_-]", "_", name) + ".protected")
    temp = target.with_suffix(".tmp")
    temp.write_bytes(data)
    temp.replace(target)

def load_secret(name, default=None):
    target = home() / (re.sub(r"[^a-zA-Z0-9_-]", "_", name) + ".protected")
    if not target.exists():
        return default
    return json.loads(protect(target.read_bytes(), decrypt=True))

def save_public(name, value):
    target = home() / (name + ".json")
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(target)

def load_public(name, default=None):
    try:
        return json.loads((home() / (name + ".json")).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def clear_saved_ssh_credentials():
    """Remove legacy login caches only; keep host identity pins and node records."""
    root = home().resolve()
    removed = 0
    for target in root.iterdir():
        if target.name.startswith('ssh-') and target.suffix in {'.protected', '.tmp'}:
            if target.is_symlink() or target.resolve().parent != root:
                raise RuntimeError('SSH 凭据缓存路径异常，请检查本机数据目录')
            if target.is_file():
                target.unlink()
                removed += 1
    saved = load_public('last-server', {})
    if isinstance(saved, dict):
        clean = {k: v for k, v in saved.items()
                 if k not in {'host', 'ssh_port', 'password', 'private_key', 'cf_token'}}
        if clean != saved:
            save_public('last-server', clean)
    return removed

class Redactor:
    def __init__(self, values=()):
        self.values = set(v for v in values if isinstance(v, str) and v)

    def add(self, *values):
        self.values.update(v for v in values if isinstance(v, str) and v)

    def __call__(self, text):
        text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", str(text))
        for value in sorted(self.values, key=len, reverse=True):
            text = text.replace(value, "[已隐藏]")
        text = re.sub(r"(?im)^.*(?:password\s*:|api\s*token\s*:|XUI_API_TOKEN=|XUI_PASSWORD=).*$", "[凭据已隐藏]", text)
        return text

def server_id(host, port):
    return str(host).strip().lower() + ':' + str(int(port))

def saved_servers():
    items = load_public('servers', [])
    allowed = {'id','name','host','ssh_port','username','last_connected','limits'}
    return [{k:v for k,v in item.items() if k in allowed} for item in items if isinstance(item,dict) and item.get('host') and item.get('ssh_port')] if isinstance(items, list) else []

def remember_server(settings):
    """Persist successful endpoints and per-server limits, never login credentials."""
    import time
    key = server_id(settings.host, settings.ssh_port)
    items = saved_servers()
    old = next((x for x in items if x.get('id') == key), {})
    item = {**old, 'id': key, 'name': old.get('name', settings.name),
            'host': settings.host, 'ssh_port': settings.ssh_port,
            'username': settings.username, 'last_connected': int(time.time())}
    if not old:
        item['limits'] = {k: getattr(settings, k) for k in LIMIT_KEYS}
    save_public('servers', [item] + [x for x in items if x.get('id') != key])

LIMIT_KEYS = ('expiry', 'quota_gb', 'vless_quota_gb', 'hy2_quota_gb', 'split_quota', 'server_due', 'reset_day')

def save_server_limits(settings):
    key = server_id(settings.host, settings.ssh_port)
    items = saved_servers()
    for item in items:
        if item.get('id') == key:
            item['limits'] = {k: getattr(settings, k) for k in LIMIT_KEYS}
    save_public('servers', items)

def forget_server(key):
    forget_login_by_id(key)
    save_public('servers', [x for x in saved_servers() if x.get('id') != key])

def login_name(key):
    import hashlib
    return 'login-v1-' + hashlib.sha256(key.encode('utf-8')).hexdigest()

def load_login_password(host, port, username):
    value = load_secret(login_name(server_id(host, port)), {})
    if not isinstance(value, dict) or value.get('username') != username:
        return ''
    password = value.get('password', '')
    return password if isinstance(password, str) else ''

def forget_login_by_id(key):
    # Exact filename derived from the endpoint; no recursive deletion.
    for suffix in ('.protected', '.tmp'):
        path = home() / (login_name(key) + suffix)
        if path.is_symlink():raise RuntimeError('密码文件路径异常')
        path.unlink(missing_ok=True)

def forget_login_password(host, port):
    forget_login_by_id(server_id(host, port))

def save_authenticated_password(settings):
    if not settings.remember_password:
        forget_login_password(settings.host, settings.ssh_port)
    elif settings.password and not settings.private_key:
        save_secret(login_name(server_id(settings.host, settings.ssh_port)),
                    {'username':settings.username,'password':settings.password})

def migrate_saved_servers():
    """Import old encrypted deployment metadata once, without importing passwords."""
    from .models import Settings
    if load_public('servers-migrated', False):return 0
    existing = {item['id'] for item in saved_servers()}
    count = 0
    for path in home().glob('*.protected'):
        if path.stem.startswith('ssh-'):continue
        try:
            record = load_secret(path.stem)
            data = record.get('settings', {})
            if not record.get('ports') or not data.get('host') or not data.get('ssh_port'):continue
            settings = Settings(**{k:v for k,v in data.items() if k in Settings.__dataclass_fields__ and k not in {'password','private_key','cf_token'}})
            key = server_id(settings.host, settings.ssh_port)
            if key not in existing:
                remember_server(settings);existing.add(key);count += 1
        except (ValueError, TypeError, OSError, AttributeError):continue
    save_public('servers-migrated', True)
    return count
