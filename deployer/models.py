from dataclasses import dataclass, field, asdict
import ipaddress
import re
import secrets
import uuid

PANEL_VERSION = "v3.9.0"

@dataclass
class Settings:
    name: str = "我的服务器"
    host: str = ""
    ssh_port: int = 0
    username: str = "root"
    password: str = field(default="", repr=False)
    private_key: str = ""
    strict_host_key: bool = False
    remember_password: bool = False
    panel_port: int = 0
    panel_user: str = ""
    panel_password: str = field(default="", repr=False)
    vless_port: int = 0
    hy2_port: int = 0
    range_low: int = 10000
    range_high: int = 30000
    vless: bool = True
    hy2: bool = True
    bbr: bool = True
    bbr_mode: str = "keep"
    firewall: bool = True
    tls_mode: str = "selfsigned"
    domain: str = ""
    email: str = ""
    cf_token: str = field(default="", repr=False)
    reality_target: str = "www.microsoft.com:443"
    reality_sni: str = "www.microsoft.com"
    panel_public: bool = False
    panel_domain: str = ""
    management_cidr: str = ""
    expiry: int = 0
    quota_gb: float = 0
    vless_quota_gb: float = 0
    hy2_quota_gb: float = 0
    split_quota: bool = False
    server_due: int = 0
    reset_day: int = 0

    def validate(self):
        self.validate_limits()
        if self.bbr_mode not in {'keep', 'native', 'v3'}:
            raise ValueError('请选择有效的 BBR 模式')
        if not re.fullmatch(r"[a-zA-Z0-9._:\[\]-]+", self.host):
            raise ValueError("服务器地址格式不正确")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.username):
            raise ValueError("SSH 用户名格式不正确")
        if self.username != "root":
            raise ValueError("首版部署需要 root；普通用户可先使用连接检查")
        if not 1 <= self.ssh_port <= 65535:
            raise ValueError("SSH 端口应在 1–65535")
        if not self.password and not self.private_key:
            raise ValueError("请填写 SSH 密码或选择私钥")
        if not self.vless and not self.hy2:
            raise ValueError("至少选择一种节点协议")
        if not 1024 <= self.range_low <= self.range_high <= 65535:
            raise ValueError("随机端口范围应在 1024–65535")
        chosen = [p for p in (self.panel_port, self.vless_port if self.vless else 0, self.hy2_port if self.hy2 else 0) if p]
        if any(not 1 <= p <= 65535 for p in chosen) or len(chosen) != len(set(chosen)) or self.ssh_port in chosen:
            raise ValueError("面板与节点端口必须有效、互不重复，且避开 SSH 端口")
        if self.hy2 or self.tls_mode in ('domain','cloudflare'):
            self.validate_hy2_certificate()
        if self.domain.strip() and self.tls_mode not in ('domain','cloudflare'):
            raise ValueError('要使用域名面板链接，请选择域名证书；无需域名时请清空访问域名')
        if self.tls_mode in ('domain','cloudflare') and 80 in [self.ssh_port]+chosen:
            raise ValueError('域名证书需要独立的 TCP 80 验证端口，SSH、面板和节点请选择其他端口')
        if self.panel_public:
            if self.panel_domain:validate_domain(self.panel_domain)
            try:
                ipaddress.ip_network(self.management_cidr, strict=False)
            except ValueError:
                raise ValueError("公网面板请填写管理来源 IP/CIDR，例如 1.2.3.4/32")
        if self.vless:
            validate_domain(self.reality_sni)
            if not re.fullmatch(r"[a-zA-Z0-9.-]+:[0-9]{1,5}", self.reality_target):
                raise ValueError("REALITY 目标应为域名:端口")

    def validate_hy2_certificate(self):
        if self.tls_mode not in {"selfsigned", "domain", "cloudflare"}:
            raise ValueError("请先选择 HY2 证书方式")
        if self.tls_mode in ('domain','cloudflare'):
            validate_domain(self.domain)

    def public_dict(self):
        return {k: v for k, v in asdict(self).items() if k not in {"password", "panel_password", "cf_token", "private_key"}}

    def validate_panel_login(self):
        validate_panel_login(self.panel_user, self.panel_password)

    def validate_limits(self):
        import math
        for value in (self.quota_gb, self.vless_quota_gb, self.hy2_quota_gb):
            if not math.isfinite(value) or not 0 <= value <= 1000000:
                raise ValueError('流量应在 0–1000000 GB，0 表示不限量')
        if self.expiry < 0 or self.server_due < 0 or not 0 <= self.reset_day <= 31:
            raise ValueError('日期或流量重置日不正确')
        if self.split_quota and self.quota_gb:
            values = ([self.vless_quota_gb] if self.vless else []) + ([self.hy2_quota_gb] if self.hy2 else [])
            if any(v == 0 for v in values) or sum(values) > self.quota_gb + 1e-9:
                raise ValueError('有限总流量下，各启用节点需设置有限配额，合计不能超过总流量')

    def quota_bytes(self, protocol):
        if self.split_quota:
            return int(getattr(self, protocol + '_quota_gb') * 1024**3)
        count = int(self.vless) + int(self.hy2)
        return int(self.quota_gb * 1024**3) // max(1, count)

def validate_domain(domain):
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", domain):
        raise ValueError("请填写完整域名，不带 https://、端口或路径")

def allocate_ports(settings, occupied, saved=None):
    result = {}
    used = set(occupied) | {settings.ssh_port}
    saved = saved or {}
    for key, enabled in (("panel", True), ("vless", settings.vless), ("hy2", settings.hy2)):
        if not enabled:
            continue
        requested = getattr(settings, key + "_port") or saved.get(key, 0)
        if requested:
            if requested in used:
                raise ValueError(f"{key} 端口 {requested} 已被占用，请更换")
            port = requested
        else:
            candidates = [p for p in range(settings.range_low, settings.range_high + 1) if p not in used and p not in {80, 443}]
            if not candidates:
                raise ValueError("随机范围内没有可用端口")
            port = secrets.choice(candidates)
        used.add(port)
        result[key] = port
    return result

def validate_panel_login(username, password):
    if not re.fullmatch(r'[a-zA-Z0-9_.@-]{1,64}', username):
        raise ValueError('请填写面板账号：1–64 位英文字母、数字或 _ . @ -')
    if not 8 <= len(password.encode('utf-8')) <= 72 or any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise ValueError('面板密码需为 8–72 字节，不能包含换行或控制字符')


def random_panel_password():
    return secrets.token_urlsafe(24)


def new_identity(settings=None):
    if settings is not None:settings.validate_panel_login()
    return {"panel_user": settings.panel_user if settings else "manager_" + secrets.token_hex(3),
            "panel_password": settings.panel_password if settings else random_panel_password(),
            "panel_path": "/" + secrets.token_urlsafe(18) + "/",
            "uuid": str(uuid.uuid4()), "hy2_password": secrets.token_urlsafe(28),
            "short_id": secrets.token_hex(8)}

def port_rules(settings, ports):
    rules = []
    if settings.panel_public:
        rules.append({"service": "管理面板", "port": ports["panel"], "protocol": "TCP", "source": settings.management_cidr})
    if settings.vless:
        rules.append({"service": "VLESS", "port": ports["vless"], "protocol": "TCP", "source": "0.0.0.0/0"})
    if settings.hy2:
        rules.append({"service": "HY2", "port": ports["hy2"], "protocol": "UDP", "source": "0.0.0.0/0"})
    return rules
