import ipaddress
import time
import requests
from .models import validate_domain

class Cloudflare:
    def __init__(self, token):
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"Authorization": "Bearer " + token, "Content-Type": "application/json"})

    def call(self, method, path, **kwargs):
        response = self.session.request(method, "https://api.cloudflare.com/client/v4" + path, timeout=25, **kwargs)
        try:
            value = response.json()
        except ValueError:
            raise RuntimeError("Cloudflare 返回无法解析的响应，请检查网络")
        if not response.ok or not value.get("success"):
            details = "; ".join(str(e.get("message", "")) for e in value.get("errors", []))
            raise RuntimeError("Cloudflare 权限或配置检查失败：" + (details or str(response.status_code)))
        return value["result"]

    def zone(self, domain):
        validate_domain(domain)
        parts = domain.split(".")
        for start in range(len(parts) - 1):
            found = self.call("GET", "/zones", params={"name": ".".join(parts[start:])})
            if found:
                return found[0]
        raise RuntimeError("Token 无权访问这个域名；请检查 Specific zone 和区域读取权限")

    def check(self, domain, host=None):
        self.call("GET", "/user/tokens/verify")
        zone = self.zone(domain)
        if zone["status"] != "active":
            raise RuntimeError("域名仍未激活，请先在注册商修改 NS，等待 Cloudflare 显示 Active")
        records = self.call("GET", f"/zones/{zone['id']}/dns_records", params={"name": domain})
        return {"zone": zone["name"], "zone_id": zone["id"], "status": zone["status"],
                "nameservers": zone.get("name_servers", []), "records": records,
                "matches": any(r.get("content") == host and not r.get("proxied") for r in records) if host else None}

    def ensure_address(self, domain, host):
        ip = ipaddress.ip_address(host)
        check = self.check(domain, host)
        record_type = "A" if ip.version == 4 else "AAAA"
        same = [r for r in check["records"] if r["type"] == record_type]
        conflicting = [r for r in check["records"] if r["type"] in {"A", "AAAA", "CNAME"} and (r.get("content") != host or r.get("proxied"))]
        if conflicting:
            raise RuntimeError("同名解析已指向其他地址或开启代理；请在 Cloudflare 教程页面核对并修改，之后重试")
        if same:
            return {"created": False, "record": same[0], "zone_id": check["zone_id"]}
        created = self.call("POST", f"/zones/{check['zone_id']}/dns_records", json={"type": record_type, "name": domain, "content": host, "ttl": 1, "proxied": False})
        return {"created": True, "record": created, "zone_id": check["zone_id"]}
