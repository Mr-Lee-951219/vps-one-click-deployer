import json
import secrets
from urllib.parse import quote, urlencode
import requests
from requests.adapters import HTTPAdapter


class FingerprintAdapter(HTTPAdapter):
    def __init__(self,fingerprint):
        self.fingerprint=fingerprint
        super().__init__()
    def init_poolmanager(self,connections,maxsize,block=False,**kwargs):
        kwargs.update(assert_hostname=False,assert_fingerprint=self.fingerprint)
        return super().init_poolmanager(connections,maxsize,block=block,**kwargs)

class Panel:
    def __init__(self, base_url, token, fingerprint=None):
        self.base = base_url.rstrip("/") + "/"
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["Authorization"] = "Bearer " + token
        if fingerprint:
            if not self.base.startswith('https://127.0.0.1:'):
                raise ValueError('证书指纹验证仅用于本机 SSH 隧道')
            self.session.mount('https://',FingerprintAdapter(fingerprint))
            # Host is localhost, while the cert names the public domain. Pin the exact cert
            # just read over authenticated SSH instead of relying on localhost's name.
            self.session.verify=False

    def call(self, method, path, payload=None):
        response = self.session.request(method, self.base + path, json=payload, timeout=35)
        response.raise_for_status()
        value = response.json()
        if not value.get("success"):
            raise RuntimeError("面板接口：" + str(value.get("msg", "操作未完成")))
        return value.get("obj")

    def list(self):
        nodes = self.call("GET", "panel/api/inbounds/list") or []
        for node in nodes:
            for key in ('settings', 'streamSettings', 'sniffing', 'allocate'):
                if isinstance(node.get(key), dict):
                    node[key] = json.dumps(node[key])
        return nodes

    def update_client(self, inbound_id, client):
        return self.call('POST', 'panel/api/clients/update/' + quote(client['email'], safe='')
                         + '?inboundIds=' + str(int(inbound_id)), client)

    def reset_client(self, email):
        return self.call('POST', 'panel/api/clients/resetTraffic/' + quote(email, safe=''))

    def ensure(self, payload):
        found = [i for i in self.list() if i.get("remark") == payload["remark"]]
        if found:
            if found[0]["port"] != payload["port"] or found[0]["protocol"] != payload["protocol"]:
                raise RuntimeError("已有同名节点与部署记录不同，请使用同步或修改功能")
            return found[0]
        return self.call("POST", "panel/api/inbounds/add", payload)

    def update(self, inbound):
        return self.call("POST", f"panel/api/inbounds/update/{inbound['id']}", inbound)

def client_base(settings, name):
    return {"email": name, "enable": True, "limitIp": 0, "totalGB": settings.quota_bytes('hy2' if name.endswith('hy2') else 'vless'),
            "expiryTime": settings.expiry, "tgId": "", "subId": secrets.token_hex(8), "reset": 0}

def build_inbounds(settings, ports, identity, certificate):
    common = {"up": 0, "down": 0, "total": 0, "enable": True, "expiryTime": 0,
              "listen": "0.0.0.0", "sniffing": json.dumps({"enabled": False}), "allocate": json.dumps({"strategy": "always", "refresh": 5, "concurrency": 3})}
    result = []
    if settings.vless:
        user = {**client_base(settings, "nodepilot-vless"), "id": identity["uuid"], "flow": "xtls-rprx-vision"}
        stream = {"network": "tcp", "security": "reality", "tcpSettings": {"header": {"type": "none"}},
                  "realitySettings": {"show": False, "target": settings.reality_target, "xver": 0,
                      "serverNames": [settings.reality_sni], "privateKey": identity["reality_private"],
                      "shortIds": [identity["short_id"]],
                      "limitFallbackUpload": {"afterBytes": 0, "bytesPerSec": 65536, "burstBytesPerSec": 131072},
                      "limitFallbackDownload": {"afterBytes": 0, "bytesPerSec": 65536, "burstBytesPerSec": 131072},
                      "settings": {"publicKey": identity["reality_public"], "fingerprint": "chrome", "serverName": settings.reality_sni, "spiderX": "/"}}}
        result.append({**common, "remark": "NodePilot · VLESS", "port": ports["vless"], "protocol": "vless",
                       "settings": json.dumps({"clients": [user], "decryption": "none", "encryption": "none", "fallbacks": []}),
                       "streamSettings": json.dumps(stream)})
    if settings.hy2:
        user = {**client_base(settings, "nodepilot-hy2"), "auth": identity["hy2_password"]}
        stream = {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "udpIdleTimeout": 60},
                  "tlsSettings": {"serverName": certificate["domain"], "minVersion": "1.3", "maxVersion": "1.3", "alpn": ["h3"],
                      "certificates": [{"certificateFile": certificate["cert"], "keyFile": certificate["key"], "oneTimeLoading": False}],
                      "settings": {"fingerprint": "", "pinnedPeerCertSha256": [certificate["fingerprint"]] if certificate["selfsigned"] else []}},
                  "finalmask": {"quicParams": {"congestion": "bbr", "bbrProfile": "standard"}}}
        result.append({**common, "remark": "NodePilot · HY2", "port": ports["hy2"], "protocol": "hysteria",
                       "settings": json.dumps({"version": 2, "clients": [user]}), "streamSettings": json.dumps(stream)})
    return result

def node_links(settings, ports, identity, cert):
    host = "[" + settings.host + "]" if ":" in settings.host else settings.host
    result = {}
    if settings.vless:
        args = {"encryption": "none", "security": "reality", "sni": settings.reality_sni,
                "fp": "chrome", "pbk": identity["reality_public"], "sid": identity["short_id"],
                "type": "tcp", "flow": "xtls-rprx-vision", "spx": "/"}
        result["VLESS"] = f"vless://{identity['uuid']}@{host}:{ports['vless']}?" + urlencode(args) + "#" + quote(settings.name + " · VLESS")
    if settings.hy2:
        address = settings.domain if not cert["selfsigned"] else host
        args = {"sni": cert["domain"]}
        if cert["selfsigned"]:
            args.update({"insecure": "1", "pinSHA256": cert["fingerprint"]})
        result["HY2"] = f"hysteria2://{quote(identity['hy2_password'], safe='')}@{address}:{ports['hy2']}/?" + urlencode(args) + "#" + quote(settings.name + " · HY2")
    return result

def client_config(settings, ports, identity, cert, protocol, socks_port):
    if protocol == "VLESS":
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": settings.host, "port": ports["vless"],
                    "users": [{"id": identity["uuid"], "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
                    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": settings.reality_sni,
                        "fingerprint": "chrome", "password": identity["reality_public"], "shortId": identity["short_id"], "spiderX": "/"}}}
    else:
        tls = {"serverName": cert["domain"], "alpn": ["h3"]}
        if cert["selfsigned"]:
            tls.update({"pinnedPeerCertSha256": cert["fingerprint"]})
        outbound = {"protocol": "hysteria", "settings": {"version": 2, "address": settings.host, "port": ports["hy2"]},
                    "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": identity["hy2_password"]},
                                       "tlsSettings": tls, "finalmask": {"quicParams": {"congestion": "bbr"}}}}
    return {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": socks_port,
               "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}], "outbounds": [outbound]}
