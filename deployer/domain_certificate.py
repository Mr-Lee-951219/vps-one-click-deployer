"""Domain checks without access to the user's DNS provider account."""
import ipaddress
import socket
from .models import validate_domain


def check_domain(domain,host):
    domain=domain.strip().lower();validate_domain(domain)
    try:address=ipaddress.ip_address(host)
    except ValueError:raise ValueError('域名证书模式请填写 VPS 的公网 IPv4 地址') from None
    if address.version!=4:raise ValueError('当前域名证书部署支持 IPv4 VPS')
    try:answers=socket.getaddrinfo(domain,80,type=socket.SOCK_STREAM)
    except socket.gaierror:raise ValueError('域名尚未解析，请先添加指向 VPS 的 A 记录，使用仅 DNS（灰云），等待解析生效') from None
    addresses={str(ipaddress.ip_address(item[4][0])) for item in answers}
    if addresses!={str(address)}:
        raise ValueError('域名解析未完全指向当前 VPS。请关闭小橙云，核对 A 记录，并删除不适用的同名 A / AAAA 记录后等待生效')
    return {'domain':domain,'address':str(address),'matches':True}
