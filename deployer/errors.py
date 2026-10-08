"""Actionable connection failures without copying credentials into dialogs."""
import socket
import paramiko


def friendly_error(error):
    if isinstance(error, paramiko.AuthenticationException):
        return 'SSH 认证失败。请核对用户名和当前密码；如果服务器重装过，请输入重装后的密码。使用私钥时请核对匹配的密钥及服务器登录权限。'
    if isinstance(error, paramiko.ssh_exception.NoValidConnectionsError):
        return '无法连接 SSH 端口。请核对服务器 IP、实际 SSH 端口、服务器是否开机，以及云安全组和本机防火墙是否放行该端口。'
    if isinstance(error, socket.gaierror):
        return '服务器地址无法解析。请核对地址拼写和本机网络；可以先使用 VPS 公网 IP 连接。'
    if isinstance(error, (TimeoutError, socket.timeout)):
        return '连接或操作超时。请检查网络与服务器状态。已经启动的后台安装任务可能仍在运行，请查看后台任务后再继续部署。'
    if isinstance(error, paramiko.SSHException):
        return 'SSH 连接未完成。请确认填写的是 SSH 端口，并检查服务器 SSH 服务和登录权限。\n详情：' + str(error)
    return str(error)
