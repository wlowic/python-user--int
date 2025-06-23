#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import subprocess
import platform
import ssl
import datetime
from urllib.parse import urlparse

# ==============================================================================
# 全局配置
# ==============================================================================

# 设置连接超时时间（秒）
socket.setdefaulttimeout(1)

# 定义要扫描的常见端口列表
# 您可以根据需要添加更多端口
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    465: 'SMTPS',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP-Proxy'
}

# ==============================================================================
# 核心功能函数
# ==============================================================================

def get_target_info(target):
    """
    解析目标，返回主机名和 IP 地址。
    """
    try:
        # 如果输入包含协议头，则提取主机名
        parsed_url = urlparse(target)
        if parsed_url.netloc:
            hostname = parsed_url.netloc
        elif parsed_url.path:
            hostname = parsed_url.path
        else:
             hostname = target
        
        ip_address = socket.gethostbyname(hostname)
        return hostname, ip_address
    except socket.gaierror:
        print(f"[!] 错误：无法解析主机名 '{target}'。请检查输入是否正确。")
        return None, None

def ping_host(ip_address):
    """
    使用系统 ping 命令检查主机是否可达。
    返回 True 表示可达，False 表示不可达。
    """
    print("\n--- [2] 开始 Ping 测试 ---")
    try:
        # 根据不同操作系统使用不同的 ping 参数
        # -n 1 (Windows) or -c 1 (Linux/macOS) 表示只发送一个包
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip_address]
        
        # 使用 subprocess.call 来执行命令，并隐藏输出
        response = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        
        if response == 0:
            print(f"[+] 主机 {ip_address} 可达。")
            return True
        else:
            print(f"[-] 主机 {ip_address} 不可达。")
            return False
    except Exception as e:
        print(f"[!] Ping 测试时发生错误: {e}")
        return False

def scan_ports(ip_address, ports_to_scan):
    """
    扫描指定 IP 地址的端口列表。
    """
    print("\n--- [3] 开始端口扫描 ---")
    open_ports = []
    for port, service_name in ports_to_scan.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip_address, port))
        sock.close()
        
        if result == 0:
            print(f"[+] 端口 {port} ({service_name}) 是开放的。")
            open_ports.append(port)
        else:
            # 静默处理关闭的端口，避免输出过多信息
            pass
            # print(f"[-] 端口 {port} ({service_name}) 是关闭的。")

    if not open_ports:
        print("[-] 未发现开放的常见端口。")
    return open_ports

def get_service_banner(ip_address, port):
    """
    尝试获取开放端口上运行的服务的 Banner 信息。
    """
    try:
        sock = socket.socket()
        sock.connect((ip_address, port))
        # 根据端口不同，可能需要发送特定数据才能触发 Banner
        # 这里只做简单的接收尝试
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        if banner:
            return banner
    except Exception:
        return None
    return None

def get_ssl_cert_info(hostname, port=443):
    """
    获取 SSL 证书的详细信息。
    """
    print(f"\n--- [4] 获取端口 {port} 的 SSL 证书信息 ---")
    try:
        # 创建一个 SSL 上下文
        context = ssl.create_default_context()
        
        # 建立一个 SSL/TLS 连接
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            print(f"[-] 无法获取端口 {port} 的 SSL 证书。")
            return

        # 解析证书信息
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert.get('issuer', []))
        valid_from_str = cert['notBefore']
        valid_to_str = cert['notAfter']
        
        # 将时间字符串转换为 datetime 对象
        valid_from = datetime.datetime.strptime(valid_from_str, '%b %d %H:%M:%S %Y %Z')
        valid_to = datetime.datetime.strptime(valid_to_str, '%b %d %H:%M:%S %Y %Z')

        print(f"[+] 通用名称 (Common Name): {subject.get('commonName', 'N/A')}")
        print(f"[+] 颁发者 (Issuer): {issuer.get('commonName', 'N/A')}")
        print(f"[+] 证书有效期从: {valid_from.strftime('%Y-%m-%d')}")
        print(f"[+] 证书有效期至: {valid_to.strftime('%Y-%m-%d')}")
        
        # 检查证书是否即将过期（例如，30天内）
        days_left = (valid_to - datetime.datetime.now()).days
        if days_left < 0:
            print("[!] 警告：证书已过期！")
        elif days_left < 30:
            print(f"[!] 警告：证书将在 {days_left} 天内过期！")
        else:
            print(f"[+] 证书剩余有效期: {days_left} 天。")

    except ssl.SSLCertVerificationError as e:
        print(f"[!] SSL 证书验证错误: {e.reason}")
    except ConnectionRefusedError:
        print(f"[-] 端口 {port} 连接被拒绝。")
    except Exception as e:
        print(f"[!] 获取 SSL 证书时发生未知错误: {e}")

def get_http_headers(hostname, port):
    """
    使用 http.client 获取 HTTP 头部信息
    """
    print(f"\n--- [5] 获取端口 {port} 的 HTTP 标头 ---")
    try:
        if port == 443:
            conn = socket.create_connection((hostname, port))
            context = ssl.create_default_context()
            conn = context.wrap_socket(conn, server_hostname=hostname)
        else:
            conn = socket.create_connection((hostname, port))

        # 发送一个 HEAD 请求，只获取标头，不获取内容
        conn.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % hostname.encode())
        response = conn.recv(4096).decode('utf-8', errors='ignore')
        conn.close()
        
        print("[+] 服务器响应标头:")
        print("--------------------")
        print(response.strip())
        print("--------------------")

    except Exception as e:
        print(f"[!] 获取 HTTP 标头时出错: {e}")

# ==============================================================================
# 主函数
# ==============================================================================

def main():
    """
    主执行函数
    """
    target = input("请输入目标域名或 IP 地址 (例如: example.com 或 8.8.8.8): ").strip()
    if not target:
        print("输入不能为空。")
        return

    hostname, ip_address = get_target_info(target)
    
    if not ip_address:
        return

    print("\n--- [1] 目标基本信息 ---")
    print(f"[+] 主机名: {hostname}")
    print(f"[+] IP 地址: {ip_address}")

    # 执行 Ping 测试
    ping_host(ip_address)

    # 执行端口扫描
    open_ports = scan_ports(ip_address, COMMON_PORTS)
    
    # 对开放的端口进行进一步探测
    if open_ports:
        print("\n--- [+] 开放端口上的服务探测 ---")
        for port in open_ports:
            banner = get_service_banner(ip_address, port)
            if banner:
                print(f"  - 端口 {port} Banner: {banner}")
            
            # 如果是 HTTPS 端口，获取证书信息
            if port == 443:
                get_ssl_cert_info(hostname, port)
            
            # 如果是 HTTP 或 HTTPS 端口，获取 HTTP 标头
            if port in [80, 443, 8080]:
                get_http_headers(hostname, port)


if __name__ == '__main__':
    main()
