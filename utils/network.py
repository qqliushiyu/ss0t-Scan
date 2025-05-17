#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络工具函数
提供常用的网络操作和解析函数
"""

import ipaddress
import os
import platform
import re
import socket
import struct
import subprocess
from typing import List, Tuple, Union, Optional, Dict, Any
import locale

def is_valid_ip(ip: str) -> bool:
    """
    检查字符串是否为有效的 IPv4 地址
    
    Args:
        ip: IP 地址字符串
    
    Returns:
        是否有效
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_ip_network(network: str) -> bool:
    """
    检查字符串是否为有效的 IPv4 网段
    
    Args:
        network: IP 网段字符串，例如 192.168.1.0/24
    
    Returns:
        是否有效
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def parse_ip_range(ip_range: str) -> List[str]:
    """
    解析 IP 范围为 IP 地址列表
    
    Args:
        ip_range: IP 范围字符串，支持以下格式:
            - 单个 IP: 192.168.1.1
            - CIDR 网段: 192.168.1.0/24
            - IP 范围: 192.168.1.1-192.168.1.10
            - 带通配符: 192.168.1.*
    
    Returns:
        IP 地址列表
    """
    # 单个 IP
    if is_valid_ip(ip_range):
        return [ip_range]
    
    # CIDR 表示法
    if '/' in ip_range:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass
    
    # 范围表示法 (192.168.1.1-192.168.1.10)
    if '-' in ip_range:
        try:
            parts = ip_range.split('-')
            if len(parts) != 2: #确保是单一的 '-' 分割
                return []
            
            start_ip_str = parts[0].strip()
            end_part_str = parts[1].strip()

            if not is_valid_ip(start_ip_str):
                return []

            end_ip_str = ""
            if is_valid_ip(end_part_str):
                end_ip_str = end_part_str
            else:
                # 尝试将 end_part_str 作为 start_ip_str 的最后一部分
                try:
                    end_octet = int(end_part_str)
                    if not (0 <= end_octet <= 255):
                        return [] # 无效的最后八位字节
                    
                    start_ip_parts = start_ip_str.split('.')
                    if len(start_ip_parts) != 4:
                        return [] # start_ip_str 格式不正确

                    # 检查 start_ip 的最后一部分是否小于 end_octet (对于 X.X.X.A-B 形式)
                    # 或者 start_ip 本身是否小于 end_ip (对于 X.X.X.A - Y.Y.Y.B 形式)
                    # 这里我们先构造 end_ip_str，后续的比较由 ipaddress 库处理
                    end_ip_str = f"{start_ip_parts[0]}.{start_ip_parts[1]}.{start_ip_parts[2]}.{end_octet}"
                    
                    # 确保构造出的 end_ip_str 是有效的
                    if not is_valid_ip(end_ip_str):
                         return [] # 构造出的 IP 仍然无效

                except ValueError: # end_part_str 不是纯数字
                    return []

            if not end_ip_str: # 如果 end_ip_str 最终还是空的
                return []

            start_ip_obj = ipaddress.IPv4Address(start_ip_str)
            end_ip_obj = ipaddress.IPv4Address(end_ip_str)
            
            start_int = int(start_ip_obj)
            end_int = int(end_ip_obj)

            if start_int > end_int: # 确保起始IP不大于结束IP
                return []
            
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]
        except (ValueError, TypeError):
            pass
    
    # 通配符表示法 (192.168.1.*)
    if '*' in ip_range:
        parts = ip_range.split('.')
        if len(parts) != 4:
            return []
        
        base_parts = []
        wildcard_positions = []
        
        for i, part in enumerate(parts):
            if part == '*':
                wildcard_positions.append(i)
            else:
                try:
                    val = int(part)
                    if 0 <= val <= 255:
                        base_parts.append(val)
                    else:
                        return []
                except ValueError:
                    return []
        
        if not wildcard_positions:
            return []
        
        result = []
        
        # 创建所有可能的组合
        def generate_ips(current_parts, pos_index=0):
            if pos_index >= len(wildcard_positions):
                result.append('.'.join(map(str, current_parts)))
                return
            
            position = wildcard_positions[pos_index]
            for i in range(256):
                new_parts = current_parts.copy()
                new_parts.insert(position, i)
                generate_ips(new_parts, pos_index + 1)
        
        generate_ips(base_parts)
        return result
    
    return []

def parse_port_range(port_range: str) -> List[int]:
    """
    解析端口范围字符串为端口列表
    
    Args:
        port_range: 端口范围字符串，支持以下格式:
            - 单个端口: 80
            - 端口范围: 80-100
            - 端口列表: 80,443,8080
            - 组合: 80-100,443,8000-8080
    
    Returns:
        端口列表
    """
    if not port_range:
        return []
    
    ports = []
    parts = port_range.split(',')
    
    for part in parts:
        part = part.strip()
        
        # 端口范围 (例如 80-100)
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 1 <= start <= end <= 65535:
                    ports.extend(range(start, end + 1))
            except ValueError:
                continue
        
        # 单个端口
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                continue
    
    return sorted(list(set(ports)))

def get_ip_by_hostname(hostname: str) -> List[str]:
    """
    通过主机名获取 IP 地址
    
    Args:
        hostname: 主机名或域名
    
    Returns:
        IP 地址列表
    """
    try:
        return socket.gethostbyname_ex(hostname)[2]
    except socket.gaierror:
        return []

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    检查指定 IP 和端口是否开放
    
    Args:
        ip: IP 地址
        port: 端口号
        timeout: 超时时间（秒）
    
    Returns:
        端口是否开放
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except (socket.error, socket.timeout, OverflowError, TypeError):
        return False

def ping(ip: str, count: int = 1, timeout: float = 1.0) -> Tuple[bool, float]:
    """
    Ping 指定 IP 地址
    
    Args:
        ip: IP 地址
        count: ping 次数
        timeout: 超时时间（秒）
    
    Returns:
        (成功标志, 响应时间(ms))
    """
    system = platform.system().lower()
    
    # 构建平台特定的 ping 命令
    if system == "windows":
        cmd = f"ping -n {count} -w {int(timeout * 1000)} {ip}"
        pattern = r"Average = (\d+)ms"
    else:  # Linux, Darwin (macOS)
        cmd = f"ping -c {count} -W {int(timeout)} {ip}"
        pattern = r"min/avg/max/[^=]+ = [^/]+/([^/]+)/[^/]+/[^/]+ ms"
    
    try:
        # 使用bytes模式读取，避免编码问题
        output = subprocess.check_output(cmd, shell=True, universal_newlines=False)
        
        # 尝试多种编码方式解码输出，确保能够处理各种字符集
        try:
            # 首先尝试UTF-8
            output_str = output.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            try:
                # 尝试系统默认编码
                output_str = output.decode(locale.getpreferredencoding(), errors='replace')
            except UnicodeDecodeError:
                try:
                    # 尝试latin-1（能解码所有可能的字节）
                    output_str = output.decode('latin-1', errors='replace')
                except UnicodeDecodeError:
                    # 最后的保障措施 - 使用ASCII并忽略所有非ASCII字符
                    output_str = output.decode('ascii', errors='ignore')
        
        # 提取平均响应时间
        match = re.search(pattern, output_str)
        if match:
            return True, float(match.group(1))
        
        # 命令成功但无法解析时间
        return True, 0.0
    except subprocess.CalledProcessError:
        return False, 0.0

def get_mac_address(ip: str) -> Optional[str]:
    """
    获取指定 IP 地址的 MAC 地址
    
    Args:
        ip: IP 地址
    
    Returns:
        MAC 地址字符串 或 None
    """
    system = platform.system().lower()
    
    if system == "windows":
        try:
            # 先进行 ping 以确保 IP 在 ARP 表中
            subprocess.call(f"ping -n 1 -w 1000 {ip}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # 获取 ARP 表，使用bytes模式读取，避免编码问题
            output = subprocess.check_output(f"arp -a {ip}", shell=True, universal_newlines=False)
            
            # 尝试多种编码方式解码输出
            try:
                # 首先尝试UTF-8
                output_str = output.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                try:
                    # 尝试系统默认编码
                    output_str = output.decode(locale.getpreferredencoding(), errors='replace')
                except UnicodeDecodeError:
                    try:
                        # 尝试latin-1（能解码所有可能的字节）
                        output_str = output.decode('latin-1', errors='replace')
                    except UnicodeDecodeError:
                        # 最后的保障措施 - 使用ASCII并忽略所有非ASCII字符
                        output_str = output.decode('ascii', errors='ignore')
            
            # 提取 MAC 地址
            matches = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output_str)
            if matches:
                return matches.group(0)
        except subprocess.CalledProcessError:
            pass
    else:  # Linux, Darwin (macOS)
        try:
            # 先进行 ping 以确保 IP 在 ARP 表中
            subprocess.call(f"ping -c 1 -W 1 {ip}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # 获取 ARP 表，使用bytes模式读取，避免编码问题
            if system == "darwin":  # macOS
                output = subprocess.check_output(f"arp -n {ip}", shell=True, universal_newlines=False)
            else:  # Linux
                output = subprocess.check_output(f"arp -n | grep '{ip} '", shell=True, universal_newlines=False)
            
            # 尝试多种编码方式解码输出
            try:
                # 首先尝试UTF-8
                output_str = output.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                try:
                    # 尝试系统默认编码
                    output_str = output.decode(locale.getpreferredencoding(), errors='replace')
                except UnicodeDecodeError:
                    try:
                        # 尝试latin-1（能解码所有可能的字节）
                        output_str = output.decode('latin-1', errors='replace')
                    except UnicodeDecodeError:
                        # 最后的保障措施 - 使用ASCII并忽略所有非ASCII字符
                        output_str = output.decode('ascii', errors='ignore')
            
            # 提取 MAC 地址
            matches = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output_str)
            if matches:
                return matches.group(0)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    return None

def tcp_ping(ip: str, port: int, timeout: float = 1.0) -> Tuple[bool, float]:
    """
    对指定 IP 和端口执行 TCP ping
    
    Args:
        ip: IP 地址
        port: 端口号
        timeout: 超时时间（秒）
    
    Returns:
        (成功标志, 响应时间(ms))
    """
    try:
        start_time = time.perf_counter()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            
            if result == 0:
                elapsed_time = (time.perf_counter() - start_time) * 1000  # 转换为毫秒
                return True, elapsed_time
    except (socket.error, socket.timeout, OverflowError, TypeError):
        pass
    
    return False, 0.0

import time
import threading

def scan_ports(ip: str, ports: List[int], timeout: float = 1.0, 
              max_threads: int = 10) -> Dict[int, Dict[str, Any]]:
    """
    扫描指定 IP 地址的多个端口
    
    Args:
        ip: IP 地址
        ports: 要扫描的端口列表
        timeout: 每个端口的超时时间（秒）
        max_threads: 最大线程数
    
    Returns:
        字典 {端口号: {"open": 是否开放, "time": 响应时间}}
    """
    results = {}
    lock = threading.Lock()
    
    def scan_port(port):
        is_open, response_time = tcp_ping(ip, port, timeout)
        with lock:
            results[port] = {
                "open": is_open,
                "time": response_time
            }
    
    # 创建线程池
    threads = []
    for port in ports:
        # 控制最大线程数
        while len(threads) >= max_threads:
            for t in threads[:]:
                if not t.is_alive():
                    threads.remove(t)
            time.sleep(0.01)
        
        thread = threading.Thread(target=scan_port, args=(port,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    
    return results 