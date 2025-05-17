#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
主机扫描模块
用于发现网络中的主机，支持 ICMP ping 和 TCP ping
"""

import concurrent.futures
import logging
import platform
import socket
import time
from typing import Dict, List, Any, Tuple, Optional

from core.base_scanner import BaseScanner, ScanResult
from utils.network import ping, get_mac_address, tcp_ping, parse_ip_range, is_valid_ip

class HostScanner(BaseScanner):
    """
    主机扫描模块
    用于发现和识别局域网或指定 IP 范围内的在线主机
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化主机扫描器"""
        super().__init__(config)
        self._stopped = False
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        valid_keys = {
            "ip_range",      # IP 范围，支持单 IP、CIDR、范围、通配符
            "ping_count",    # ping 次数
            "ping_timeout",  # ping 超时时间
            "tcp_ports",     # TCP ping 的端口列表
            "max_threads",   # 最大线程数
            "get_mac",       # 是否获取 MAC 地址
            "detect_os",     # 是否检测操作系统
            "scan_method"    # 扫描方法: icmp, tcp, all
        }
        
        required_keys = ["ip_range"]
        
        # 检查必要参数
        for key in required_keys:
            if key not in self.config:
                return False, f"缺少必要参数: {key}"
        
        # 检查 IP 范围格式
        ip_range = self.config.get("ip_range")
        if not ip_range:
            return False, "IP 范围不能为空"
        
        # 设置默认值
        if "ping_count" not in self.config:
            self.config["ping_count"] = 1
        
        if "ping_timeout" not in self.config:
            self.config["ping_timeout"] = 1.0
        
        if "tcp_ports" not in self.config:
            self.config["tcp_ports"] = [80, 443, 22, 445]
        elif isinstance(self.config["tcp_ports"], str):
            try:
                self.config["tcp_ports"] = [int(p.strip()) for p in self.config["tcp_ports"].split(",")]
            except ValueError:
                return False, "TCP 端口格式无效，应为逗号分隔的数字"
        
        if "max_threads" not in self.config:
            self.config["max_threads"] = 50
        
        if "get_mac" not in self.config:
            self.config["get_mac"] = True
        
        if "detect_os" not in self.config:
            self.config["detect_os"] = False
        
        if "scan_method" not in self.config:
            self.config["scan_method"] = "all"
        elif self.config["scan_method"] not in ["icmp", "tcp", "all"]:
            return False, "扫描方法无效，应为 icmp, tcp 或 all"
        
        return True, None
    
    def detect_os(self, ip: str) -> str:
        """
        检测目标主机的操作系统
        
        Args:
            ip: 目标 IP 地址
        
        Returns:
            操作系统信息
        """
        try:
            # 实现简单的 TTL 检测逻辑
            # 在实际项目中，可以使用更复杂的指纹识别方法
            success, _ = ping(ip, count=1, timeout=self.config["ping_timeout"])
            if not success:
                return "Unknown"
            
            # 这里只是一个简单示例，实际实现可能需要解析 ping 命令的 TTL 值
            # 或使用 nmap 等工具的 OS 检测功能
            return "Windows/Linux/MacOS"
        except Exception as e:
            self.logger.error(f"OS detection error for {ip}: {str(e)}")
            return "Unknown"
    
    def scan_host(self, ip: str) -> Dict[str, Any]:
        """
        扫描单个主机
        
        Args:
            ip: 目标 IP 地址
        
        Returns:
            主机信息字典
        """
        if self._stopped:
            return {}
        
        result = {
            "ip": ip,
            "status": "down",
            "response_time": 0,
            "mac_address": "",
            "hostname": "",
            "os": ""
        }
        
        try:
            # 检查扫描是否已经停止
            if self._stopped:
                return result
                
            scan_method = self.config["scan_method"]
            
            # ICMP Ping
            if scan_method in ["icmp", "all"]:
                try:
                    ping_count = self.config["ping_count"]
                    ping_timeout = self.config["ping_timeout"]
                    
                    success, response_time = ping(ip, count=ping_count, timeout=ping_timeout)
                    if success:
                        result["status"] = "up"
                        result["response_time"] = response_time
                except Exception as e:
                    self.logger.error(f"ICMP Ping {ip} 时出错: {str(e)}")
            
            # 如果已停止，返回当前结果
            if self._stopped:
                return result
            
            # TCP Ping (如果 ICMP 失败或指定了 TCP 扫描)
            if (scan_method == "tcp" or 
                (scan_method == "all" and result["status"] == "down")):
                
                for port in self.config["tcp_ports"]:
                    try:
                        success, response_time = tcp_ping(
                            ip, port, timeout=self.config["ping_timeout"]
                        )
                        if success:
                            result["status"] = "up"
                            result["response_time"] = response_time
                            break
                    except Exception as e:
                        self.logger.error(f"TCP Ping {ip}:{port} 时出错: {str(e)}")
                    
                    # 检查扫描是否已经停止
                    if self._stopped:
                        return result
            
            # 如果主机在线，获取更多信息
            if result["status"] == "up":
                # 获取主机名
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    result["hostname"] = hostname
                except (socket.herror, socket.gaierror, UnicodeError, UnicodeDecodeError):
                    result["hostname"] = ""
                except Exception as e:
                    self.logger.error(f"获取 {ip} 的主机名时出错: {str(e)}")
                    result["hostname"] = ""
                
                # 如果已停止，返回当前结果
                if self._stopped:
                    return result
                
                # 获取 MAC 地址
                if self.config["get_mac"]:
                    try:
                        mac = get_mac_address(ip)
                        if mac:
                            result["mac_address"] = mac
                    except (UnicodeError, UnicodeDecodeError) as e:
                        self.logger.error(f"解码 {ip} 的MAC地址时出错: {str(e)}")
                        result["mac_address"] = ""
                    except Exception as e:
                        self.logger.error(f"获取 {ip} 的MAC地址时出错: {str(e)}")
                        result["mac_address"] = ""
                
                # 如果已停止，返回当前结果
                if self._stopped:
                    return result
                
                # 检测操作系统
                if self.config["detect_os"]:
                    try:
                        result["os"] = self.detect_os(ip)
                    except (UnicodeError, UnicodeDecodeError) as e:
                        self.logger.error(f"解码 {ip} 的操作系统信息时出错: {str(e)}")
                        result["os"] = "Unknown"
                    except Exception as e:
                        self.logger.error(f"检测 {ip} 的操作系统时出错: {str(e)}")
                        result["os"] = "Unknown"
        
        except (UnicodeError, UnicodeDecodeError) as e:
            self.logger.error(f"扫描 {ip} 时出现编码错误: {str(e)}")
            # 即使出错也返回基本信息，避免中断整个扫描
        except Exception as e:
            self.logger.error(f"扫描 {ip} 时出错: {str(e)}")
            # 即使出错也返回基本信息，避免中断整个扫描
        
        return result
    
    def run_scan(self) -> ScanResult:
        """
        执行主机扫描
        
        Returns:
            扫描结果
        """
        self._stopped = False
        ip_range = self.config["ip_range"]
        
        # 解析IP范围，支持逗号分隔的列表
        ip_list = []
        if isinstance(ip_range, str) and ',' in ip_range:
            for item in ip_range.split(','):
                item = item.strip()
                if not item:
                    continue
                
                if is_valid_ip(item):
                    ip_list.append(item)
                else:
                    parsed = parse_ip_range(item)
                    if parsed:
                        ip_list.extend(parsed)
        else:
            ip_list = parse_ip_range(ip_range)
        
        if not ip_list:
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"无法解析 IP 范围: {self.config['ip_range']}"
            )
        
        total_ip_count = len(ip_list)
        self.logger.info(f"开始扫描 {total_ip_count} 个目标 IP")
        
        # 更新进度信息
        self.update_progress(10, f"准备扫描 {total_ip_count} 个目标 IP")
        
        results = []
        max_threads = min(self.config["max_threads"], total_ip_count)
        
        try:
            self.update_progress(15, f"创建扫描任务，使用 {max_threads} 个线程")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_ip = {
                    executor.submit(self.scan_host, ip): ip for ip in ip_list
                }
                
                completed = 0
                online_hosts = 0
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        host_result = future.result()
                        if host_result and host_result.get('status') == 'up':
                            results.append(host_result)
                            online_hosts += 1
                            self.logger.debug(f"Found online host: {ip}")
                            # 发送找到主机的详细信息，用于实时更新拓扑图
                            self.update_progress(
                                min(15 + int(completed * 80 / total_ip_count), 95),
                                f"Found host {ip} ({host_result.get('hostname', '')})"
                            )
                    except Exception as e:
                        self.logger.error(f"扫描 {ip} 时出错: {str(e)}")
                    
                    # 更新进度
                    completed += 1
                    if completed % (max(1, total_ip_count // 10)) == 0 or completed == total_ip_count:
                        progress = min(15 + int(completed * 80 / total_ip_count), 95)
                        self.update_progress(
                            progress, 
                            f"已扫描 {completed}/{total_ip_count} 个主机，发现 {online_hosts} 个在线主机"
                        )
        
        except KeyboardInterrupt:
            self._stopped = True
            self.logger.warning("扫描被用户中断")
            return ScanResult(
                success=False,
                data=results,
                error_msg="扫描被用户中断"
            )
        
        # 统计结果
        online_count = len(results)
        self.logger.info(f"扫描完成，发现 {online_count}/{total_ip_count} 个在线主机")
        self.update_progress(95, f"扫描完成，正在整理结果")
        
        result = ScanResult(
            success=True,
            data=results
        )
        
        # 添加元数据
        result.metadata = {
            'total_scanned': total_ip_count,
            'online_hosts': online_count
        }
        
        return result
    
    def stop(self) -> None:
        """停止扫描"""
        self._stopped = True
        super().stop() 