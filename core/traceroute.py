#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
路由追踪模块
提供多平台的路由跟踪功能，支持 ICMP 和 UDP 模式
"""

import concurrent.futures
import logging
import platform
import re
import socket
import subprocess
import time
from typing import Dict, List, Any, Tuple, Optional

from core.base_scanner import BaseScanner, ScanResult
from utils.network import is_valid_ip

class Traceroute(BaseScanner):
    """
    路由追踪模块
    用于跟踪数据包从源主机到目标主机经过的网络路径
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化路由追踪模块"""
        super().__init__(config)
        self._stopped = False
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        valid_keys = {
            "target",        # 目标主机（IP 或域名）
            "max_hops",      # 最大跳数
            "timeout",       # 超时时间
            "method",        # 追踪方法: icmp, udp
            "port",          # UDP 端口
            "probe_count",   # 每跳探测次数
            "resolve",       # 是否解析主机名
            "concurrent"     # 是否并发探测
        }
        
        required_keys = ["target"]
        
        # 检查必要参数
        for key in required_keys:
            if key not in self.config:
                return False, f"缺少必要参数: {key}"
        
        # 验证目标
        target = self.config["target"]
        if not is_valid_ip(target):
            try:
                socket.gethostbyname(target)
            except socket.gaierror:
                return False, f"无效的目标: {target}"
        
        # 设置默认值
        if "max_hops" not in self.config:
            self.config["max_hops"] = 30
        
        if "timeout" not in self.config:
            self.config["timeout"] = 1.0
        
        if "method" not in self.config:
            # 默认方法根据平台决定
            system = platform.system().lower()
            if system == "windows":
                self.config["method"] = "icmp"  # Windows 使用 ICMP
            else:
                self.config["method"] = "udp"   # Linux/MacOS 默认使用 UDP
        elif self.config["method"] not in ["icmp", "udp"]:
            return False, f"无效的追踪方法: {self.config['method']}"
        
        if "port" not in self.config:
            self.config["port"] = 33434  # 标准 traceroute 端口
        
        if "probe_count" not in self.config:
            self.config["probe_count"] = 3
        
        if "resolve" not in self.config:
            self.config["resolve"] = True
        
        if "concurrent" not in self.config:
            self.config["concurrent"] = False
        
        return True, None
    
    def resolve_hostname(self, ip: str) -> str:
        """
        解析 IP 的主机名
        
        Args:
            ip: IP 地址
        
        Returns:
            主机名或原始 IP（如果解析失败）
        """
        if not self.config["resolve"] or not ip:
            return ip
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return ip
    
    def system_traceroute(self) -> List[Dict[str, Any]]:
        """
        使用系统命令执行路由追踪
        
        Returns:
            追踪结果列表
        """
        target = self.config["target"]
        max_hops = self.config["max_hops"]
        timeout = self.config["timeout"]
        method = self.config["method"]
        probe_count = self.config["probe_count"]
        port = self.config["port"]
        
        system = platform.system().lower()
        cmd = []
        
        # 根据不同平台构建命令
        if system == "windows":
            cmd = ["tracert"]
            if not self.config["resolve"]:
                cmd.append("-d")
            cmd.extend(["-h", str(max_hops)])
            cmd.extend(["-w", str(int(timeout * 1000))])
            cmd.append(target)
        
        elif system == "darwin":  # macOS
            cmd = ["traceroute"]
            if not self.config["resolve"]:
                cmd.append("-n")
            cmd.extend(["-m", str(max_hops)])
            cmd.extend(["-w", str(int(timeout))])
            cmd.extend(["-q", str(probe_count)])
            
            if method == "icmp":
                cmd.append("-I")  # ICMP 模式
            else:
                cmd.extend(["-p", str(port)])  # UDP 端口
            
            cmd.append(target)
        
        else:  # Linux
            cmd = ["traceroute"]
            if not self.config["resolve"]:
                cmd.append("-n")
            cmd.extend(["-m", str(max_hops)])
            cmd.extend(["-w", str(int(timeout))])
            cmd.extend(["-q", str(probe_count)])
            
            if method == "icmp":
                cmd.append("-I")  # ICMP 模式
            else:
                cmd.extend(["-p", str(port)])  # UDP 端口
            
            cmd.append(target)
        
        self.logger.debug(f"执行系统命令: {' '.join(cmd)}")
        
        try:
            # 执行系统命令
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                universal_newlines=True
            )
            
            results = []
            hop = 0
            
            # 逐行处理输出
            for line in process.stdout:
                line = line.strip()
                
                if self._stopped:
                    process.terminate()
                    break
                
                # 跳过标题行
                if "traceroute to" in line or "Tracing route to" in line or hop == 0:
                    if hop == 0:
                        hop = 1
                    continue
                
                self.logger.debug(f"原始输出: {line}")
                
                # 提取跳数和 IP
                if system == "windows":
                    # Windows 格式: "  1     1 ms     1 ms     1 ms  192.168.1.1"
                    match = re.match(r"^\s*(\d+)(?:\s+|\*+)(?:<?(\d+)(?:ms)?)?(?:\s+|\*+)(?:<?(\d+)(?:ms)?)?(?:\s+|\*+)(?:<?(\d+)(?:ms)?)?\s+([\w\.-]+|\*)", line)
                    if match:
                        hop_num = int(match.group(1))
                        times = [t for t in [match.group(2), match.group(3), match.group(4)] if t]
                        ip = match.group(5)
                        
                        if ip == "*":
                            ip = ""
                        
                        hop_result = {
                            "hop": hop_num,
                            "ip": ip,
                            "hostname": self.resolve_hostname(ip) if ip and ip != "*" else "",
                            "times": [float(t) for t in times] if times else [],
                            "avg_time": sum([float(t) for t in times]) / len(times) if times else 0,
                            "loss_rate": 1.0 - (len(times) / 3.0)
                        }
                        
                        results.append(hop_result)
                        hop = hop_num
                
                else:  # Linux/macOS
                    # Unix 格式: " 1  192.168.1.1 (192.168.1.1)  1.123 ms  1.456 ms  1.789 ms"
                    match = re.match(r"^\s*(\d+)\s+(?:([\w\.-]+)?\s+\(([\d\.]+)\)|(\*))(?:\s+(\d+\.\d+)(?:\s+ms))?(?:\s+(\d+\.\d+)(?:\s+ms))?(?:\s+(\d+\.\d+)(?:\s+ms))?", line)
                    
                    if match:
                        hop_num = int(match.group(1))
                        hostname = match.group(2) or ""
                        ip = match.group(3) or ""
                        if match.group(4) == "*":
                            ip = ""
                            hostname = ""
                        
                        times = [t for t in [match.group(5), match.group(6), match.group(7)] if t]
                        
                        hop_result = {
                            "hop": hop_num,
                            "ip": ip,
                            "hostname": hostname or self.resolve_hostname(ip) if ip else "",
                            "times": [float(t) for t in times] if times else [],
                            "avg_time": sum([float(t) for t in times]) / len(times) if times else 0,
                            "loss_rate": 1.0 - (len(times) / 3.0)
                        }
                        
                        results.append(hop_result)
                        hop = hop_num
            
            process.wait()
            
            return results
        
        except (subprocess.SubprocessError, ValueError, IndexError) as e:
            self.logger.error(f"系统命令执行失败: {str(e)}")
            return []
    
    def python_traceroute(self) -> List[Dict[str, Any]]:
        """
        使用 Python 实现路由追踪
        当系统命令不可用或需要更细粒度控制时使用
        
        Returns:
            追踪结果列表
        """
        # 这里是一个简化实现，真实项目中可以使用 scapy 等库实现更完整的功能
        self.logger.warning("Python 实现的路由追踪功能尚未完成，请使用系统命令")
        return []
    
    def run_scan(self) -> ScanResult:
        """
        执行路由追踪
        
        Returns:
            扫描结果
        """
        self._stopped = False
        target = self.config["target"]
        
        self.logger.info(f"开始对 {target} 进行路由追踪")
        
        # 执行系统命令
        results = self.system_traceroute()
        
        if not results and not self._stopped:
            self.logger.warning("系统命令追踪失败，尝试使用 Python 实现")
            results = self.python_traceroute()
        
        # 添加目标信息
        if results:
            # 获取目标 IP
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                target_ip = target if is_valid_ip(target) else ""
            
            # 检查最后一跳是否是目标
            last_hop = results[-1]
            if last_hop["ip"] != target_ip:
                # 如果最后一跳不是目标，可能是追踪未完成或目标不响应
                self.logger.info(f"追踪未能到达目标 {target}({target_ip})")
        
        self.logger.info(f"路由追踪完成，共 {len(results)} 跳")
        
        return ScanResult(
            success=len(results) > 0,
            data=results,
            error_msg="" if results else "追踪失败，未获取到有效路径"
        )
    
    def stop(self) -> None:
        """停止追踪"""
        self._stopped = True
        super().stop() 