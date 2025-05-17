#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP Ping 模块
用于检测TCP端口连通性并测量响应时间
"""

import concurrent.futures
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional

from core.base_scanner import BaseScanner, ScanResult
from utils.network import tcp_ping, parse_ip_range, parse_port_range, is_valid_ip

class TcpPing(BaseScanner):
    """
    TCP Ping 模块
    通过尝试建立TCP连接检测主机端口可达性和响应时间
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化 TCP Ping 模块"""
        super().__init__(config)
        self._stopped = False
        self._lock = threading.Lock()  # 数据同步锁
        self._results = []             # 扫描结果
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        valid_keys = {
            "targets",        # 目标主机（IP 或 IP 范围）
            "ports",          # 端口或端口范围
            "count",          # ping 次数，0表示持续ping，默认为 4
            "interval",       # ping 间隔（秒）
            "timeout",        # 连接超时时间
            "max_threads",    # 最大线程数
            "threshold",      # 报警阈值（ms），超过此值记为异常
            "continuous",     # 是否持续ping，为True时忽略count值
        }
        
        required_keys = ["targets", "ports"]
        
        # 检查必要参数
        for key in required_keys:
            if key not in self.config:
                return False, f"缺少必要参数: {key}"
        
        # 设置默认值
        if "count" not in self.config:
            self.config["count"] = 4
        
        if "interval" not in self.config:
            self.config["interval"] = 1.0
        
        if "timeout" not in self.config:
            self.config["timeout"] = 2.0
        
        if "max_threads" not in self.config:
            self.config["max_threads"] = 20
        
        if "threshold" not in self.config:
            self.config["threshold"] = 200.0  # 200ms
        
        if "continuous" not in self.config:
            self.config["continuous"] = False
        
        return True, None
    
    def parse_targets(self) -> List[str]:
        """
        解析目标列表
        
        Returns:
            目标 IP 列表
        """
        targets = self.config["targets"]
        
        # 如果是字符串，可能是单个 IP 或 IP 范围
        if isinstance(targets, str):
            # 处理逗号分隔的列表
            if ',' in targets:
                result = []
                for target in targets.split(','):
                    target = target.strip()
                    if not target:
                        continue
                    
                    if is_valid_ip(target):
                        result.append(target)
                    else:
                        parsed = parse_ip_range(target)
                        if parsed:
                            result.extend(parsed)
                
                if not result:
                    self.logger.error(f"无法解析目标: {targets}，未找到有效IP")
                
                return result
            else:
                # 单个IP或IP范围
                return parse_ip_range(targets)
        
        # 如果是列表，处理每个项目
        if isinstance(targets, list):
            result = []
            for target in targets:
                if isinstance(target, str):
                    if ',' in target:
                        # 处理列表中的逗号分隔项
                        for sub_target in target.split(','):
                            sub_target = sub_target.strip()
                            if not sub_target:
                                continue
                            
                            if is_valid_ip(sub_target):
                                result.append(sub_target)
                            else:
                                result.extend(parse_ip_range(sub_target))
                    else:
                        result.extend(parse_ip_range(target))
                else:
                    self.logger.warning(f"无效的目标格式: {target}")
            return result
        
        self.logger.error(f"无法解析目标: {targets}")
        return []
    
    def parse_ports(self) -> List[int]:
        """
        解析端口列表
        
        Returns:
            端口列表
        """
        ports = self.config["ports"]
        
        # 如果是整数
        if isinstance(ports, int):
            if 1 <= ports <= 65535:
                return [ports]
            return []
        
        # 如果是字符串，可能是端口范围
        if isinstance(ports, str):
            return parse_port_range(ports)
        
        # 如果是列表
        if isinstance(ports, list):
            result = []
            for port in ports:
                if isinstance(port, int) and 1 <= port <= 65535:
                    result.append(port)
                elif isinstance(port, str):
                    result.extend(parse_port_range(port))
            return sorted(list(set(result)))
        
        return []
    
    def tcp_ping_host(self, ip: str, port: int) -> Dict[str, Any]:
        """
        TCP Ping 单个主机的单个端口
        
        Args:
            ip: 目标 IP
            port: 目标端口
        
        Returns:
            结果字典
        """
        if self._stopped:
            return {}
        
        timestamp = datetime.now().isoformat()
        success, response_time = tcp_ping(ip, port, timeout=self.config["timeout"])
        
        # 判断是否超过阈值
        is_slow = success and response_time > self.config["threshold"]
        status = "open" if success else "closed"
        
        result = {
            "ip": ip,
            "port": port,
            "timestamp": timestamp,
            "status": status,
            "response_time": response_time,
            "is_slow": is_slow
        }
        
        return result
    
    def scan_target(self, ip: str, ports: List[int]) -> List[Dict[str, Any]]:
        """
        扫描单个目标的多个端口
        
        Args:
            ip: 目标 IP
            ports: 端口列表
        
        Returns:
            结果列表
        """
        if self._stopped:
            return []
        
        results = []
        count = self.config["count"]
        interval = self.config["interval"]
        continuous = self.config["continuous"]
        
        # 当continuous为True或count为0时，持续ping
        if continuous or count == 0:
            count = float('inf')  # 无限循环
        
        iteration = 0
        while iteration < count and not self._stopped:
            iteration += 1
            
            start_time = time.time()
            batch_results = []
            
            # 使用线程池并发扫描端口
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["max_threads"]) as executor:
                future_to_port = {
                    executor.submit(self.tcp_ping_host, ip, port): port for port in ports
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result:
                            batch_results.append(result)
                            
                            # 实时添加到_results，用于UI实时更新
                            with self._lock:
                                self._results.append(result)
                            
                    except Exception as e:
                        self.logger.error(f"TCP Ping {ip}:{port} 时出错: {str(e)}")
            
            results.extend(batch_results)
            
            # 更新进度信息
            if continuous or count > 1:
                progress_msg = f"正在Ping {ip} 上的 {len(ports)} 个端口 (第 {iteration} 次"
                if continuous:
                    progress_msg += "/持续模式)"
                else:
                    progress_msg += f"/{count})"
                    
                # 计算百分比，持续模式下固定为50%
                if continuous:
                    percent = 50
                else:
                    percent = min(95, int((iteration / count) * 100))
                    
                self.update_progress(percent, progress_msg)
            
            # 检查是否需要继续
            if self._stopped or iteration >= count:
                break
            
            # 计算等待时间
            elapsed = time.time() - start_time
            wait_time = max(0, interval - elapsed)
            
            if wait_time > 0:
                time.sleep(wait_time)
        
        return results
    
    def run_scan(self) -> ScanResult:
        """
        执行 TCP Ping 扫描
        
        Returns:
            扫描结果
        """
        self._stopped = False
        self._results = []
        
        targets = self.parse_targets()
        if not targets:
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"无法解析目标: {self.config['targets']}"
            )
        
        ports = self.parse_ports()
        if not ports:
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"无法解析端口: {self.config['ports']}"
            )
        
        # 记录扫描信息
        target_count = len(targets)
        port_count = len(ports)
        ping_count = self.config["count"]
        continuous = self.config["continuous"]
        
        # 持续模式的日志输出
        if continuous or ping_count == 0:
            self.logger.info(
                f"开始持续 TCP Ping 扫描，目标: {target_count} 个主机，"
                f"端口: {port_count} 个"
            )
        else:
            self.logger.info(
                f"开始 TCP Ping 扫描，目标: {target_count} 个主机，"
                f"端口: {port_count} 个，重复: {ping_count} 次"
            )
        
        all_results = []
        scanner = self  # 保存scanner引用供线程使用
        
        # 创建扫描线程以支持持续模式
        class ScanThread(threading.Thread):
            def __init__(self, scanner):
                super().__init__()
                self.scanner = scanner
                self.daemon = True
                
            def run(self):
                # 循环计数器，用于持续模式的进度更新
                iteration = 0
                
                # 对每个目标进行扫描
                while not self.scanner._stopped:
                    iteration += 1
                    
                    # 非持续模式只执行一次
                    if not continuous and iteration > 1:
                        break
                    
                    # 进度更新，持续模式下显示迭代次数
                    if continuous:
                        self.scanner.update_progress(50, f"持续TCP Ping扫描 (第 {iteration} 次迭代)")
                    
                    for i, ip in enumerate(targets):
                        if self.scanner._stopped:
                            break
                        
                        self.scanner.logger.info(f"扫描目标 {i+1}/{target_count}: {ip}")
                        
                        # 扫描当前目标的所有端口
                        results = self.scanner.scan_target(ip, ports)
                        with self.scanner._lock:
                            all_results.extend(results)
                            
                            # 在持续模式下，为了防止内存占用过大，保留最近1000条结果
                            if continuous and len(self.scanner._results) > 1000:
                                self.scanner._results = self.scanner._results[-1000:]
        
        # 如果是持续模式，使用单独的线程进行扫描
        if continuous or ping_count == 0:
            scan_thread = ScanThread(scanner)
            scan_thread.start()
            
            # 等待线程启动
            time.sleep(0.1)
            
            # 创建一个初始结果，用于UI展示
            return ScanResult(
                success=True,
                data=self._results,  # 初始为空列表，会由UI不断获取self._results进行更新
                metadata={
                    "target_count": target_count,
                    "port_count": port_count,
                    "ping_count": "持续",
                    "continuous": True,
                    "stats": {"total_checks": 0, "hosts": []}
                }
            )
        
        # 非持续模式，直接在当前线程扫描
        else:
            # 对每个目标进行扫描
            for i, ip in enumerate(targets):
                if self._stopped:
                    break
                
                self.logger.info(f"扫描目标 {i+1}/{target_count}: {ip}")
                
                # 扫描当前目标的所有端口
                results = self.scan_target(ip, ports)
                all_results.extend(results)
        
        # 统计结果
        success_count = sum(1 for r in all_results if r["status"] == "open")
        slow_count = sum(1 for r in all_results if r["is_slow"])
        
        self.logger.info(
            f"TCP Ping 扫描完成，共扫描 {len(all_results)} 次，"
            f"{success_count} 次成功，{slow_count} 次响应慢"
        )
        
        # 按 IP 和端口分组统计
        stats = self.analyze_results(all_results)
        
        result = ScanResult(
            success=True,
            data=all_results,
            metadata={
                "target_count": target_count,
                "port_count": port_count,
                "ping_count": ping_count,
                "success_count": success_count,
                "slow_count": slow_count,
                "stats": stats
            }
        )
        
        return result
    
    def analyze_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析扫描结果
        
        Args:
            results: 扫描结果列表
        
        Returns:
            分析结果字典
        """
        if not results:
            return {}
        
        # 按 IP 和端口分组
        hosts = {}
        
        for result in results:
            ip = result["ip"]
            port = result["port"]
            key = f"{ip}:{port}"
            
            if key not in hosts:
                hosts[key] = {
                    "ip": ip,
                    "port": port,
                    "total": 0,
                    "open": 0,
                    "closed": 0,
                    "slow": 0,
                    "avg_time": 0,
                    "min_time": float('inf'),
                    "max_time": 0,
                    "last_status": "unknown",
                    "last_check": None
                }
            
            host = hosts[key]
            host["total"] += 1
            
            if result["status"] == "open":
                host["open"] += 1
                response_time = result["response_time"]
                
                # 更新时间统计
                if response_time < host["min_time"]:
                    host["min_time"] = response_time
                if response_time > host["max_time"]:
                    host["max_time"] = response_time
                
                # 累计平均时间
                host["avg_time"] = (host["avg_time"] * (host["open"] - 1) + response_time) / host["open"]
                
                if result["is_slow"]:
                    host["slow"] += 1
            else:
                host["closed"] += 1
            
            host["last_status"] = result["status"]
            host["last_check"] = result["timestamp"]
        
        # 处理特殊情况
        for key, host in hosts.items():
            # 修正可能的无效最小值
            if host["min_time"] == float('inf'):
                host["min_time"] = 0
            
            # 计算可用性
            if host["total"] > 0:
                host["availability"] = (host["open"] / host["total"]) * 100
            else:
                host["availability"] = 0
            
            # 计算延迟稳定性 (抖动)
            if "jitter" not in host:
                host["jitter"] = 0
        
        return {
            "total_checks": len(results),
            "hosts": list(hosts.values())
        }
    
    def stop(self) -> None:
        """停止扫描"""
        self.logger.info("TCP Ping 扫描正在停止")
        self._stopped = True
        
        # 记录停止事件
        self.logger.debug(f"TCP Ping 扫描停止标志已设置: {self._stopped}")
        
        # 确保调用父类的stop方法
        super().stop()
        
        self.logger.info("TCP Ping 扫描已停止") 