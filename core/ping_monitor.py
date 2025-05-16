#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ping 监控模块
用于监控主机状态，持续 ping 并记录结果
"""

import concurrent.futures
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional

from core.base_scanner import BaseScanner, ScanResult
from utils.network import ping, parse_ip_range, is_valid_ip

class PingMonitor(BaseScanner):
    """
    Ping 监控模块
    用于持续监控主机状态，支持多主机并发监控
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化 Ping 监控模块"""
        super().__init__(config)
        self._stopped = False
        self._lock = threading.Lock()  # 数据同步锁
        self._results = []             # 监控结果
        self._monitor_thread = None    # 监控线程
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        valid_keys = {
            "targets",        # 目标主机（IP 或 IP 范围）
            "interval",       # 监控间隔（秒）
            "count",          # 监控次数，0 表示持续监控
            "timeout",        # ping 超时时间
            "max_threads",    # 最大线程数
            "threshold",      # 报警阈值（ms），超过此值记为异常
            "loss_threshold", # 丢包阈值（0-1），超过此值记为异常
            "resolve",        # 是否解析主机名
            "save_result"     # 是否保存结果
        }
        
        required_keys = ["targets"]
        
        # 检查必要参数
        for key in required_keys:
            if key not in self.config:
                return False, f"缺少必要参数: {key}"
        
        # 设置默认值
        if "interval" not in self.config:
            self.config["interval"] = 5.0
        
        if "count" not in self.config:
            self.config["count"] = 0  # 0 表示持续监控
        
        if "timeout" not in self.config:
            self.config["timeout"] = 1.0
        
        if "max_threads" not in self.config:
            self.config["max_threads"] = 10
        
        if "threshold" not in self.config:
            self.config["threshold"] = 200.0  # 200ms
        
        if "loss_threshold" not in self.config:
            self.config["loss_threshold"] = 0.2  # 20% 丢包率
        
        if "resolve" not in self.config:
            self.config["resolve"] = True
        
        if "save_result" not in self.config:
            self.config["save_result"] = True
        
        return True, None
    
    def ping_host(self, ip: str) -> Dict[str, Any]:
        """
        Ping 单个主机
        
        Args:
            ip: 目标 IP
        
        Returns:
            结果字典
        """
        if self._stopped:
            return {}
        
        timestamp = datetime.now().isoformat()
        success, response_time = ping(ip, count=1, timeout=self.config["timeout"])
        
        # 判断是否超过阈值
        is_slow = success and response_time > self.config["threshold"]
        status = "up" if success else "down"
        
        result = {
            "ip": ip,
            "timestamp": timestamp,
            "status": status,
            "response_time": response_time,
            "is_slow": is_slow
        }
        
        return result
    
    def monitor_thread(self) -> None:
        """
        监控线程函数
        持续监控所有目标主机
        """
        targets = self.parse_targets()
        count = self.config["count"]
        interval = self.config["interval"]
        max_threads = min(self.config["max_threads"], 20)  # 限制最大线程数为20
        
        # 对大量IP进行批处理，避免一次创建过多线程
        batch_size = min(50, len(targets))  # 每批最多处理50个IP
        
        current_count = 0
        
        while not self._stopped and (count == 0 or current_count < count):
            start_time = time.time()
            batch_results = []
            
            # 将目标分成多个批次处理
            for batch_start in range(0, len(targets), batch_size):
                batch_end = min(batch_start + batch_size, len(targets))
                batch_targets = targets[batch_start:batch_end]
                
                # 使用线程池并发 ping 当前批次的目标
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                    future_to_ip = {
                        executor.submit(self.ping_host, ip): ip for ip in batch_targets
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            result = future.result()
                            if result:
                                batch_results.append(result)
                        except Exception as e:
                            self.logger.error(f"Ping {ip} 时出错: {str(e)}")
                
                # 每批次处理完后稍微暂停，避免系统资源占用过高
                if not self._stopped and batch_end < len(targets):
                    time.sleep(0.1)
            
            # 更新结果
            with self._lock:
                self._results.extend(batch_results)
            
            # 统计结果
            up_count = sum(1 for r in batch_results if r["status"] == "up")
            slow_count = sum(1 for r in batch_results if r["is_slow"])
            
            self.logger.info(
                f"监控批次 {current_count + 1}: "
                f"{up_count}/{len(targets)} 在线, "
                f"{slow_count}/{max(1, up_count)} 缓慢"
            )
            
            # 增加计数
            current_count += 1
            
            # 计算下一次检查时间并等待
            elapsed = time.time() - start_time
            wait_time = max(0, interval - elapsed)
            
            if wait_time > 0 and not self._stopped and (count == 0 or current_count < count):
                time.sleep(wait_time)
    
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
    
    def analyze_results(self) -> Dict[str, Any]:
        """
        分析监控结果
        
        Returns:
            分析报告字典
        """
        with self._lock:
            results = self._results.copy()
        
        if not results:
            return {
                "total_checks": 0,
                "hosts": {}
            }
        
        # 按主机分组
        hosts = {}
        for result in results:
            ip = result["ip"]
            if ip not in hosts:
                hosts[ip] = {
                    "total": 0,
                    "up": 0,
                    "down": 0,
                    "slow": 0,
                    "avg_time": 0,
                    "min_time": float('inf'),
                    "max_time": 0,
                    "last_status": "unknown",
                    "last_check": None,
                    "checks": []
                }
            
            host = hosts[ip]
            host["total"] += 1
            host["checks"].append(result)
            
            if result["status"] == "up":
                host["up"] += 1
                response_time = result["response_time"]
                
                # 更新时间统计
                if response_time < host["min_time"]:
                    host["min_time"] = response_time
                if response_time > host["max_time"]:
                    host["max_time"] = response_time
                
                # 累计平均时间
                host["avg_time"] = (host["avg_time"] * (host["up"] - 1) + response_time) / host["up"]
                
                if result["is_slow"]:
                    host["slow"] += 1
            else:
                host["down"] += 1
            
            host["last_status"] = result["status"]
            host["last_check"] = result["timestamp"]
        
        # 为每个主机计算统计信息
        for ip, host in hosts.items():
            # 修正可能的无效最小值
            if host["min_time"] == float('inf'):
                host["min_time"] = 0
            
            # 计算可用性和丢包率
            if host["total"] > 0:
                host["availability"] = host["up"] / host["total"] * 100
                host["loss_rate"] = host["down"] / host["total"]
            else:
                host["availability"] = 0
                host["loss_rate"] = 1.0
            
            # 计算延迟稳定性 (抖动)
            if host["up"] > 1:
                times = [r["response_time"] for r in host["checks"] if r["status"] == "up"]
                if times:
                    import statistics
                    try:
                        host["jitter"] = statistics.stdev(times)
                    except statistics.StatisticsError:
                        host["jitter"] = 0
                else:
                    host["jitter"] = 0
            else:
                host["jitter"] = 0
        
        return {
            "total_checks": len(results),
            "hosts": hosts
        }
    
    def run_scan(self) -> ScanResult:
        """
        执行 Ping 监控
        
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
        
        target_count = len(targets)
        
        # 记录大量IP的警告日志
        if target_count > 100:
            self.logger.warning(f"Ping监控目标数量较大 ({target_count} 个IP)，可能影响性能")
        
        self.logger.info(f"开始 Ping 监控，目标: {target_count} 个主机，间隔: {self.config['interval']}秒")
        
        # 启动监控线程
        self._monitor_thread = threading.Thread(target=self.monitor_thread)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        
        # 非阻塞模式下，直接返回初始状态
        if self.config["count"] == 0:
            # 不记录"Scan completed"日志，因为监控仍在进行中
            result = ScanResult(
                success=True,
                data=[{
                    "status": "running",
                    "message": f"监控已启动，目标: {target_count} 个主机，间隔: {self.config['interval']}秒",
                    "targets": target_count
                }]
            )
            
            # 添加元数据
            result.metadata = {
                "target_count": target_count,
                "interval": self.config["interval"],
                "mode": "continuous"
            }
            
            return result
        
        # 阻塞模式下，等待监控完成
        self._monitor_thread.join()
        
        # 分析结果
        analysis = self.analyze_results()
        
        self.logger.info(f"Ping 监控完成，共 {analysis['total_checks']} 次检查")
        
        result = ScanResult(
            success=True,
            data=[analysis]
        )
        
        # 添加元数据
        result.metadata = {
            "target_count": target_count,
            "interval": self.config["interval"],
            "mode": "limited",
            "total_checks": analysis.get("total_checks", 0)
        }
        
        return result
    
    def get_results(self) -> List[Dict[str, Any]]:
        """
        获取当前监控结果
        
        Returns:
            结果列表
        """
        with self._lock:
            return self._results.copy()
    
    def get_status(self) -> Dict[str, Any]:
        """
        获取监控状态
        
        Returns:
            状态字典
        """
        is_running = self._monitor_thread is not None and self._monitor_thread.is_alive()
        
        return {
            "running": is_running,
            "targets": len(self.parse_targets()),
            "interval": self.config["interval"],
            "count": self.config["count"],
            "current_results": len(self._results)
        }
    
    def stop(self) -> None:
        """停止监控"""
        self._stopped = True
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)
        
        self.logger.info("Ping 监控已停止")
        super().stop() 