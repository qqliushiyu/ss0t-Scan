#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
端口扫描模块
用于扫描目标主机的开放端口，支持服务识别和 Banner 获取
"""

import concurrent.futures
import socket
import threading
import time
from typing import Dict, List, Any, Tuple, Optional

from core.base_scanner import BaseScanner, ScanResult
from utils.network import parse_ip_range, parse_port_range, is_port_open

# 确保类名与文件名匹配，方便导入
class PortScanner(BaseScanner):
    """
    端口扫描模块
    用于扫描目标主机的开放端口、检测运行的服务和获取 Banner 信息
    """
    
    VERSION = "1.0.0"
    
    # 常见端口服务
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化端口扫描器"""
        super().__init__(config)
        self._stopped = False
        self._scan_lock = threading.Lock()
        self._scan_count = 0
        self._total_ports = 0
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        valid_keys = {
            "target",        # 目标 IP 或 IP 范围
            "ports",         # 端口范围
            "timeout",       # 超时时间
            "max_threads",   # 最大线程数
            "get_banner",    # 是否获取 Banner
            "get_service",   # 是否识别服务
            "scan_delay"     # 扫描延迟 (ms)
        }
        
        required_keys = ["target"]
        
        # 检查必要参数
        for key in required_keys:
            if key not in self.config:
                return False, f"缺少必要参数: {key}"
        
        # 设置默认值
        if "ports" not in self.config:
            # 使用一些常见端口
            self.config["ports"] = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"
        
        if "timeout" not in self.config:
            self.config["timeout"] = 1.0
        
        if "max_threads" not in self.config:
            self.config["max_threads"] = 100
        
        if "get_banner" not in self.config:
            self.config["get_banner"] = True
        
        if "get_service" not in self.config:
            self.config["get_service"] = True
        
        if "scan_delay" not in self.config:
            self.config["scan_delay"] = 0
        
        return True, None
    
    def get_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """
        获取服务 Banner
        
        Args:
            ip: 目标 IP
            port: 目标端口
            timeout: 超时时间
        
        Returns:
            Banner 字符串
        """
        if self._stopped:
            return ""
        
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                
                # 根据不同端口使用不同的请求数据
                if port == 80 or port == 8080:
                    s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                elif port == 21:
                    pass  # FTP 服务会自动发送 Banner
                elif port == 25:
                    pass  # SMTP 服务会自动发送 Banner
                elif port == 22:
                    pass  # SSH 服务会自动发送 Banner
                
                # 接收数据
                data = s.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
        except (socket.timeout, socket.error, UnicodeDecodeError) as e:
            self.logger.debug(f"获取 {ip}:{port} Banner 失败: {str(e)}")
        
        return banner
    
    def guess_service(self, port: int, banner: str = "") -> str:
        """
        根据端口和 Banner 猜测服务类型
        
        Args:
            port: 端口号
            banner: 服务 Banner
        
        Returns:
            服务名称
        """
        # 先从常见端口映射表查找
        service = self.COMMON_PORTS.get(port, "")
        
        # 如果有 Banner，尝试从 Banner 获取更多信息
        if banner:
            banner_lower = banner.lower()
            
            # 检查常见服务标识
            if "ssh" in banner_lower:
                service = "SSH"
            elif "ftp" in banner_lower:
                service = "FTP"
            elif "http" in banner_lower:
                if "nginx" in banner_lower:
                    service = "Nginx"
                elif "apache" in banner_lower:
                    service = "Apache"
                elif "iis" in banner_lower:
                    service = "IIS"
                else:
                    service = "HTTP"
            elif "smtp" in banner_lower:
                service = "SMTP"
            elif "pop3" in banner_lower:
                service = "POP3"
            elif "imap" in banner_lower:
                service = "IMAP"
            elif "mysql" in banner_lower:
                service = "MySQL"
            elif "postgresql" in banner_lower:
                service = "PostgreSQL"
            elif "microsoft sql server" in banner_lower:
                service = "MSSQL"
            elif "vnc" in banner_lower:
                service = "VNC"
            elif "rdp" in banner_lower:
                service = "RDP"
            elif "redis" in banner_lower:
                service = "Redis"
            elif "mongodb" in banner_lower:
                service = "MongoDB"
        
        return service or "Unknown"
    
    def scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        """
        扫描单个端口
        
        Args:
            ip: 目标 IP
            port: 目标端口
        
        Returns:
            端口信息字典
        """
        if self._stopped:
            return {}
        
        # 更新进度
        with self._scan_lock:
            self._scan_count += 1
            progress = int(self._scan_count * 100 / self._total_ports)
            if progress % 10 == 0:
                self.logger.debug(f"扫描进度: {progress}%")
        
        # 端口扫描延迟 (毫秒)
        if self.config["scan_delay"] > 0:
            time.sleep(self.config["scan_delay"] / 1000)
        
        result = {
            "ip": ip,
            "port": port,
            "status": "closed",
            "service": "",
            "banner": ""
        }
        
        # 检查端口是否开放
        is_open = is_port_open(ip, port, self.config["timeout"])
        
        if is_open:
            result["status"] = "open"
            
            # 获取 Banner
            if self.config["get_banner"]:
                banner = self.get_banner(ip, port, self.config["timeout"])
                if banner:
                    result["banner"] = banner
            
            # 识别服务
            if self.config["get_service"]:
                result["service"] = self.guess_service(port, result["banner"])
        
        return result
    
    def run_scan(self) -> ScanResult:
        """
        执行端口扫描
        
        Returns:
            扫描结果
        """
        self._stopped = False
        self._scan_count = 0
        
        # 解析目标 IP
        ip_list = parse_ip_range(self.config["target"])
        if not ip_list:
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"无法解析目标 IP 范围: {self.config['target']}"
            )
        
        # 解析端口范围
        if isinstance(self.config["ports"], str):
            port_list = parse_port_range(self.config["ports"])
        else:
            port_list = self.config["ports"]
        
        if not port_list:
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"无法解析端口范围: {self.config['ports']}"
            )
        
        # 计算总扫描量
        self._total_ports = len(ip_list) * len(port_list)
        self.logger.info(f"开始扫描 {len(ip_list)} 个目标的 {len(port_list)} 个端口，共 {self._total_ports} 个连接")
        
        # 更新进度信息
        self.update_progress(10, f"准备扫描 {len(ip_list)} 个主机的 {len(port_list)} 个端口")
        
        results = []
        max_threads = min(self.config["max_threads"], self._total_ports)
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # 创建所有扫描任务
                self.update_progress(15, f"创建扫描任务，使用 {max_threads} 个线程")
                future_to_port = {}
                for ip in ip_list:
                    for port in port_list:
                        future = executor.submit(self.scan_port, ip, port)
                        future_to_port[future] = (ip, port)
                
                # 处理结果
                completed = 0
                for future in concurrent.futures.as_completed(future_to_port):
                    ip, port = future_to_port[future]
                    try:
                        port_result = future.result()
                        if port_result and port_result["status"] == "open":
                            results.append(port_result)
                            # 添加详细的进度消息，用于实时更新图表
                            self.update_progress(
                                min(15 + int(completed * 80 / self._total_ports), 95),
                                f"Found open port {ip}:{port} ({port_result.get('service', '')})"
                            )
                    except Exception as e:
                        self.logger.error(f"扫描 {ip}:{port} 时出错: {str(e)}")
                    
                    # 更新进度
                    completed += 1
                    if completed % (max(1, self._total_ports // 20)) == 0 or completed == self._total_ports:
                        progress = min(15 + int(completed * 80 / self._total_ports), 95)
                        self.update_progress(
                            progress, 
                            f"已扫描 {completed}/{self._total_ports} 个端口，发现 {len(results)} 个开放端口"
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
        open_ports = len(results)
        open_ips = len(set(r["ip"] for r in results))
        
        self.logger.info(f"扫描完成，发现 {open_ips} 个主机的 {open_ports} 个开放端口")
        self.update_progress(95, f"扫描完成，正在整理结果")
        
        result = ScanResult(
            success=True,
            data=results
        )
        
        # 添加元数据
        result.metadata = {
            'total_scanned': self._total_ports,
            'open_ports': open_ports,
            'open_hosts': open_ips
        }
        
        return result
    
    def stop(self) -> None:
        """停止扫描"""
        self._stopped = True
        super().stop()

# 测试代码（运行该模块时执行）
if __name__ == "__main__":
    from core.scanner_manager import scanner_manager
    
    # 发现扫描器
    scanner_manager.discover_scanners()
    
    # 获取并打印所有扫描器
    print("已注册的所有扫描器:")
    for scanner_id, scanner_class in scanner_manager.get_all_scanners().items():
        print(f"{scanner_id} -> {scanner_class.__name__}")
    
    # 特别检查PortScanner
    port_scanner = scanner_manager.get_scanner("portscanner")
    if port_scanner:
        print(f"\nPortScanner类已成功注册: {port_scanner.__name__}")
    else:
        print("\n错误: PortScanner类未成功注册!") 