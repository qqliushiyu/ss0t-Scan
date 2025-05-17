#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS 检测模块
用于 DNS 解析、子域名探测和 DNS 记录类型查询
"""

import concurrent.futures
import socket
import time
from typing import Dict, List, Any, Tuple, Optional

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.name
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

from core.base_scanner import BaseScanner, ScanResult

class DnsChecker(BaseScanner):
    """
    DNS 检测模块
    提供域名解析、子域名探测和 DNS 记录类型查询功能
    """
    
    VERSION = "1.0.0"
    
    # 常见 DNS 记录类型
    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV"]
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化 DNS 检测模块"""
        super().__init__(config)
        self._stopped = False
        
        if not DNSPYTHON_AVAILABLE:
            self.logger.warning("dnspython 库未安装，某些功能将不可用。请运行: pip install dnspython")
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        if not DNSPYTHON_AVAILABLE:
            return False, "dnspython 库未安装，请运行: pip install dnspython"
        
        valid_keys = {
            "domain",         # 目标域名
            "record_types",   # 要查询的记录类型
            "nameservers",    # 使用的 DNS 服务器
            "timeout",        # 查询超时时间
            "max_threads",    # 最大线程数
            "subdomain_scan", # 是否扫描子域名
            "subdomain_dict", # 子域名字典文件路径
            "zone_transfer"   # 是否尝试区域传送
        }
        
        required_keys = ["domain"]
        
        # 检查必要参数
        for key in required_keys:
            if key not in self.config:
                return False, f"缺少必要参数: {key}"
        
        # 设置默认值
        if "record_types" not in self.config:
            self.config["record_types"] = self.RECORD_TYPES
        elif isinstance(self.config["record_types"], str):
            self.config["record_types"] = [rt.strip().upper() for rt in self.config["record_types"].split(",")]
        
        if "nameservers" not in self.config:
            self.config["nameservers"] = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        elif isinstance(self.config["nameservers"], str):
            self.config["nameservers"] = [ns.strip() for ns in self.config["nameservers"].split(",")]
        
        if "timeout" not in self.config:
            self.config["timeout"] = 2.0
        
        if "max_threads" not in self.config:
            self.config["max_threads"] = 10
        
        if "subdomain_scan" not in self.config:
            self.config["subdomain_scan"] = False
        
        if "zone_transfer" not in self.config:
            self.config["zone_transfer"] = True
        
        return True, None
    
    def query_dns_record(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """
        查询 DNS 记录
        
        Args:
            domain: 域名
            record_type: 记录类型
        
        Returns:
            记录列表
        """
        if self._stopped:
            return []
        
        results = []
        
        try:
            # 创建解析器
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.config["timeout"]
            resolver.lifetime = self.config["timeout"]
            
            # 设置使用的 DNS 服务器
            if self.config["nameservers"]:
                resolver.nameservers = self.config["nameservers"]
            
            # 查询记录
            answers = resolver.resolve(domain, record_type)
            
            for answer in answers:
                record_data = str(answer)
                
                # 根据记录类型进行特殊处理
                if record_type == "MX":
                    record_data = f"{answer.preference} {answer.exchange}"
                elif record_type == "SOA":
                    record_data = f"{answer.mname} {answer.rname} {answer.serial} {answer.refresh} {answer.retry} {answer.expire} {answer.minimum}"
                elif record_type == "SRV":
                    record_data = f"{answer.priority} {answer.weight} {answer.port} {answer.target}"
                
                results.append({
                    "domain": domain,
                    "type": record_type,
                    "data": record_data,
                    "ttl": answers.ttl
                })
        
        except dns.resolver.NoAnswer:
            self.logger.debug(f"域名 {domain} 没有 {record_type} 记录")
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"域名 {domain} 不存在")
        except dns.resolver.NoNameservers:
            self.logger.debug(f"没有可用的 DNS 服务器来解析 {domain}")
        except dns.exception.Timeout:
            self.logger.debug(f"查询 {domain} 的 {record_type} 记录超时")
        except Exception as e:
            self.logger.error(f"查询 {domain} 的 {record_type} 记录时出错: {str(e)}")
        
        return results
    
    def try_zone_transfer(self, domain: str) -> List[Dict[str, Any]]:
        """
        尝试区域传送
        
        Args:
            domain: 域名
        
        Returns:
            记录列表
        """
        results = []
        
        # 首先获取域名的 NS 记录
        ns_records = self.query_dns_record(domain, "NS")
        nameservers = [record["data"] for record in ns_records]
        
        if not nameservers:
            self.logger.debug(f"无法获取 {domain} 的 NS 记录")
            return results
        
        # 尝试对每个 NS 服务器进行区域传送
        for ns in nameservers:
            try:
                self.logger.debug(f"尝试从 {ns} 进行 {domain} 的区域传送")
                
                # 移除末尾的点号
                if ns.endswith("."):
                    ns = ns[:-1]
                
                # 区域传送请求
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=self.config["timeout"]))
                
                # 处理区域传送结果
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            record_type = dns.rdatatype.to_text(rdataset.rdtype)
                            record_data = str(rdata)
                            
                            # 构建完整域名
                            full_name = name.to_text() + "." + domain if name != "@" else domain
                            
                            results.append({
                                "domain": full_name,
                                "type": record_type,
                                "data": record_data,
                                "source": "zone_transfer",
                                "nameserver": ns
                            })
                
                self.logger.info(f"成功从 {ns} 获取 {domain} 的区域传送，获取到 {len(results)} 条记录")
                
                # 如果一个 NS 成功，就不再继续尝试其他 NS
                if results:
                    break
            
            except Exception as e:
                self.logger.debug(f"从 {ns} 进行 {domain} 的区域传送失败: {str(e)}")
        
        return results
    
    def scan_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """
        扫描子域名
        
        Args:
            domain: 主域名
        
        Returns:
            子域名记录列表
        """
        if not self.config.get("subdomain_scan"):
            return []
        
        results = []
        subdomains = []
        
        # 获取子域名字典
        subdomain_dict = self.config.get("subdomain_dict")
        if subdomain_dict:
            try:
                with open(subdomain_dict, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            except IOError as e:
                self.logger.error(f"读取子域名字典失败: {str(e)}")
        
        # 如果没有提供字典或读取失败，使用内置常见子域名列表
        if not subdomains:
            subdomains = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
                "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "admin",
                "blog", "shop", "dev", "test", "api", "secure", "m", "mobile", "portal",
                "vpn", "cdn", "cloud", "git", "svn", "jenkins", "gitlab", "docs", "wiki"
            ]
        
        self.logger.info(f"开始扫描 {domain} 的子域名，共 {len(subdomains)} 个")
        
        # 使用线程池进行并发查询
        max_threads = min(self.config["max_threads"], len(subdomains))
        valid_subdomains = []
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # 提交所有子域名查询任务
                future_to_subdomain = {}
                for subdomain in subdomains:
                    # 构建完整子域名
                    full_domain = f"{subdomain}.{domain}"
                    
                    # 提交任务
                    future = executor.submit(self.query_dns_record, full_domain, "A")
                    future_to_subdomain[future] = full_domain
                
                # 处理结果
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    full_domain = future_to_subdomain[future]
                    try:
                        records = future.result()
                        if records:
                            valid_subdomains.append(full_domain)
                            results.extend(records)
                    except Exception as e:
                        self.logger.error(f"扫描子域名 {full_domain} 时出错: {str(e)}")
        
        except KeyboardInterrupt:
            self._stopped = True
            self.logger.warning("子域名扫描被用户中断")
        
        self.logger.info(f"子域名扫描完成，发现 {len(valid_subdomains)} 个有效子域名")
        
        return results
    
    def run_scan(self) -> ScanResult:
        """
        执行 DNS 检测
        
        Returns:
            扫描结果
        """
        if not DNSPYTHON_AVAILABLE:
            return ScanResult(
                success=False,
                data=[],
                error_msg="dnspython 库未安装，请运行: pip install dnspython"
            )
        
        self._stopped = False
        domain = self.config["domain"]
        record_types = self.config["record_types"]
        
        self.logger.info(f"开始 DNS 检测，目标: {domain}，记录类型: {','.join(record_types)}")
        
        all_results = []
        
        # 尝试区域传送
        if self.config["zone_transfer"]:
            zone_transfer_results = self.try_zone_transfer(domain)
            all_results.extend(zone_transfer_results)
            
            # 如果区域传送成功，就不需要继续查询了
            if zone_transfer_results:
                self.logger.info(f"区域传送成功，获取到 {len(zone_transfer_results)} 条记录")
                
                return ScanResult(
                    success=True,
                    data=all_results
                )
        
        # 对每种记录类型进行查询
        for record_type in record_types:
            if self._stopped:
                break
            
            self.logger.debug(f"查询 {domain} 的 {record_type} 记录")
            
            try:
                records = self.query_dns_record(domain, record_type)
                all_results.extend(records)
            except Exception as e:
                self.logger.error(f"查询 {domain} 的 {record_type} 记录时出错: {str(e)}")
        
        # 扫描子域名
        if self.config["subdomain_scan"] and not self._stopped:
            subdomain_results = self.scan_subdomains(domain)
            all_results.extend(subdomain_results)
        
        self.logger.info(f"DNS 检测完成，共获取到 {len(all_results)} 条记录")
        
        return ScanResult(
            success=True,
            data=all_results
        )
    
    def stop(self) -> None:
        """停止检测"""
        self._stopped = True
        super().stop() 