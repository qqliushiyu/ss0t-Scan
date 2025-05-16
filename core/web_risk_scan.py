#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web风险扫描模块
用于检测Web服务的安全配置和常见漏洞
"""

import concurrent.futures
from concurrent.futures import TimeoutError as FutureTimeoutError
import json
import re
import socket
import ssl
import time
import urllib.parse
from typing import Dict, List, Any, Tuple, Optional, Callable
import requests
import threading
import multiprocessing
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# 导入连接池管理器
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 禁用SSL警告
urllib3.disable_warnings(InsecureRequestWarning)

from core.base_scanner import BaseScanner, ScanResult
from utils.network import parse_ip_range

# 导入插件系统
from plugins import plugin_manager

class WebRiskScanner(BaseScanner):
    """
    Web风险扫描模块
    用于检测Web服务的安全配置和常见漏洞
    """
    
    VERSION = "2.0.0"
    
    # 默认Web漏洞检测路径
    DEFAULT_VULN_PATHS = {
        "目录遍历": [
            "/../../../../etc/passwd",
            "/..\../..\../windows/win.ini",
            "/etc/passwd"
        ],
        "文件包含": [
            "/index.php?file=../../etc/passwd",
            "/main.php?page=../../etc/passwd"
        ],
        "SQL注入": [
            "/index.php?id=1'",
            "/search.php?q=1' OR '1'='1",
            "/login.php?username=admin' OR '1'='1&password=anything"
        ],
        "XSS": [
            "/search.php?q=<script>alert(1)</script>",
            "/index.php?name=<script>alert('XSS')</script>"
        ],
        "敏感文件": [
            "/.git/HEAD",
            "/.env",
            "/wp-config.php",
            "/config.php",
            "/phpinfo.php",
            "/admin/",
            "/robots.txt",
            "/.svn/entries"
        ]
    }
    
    # 默认Web指纹特征
    DEFAULT_WEB_FINGERPRINTS = {
        "WordPress": [
            {"path": "/wp-login.php", "pattern": "WordPress"},
            {"path": "/", "pattern": "wp-content"}
        ],
        "Joomla": [
            {"path": "/administrator/", "pattern": "Joomla"},
            {"path": "/", "pattern": "joomla"}
        ],
        "Drupal": [
            {"path": "/", "pattern": "Drupal"},
            {"path": "/CHANGELOG.txt", "pattern": "Drupal"}
        ],
        "phpMyAdmin": [
            {"path": "/phpmyadmin/", "pattern": "phpMyAdmin"},
            {"path": "/phpMyAdmin/", "pattern": "phpMyAdmin"}
        ],
        "Apache": [
            {"path": "/", "header": "Server", "pattern": "Apache"}
        ],
        "Nginx": [
            {"path": "/", "header": "Server", "pattern": "nginx"}
        ],
        "IIS": [
            {"path": "/", "header": "Server", "pattern": "Microsoft-IIS"}
        ],
        "PHP": [
            {"path": "/", "header": "X-Powered-By", "pattern": "PHP"}
        ],
        "ASP.NET": [
            {"path": "/", "header": "X-AspNet-Version", "pattern": ".*"},
            {"path": "/", "header": "X-Powered-By", "pattern": "ASP.NET"}
        ]
    }
    
    # 默认WAF签名
    DEFAULT_WAF_SIGNATURES = {
        "Cloudflare": ["cloudflare-nginx", "__cfduid", "cf-ray"],
        "AWS WAF": ["x-amzn-waf", "aws-waf"],
        "Akamai": ["akamai"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "F5 BIG-IP": ["bigip", "f5"],
        "Incapsula": ["incap_ses", "incap_visid"],
        "Sucuri": ["sucuri"],
        "Imperva": ["imperva", "incapsula"]
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化Web风险扫描模块"""
        super().__init__(config)
        self._stopped = False
        self._scanned_urls = 0
        self._total_urls = 0
        self._sessions = []  # 跟踪所有请求会话
        self._futures = []   # 跟踪所有正在执行的任务
        self._lock = threading.Lock()  # 用于线程安全操作
        
        # 初始化结果列表
        self.results = []
        
        # 加载自定义漏洞路径、Web指纹和WAF签名
        self.load_custom_data()
        
        self._result_callback = None
        
        # 初始化插件管理器
        self._init_plugins()
    
    def _init_plugins(self):
        """初始化插件管理器并发现可用插件"""
        # 确保插件管理器已初始化
        plugin_manager.init_plugins()
        
        # 获取所有可用插件的信息
        all_plugins = plugin_manager.get_plugin_info_list()
        if all_plugins:
            self.logger.info(f"发现 {len(all_plugins)} 个Web风险扫描插件")
            for plugin_info in all_plugins:
                self.logger.info(f"  - {plugin_info['name']} v{plugin_info['version']} ({plugin_info['category']})")
        else:
            self.logger.warning("未发现任何Web风险扫描插件")
        
        # 从配置中获取禁用的插件
        disabled_plugins = self.config.get('disabled_plugins', [])
        if disabled_plugins:
            for plugin_id in disabled_plugins:
                plugin_manager.disable_plugin(plugin_id)
                self.logger.info(f"已禁用插件: {plugin_id}")
    
    def _get_plugin_config(self, plugin_id: str) -> Dict[str, Any]:
        """
        获取特定插件的配置
        
        Args:
            plugin_id: 插件ID
            
        Returns:
            插件配置
        """
        plugins_config = self.config.get('plugins_config', {})
        return plugins_config.get(plugin_id, {})
    
    def load_vuln_paths(self) -> Dict[str, List[str]]:
        """从配置加载自定义漏洞检测路径"""
        # 先使用默认值
        vuln_paths = self.DEFAULT_VULN_PATHS.copy()
        
        # 从配置管理器读取自定义配置
        from utils.config import ConfigManager
        config = ConfigManager()
        
        # 读取各类漏洞路径
        dir_traversal = config.get("web_risk_scan", "dir_traversal_paths", fallback="")
        if dir_traversal:
            vuln_paths["目录遍历"] = [path.strip() for path in dir_traversal.split(',')]
        
        file_inclusion = config.get("web_risk_scan", "file_inclusion_paths", fallback="")
        if file_inclusion:
            vuln_paths["文件包含"] = [path.strip() for path in file_inclusion.split(',')]
        
        sql_injection = config.get("web_risk_scan", "sql_injection_paths", fallback="")
        if sql_injection:
            vuln_paths["SQL注入"] = [path.strip() for path in sql_injection.split(',')]
        
        xss = config.get("web_risk_scan", "xss_paths", fallback="")
        if xss:
            vuln_paths["XSS"] = [path.strip() for path in xss.split(',')]
        
        sensitive_files = config.get("web_risk_scan", "sensitive_files", fallback="")
        if sensitive_files:
            vuln_paths["敏感文件"] = [path.strip() for path in sensitive_files.split(',')]
        
        self.logger.debug(f"已加载 {sum(len(paths) for paths in vuln_paths.values())} 个漏洞检测路径")
        return vuln_paths
    
    def load_web_fingerprints(self) -> Dict[str, List[Dict[str, str]]]:
        """从配置加载自定义Web指纹特征"""
        # 先使用默认值
        fingerprints = self.DEFAULT_WEB_FINGERPRINTS.copy()
        
        # 从配置管理器读取自定义配置
        from utils.config import ConfigManager
        config = ConfigManager()
        
        # 读取Web指纹配置 (格式: 技术名:路径:模式,技术名:路径:模式,...)
        fp_str = config.get("web_risk_scan", "web_fingerprints", fallback="")
        if fp_str:
            # 解析配置字符串
            for fp_item in fp_str.split(','):
                parts = fp_item.split(':')
                if len(parts) >= 3:
                    tech_name = parts[0].strip()
                    path = parts[1].strip()
                    pattern = parts[2].strip()
                    
                    # 添加或更新指纹
                    if tech_name not in fingerprints:
                        fingerprints[tech_name] = []
                    
                    # 检查是否有header参数
                    if len(parts) > 3:
                        fingerprints[tech_name].append({
                            "path": path,
                            "header": parts[3].strip(),
                            "pattern": pattern
                        })
                    else:
                        fingerprints[tech_name].append({
                            "path": path,
                            "pattern": pattern
                        })
        
        self.logger.debug(f"已加载 {sum(len(fps) for fps in fingerprints.values())} 个Web指纹特征")
        return fingerprints
    
    def load_waf_signatures(self) -> Dict[str, List[str]]:
        """从配置加载自定义WAF签名"""
        # 先使用默认值
        signatures = self.DEFAULT_WAF_SIGNATURES.copy()
        
        # 从配置管理器读取自定义配置
        from utils.config import ConfigManager
        config = ConfigManager()
        
        # 读取WAF签名配置 (格式: WAF名称:签名1,签名2;WAF名称:签名1,签名2;...)
        waf_str = config.get("web_risk_scan", "waf_signatures", fallback="")
        if waf_str:
            # 解析配置字符串
            for waf_item in waf_str.split(';'):
                parts = waf_item.split(':')
                if len(parts) == 2:
                    waf_name = parts[0].strip()
                    signatures_list = [sig.strip() for sig in parts[1].split(',')]
                    
                    # 添加或更新WAF签名
                    signatures[waf_name] = signatures_list
        
        self.logger.debug(f"已加载 {sum(len(sigs) for sigs in signatures.values())} 个WAF签名")
        return signatures
    
    def set_result_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        设置实时结果回调函数
        
        Args:
            callback: 回调函数，接收一个结果字典
        """
        self._result_callback = callback
        self.logger.debug("已设置实时结果回调函数")
    
    def add_result(self, result: Dict[str, Any]) -> None:
        """
        添加扫描结果并触发回调

        Args:
            result: 结果字典
        """
        # 先添加到结果列表
        self.results.append(result)
        
        # 回调通知UI
        if self._result_callback:
            try:
                # 在主线程中执行回调
                self._result_callback(result)
                # 添加额外的日志以便调试
                check_type = result.get("check_type", "unknown")
                url = result.get("url", "unknown")
                self.logger.debug(f"已发送实时结果: {check_type} - {url}")
            except Exception as e:
                self.logger.error(f"回调函数执行出错: {str(e)}")
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        if not self.config:
            return False, "配置不能为空"
        
        # 检查目标
        targets = self.config.get("targets")
        if not targets:
            return False, "必须提供目标"
        
        # 检查端口
        ports = self.config.get("ports")
        if not ports:
            self.config["ports"] = "80,443"  # 使用默认端口
        
        # 检查线程数
        threads = self.config.get("threads")
        if threads:
            try:
                threads = int(threads)
                if threads < 1:
                    return False, "线程数必须大于0"
                if threads > 500:
                    return False, "线程数过大，建议不超过500"
            except ValueError:
                return False, "线程数必须是整数"
        else:
            self.config["threads"] = 10  # 默认10个线程
        
        # 检查超时
        timeout = self.config.get("timeout")
        if timeout:
            try:
                timeout = int(timeout)
                if timeout < 1:
                    return False, "超时时间必须大于0"
                if timeout > 60:
                    return False, "超时时间过长，建议不超过60秒"
            except ValueError:
                return False, "超时时间必须是整数"
        else:
            self.config["timeout"] = 10  # 默认10秒超时
        
        # 检查扫描深度
        scan_depth = self.config.get("scan_depth", 1)
        try:
            scan_depth = int(scan_depth)
            if scan_depth < 0 or scan_depth > 2:
                return False, "扫描深度必须在0-2之间"
            self.config["scan_depth"] = scan_depth
        except ValueError:
            return False, "扫描深度必须是整数"
        
        # 配置是否显示失败的目标
        show_failed_targets = self.config.get("show_failed_targets")
        if show_failed_targets is None:
            self.config["show_failed_targets"] = False
        else:
            self.config["show_failed_targets"] = bool(show_failed_targets)
        
        # 验证插件配置
        plugins_config = self.config.get('plugins_config', {})
        if plugins_config and not isinstance(plugins_config, dict):
            return False, "plugins_config必须是一个字典"
        
        disabled_plugins = self.config.get('disabled_plugins', [])
        if disabled_plugins and not isinstance(disabled_plugins, list):
            return False, "disabled_plugins必须是一个列表"
        
        return True, None
    
    def prepare_urls(self) -> List[str]:
        """
        准备要扫描的URL列表
        
        Returns:
            要扫描的URL列表
        """
        targets = self.config.get("targets", "")
        ports = self.config.get("ports", "80,443")
        
        # 将端口转换为列表
        port_list = []
        for port in ports.split(","):
            port = port.strip()
            if not port:
                continue
                
            # 处理端口范围（例如：8000-8100）
            if "-" in port:
                start, end = port.split("-")
                try:
                    start = int(start.strip())
                    end = int(end.strip())
                    port_list.extend(range(start, end + 1))
                except ValueError:
                    self.logger.warning(f"跳过无效的端口范围: {port}")
            else:
                try:
                    port_list.append(int(port))
                except ValueError:
                    self.logger.warning(f"跳过无效的端口: {port}")
        
        # 如果没有有效端口，使用默认端口
        if not port_list:
            port_list = [80, 443]
        
        # 处理目标（IP、域名、IP段）
        urls = []
        for target in targets.split(","):
            target = target.strip()
            if not target:
                continue
                
            # 处理URL格式
            if target.startswith(("http://", "https://")):
                # 已经是完整URL
                urls.append(target)
            elif "/" in target and not target.startswith("/"):
                # 可能是IP段，例如 192.168.1.0/24
                ips = parse_ip_range(target)
                for ip in ips:
                    for port in port_list:
                        # 根据端口确定协议
                        protocol = "https" if port == 443 else "http"
                        urls.append(f"{protocol}://{ip}:{port}")
            else:
                # 单个IP或域名
                for port in port_list:
                    # 根据端口确定协议
                    protocol = "https" if port == 443 else "http"
                    
                    # 对于默认端口，不需要在URL中显示端口号
                    if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
                        urls.append(f"{protocol}://{target}")
                    else:
                        urls.append(f"{protocol}://{target}:{port}")
        
        self.logger.info(f"共准备 {len(urls)} 个URL进行扫描")
        return urls
    
    def scan_url(self, url: str, basic_result: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        扫描单个URL
        
        Args:
            url: 要扫描的URL
            basic_result: 可选的基本结果，如果提供则复用存活检测的结果
            
        Returns:
            扫描结果列表
        """
        if self._stopped:
            return []
        
        results = []
        
        # 如果提供了基本结果，则添加到结果列表中
        if basic_result:
            results.append(basic_result)
        
        try:
            self.logger.debug(f"开始详细扫描URL: {url}")
            
            # 创建一个会话用于所有请求
            session = requests.Session()
            
            # 设置重试机制
            retries = Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["GET", "HEAD", "OPTIONS"]
            )
            
            # 配置会话
            session.mount("http://", HTTPAdapter(max_retries=retries))
            session.mount("https://", HTTPAdapter(max_retries=retries))
            
            # 设置请求头
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Connection': 'keep-alive'
            })
            
            # 获取配置参数
            timeout = self.config.get("timeout", 10)
            verify_ssl = self.config.get("verify_ssl", False)
            follow_redirects = self.config.get("follow_redirects", True)
            scan_depth = self.config.get("scan_depth", 1)
            
            # 记录会话，以便在停止时关闭
            self._sessions.append(session)
            
            # 获取页面内容 - 我们在这里发送请求而不是在基本信息检查部分
            # 因为存活检测已经检查了URL是否可访问
            try:
                response = session.get(
                    url, 
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=follow_redirects
                )
            except Exception as e:
                self.logger.error(f"获取{url}内容时出错: {str(e)}")
                # 返回已收集的结果
                return results
            
            # === 使用插件系统扫描 ===
            plugin_results = self._scan_with_plugins(url, session)
            results.extend(plugin_results)
            
            # === SSL安全检查 ===
            if url.startswith("https://"):
                try:
                    ssl_results = self._check_ssl_security(url)
                    results.extend(ssl_results)
                except Exception as e:
                    self.logger.error(f"检查 {url} 的SSL安全性时出错: {str(e)}")
            
            # === 检查服务器信息 ===
            try:
                server_result = self.check_server_info(url, response)
                if server_result:
                    # 确保server_info结果有正确的check_type
                    if "check_type" not in server_result:
                        server_result["check_type"] = "server_info"
                    
                    # 添加到结果列表
                    results.append(server_result)
                    self.add_result(server_result)
                    self.logger.debug(f"已添加服务器信息结果: {server_result}")
                else:
                    self.logger.warning(f"未能获取 {url} 的服务器信息")
            except Exception as e:
                self.logger.error(f"检查 {url} 的服务器信息时出错: {str(e)}", exc_info=True)
                # 记录错误但继续其他检查
                error_result = {
                    "check_type": "error",
                    "url": url,
                    "error_source": "server_info",
                    "error": str(e)
                }
                results.append(error_result)
                self.add_result(error_result)
            
            return results
        
        except Exception as e:
            self.logger.error(f"扫描URL {url} 时出错: {str(e)}", exc_info=True)
            error_result = {
                "check_type": "error",
                "url": url,
                "error": str(e)
            }
            results.append(error_result)
            self.add_result(error_result)
            return results
    
    def _scan_with_plugins(self, url: str, session: requests.Session) -> List[Dict[str, Any]]:
        """
        使用插件系统扫描URL
        
        Args:
            url: 目标URL
            session: 请求会话
            
        Returns:
            插件扫描结果列表
        """
        results = []
        
        # 获取扫描配置
        timeout = self.config.get("timeout", 10)
        verify_ssl = self.config.get("verify_ssl", False)
        follow_redirects = self.config.get("follow_redirects", True)
        scan_depth = self.config.get("scan_depth", 1)
        
        # 准备传递给插件的参数
        kwargs = {
            "timeout": timeout,
            "verify_ssl": verify_ssl,
            "follow_redirects": follow_redirects,
            "scan_depth": scan_depth
        }
        
        # 获取所有启用的插件
        enabled_plugins = plugin_manager.get_enabled_plugins()
        
        # 根据扫描深度过滤插件
        filtered_plugins = {}
        for plugin_id, plugin_class in enabled_plugins.items():
            if self._stopped:
                break
            
            # 获取插件实例
            plugin_config = self._get_plugin_config(plugin_id)
            plugin = plugin_manager.get_plugin(plugin_id, plugin_config)
            
            if not plugin:
                self.logger.warning(f"无法创建插件实例: {plugin_id}")
                continue
                
            # 检查插件是否适用于当前扫描深度
            # 假设插件有一个min_depth属性，表示最小所需深度
            min_depth = getattr(plugin, 'MIN_DEPTH', 0)
            if scan_depth >= min_depth:
                filtered_plugins[plugin_id] = plugin_class
            else:
                self.logger.debug(f"跳过插件 {plugin_id}，当前扫描深度 {scan_depth} < 所需深度 {min_depth}")
        
        # 使用过滤后的插件进行扫描
        for plugin_id, plugin_class in filtered_plugins.items():
            if self._stopped:
                break
                
            try:
                # 获取插件配置
                plugin_config = self._get_plugin_config(plugin_id)
                
                # 创建插件实例
                plugin = plugin_manager.get_plugin(plugin_id, plugin_config)
                
                if not plugin:
                    self.logger.warning(f"无法创建插件实例: {plugin_id}")
                    continue
                
                # 验证插件配置
                is_valid, error_msg = plugin.validate_config()
                if not is_valid:
                    self.logger.warning(f"插件 {plugin_id} 配置无效: {error_msg}")
                    continue
                
                # 根据扫描深度调整插件行为（如果插件支持）
                if hasattr(plugin, 'set_scan_depth'):
                    plugin.set_scan_depth(scan_depth)
                
                # 执行插件检查
                self.logger.info(f"使用插件 {plugin.NAME} 扫描 {url}")
                plugin_results = plugin.check(url, session, **kwargs)
                
                # 添加结果
                for plugin_result in plugin_results:
                    # 将插件结果转换为标准格式
                    result = {
                        "url": url,
                        "check_type": plugin_result.get("check_type", "plugin_result"),
                        "plugin_name": plugin.NAME,
                        "plugin_id": plugin_id,
                    }
                    
                    # 检查是否已经设置了检查类型
                    if "check_type" not in plugin_result:
                        result["risk_name"] = plugin_result.get("name", "未知风险")
                        result["severity"] = plugin_result.get("severity", "中")
                        result["details"] = plugin_result.get("details", "")
                        result["recommendation"] = plugin_result.get("recommendation", "")
                    
                    # 将原始结果的其他字段合并进来
                    for key, value in plugin_result.items():
                        if key not in result:
                            result[key] = value
                    
                    # 添加到结果列表
                    results.append(result)
                    
                    # 实时发送给UI
                    self.add_result(result)
                    
                    # 根据检查类型记录日志
                    check_type = result.get("check_type", "plugin_result")
                    if check_type == "plugin_result":
                        self.logger.info(f"插件 {plugin.NAME} 发现风险: {result.get('risk_name', '未知')} - {url}")
                    else:
                        self.logger.info(f"插件 {plugin.NAME} 检测到 {check_type}: {url}")
                
            except Exception as e:
                self.logger.error(f"执行插件 {plugin_id} 时出错: {str(e)}", exc_info=True)
                
                # 添加错误结果
                error_result = {
                    "url": url,
                    "check_type": "error",
                    "plugin_name": plugin_id,
                    "error": str(e)
                }
                results.append(error_result)
                self.add_result(error_result)
        
        # 补充内置功能检测
        # 如果没有WAF检测插件，使用内置WAF检测
        if scan_depth > 0 and not any(p.NAME.lower().find("waf") != -1 for p in [plugin_manager.get_plugin(pid) for pid in filtered_plugins]):
            try:
                waf_name = self.detect_waf(url, session)
                if waf_name:
                    waf_result = {
                        "check_type": "waf",
                        "url": url,
                        "waf_name": waf_name
                    }
                    results.append(waf_result)
                    self.add_result(waf_result)
            except Exception as e:
                self.logger.error(f"内置WAF检测出错: {str(e)}")
        
        return results
    
    def run_scan(self) -> ScanResult:
        """
        执行Web风险扫描
        
        Returns:
            扫描结果
        """
        if self._stopped:
            return ScanResult(success=False, data=[], error_msg="扫描已停止")
        
        all_results = []
        start_time = time.time()
        
        try:
            # 准备URL列表
            urls = self.prepare_urls()
            if not urls:
                return ScanResult(success=False, data=[], error_msg="无有效URL")
            
            self._total_urls = len(urls)
            self._scanned_urls = 0
            
            # 获取线程数
            thread_count = min(int(self.config.get("threads", 10)), len(urls))
            
            # 显示扫描开始的详细信息
            scan_info = {
                "targets": len(urls),
                "threads": thread_count,
                "scan_depth": self.config.get("scan_depth", 1),
                "verify_ssl": self.config.get("verify_ssl", False),
                "timeout": self.config.get("timeout", 10)
            }
            self.logger.info(f"开始Web风险扫描: {scan_info}")
            
            # 第一步: 进行存活性检测
            alive_urls = []
            alive_results = {}  # 存储存活检测的基本结果，避免重复请求
            status_code_stats = {}  # 记录不同状态码的统计
            
            self.update_progress(5, f"正在检测目标存活性 (0/{self._total_urls})...")
            self.logger.info(f"开始对 {self._total_urls} 个目标进行存活性检测...")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                # 提交存活检测任务
                future_to_url = {executor.submit(self.check_url_alive, url): url for url in urls}
                completed = 0
                
                # 处理存活检测结果
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    completed += 1
                    progress = 5 + (completed / self._total_urls) * 25  # 存活检测占总进度的25%
                    
                    # 显示更详细的进度信息
                    elapsed = time.time() - start_time
                    remaining = (elapsed / completed) * (self._total_urls - completed) if completed > 0 else 0
                    progress_msg = f"正在检测目标存活性 ({completed}/{self._total_urls}) - 已用时: {int(elapsed)}秒, 预计剩余: {int(remaining)}秒"
                    
                    self.update_progress(int(progress), progress_msg)
                    
                    try:
                        is_alive, basic_result = future.result()
                        
                        # 记录状态码统计
                        status_code = basic_result.get("status_code", 0)
                        status_code_stats[status_code] = status_code_stats.get(status_code, 0) + 1
                        
                        if is_alive:
                            alive_urls.append(url)
                            if basic_result:
                                alive_results[url] = basic_result
                                # 记录响应时间，可用于后续分析
                                response_time = basic_result.get("response_time", 0)
                                if response_time > 0:
                                    self.logger.debug(f"URL {url} 响应时间: {response_time}ms")
                                
                                # 只有存活的目标才添加到结果列表
                                all_results.append(basic_result)
                                self.add_result(basic_result)
                        elif self.config.get("show_failed_targets", False):
                            # 只有当配置允许显示失败目标时，才添加到结果列表
                            all_results.append(basic_result)
                            self.add_result(basic_result)
                    except Exception as e:
                        self.logger.error(f"检测URL {url} 存活性时出错: {str(e)}", exc_info=True)
                        error_result = {
                            "check_type": "error",
                            "url": url,
                            "error": str(e)
                        }
                        all_results.append(error_result)
                        if self._result_callback:
                            self._result_callback(error_result)
                    
                    # 检查是否已停止
                    if self._stopped:
                        return ScanResult(success=False, data=all_results, error_msg="扫描已中止")
            
            # 更新存活的URL数量
            alive_count = len(alive_urls)
            alive_percent = (alive_count / self._total_urls) * 100 if self._total_urls > 0 else 0
            self.logger.info(f"检测到 {alive_count}/{self._total_urls} 个目标存活 ({alive_percent:.1f}%)")
            
            # 输出状态码统计信息
            self.logger.info("状态码统计:")
            for status_code, count in sorted(status_code_stats.items()):
                status_desc = ""
                if 200 <= status_code < 300:
                    status_desc = "成功响应"
                elif 300 <= status_code < 400:
                    status_desc = "重定向"
                elif 400 <= status_code < 500:
                    status_desc = "客户端错误"
                elif 500 <= status_code < 600:
                    status_desc = "服务器错误" 
                elif status_code == 0:
                    status_desc = "连接失败"
                self.logger.info(f"  - 状态码 {status_code} ({status_desc}): {count} 个URL")
            
            if alive_count == 0:
                elapsed = time.time() - start_time
                self.update_progress(100, f"未发现存活目标，扫描完成 (总用时: {int(elapsed)}秒)")
                self.logger.warning("未发现存活目标，扫描将终止")
                return ScanResult(
                    success=True,
                    data=all_results,
                    metadata={
                        "target_urls": urls,
                        "scan_config": self.config.copy(),
                        "plugin_info": plugin_manager.get_plugin_info_list(),
                        "status_code_stats": status_code_stats,
                        "scan_time": int(elapsed)
                    }
                )
            
            # 第二步: 对存活的URL进行详细扫描
            detail_scan_start = time.time()
            self.update_progress(30, f"开始详细扫描 (0/{alive_count})...")
            self.logger.info(f"开始对 {alive_count} 个存活目标进行详细安全扫描...")
            self._total_urls = alive_count
            self._scanned_urls = 0
            
            # 使用线程池并发扫描
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                # 提交所有任务，传递存活检测的基本结果
                future_to_url = {}
                for url in alive_urls:
                    # 获取对应的基本结果，如果有的话
                    basic_result = alive_results.get(url)
                    # 提交任务，传递基本结果
                    future = executor.submit(self.scan_url, url, basic_result)
                    future_to_url[future] = url
                
                self._futures = list(future_to_url.keys())
                
                # 处理结果
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    self._scanned_urls += 1
                    progress = 30 + (self._scanned_urls / alive_count) * 70  # 详细扫描占总进度的70%
                    
                    # 更精确的进度显示
                    elapsed = time.time() - detail_scan_start
                    remaining = (elapsed / self._scanned_urls) * (alive_count - self._scanned_urls) if self._scanned_urls > 0 else 0
                    total_elapsed = time.time() - start_time
                    
                    progress_msg = (
                        f"详细扫描进度 ({self._scanned_urls}/{alive_count}) - "
                        f"已用时: {int(total_elapsed)}秒, 预计剩余: {int(remaining)}秒"
                    )
                    
                    self.update_progress(int(progress), progress_msg)
                    
                    try:
                        url_results = future.result()
                        all_results.extend(url_results)
                    except Exception as e:
                        self.logger.error(f"处理URL {url} 的详细扫描结果时出错: {str(e)}", exc_info=True)
                        error_result = {
                            "check_type": "error",
                            "url": url,
                            "error": str(e)
                        }
                        all_results.append(error_result)
                        if self._result_callback:
                            self._result_callback(error_result)
                    
                    # 检查是否已停止
                    if self._stopped:
                        break
            
            # 计算总扫描时间
            total_elapsed = time.time() - start_time
            
            # 生成扫描报告
            if not self._stopped:
                self.update_progress(100, f"扫描完成，总用时: {int(total_elapsed)}秒")
                
                # 结果统计
                result_types = {}
                for result in all_results:
                    check_type = result.get("check_type", "unknown")
                    result_types[check_type] = result_types.get(check_type, 0) + 1
                
                # 添加元数据
                metadata = {
                    "target_urls": urls,
                    "alive_urls": alive_urls,
                    "scan_config": self.config.copy(),
                    "plugin_info": plugin_manager.get_plugin_info_list(),
                    "status_code_stats": status_code_stats,
                    "result_types": result_types,
                    "scan_time": int(total_elapsed),
                    "summary": {
                        "total_urls": len(urls),
                        "alive_urls": len(alive_urls),
                        "success_rate": round(len(alive_urls) / len(urls) * 100, 2) if urls else 0,
                        "total_elapsed": int(total_elapsed),
                        "scan_start_time": int(start_time),
                        "scan_end_time": int(time.time())
                    }
                }
                
                self.logger.info(f"扫描完成，总用时: {int(total_elapsed)}秒")
                self.logger.info(f"结果统计: {result_types}")
                
                return ScanResult(
                    success=True,
                    data=all_results,
                    metadata=metadata
                )
            else:
                self.update_progress(100, f"扫描已中止，已用时: {int(total_elapsed)}秒")
                return ScanResult(
                    success=False,
                    data=all_results,
                    error_msg="扫描已中止"
                )
                
        except Exception as e:
            total_elapsed = time.time() - start_time
            self.logger.error(f"执行扫描时出错: {str(e)}", exc_info=True)
            return ScanResult(
                success=False,
                data=all_results,
                error_msg=f"扫描错误: {str(e)}",
                metadata={"scan_time": int(total_elapsed)}
            )
    
    def stop(self) -> None:
        """
        停止扫描
        """
        if not self._stopped:
            stop_start_time = time.time()
            self.logger.info("正在停止Web风险扫描...")
            self._stopped = True
            
            # 取消未完成的任务
            cancelled_count = 0
            for future in self._futures:
                if not future.done() and not future.cancelled():
                    future.cancel()
                    cancelled_count += 1
            
            # 关闭所有会话
            for session in self._sessions:
                try:
                    session.close()
                except Exception as e:
                    self.logger.error(f"关闭会话时出错: {str(e)}")
            
            # 清理资源
            self._futures.clear()
            self._sessions.clear()
            
            stop_elapsed = time.time() - stop_start_time
            self.logger.info(f"扫描已停止，取消了 {cancelled_count} 个未完成任务，用时 {stop_elapsed:.2f} 秒")
            
            # 更新进度状态
            self.update_progress(100, f"扫描已手动停止，取消了 {cancelled_count} 个任务")
            
        # 调用父类的stop方法
        super().stop()
    
    def load_custom_data(self):
        """
        加载自定义数据
        """
        # 加载自定义漏洞路径
        self.vuln_paths = self.load_vuln_paths()
        
        # 加载自定义Web指纹
        self.web_fingerprints = self.load_web_fingerprints()
        
        # 加载自定义WAF签名
        self.waf_signatures = self.load_waf_signatures()
        
        self.logger.debug("已加载自定义数据")
    
    # 保留其他必要的方法，如detect_waf, scan_web_security_headers, check_vulnerabilities等

    def detect_waf(self, url: str, session: requests.Session) -> Optional[str]:
        """
        检测WAF
        
        Args:
            url: 目标URL
            session: 请求会话
        
        Returns:
            WAF名称，若未检测到则为None
        """
        waf_signatures = self.waf_signatures
        
        try:
            # 发送特殊请求尝试触发WAF
            xss_payload = f"{url}?q=<script>alert(1)</script>"
            sqli_payload = f"{url}?id=1' OR '1'='1"
            
            headers = {'User-Agent': self.config["user_agent"]}
            
            for payload in [xss_payload, sqli_payload]:
                response = session.get(
                    payload, 
                    headers=headers, 
                    timeout=self.config["timeout"],
                    verify=self.config["verify_ssl"],
                    allow_redirects=self.config["follow_redirects"]
                )
                
                # 检查响应头和Cookie
                all_headers = str(response.headers).lower()
                cookies = str(response.cookies).lower()
                
                for waf, signatures in waf_signatures.items():
                    for signature in signatures:
                        if signature.lower() in all_headers or signature.lower() in cookies:
                            return waf
                
                # 检查特定WAF响应
                if response.status_code == 406 or response.status_code == 501:
                    return "Unknown WAF"
                
        except Exception as e:
            self.logger.debug(f"WAF检测失败: {str(e)}")
        
        return None
    
    def scan_web_security_headers(self, url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        扫描Web安全响应头
        
        Args:
            url: 目标URL
            headers: 响应头
        
        Returns:
            安全头检测结果列表
        """
        results = []
        
        security_headers = {
            "Strict-Transport-Security": {
                "description": "HSTS可防止SSL剥离攻击",
                "recommendation": "添加头 Strict-Transport-Security: max-age=31536000; includeSubDomains"
            },
            "Content-Security-Policy": {
                "description": "CSP减少XSS风险",
                "recommendation": "实施适当的内容安全策略"
            },
            "X-Content-Type-Options": {
                "description": "防止MIME类型嗅探",
                "recommendation": "添加头 X-Content-Type-Options: nosniff"
            },
            "X-Frame-Options": {
                "description": "防止点击劫持",
                "recommendation": "添加头 X-Frame-Options: DENY 或 SAMEORIGIN"
            },
            "X-XSS-Protection": {
                "description": "启用浏览器XSS过滤",
                "recommendation": "添加头 X-XSS-Protection: 1; mode=block"
            },
            "Referrer-Policy": {
                "description": "控制引用传递信息",
                "recommendation": "添加头 Referrer-Policy: strict-origin-when-cross-origin"
            },
            "Permissions-Policy": {
                "description": "控制浏览器特性",
                "recommendation": "实施适当的权限策略"
            }
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, info in security_headers.items():
            header_found = False
            for actual_header in headers_lower:
                if header.lower() == actual_header:
                    header_found = True
                    break
            
            header_result = {
                "url": url,
                "check_type": "security_header",
                "header": header,
                "status": "present" if header_found else "missing",
                "description": info["description"],
                "recommendation": info["recommendation"] if not header_found else ""
            }
            
            # 添加到结果列表
            results.append(header_result)
            
            # 仅对缺失的安全头（可能存在安全问题的）立即发送给UI
            if not header_found:
                self.add_result(header_result)
                self.logger.debug(f"发现缺失安全头: {header} - {url}")
        
        return results
    
    def check_vulnerabilities(self, base_url: str, session: requests.Session, max_paths_per_vuln: int = 3) -> List[Dict[str, Any]]:
        """
        检查常见Web漏洞
        
        Args:
            base_url: 基础URL
            session: 请求会话
            max_paths_per_vuln: 每类漏洞最多测试的路径数
        
        Returns:
            漏洞检测结果列表
        """
        results = []
        
        # 对每种漏洞类型进行检查
        for vuln_type, paths in self.vuln_paths.items():
            # 检查是否停止
            if self._stopped:
                return results
            
            # 限制每类漏洞测试的路径数量
            for path in paths[:max_paths_per_vuln]:
                if self._stopped:
                    return results
                
                try:
                    test_url = urllib.parse.urljoin(base_url, path)
                    
                    # 使用较短的超时时间
                    vuln_timeout = min(3, self.config["timeout"])
                    response = session.get(
                        test_url,
                        timeout=vuln_timeout,
                        verify=self.config["verify_ssl"],
                        allow_redirects=self.config["follow_redirects"]
                    )
                    
                    vuln_found = False
                    detail = ""
                    
                    # 根据漏洞类型判断是否存在漏洞
                    if vuln_type == "目录遍历" or vuln_type == "文件包含":
                        if "root:" in response.text or "[boot loader]" in response.text:
                            vuln_found = True
                            detail = "发现敏感系统文件内容"
                    
                    elif vuln_type == "SQL注入":
                        if "SQL syntax" in response.text or "mysql_fetch_array" in response.text or "ORA-" in response.text:
                            vuln_found = True
                            detail = "SQL错误信息泄露"
                    
                    elif vuln_type == "XSS":
                        if "<script>alert" in response.text:
                            vuln_found = True
                            detail = "XSS代码未被过滤"
                    
                    elif vuln_type == "敏感文件":
                        if response.status_code == 200:
                            if path == "/.git/HEAD" and "ref:" in response.text:
                                vuln_found = True
                                detail = "Git仓库信息泄露"
                            elif path == "/.env" and "APP_" in response.text:
                                vuln_found = True
                                detail = "环境配置文件泄露"
                            elif path == "/phpinfo.php" and "PHP Version" in response.text:
                                vuln_found = True
                                detail = "PHP信息泄露"
                            elif path == "/robots.txt" and "Disallow:" in response.text:
                                vuln_found = True
                                detail = "robots.txt包含敏感路径"
                            elif path == "/admin/" and response.status_code == 200:
                                vuln_found = True
                                detail = "管理面板可能存在未授权访问"
                            # 对其他敏感文件，如果能访问就认为可能存在问题
                            else:
                                vuln_found = True
                                detail = f"发现敏感文件: {path}"
                    
                    if vuln_found:
                        vuln_result = {
                            "url": test_url,
                            "check_type": "vulnerability",
                            "vulnerability": vuln_type,
                            "status": "vulnerable",
                            "details": detail,
                            "recommendation": "修复相关漏洞，确保安全过滤或禁止访问"
                        }
                        
                        # 添加到结果列表
                        results.append(vuln_result)
                        
                        # 立即发送给UI，让界面实时更新
                        self.add_result(vuln_result)
                        self.logger.info(f"发现漏洞: {vuln_type} - {test_url} - {detail}")
                        
                        # 找到一个漏洞后就跳过同类型的其他测试，减少测试时间
                        break
                
                except Exception as e:
                    self.logger.debug(f"检查漏洞 {vuln_type} 在 {base_url} 失败: {str(e)}")
                    
                    # 出现异常时也检查是否停止
                    if self._stopped:
                        return results
        
        return results
    
    def _check_ssl_security(self, url: str) -> List[Dict[str, Any]]:
        """
        检查SSL/TLS安全性
        
        Args:
            url: 目标URL
            
        Returns:
            安全头检测结果列表
        """
        results = []
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # 使用较短的超时时间
            ssl_timeout = min(2, self.config["timeout"] // 2)
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=ssl_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    
                    ssl_result = {
                        "url": url,
                        "check_type": "ssl",
                        "cipher_suite": f"{cipher[0]} {cipher[1]} bits",
                        "tls_version": cipher[1],
                        "issuer": dict(cert['issuer'][0]),
                        "subject": dict(cert['subject'][0]),
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter']
                    }
                    
                    # 添加到结果列表
                    results.append(ssl_result)
                    
                    # 立即发送给UI进行实时更新
                    self.add_result(ssl_result)
                    self.logger.debug(f"SSL信息已获取: {url}")
        except Exception as e:
            self.logger.debug(f"SSL检查失败: {str(e)}")
        
        return results

    def _analyze_headers(self, result: Dict[str, Any], headers: Dict[str, str]) -> None:
        """
        分析响应头并填充结果字典
        
        Args:
            result: 结果字典
            headers: 响应头
        """
        result["server"] = headers.get('Server', '')
        result["powered_by"] = headers.get('X-Powered-By', '')
        
        # 检查响应头中的技术指纹
        for tech, fingerprints in self.web_fingerprints.items():
            for fp in fingerprints:
                if "header" in fp:
                    header_value = headers.get(fp["header"], "")
                    if re.search(fp["pattern"], header_value, re.I):
                        if tech not in result["technologies"]:
                            result["technologies"].append(tech)
                else:
                    try:
                        if fp["path"] == "/":
                            # 已经有响应，直接检查
                            if fp["pattern"].lower() in headers.get('Content-Type', '').lower():
                                if tech not in result["technologies"]:
                                    result["technologies"].append(tech)
                    except:
                        pass

    def update_progress(self, progress: int, message: str) -> None:
        """
        更新扫描进度
        
        Args:
            progress: 当前进度百分比
            message: 进度消息
        """
        if self._result_callback:
            self._result_callback({
                "check_type": "progress",
                "progress": progress,
                "message": message
            })

    def check_server_info(self, url: str, response: requests.Response) -> Dict[str, Any]:
        """
        检查服务器信息
        
        Args:
            url: 目标URL
            response: HTTP响应对象
        
        Returns:
            服务器信息字典
        """
        try:
            headers = response.headers
            server = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')
            
            server_info = {
                "check_type": "server_info",  # 确保设置正确的检查类型
                "url": url,
                "server": server,
                "powered_by": powered_by,
                "technologies": []
            }
            
            # 详细日志记录技术检测过程
            self.logger.debug(f"开始检测 {url} 的服务器技术信息")
            self.logger.debug(f"服务器头: {server}, X-Powered-By: {powered_by}")
            
            # 检查响应内容和头中的技术指纹
            if hasattr(self, 'web_fingerprints') and self.web_fingerprints:
                for tech, fingerprints in self.web_fingerprints.items():
                    for fp in fingerprints:
                        try:
                            if "header" in fp:
                                header_name = fp["header"]
                                header_value = headers.get(header_name, "")
                                pattern = fp["pattern"]
                                
                                self.logger.debug(f"检查头技术指纹: {tech}, 头: {header_name}, 值: {header_value}, 模式: {pattern}")
                                
                                if re.search(pattern, header_value, re.I):
                                    if tech not in server_info["technologies"]:
                                        server_info["technologies"].append(tech)
                                        self.logger.debug(f"在头部中检测到技术: {tech}")
                            else:
                                if "path" in fp and fp["path"] == "/":
                                    pattern = fp["pattern"]
                                    # 确保响应内容可以被访问且为文本
                                    if hasattr(response, 'text') and response.text:
                                        # 检查HTML内容中的技术指纹
                                        self.logger.debug(f"检查内容技术指纹: {tech}, 模式: {pattern}")
                                        if pattern.lower() in response.text.lower():
                                            if tech not in server_info["technologies"]:
                                                server_info["technologies"].append(tech)
                                                self.logger.debug(f"在内容中检测到技术: {tech}")
                        except Exception as e:
                            self.logger.error(f"检测技术 {tech} 时出错: {str(e)}")
            else:
                self.logger.warning(f"web_fingerprints 未定义或为空，无法进行技术指纹检测")
            
            self.logger.info(f"URL {url} 的服务器信息: {server}, 技术: {', '.join(server_info['technologies'])}")
            return server_info
        except Exception as e:
            self.logger.error(f"检查服务器信息时发生错误: {str(e)}", exc_info=True)
            # 返回基本信息，确保不会因为异常而丢失记录
            return {
                "check_type": "server_info",
                "url": url,
                "server": headers.get('Server', '') if 'headers' in locals() else "检测失败",
                "powered_by": headers.get('X-Powered-By', '') if 'headers' in locals() else "",
                "technologies": [],
                "error": str(e)
            }

    def check_url_alive(self, url: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        检查URL是否存活
        
        Args:
            url: 要检查的URL
            
        Returns:
            (是否存活, 基本结果字典)
        """
        if self._stopped:
            return False, None
        
        # 创建一个基本结果
        basic_result = {
            "check_type": "basic_info",
            "url": url,
            "status_code": None,
            "server": None,
            "powered_by": None,
            "technologies": [],
            "headers": {},
            "response_time": None
        }
        
        try:
            # 创建临时会话用于检测存活性
            session = requests.Session()
            
            # 设置请求头
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            })
            
            # 获取配置参数
            timeout = min(self.config.get("timeout", 10), 5)  # 存活检测的超时时间更短
            verify_ssl = self.config.get("verify_ssl", False)
            
            # 先尝试HEAD请求，更快且消耗更少资源
            try:
                start_time = time.time()
                head_response = session.head(
                    url, 
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
                response_time = time.time() - start_time
                
                basic_result["status_code"] = head_response.status_code
                basic_result["response_time"] = round(response_time * 1000)  # 毫秒
                self._analyze_headers(basic_result, head_response.headers)
                basic_result["headers"] = dict(head_response.headers)
                
                # 判断网站是否存活 - 优化判断逻辑
                # 200-399: 成功或重定向，网站存活
                # 401, 403: 认证或权限问题，但网站存在
                # 其他状态码视为不存活
                status_code = head_response.status_code
                is_alive = (200 <= status_code < 400) or status_code in [401, 403]
                
                self.logger.debug(f"URL {url} 存活检测 (HEAD): 状态码={status_code}, 响应时间={basic_result['response_time']}ms, 存活={is_alive}")
                
                # 如果HEAD请求判断为不存活，但状态码非0（表示请求成功但返回了错误状态码）
                # 尝试GET请求进一步确认
                if not is_alive and status_code != 0:
                    # 可能是服务器不支持HEAD请求，尝试GET请求
                    self.logger.debug(f"HEAD请求返回状态码 {status_code}，尝试使用GET请求确认")
                else:
                    # 添加到扫描历史并返回结果
                    session.close()
                    return is_alive, basic_result
                
            except (requests.RequestException, ConnectionError, TimeoutError) as e:
                # HEAD 失败，尝试 GET
                self.logger.debug(f"HEAD请求失败: {str(e)}，尝试GET请求")
            
            # 如果HEAD失败或需要进一步确认，使用GET请求
            try:
                start_time = time.time()
                get_response = session.get(
                    url, 
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True,
                    stream=True  # 使用流式请求，避免下载大量数据
                )
                
                # 只读取前1KB数据
                content = get_response.raw.read(1024)
                get_response.close()
                
                response_time = time.time() - start_time
                
                basic_result["status_code"] = get_response.status_code
                basic_result["response_time"] = round(response_time * 1000)  # 毫秒
                self._analyze_headers(basic_result, get_response.headers)
                basic_result["headers"] = dict(get_response.headers)
                
                # 判断网站是否存活 - 优化判断逻辑
                status_code = get_response.status_code
                is_alive = (200 <= status_code < 400) or status_code in [401, 403]
                
                self.logger.debug(f"URL {url} 存活检测 (GET): 状态码={status_code}, 响应时间={basic_result['response_time']}ms, 存活={is_alive}")
                
                # 添加到扫描历史
                session.close()
                return is_alive, basic_result
                
            except (requests.RequestException, ConnectionError, TimeoutError) as e:
                basic_result["error"] = str(e)
                basic_result["status_code"] = 0
                self.logger.debug(f"URL {url} 无法访问: {str(e)}")
                session.close()
                return False, basic_result
                
        except Exception as e:
            self.logger.error(f"检测URL {url} 存活性时出错: {str(e)}")
            basic_result["error"] = str(e)
            basic_result["status_code"] = 0
            return False, basic_result 