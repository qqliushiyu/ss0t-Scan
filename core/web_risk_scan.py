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
import logging

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
        # Set urllib3.connectionpool logger to ERROR to suppress connection timeout warnings
        try:
            urllib3_logger = logging.getLogger("urllib3.connectionpool")
            if urllib3_logger: # Check if logger exists
                urllib3_logger.setLevel(logging.ERROR)
                # Also check if a handler is present and if its level is lower than ERROR
                # This is an extra step, usually setting logger level is enough
                for handler in urllib3_logger.handlers:
                    if handler.level < logging.ERROR:
                         handler.setLevel(logging.ERROR) # Ensure handler also respects the new level
            # Fallback if specific logger not found, try to configure urllib3 globally, though less ideal
            else: 
                logging.getLogger("urllib3").setLevel(logging.ERROR)


        except Exception as e:
            # Use a generic logger if self.logger is not yet initialized
            logging.getLogger(__name__).warning(f"Failed to set urllib3 log level: {e}")

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
                response.raise_for_status() # Check for HTTP errors (4xx or 5xx)

            except requests.exceptions.ConnectTimeout as e:
                self.logger.debug(f"连接 {url} 超时 (ConnectTimeout): {str(e)}")
                return results # 返回已收集的结果，因为无法连接
            except requests.exceptions.ConnectionError as e:
                self.logger.debug(f"连接 {url} 失败 (ConnectionError): {str(e)}")
                return results # 返回已收集的结果，因为无法连接
            except requests.exceptions.Timeout as e: # Catches other timeouts like ReadTimeout
                self.logger.warning(f"读取 {url} 内容超时 (Timeout): {str(e)}")
                # 即使读取超时，也可能已经有部分结果（如headers），所以不立即返回
                # 但后续依赖response对象的插件可能失败
            except requests.exceptions.HTTPError as e:
                self.logger.warning(f"访问 {url} 时发生HTTP错误: {e.response.status_code} - {e.response.reason}")
                # HTTP错误意味着服务器有响应，可以继续尝试分析已有的response（如果有）
            except requests.exceptions.RequestException as e:
                self.logger.error(f"获取 {url} 内容时发生请求异常: {type(e).__name__} - {str(e)}")
                return results
            except Exception as e:
                self.logger.error(f"获取{url}内容时发生未知错误: {type(e).__name__} - {str(e)}", exc_info=True)
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
            return ScanResult(success=False, data=[], error_msg="扫描已提前停止")
        
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
            
            # 重置结果计数器
            self.result_counts = {}
            
            # 确保在开始新扫描前，之前的执行器已关闭
            if hasattr(self, '_executor') and self._executor:
                if not self._executor._shutdown:
                    self.logger.warning("检测到旧的线程池未关闭，正在尝试关闭...")
                    self._executor.shutdown(wait=True, cancel_futures=True) # 等待关闭
                self._executor = None # 显式置空

            # 创建新的线程池
            # 使用 with 语句确保线程池最终能关闭
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count, thread_name_prefix="WebScanWorker") as executor:
                self._executor = executor # 保存引用，以便stop方法可以访问
                futures_map = {}

                # 1. 存活性检测 (如果需要)
                # 这里假设存活性检测已经集成到scan_url或由插件处理
                # 如果需要单独的存活性检测阶段，应在此处实现并检查self._stopped

                # 2. 提交详细扫描任务
                self.logger.info(f"开始对 {len(urls)} 个目标提交详细安全扫描任务...")
                for url in urls:
                    if self._stopped:
                        self.logger.info("扫描在任务提交阶段被停止")
                        # 取消已提交但未开始的future
                        # futures_map 的键是 Future 对象
                        for future_obj in futures_map.keys(): 
                            if isinstance(future_obj, concurrent.futures.Future):
                                if not future_obj.done():
                                    future_obj.cancel()
                            else:
                                # This case should ideally not happen if futures_map is populated correctly
                                self.logger.error(f" futures_map 中发现意外的键类型: {type(future_obj)}. 无法取消。")
                        break 
                    
                    future = executor.submit(self.scan_url, url)
                    futures_map[future] = url # Key: Future, Value: URL
                
                # 等待任务完成
                processed_count = 0
                for future in concurrent.futures.as_completed(futures_map): # future here is a Future object from futures_map.keys()
                    if self._stopped:
                        self.logger.info("扫描在等待任务完成阶段被停止")
                        # 尝试取消剩余的future 
                        # futures_map 的键是 Future 对象
                        for future_obj in futures_map.keys(): # Iterate over Future objects
                            if isinstance(future_obj, concurrent.futures.Future): # Redundant check, but safe
                                if not future_obj.done():
                                    future_obj.cancel()
                            # else: # Should not be reached if map is {Future: URL}
                                # self.logger.error(f"处理 futures_map 时发现意外的键类型: {type(future_obj)}. 无法取消。")
                        break

                    url = futures_map[future] # Get URL using the completed Future object as key
                    try:
                        results = future.result()
                        if results:
                            all_results.extend(results)
                    except concurrent.futures.CancelledError:
                        self.logger.info(f"URL {url} 的扫描任务被取消。")
                    except Exception as e:
                        self.logger.error(f"URL {url} 扫描失败: {type(e).__name__} - {str(e)}", exc_info=False)
                        self.add_result({"url": url, "check_type": "error", "error": str(e)})
                    
                    processed_count += 1
                    progress_percent = (processed_count * 100) // self._total_urls
                    self.update_progress(progress_percent, f"已处理 {processed_count}/{self._total_urls} 个目标")
                
                if self._stopped:
                    self.logger.info("扫描被中断，部分任务可能未完成。")

            # 清理 _executor 引用
            self._executor = None

        except Exception as e:
            self.logger.error(f"Web风险扫描执行期间发生严重错误: {str(e)}", exc_info=True)
            return ScanResult(success=False, data=all_results, error_msg=str(e), metadata=self.get_scan_metadata())
            
        end_time = time.time()
        duration = int(end_time - start_time)
        
        summary_message = f"扫描完成，总用时: {duration // 60}分{duration % 60}秒"
        self.logger.info(summary_message)
        self.logger.info(f"结果统计: {json.dumps(self.result_counts)}")
        
        # 更新最终进度
        self.update_progress(100, summary_message)
        
        return ScanResult(success=True, data=all_results, metadata=self.get_scan_metadata())

    def stop(self) -> None:
        """
        停止扫描
        """
        if not self._stopped:
            stop_start_time = time.time()
            self.logger.info("正在停止Web风险扫描...")
            
            # 立即设置停止标志，所有插件和扫描逻辑应检查此标志
            self._stopped = True
            
            # 尝试优雅地关闭线程池
            if hasattr(self, '_executor') and self._executor:
                self.logger.info("正在请求关闭扫描线程池 (等待最多3秒)...")
                # cancel_futures=True 将尝试取消队列中未开始的任务
                # shutdown(wait=True)会等待正在执行的任务完成（除非它们自己检查_stopped并退出）
                try:
                    self._executor.shutdown(wait=True, cancel_futures=True) 
                    self.logger.info("扫描线程池已关闭。")
                except Exception as e: # pylint: disable=broad-except
                    self.logger.error(f"关闭扫描线程池时发生错误: {e}. 可能有任务未完全停止。")

            # 停止所有插件
            # 插件的stop方法应确保其内部任务尽快结束
            if hasattr(self, 'loaded_plugins'):
                for plugin_id, plugin_instance in self.loaded_plugins.items():
                    if hasattr(plugin_instance, 'stop'):
                        try:
                            self.logger.info(f"正在停止插件: {plugin_id}...")
                            plugin_instance.stop()
                        except Exception as e:
                            self.logger.error(f"停止插件 {plugin_id} 时出错: {str(e)}")
            
            # 不再使用ctypes强制终止线程，因为这非常危险
            # self.logger.info("ctypes线程终止逻辑已被移除以提高稳定性。")

            # 清理会话和future列表 (以防万一)
            # 这些应该在线程池关闭和插件停止后自然清理
            cancelled_futures = 0
            if hasattr(self, '_futures') and self._futures:
                for future in self._futures:
                    if not future.done():
                        if future.cancel(): # cancel() 返回True如果成功取消
                            cancelled_futures +=1
                self._futures.clear()

            if hasattr(self, '_sessions') and self._sessions:
                for session in self._sessions:
                    try:
                        session.close()
                    except: # pylint: disable=bare-except
                        pass
                self._sessions.clear()

            self.logger.info(f"Web风险扫描停止请求处理完毕。取消了 {cancelled_futures} 个 futures。用时 {time.time() - stop_start_time:.2f} 秒。")

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
    
    def get_scan_metadata(self) -> Dict[str, Any]:
        """
        获取扫描元数据
        
        Returns:
            扫描元数据字典
        """
        # 构建 scan_config 字典，包含报告中期望的配置项
        report_scan_config = {}
        important_configs_for_report = [
            "targets", "ports", "threads", "timeout", "verify_ssl", 
            "follow_redirects", "scan_depth", "user_agent",
            "scan_headers", "scan_ssl", "detect_waf", "custom_headers", "cookies"
            # 可以根据需要添加更多配置项
        ]
        for key in important_configs_for_report:
            if key in self.config:
                report_scan_config[key] = self.config[key]

        return {
            "scanner_version": self.VERSION,
            "scan_config": report_scan_config, # 使用 "scan_config" 作为键名
            "total_urls_prepared": self._total_urls if hasattr(self, '_total_urls') else 'N/A',
            "urls_scanned_completed": self._scanned_urls if hasattr(self, '_scanned_urls') else 'N/A',
            "plugin_info": plugin_manager.get_plugin_info_list(enabled_only=True) # 更新调用
        }
    
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
            
            # 使用 .get() 提供默认值，增加健壮性
            user_agent = self.config.get("user_agent", 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36')
            timeout = self.config.get("timeout", 10)
            verify_ssl = self.config.get("verify_ssl", False)
            follow_redirects = self.config.get("follow_redirects", True)
            
            headers = {'User-Agent': user_agent}
            
            for payload in [xss_payload, sqli_payload]:
                response = session.get(
                    payload, 
                    headers=headers, 
                    timeout=timeout,
                    verify=verify_ssl, # 使用获取的配置
                    allow_redirects=follow_redirects # 使用获取的配置
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
        
        # 从配置获取相关参数，增加健壮性
        timeout = self.config.get("timeout", 10)
        verify_ssl = self.config.get("verify_ssl", False)
        follow_redirects = self.config.get("follow_redirects", True)
        vuln_timeout = min(3, timeout) # 使用较短的超时时间

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
                    response = session.get(
                        test_url,
                        timeout=vuln_timeout, # 已在上面获取和计算
                        verify=verify_ssl, # 使用获取的配置
                        allow_redirects=follow_redirects # 使用获取的配置
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
        # 调用基类的进度回调，确保进度能传递到UI
        if self.progress_callback:
            self.progress_callback(progress, message)
        else:
            super().update_progress(progress, message)
        
        # 不再直接调用自定义结果回调，避免重复更新
        # 注释掉以下代码，防止多重回调冲突
        # if self._result_callback:
        #     self._result_callback({
        #         "check_type": "progress",
        #         "progress": progress,
        #         "message": message
        #     })

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
            follow_redirects = self.config.get("follow_redirects", True) # 从配置读取

            # 先尝试HEAD请求，更快且消耗更少资源
            try:
                start_time = time.time()
                head_response = session.head(
                    url, 
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=follow_redirects # 使用配置值
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
                    allow_redirects=follow_redirects, # 使用配置值
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

    def execute(self) -> ScanResult:
        """
        执行扫描
        
        Returns:
            扫描结果
        """
        # 重置状态
        self._stopped = False
        self._scanned_urls = 0
        self._total_urls = 0
        self._sessions = []
        self._futures = []
        
        # 清理线程池资源，确保干净重启
        try:
            import concurrent.futures
            import gc
            import sys
            
            # 强制垃圾回收，刷新内存中的对象引用
            gc.collect()
            
            # 关闭所有未关闭的线程池
            executors_found = 0
            for obj in gc.get_objects():
                if isinstance(obj, concurrent.futures.ThreadPoolExecutor):
                    try:
                        if not getattr(obj, '_shutdown', True):
                            obj.shutdown(wait=False)
                            executors_found += 1
                    except Exception as e:
                        self.logger.warning(f"关闭已存在的线程池时出错: {str(e)}")
            
            if executors_found > 0:
                self.logger.info(f"已关闭 {executors_found} 个未关闭的线程池")
                
            # 重置concurrent.futures内部状态
            if 'concurrent.futures' in sys.modules:
                try:
                    sys.modules['concurrent.futures']._shutdown = False
                except:
                    pass
                
        except Exception as e:
            self.logger.warning(f"清理线程池资源时出错，但会继续扫描: {str(e)}")
        
        # 清理网络连接
        try:
            import socket
            socket.setdefaulttimeout(10)  # 恢复正常超时设置
            
            # 重置请求库连接池
            import requests
            from urllib3.util.retry import Retry
            requests.packages.urllib3.disable_warnings()
            
            # 安全地关闭连接池
            try:
                from requests.adapters import HTTPAdapter
                adapter = HTTPAdapter()
                if hasattr(adapter, 'close'):
                    adapter.close()
            except Exception as e:
                self.logger.warning(f"关闭连接池适配器时出错: {str(e)}")
                
        except Exception as e:
            self.logger.warning(f"清理网络连接时出错: {str(e)}")
        
        # 开始扫描
        try:
            return self.run_scan()
        except Exception as e:
            self.logger.error(f"执行扫描时出错: {str(e)}")
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"扫描出错: {str(e)}"
            ) 