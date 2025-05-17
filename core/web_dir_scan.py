#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web目录扫描模块
用于扫描网站目录结构，发现敏感文件和隐藏路径
"""

import concurrent.futures
import json
import os
import requests
import time
import urllib.parse
from typing import Dict, List, Any, Tuple, Optional, Set

from core.base_scanner import BaseScanner, ScanResult
from utils.config import config_manager

class WebDirScanner(BaseScanner):
    """
    Web目录扫描模块
    用于扫描网站目录结构，发现敏感文件和隐藏路径
    支持常见字典路径扫描、过滤状态码
    """
    
    VERSION = "1.0.0"
    
    # 常见状态码描述
    STATUS_CODES = {
        200: "正常",
        201: "已创建",
        301: "永久重定向",
        302: "临时重定向",
        400: "请求错误",
        401: "未授权",
        403: "禁止访问",
        404: "未找到",
        500: "服务器错误",
        502: "网关错误",
        503: "服务不可用"
    }
    
    # 默认字典目录
    DEFAULT_DICT_DIR = "config/dicts"
    
    # 默认常见扩展名
    DEFAULT_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".js", ".css", ".bak", ".txt", ".zip", ".rar", ".tar.gz", ".sql"]
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化Web目录扫描器"""
        super().__init__(config)
        self._stopped = False
        self._scanned_paths = set()  # 已扫描路径集合
        self._found_paths = []       # 发现的路径列表
        self._scan_count = 0         # 扫描计数
        self._total_paths = 0        # 总路径数
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数
        
        Returns:
            (成功标志, 错误信息)
        """
        valid_keys = {
            "target",           # 目标URL
            "dict_file",        # 字典文件路径
            "extensions",       # 扩展名列表
            "timeout",          # 请求超时
            "threads",          # 线程数
            "status_codes",     # 过滤状态码
            "user_agent",       # UA标头
            "follow_redirects", # 是否跟随重定向
            "cookies",          # Cookie字符串
            "auth",             # 认证信息
            "scan_delay",       # 扫描延迟(ms)
            "custom_headers"    # 自定义HTTP头
        }
        
        required_keys = ["target"]
        
        # 检查必要参数
        for key in required_keys:
            if key not in self.config:
                return False, f"缺少必要参数: {key}"
        
        # 验证目标URL格式
        target = self.config["target"]
        if not target.startswith(("http://", "https://")):
            return False, "目标URL必须以http://或https://开头"
        
        # 设置默认值
        if "timeout" not in self.config:
            self.config["timeout"] = 10.0
        
        if "threads" not in self.config:
            self.config["threads"] = 10
        
        if "status_codes" not in self.config:
            # 默认只接受200, 201, 301, 302状态码
            self.config["status_codes"] = [200, 201, 301, 302]
        elif isinstance(self.config["status_codes"], str):
            # 如果是字符串，转换为列表
            codes = [int(code.strip()) for code in self.config["status_codes"].split(",")]
            self.config["status_codes"] = codes
        
        if "follow_redirects" not in self.config:
            self.config["follow_redirects"] = True
        
        if "scan_delay" not in self.config:
            self.config["scan_delay"] = 0
        
        if "user_agent" not in self.config:
            self.config["user_agent"] = config_manager.get("web_scan", "user_agent", 
                fallback="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
        
        return True, None
    
    def load_dictionary(self) -> List[str]:
        """
        加载目录字典
        
        Returns:
            路径列表
        """
        paths = []
        
        # 使用指定的字典文件
        if "dict_file" in self.config and self.config["dict_file"]:
            dict_file = self.config["dict_file"]
            if not os.path.isabs(dict_file):
                # 相对路径，从默认字典目录加载
                dict_file = os.path.join(self.DEFAULT_DICT_DIR, dict_file)
            
            if os.path.exists(dict_file):
                try:
                    with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            path = line.strip()
                            if path and not path.startswith('#'):
                                paths.append(path)
                    
                    self.logger.info(f"从字典 {dict_file} 加载了 {len(paths)} 个路径")
                except IOError as e:
                    self.logger.error(f"加载字典文件失败: {str(e)}")
                    # 使用内置简易字典
                    paths = self._get_builtin_paths()
            else:
                self.logger.warning(f"字典文件 {dict_file} 不存在，使用内置字典")
                # 使用内置简易字典
                paths = self._get_builtin_paths()
        else:
            # 使用内置简易字典
            self.logger.info("未指定字典文件，使用内置字典")
            paths = self._get_builtin_paths()
        
        # 处理扩展名
        if "extensions" in self.config and self.config["extensions"]:
            extensions = self.config["extensions"]
            if isinstance(extensions, str):
                extensions = [ext.strip() for ext in extensions.split(",")]
        else:
            extensions = self.DEFAULT_EXTENSIONS
        
        # 添加带扩展名的路径
        original_count = len(paths)
        extended_paths = []
        
        for path in paths:
            # 如果路径已经有扩展名，不增加额外扩展
            if '.' in path.split('/')[-1]:
                extended_paths.append(path)
                continue
            
            # 添加原始路径
            extended_paths.append(path)
            
            # 添加带扩展名的路径
            for ext in extensions:
                if not ext.startswith('.'):
                    ext = '.' + ext
                extended_paths.append(f"{path}{ext}")
        
        self.logger.info(f"处理扩展名后，字典大小从 {original_count} 增加到 {len(extended_paths)}")
        
        return extended_paths
    
    def _get_builtin_paths(self) -> List[str]:
        """
        获取内置字典路径列表
        
        Returns:
            内置路径列表
        """
        # 常见目录和文件的内置列表
        return [
            "admin", "login", "wp-admin", "administrator", "phpmyadmin",
            "manager", "manage", "user", "users", "wp-login.php", "console",
            "config", "configuration", "setup", "install", "backup", "backups",
            "dump", "db", "database", "log", "logs", "tmp", "temp", "test",
            "upload", "uploads", "api", "apis", "v1", "v2", "docs", "doc",
            "documentation", "dashboard", "status", "stats", "phpinfo.php",
            "info.php", "server-status", ".git", ".svn", ".env", ".htaccess",
            "robots.txt", "sitemap.xml", "index.bak", "config.php.bak",
            "admin.php", "login.php", "signin.php", "register.php", "password",
            "reset", "old", "new", "dev", "development", "staging", "prod",
            "production", "test", "demo", "beta", "files", "file", "static",
            "assets", "css", "js", "images", "img", "media", "themes", "theme",
            "templates", "template", "includes", "inc", "scripts", "script",
            "lib", "libs", "library", "panel", "cpanel", "webadmin", "readme",
            "README.md", "CHANGELOG.md", "LICENSE", "web.config", "config.xml",
            "server.xml", "app.js", "app.php", "config.ini", "settings.php"
        ]
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        扫描单个URL
        
        Args:
            url: 目标URL
        
        Returns:
            扫描结果字典
        """
        if self._stopped:
            return None
        
        self._scan_count += 1
        
        # 更新进度
        percent = int(self._scan_count * 100 / self._total_paths) if self._total_paths > 0 else 0
        if self._scan_count % 10 == 0 or percent >= 100:
            self.update_progress(
                percent,
                f"已扫描: {self._scan_count}/{self._total_paths}, 已发现: {len(self._found_paths)}"
            )
        
        # 设置请求头
        headers = {
            'User-Agent': self.config.get("user_agent")
        }
        
        # 添加自定义请求头
        custom_headers = self.config.get("custom_headers", {})
        if custom_headers:
            if isinstance(custom_headers, str):
                try:
                    headers.update(json.loads(custom_headers))
                except Exception as e:
                    self.logger.warning(f"解析自定义请求头失败: {str(e)}")
            elif isinstance(custom_headers, dict):
                headers.update(custom_headers)
        
        # 添加Cookie
        cookies = None
        if "cookies" in self.config and self.config["cookies"]:
            try:
                if isinstance(self.config["cookies"], str):
                    cookies = {}
                    for cookie in self.config["cookies"].split(";"):
                        if "=" in cookie:
                            key, value = cookie.split("=", 1)
                            cookies[key.strip()] = value.strip()
                elif isinstance(self.config["cookies"], dict):
                    cookies = self.config["cookies"]
            except Exception as e:
                self.logger.warning(f"解析Cookie失败: {str(e)}")
        
        # 添加认证
        auth = None
        if "auth" in self.config and self.config["auth"]:
            try:
                if isinstance(self.config["auth"], str) and ":" in self.config["auth"]:
                    username, password = self.config["auth"].split(":", 1)
                    auth = (username, password)
                elif isinstance(self.config["auth"], (list, tuple)) and len(self.config["auth"]) == 2:
                    auth = tuple(self.config["auth"])
            except Exception as e:
                self.logger.warning(f"解析认证信息失败: {str(e)}")
        
        try:
            # 添加扫描延迟
            scan_delay = float(self.config.get("scan_delay", 0)) / 1000.0
            if scan_delay > 0:
                time.sleep(scan_delay)
            
            # 发送请求
            timeout = float(self.config.get("timeout", 10.0))
            allow_redirects = bool(self.config.get("follow_redirects", True))
            
            response = requests.get(
                url,
                headers=headers,
                cookies=cookies,
                auth=auth,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False  # 禁用SSL验证
            )
            
            # 获取状态码和长度
            status_code = response.status_code
            content_length = len(response.content)
            
            # 检查状态码是否在接受列表中
            accepted_codes = self.config.get("status_codes", [200, 201, 301, 302])
            
            if status_code in accepted_codes:
                # 提取页面标题
                title = ""
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')
                    if soup.title:
                        title = soup.title.string.strip()
                except Exception:
                    # BeautifulSoup可能未安装或解析失败
                    import re
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()
                
                # 计算路径相对于根URL的部分
                target_url = self.config["target"]
                path = url[len(target_url):] if url.startswith(target_url) else url
                
                # 记录结果
                result = {
                    "url": url,
                    "path": path,
                    "status_code": status_code,
                    "status": self.STATUS_CODES.get(status_code, "未知"),
                    "content_length": content_length,
                    "title": title,
                    "redirect_url": response.url if response.url != url and allow_redirects else ""
                }
                
                # 添加到发现列表
                self._found_paths.append(result)
                return result
        
        except requests.RequestException as e:
            self.logger.debug(f"扫描URL失败: {url}, 错误: {str(e)}")
        
        return None
    
    def run_scan(self) -> ScanResult:
        """
        执行扫描操作
        
        Returns:
            扫描结果
        """
        # 禁用"不安全请求"的警告
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        target_url = self.config["target"]
        
        # 确保URL以斜杠结尾
        if not target_url.endswith('/'):
            target_url += '/'
            self.config["target"] = target_url
        
        self.logger.info(f"开始扫描目标: {target_url}")
        self.update_progress(0, "正在加载字典...")
        
        # 加载字典
        paths = self.load_dictionary()
        self._total_paths = len(paths)
        
        # 重置计数器
        self._scan_count = 0
        self._found_paths = []
        self._scanned_paths = set()
        
        self.logger.info(f"字典加载完成，共 {self._total_paths} 个路径")
        self.update_progress(0, f"开始扫描，共 {self._total_paths} 个路径")
        
        # 转换为完整URL
        urls = []
        for path in paths:
            if path.startswith('/'):
                path = path[1:]
            url = target_url + path
            urls.append(url)
        
        # 配置线程池
        max_threads = int(self.config.get("threads", 10))
        
        # 限制线程数，避免过大导致性能问题
        max_threads = min(max_threads, 50)
        
        results = []
        
        try:
            # 使用线程池进行并发扫描
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
                
                for future in concurrent.futures.as_completed(future_to_url):
                    if self._stopped:
                        break
                    
                    result = future.result()
                    if result:
                        results.append(result)
            
            self.logger.info(f"扫描完成，共尝试 {self._scan_count} 个路径，发现 {len(results)} 个结果")
            return ScanResult(success=True, data=results)
        
        except Exception as e:
            self.logger.error(f"扫描过程中发生错误: {str(e)}", exc_info=True)
            return ScanResult(
                success=False,
                data=results,
                error_msg=f"扫描错误: {str(e)}"
            )
    
    def stop(self) -> None:
        """停止扫描"""
        self._stopped = True
        super().stop() 