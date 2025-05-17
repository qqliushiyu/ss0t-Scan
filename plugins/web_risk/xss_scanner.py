#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS漏洞检测插件
用于检测Web应用是否存在跨站脚本攻击漏洞
"""

import re
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, quote

from plugins.base_plugin import WebRiskPlugin

class XSSScanner(WebRiskPlugin):
    """XSS漏洞检测插件"""
    
    NAME = "XSS漏洞检测"
    DESCRIPTION = "检测Web应用是否存在跨站脚本攻击漏洞"
    VERSION = "1.0.0"
    AUTHOR = "NetTools"
    CATEGORY = "漏洞检测"
    
    # XSS测试负载
    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "'-alert(1)-'",
        "';alert(1)//",
        "\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "\" onmouseover=\"alert(1)\"",
        "<img src=\"x\" onerror=\"alert(1)\">"
    ]
    
    # 要测试的路径和参数类型
    TEST_PATHS = [
        ("/search.php", "q"),
        ("/index.php", "query"),
        ("/index.php", "search"),
        ("/profile.php", "name"),
        ("/comment.php", "text"),
        ("/post.php", "content"),
        ("/feedback.php", "message"),
        ("/contact.php", "email"),
        ("/search", "q"),
        ("/view.php", "page")
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化XSS检测插件"""
        super().__init__(config)
        
        # 从配置中加载自定义测试路径
        if config and 'custom_paths' in config:
            custom_paths = config['custom_paths']
            if isinstance(custom_paths, list):
                for path in custom_paths:
                    if isinstance(path, tuple) and len(path) == 2:
                        self.TEST_PATHS.append(path)
    
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行XSS检测
        
        Args:
            target: 目标URL
            session: 请求会话对象
            **kwargs: 其他参数
            
        Returns:
            检测结果列表
        """
        results = []
        
        # 确保target以/结尾
        if not target.endswith('/'):
            target = target + '/'
        
        # 使用提供的会话或创建新会话
        if session is None:
            session = requests.Session()
            # 设置请求头
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
            })
        
        # 获取额外配置
        timeout = kwargs.get('timeout', 10)
        max_test_paths = kwargs.get('max_test_paths', len(self.TEST_PATHS))
        verify_ssl = kwargs.get('verify_ssl', False)
        
        # 限制测试路径数量
        test_paths = self.TEST_PATHS[:max_test_paths]
        
        # 测试每个路径
        for path, param in test_paths:
            url = urljoin(target, path.lstrip('/'))
            
            # 测试每个负载
            for payload in self.PAYLOADS:
                # 构造请求参数
                params = {param: payload}
                
                try:
                    # 发送GET请求
                    response = session.get(
                        url, 
                        params=params, 
                        timeout=timeout,
                        verify=verify_ssl,
                        allow_redirects=False
                    )
                    
                    # 检查响应中是否包含未经过滤的XSS负载
                    if self._check_xss_in_response(response, payload):
                        # 发现XSS漏洞
                        vuln_url = f"{url}?{param}={quote(payload)}"
                        vuln_result = {
                            "name": "跨站脚本攻击漏洞",
                            "check_type": "plugin_result",
                            "vulnerability": "XSS",
                            "url": target,
                            "path": path,
                            "param": param,
                            "payload": payload,
                            "status": "vulnerable",
                            "severity": "高",
                            "details": f"在参数 {param} 中发现可能的XSS漏洞，测试URL: {vuln_url}",
                            "vector": vuln_url,
                            "recommendation": "对所有用户输入进行HTML编码、使用内容安全策略(CSP)并采用XSS过滤器。"
                        }
                        
                        # 添加到结果列表
                        results.append(vuln_result)
                        
                        # 一旦在一个参数中发现漏洞，跳过该参数的其他测试
                        break
                
                except (requests.RequestException, ConnectionError, TimeoutError) as e:
                    self.logger.warning(f"测试 {url} 时出错: {str(e)}")
                    continue
        
        # 如果没有发现漏洞，添加一个安全的结果
        if not results:
            results.append({
                "name": "XSS检测结果",
                "check_type": "plugin_result",
                "vulnerability": "XSS",
                "url": target,
                "status": "safe",
                "severity": "无",
                "details": "未发现XSS漏洞",
                "recommendation": "继续保持良好的安全实践，定期进行安全测试。"
            })
        
        return results
    
    def _check_xss_in_response(self, response: requests.Response, payload: str) -> bool:
        """
        检查响应中是否包含未经过滤的XSS负载
        
        Args:
            response: HTTP响应
            payload: XSS负载
        
        Returns:
            是否发现XSS漏洞
        """
        content_type = response.headers.get('Content-Type', '').lower()
        
        # 只检查HTML响应
        if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
            return False
        
        # 检查负载是否存在于响应中
        if payload in response.text:
            # 对于<script>标签，需要确保它们不在注释或字符串中
            if '<script>' in payload:
                # 使用正则表达式检查script标签是否在有效的HTML环境中
                script_pattern = re.escape(payload)
                script_regex = re.compile(script_pattern, re.IGNORECASE)
                
                # 如果匹配，并且不在注释或引号中
                if script_regex.search(response.text):
                    comment_pattern = r'<!--.*?' + script_pattern + r'.*?-->'
                    string_pattern = r'[\'"].*?' + script_pattern + r'.*?[\'"]'
                    
                    # 如果负载不在注释或字符串中
                    if not re.search(comment_pattern, response.text, re.DOTALL) and \
                       not re.search(string_pattern, response.text, re.DOTALL):
                        return True
            else:
                # 对于其他类型的XSS负载
                return True
        
        return False
        
    def validate_config(self) -> tuple:
        """验证配置"""
        # 如果配置中包含custom_paths，确保它是一个列表
        if 'custom_paths' in self.config:
            custom_paths = self.config['custom_paths']
            if not isinstance(custom_paths, list):
                return False, "custom_paths必须是一个列表"
                
            # 确保每个项目是一个二元组
            for path in custom_paths:
                if not isinstance(path, tuple) or len(path) != 2:
                    return False, "custom_paths中的每个项目必须是(路径, 参数名)的元组"
        
        return True, None 