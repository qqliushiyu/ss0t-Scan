#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL注入检测插件
用于检测Web应用是否存在SQL注入漏洞
"""

import re
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from plugins.base_plugin import WebRiskPlugin

class SQLInjectionScanner(WebRiskPlugin):
    """SQL注入漏洞检测插件"""
    
    NAME = "SQL注入检测"
    DESCRIPTION = "检测Web应用是否存在SQL注入漏洞"
    VERSION = "1.0.0"
    AUTHOR = "NetTools"
    CATEGORY = "漏洞检测"
    
    # SQL注入测试负载
    PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 1=1 #",
        '" OR 1=1 --',
        "' UNION SELECT 1,2,3 --",
        "' AND 1=0 UNION SELECT 1,2,3 --",
        "'; WAITFOR DELAY '0:0:5' --",
        "1' OR '1'='1",
        "admin' --",
        "admin' #",
        "' OR '1'='1' -- -",
        "' OR '1'='1' /* ",
    ]
    
    # SQL错误模式
    ERROR_PATTERNS = [
        r"SQL syntax.*?MySQL", 
        r"Warning.*?mysqli",
        r"Warning.*?SQLite3",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Microsoft SQL Native Client error",
        r"SQL Server.*?Error",
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"PLS-[0-9]{4}",
        r"PostgreSQL.*?ERROR",
        r"ERROR:.*?syntax error",
        r"Division by zero",
        r"supplied argument is not a valid MySQL result resource",
        r"mysql_fetch_array\(\)",
        r"Incorrect syntax near",
        r"Unclosed quotation mark",
        r"Syntax error in string in query expression",
        r"You have an error in your SQL syntax",
        r"SQLite3::query\(\)"
    ]
    
    # 要测试的路径和参数类型
    TEST_PATHS = [
        ("/index.php", "id"),
        ("/search.php", "q"),
        ("/product.php", "id"),
        ("/article.php", "id"),
        ("/login.php", "username"),
        ("/user.php", "id"),
        ("/profile.php", "id"),
        ("/view.php", "page"),
        ("/news.php", "id"),
        ("/item.php", "id")
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化SQL注入检测插件"""
        super().__init__(config)
        
        # 编译正则表达式
        self.error_regex = re.compile('|'.join(self.ERROR_PATTERNS), re.IGNORECASE)
        
        # 从配置中加载自定义测试路径
        if config and 'custom_paths' in config:
            custom_paths = config['custom_paths']
            if isinstance(custom_paths, list):
                for path in custom_paths:
                    if isinstance(path, tuple) and len(path) == 2:
                        self.TEST_PATHS.append(path)
    
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行SQL注入检测
        
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
                    
                    # 检查是否存在SQL错误
                    if self.error_regex.search(response.text):
                        # 发现SQL注入漏洞
                        vuln_url = f"{url}?{param}={payload}"
                        results.append({
                            "check_type": "vulnerability",
                            "vulnerability": "SQL注入",
                            "url": target,
                            "path": path,
                            "param": param,
                            "payload": payload,
                            "status": "vulnerable",
                            "details": f"在参数 {param} 中发现可能的SQL注入点",
                            "vector": vuln_url,
                            "recommendation": "对所有用户输入进行参数化查询处理，避免直接拼接SQL语句。"
                        })
                        
                        # 一旦在一个参数中发现漏洞，跳过该参数的其他测试
                        break
                
                except (requests.RequestException, ConnectionError, TimeoutError) as e:
                    self.logger.warning(f"测试 {url} 时出错: {str(e)}")
                    continue
        
        # 如果没有发现漏洞，添加一个安全的结果
        if not results:
            results.append({
                "check_type": "vulnerability",
                "vulnerability": "SQL注入",
                "url": target,
                "status": "safe",
                "details": "未发现SQL注入漏洞",
                "recommendation": "继续保持良好的安全实践，定期进行安全测试。"
            })
        
        return results
        
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