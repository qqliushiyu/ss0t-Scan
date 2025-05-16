#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
通用Web漏洞检测插件
用于检测Web应用是否存在常见漏洞，如目录遍历、文件包含、敏感文件等
"""

import re
import requests
import urllib.parse
from typing import Dict, List, Any, Optional

from plugins.base_plugin import WebRiskPlugin

class VulnScanner(WebRiskPlugin):
    """通用Web漏洞检测插件"""
    
    NAME = "通用漏洞检测"
    DESCRIPTION = "检测Web应用是否存在目录遍历、文件包含、敏感文件等漏洞"
    VERSION = "1.0.0"
    AUTHOR = "NetTools"
    CATEGORY = "漏洞检测"
    
    # 默认漏洞检测路径
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
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化通用漏洞检测插件"""
        super().__init__(config)
        
        # 从配置中加载自定义漏洞路径
        self.vuln_paths = self.DEFAULT_VULN_PATHS.copy()
        if config and 'custom_paths' in config:
            for vuln_type, paths in config['custom_paths'].items():
                if isinstance(paths, list):
                    self.vuln_paths[vuln_type] = paths
    
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行漏洞检测
        
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
        verify_ssl = kwargs.get('verify_ssl', False)
        follow_redirects = kwargs.get('follow_redirects', True)
        max_paths_per_vuln = kwargs.get('max_paths_per_vuln', 3)
        scan_depth = kwargs.get('scan_depth', 1)
        
        # 根据扫描深度调整测试路径数量
        if scan_depth == 0:
            return [{
                "check_type": "vulnerability",
                "vulnerability": "通用漏洞",
                "url": target,
                "status": "skipped",
                "details": "根据扫描深度设置跳过漏洞检测"
            }]
        elif scan_depth == 1:
            max_paths_per_vuln = 1
        
        # 对每种漏洞类型进行检查
        for vuln_type, paths in self.vuln_paths.items():
            # 限制每类漏洞测试的路径数量
            for path in paths[:max_paths_per_vuln]:
                try:
                    test_url = urllib.parse.urljoin(target, path.lstrip('/'))
                    
                    # 使用较短的超时时间
                    vuln_timeout = min(3, timeout)
                    response = session.get(
                        test_url,
                        timeout=vuln_timeout,
                        verify=verify_ssl,
                        allow_redirects=follow_redirects
                    )
                    
                    vuln_found = False
                    detail = ""
                    
                    # 根据漏洞类型判断是否存在漏洞
                    if vuln_type == "目录遍历" or vuln_type == "文件包含":
                        if "root:" in response.text or "[boot loader]" in response.text:
                            vuln_found = True
                            detail = "发现敏感系统文件内容"
                    
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
                        results.append({
                            "url": test_url,
                            "check_type": "vulnerability",
                            "vulnerability": vuln_type,
                            "status": "vulnerable",
                            "details": detail,
                            "recommendation": "修复相关漏洞，确保安全过滤或禁止访问"
                        })
                        
                        # 找到一个漏洞后就跳过同类型的其他测试，减少测试时间
                        break
                
                except Exception as e:
                    self.logger.debug(f"检查漏洞 {vuln_type} 在 {target} 失败: {str(e)}")
                    continue
        
        # 如果没有发现漏洞，添加一个安全的结果
        if not results:
            results.append({
                "check_type": "vulnerability",
                "vulnerability": "通用漏洞",
                "url": target,
                "status": "safe",
                "details": "未发现常见漏洞",
                "recommendation": "继续保持良好的安全实践，定期进行安全测试。"
            })
        
        return results
    
    def validate_config(self) -> tuple:
        """验证配置"""
        # 如果配置中包含custom_paths，确保它是一个字典
        if 'custom_paths' in self.config:
            custom_paths = self.config['custom_paths']
            if not isinstance(custom_paths, dict):
                return False, "custom_paths必须是一个字典"
                
            # 确保每个值是一个列表
            for vuln_type, paths in custom_paths.items():
                if not isinstance(paths, list):
                    return False, f"漏洞类型 '{vuln_type}' 的路径必须是一个列表"
        
        return True, None 