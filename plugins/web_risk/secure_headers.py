#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
安全响应头检测插件
用于检查Web服务器是否配置了安全相关的HTTP头
"""

import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from plugins.base_plugin import WebRiskPlugin

class SecureHeadersScanner(WebRiskPlugin):
    """安全响应头检测插件"""
    
    NAME = "安全响应头检测"
    DESCRIPTION = "检查Web服务器是否配置了安全相关的HTTP头"
    VERSION = "1.0.0"
    AUTHOR = "NetTools"
    CATEGORY = "安全配置"
    
    # 重要的安全响应头及其建议值
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': '强制使用HTTPS连接',
            'recommendation': '建议设置为max-age=31536000; includeSubDomains; preload',
            'severity': '高'
        },
        'Content-Security-Policy': {
            'description': '控制允许加载的资源来源，有效防止XSS攻击',
            'recommendation': '根据应用需求配置适当的CSP策略',
            'severity': '高'
        },
        'X-Content-Type-Options': {
            'description': '防止浏览器MIME类型嗅探',
            'recommendation': '设置为nosniff',
            'severity': '中'
        },
        'X-Frame-Options': {
            'description': '防止网页被嵌入框架，抵御点击劫持攻击',
            'recommendation': '设置为DENY或SAMEORIGIN',
            'severity': '中'
        },
        'X-XSS-Protection': {
            'description': '启用浏览器XSS过滤器',
            'recommendation': '设置为1; mode=block',
            'severity': '中'
        },
        'Referrer-Policy': {
            'description': '控制HTTP请求中Referer头的内容',
            'recommendation': '设置为strict-origin-when-cross-origin或no-referrer-when-downgrade',
            'severity': '低'
        },
        'Feature-Policy': {
            'description': '控制浏览器功能和API的使用',
            'recommendation': '根据应用需求进行配置',
            'severity': '低'
        },
        'Permissions-Policy': {
            'description': '控制浏览器功能和API的使用(Feature-Policy的继任者)',
            'recommendation': '根据应用需求进行配置',
            'severity': '低'
        },
        'Cache-Control': {
            'description': '控制页面缓存策略',
            'recommendation': '对敏感页面设置为no-store, no-cache, must-revalidate, private',
            'severity': '中'
        }
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化安全响应头检测插件"""
        super().__init__(config)
        
        # 从配置中加载自定义检查的头
        if config and 'custom_headers' in config:
            custom_headers = config['custom_headers']
            if isinstance(custom_headers, dict):
                self.SECURITY_HEADERS.update(custom_headers)
    
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行安全响应头检测
        
        Args:
            target: 目标URL
            session: 请求会话对象
            **kwargs: 其他参数
            
        Returns:
            检测结果列表
        """
        results = []
        
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
        paths_to_check = kwargs.get('paths_to_check', ['/'])
        
        # 如果没有提供路径，检查根路径
        if not paths_to_check:
            paths_to_check = ['/']
        
        # 确保target末尾有斜杠
        if not target.endswith('/'):
            target = target + '/'
        
        # 检查每个路径
        for path in paths_to_check:
            url = urljoin(target, path.lstrip('/'))
            
            try:
                # 发送GET请求
                response = session.get(
                    url, 
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=False
                )
                
                # 检查安全头
                for header, info in self.SECURITY_HEADERS.items():
                    header_value = response.headers.get(header)
                    
                    if not header_value:
                        # 缺少安全头
                        results.append({
                            "check_type": "security_header",
                            "url": target,
                            "path": path,
                            "header": header,
                            "status": "missing",
                            "details": f"未配置 {header} 响应头",
                            "description": info['description'],
                            "recommendation": info['recommendation'],
                            "severity": info['severity']
                        })
                    else:
                        # 安全头存在，但可能需要进一步检查其值
                        # 这里可以根据需要添加更详细的值检查逻辑
                        results.append({
                            "check_type": "security_header",
                            "url": target,
                            "path": path,
                            "header": header,
                            "value": header_value,
                            "status": "present",
                            "details": f"已配置 {header} 响应头",
                            "description": info['description'],
                            "recommendation": "验证当前配置是否符合安全最佳实践"
                        })
            
            except (requests.RequestException, ConnectionError, TimeoutError) as e:
                self.logger.warning(f"检查 {url} 时出错: {str(e)}")
                results.append({
                    "check_type": "security_header",
                    "url": target,
                    "path": path,
                    "status": "error",
                    "details": f"检查安全头时出错: {str(e)}"
                })
        
        # 如果没有发现任何结果（可能是因为错误），添加一个通用结果
        if not results:
            results.append({
                "check_type": "security_header",
                "url": target,
                "status": "unknown",
                "details": "无法检查安全响应头"
            })
        
        return results
    
    def validate_config(self) -> tuple:
        """验证配置"""
        # 如果配置中包含custom_headers，确保它是一个字典
        if 'custom_headers' in self.config:
            custom_headers = self.config['custom_headers']
            if not isinstance(custom_headers, dict):
                return False, "custom_headers必须是一个字典"
                
            # 确保每个项目包含必要的字段
            for header, info in custom_headers.items():
                if not isinstance(info, dict):
                    return False, f"头 '{header}' 的信息必须是一个字典"
                
                required_fields = ['description', 'recommendation', 'severity']
                for field in required_fields:
                    if field not in info:
                        return False, f"头 '{header}' 的信息缺少必要字段 '{field}'"
        
        return True, None 