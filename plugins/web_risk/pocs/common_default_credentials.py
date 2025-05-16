#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
常见Web应用默认凭据检测 POC
"""

import requests
import re
import time
from typing import Tuple, Dict, Any, List, Optional

# POC信息
name = "常见Web应用默认凭据检测"
description = "检测常见Web应用是否使用默认凭据，包括常见路由器、CMS、管理面板等"
author = "ss0t-scna"
type = "凭据检测"
severity = "high"  # 严重程度: critical, high, medium, low, info

# 常见默认凭据列表
DEFAULT_CREDENTIALS = [
    # 格式: [应用名称, 登录路径, 请求方法, 数据格式(form/json), 用户字段, 密码字段, 用户名, 密码, 成功标记]
    
    # 路由器和网络设备
    ["TP-Link Router", "/login.htm", "POST", "form", "username", "password", "admin", "admin", "success"],
    ["TP-Link Router", "/login.htm", "POST", "form", "username", "password", "admin", "password", "success"],
    ["D-Link Router", "/login.htm", "POST", "form", "username", "password", "admin", "admin", "success"],
    ["D-Link Router", "/login.htm", "POST", "form", "username", "password", "admin", "", "success"],
    ["Netgear Router", "/login.htm", "POST", "form", "username", "password", "admin", "password", "success"],
    ["Cisco Router", "/login.html", "POST", "form", "username", "password", "cisco", "cisco", "success"],
    ["Mikrotik RouterOS", "/login", "POST", "form", "username", "password", "admin", "", "success"],
    
    # Web服务器和管理面板
    ["phpMyAdmin", "/phpmyadmin/index.php", "POST", "form", "pma_username", "pma_password", "root", "", "success"],
    ["phpMyAdmin", "/phpmyadmin/index.php", "POST", "form", "pma_username", "pma_password", "root", "root", "success"],
    ["phpMyAdmin", "/phpmyadmin/index.php", "POST", "form", "pma_username", "pma_password", "admin", "admin", "success"],
    ["cPanel", "/login", "POST", "form", "user", "pass", "admin", "admin", "success"],
    ["Webmin", "/session_login.cgi", "POST", "form", "user", "pass", "admin", "admin", "success"],
    ["Webmin", "/session_login.cgi", "POST", "form", "user", "pass", "root", "root", "success"],
    ["Tomcat Manager", "/manager/html", "GET", "basic", "username", "password", "tomcat", "tomcat", "success"],
    ["Tomcat Manager", "/manager/html", "GET", "basic", "username", "password", "admin", "admin", "success"],
    
    # 内容管理系统 (CMS)
    ["WordPress", "/wp-login.php", "POST", "form", "log", "pwd", "admin", "admin", "success"],
    ["WordPress", "/wp-login.php", "POST", "form", "log", "pwd", "admin", "password", "success"],
    ["Joomla", "/administrator/index.php", "POST", "form", "username", "passwd", "admin", "admin", "success"],
    ["Joomla", "/administrator/index.php", "POST", "form", "username", "passwd", "admin", "password", "success"],
    ["Drupal", "/user/login", "POST", "form", "name", "pass", "admin", "admin", "success"],
    ["Drupal", "/user/login", "POST", "form", "name", "pass", "admin", "password", "success"],
    ["Magento", "/admin", "POST", "form", "login[username]", "login[password]", "admin", "admin123", "success"],
    
    # 监控和运维系统
    ["Zabbix", "/zabbix/index.php", "POST", "form", "name", "password", "Admin", "zabbix", "success"],
    ["Zabbix", "/zabbix/index.php", "POST", "form", "name", "password", "admin", "admin", "success"],
    ["Nagios", "/nagios/cgi-bin/login.cgi", "POST", "form", "username", "password", "nagiosadmin", "nagiosadmin", "success"],
    ["Grafana", "/login", "POST", "json", "user", "password", "admin", "admin", "success"],
    ["Jenkins", "/j_acegi_security_check", "POST", "form", "j_username", "j_password", "admin", "admin", "success"],
    
    # 数据库
    ["MongoDB Express", "/login", "POST", "form", "username", "password", "admin", "admin", "success"],
    ["Redis Commander", "/login", "POST", "form", "username", "password", "admin", "admin", "success"],
    ["Adminer", "/adminer.php", "POST", "form", "auth[username]", "auth[password]", "root", "", "success"],
    
    # 其他
    ["Gitlab", "/users/sign_in", "POST", "form", "user[login]", "user[password]", "root", "5iveL!fe", "success"],
    ["Gitlab", "/users/sign_in", "POST", "form", "user[login]", "user[password]", "admin", "admin", "success"],
    ["Elasticsearch", "/_security/_authenticate", "GET", "basic", "username", "password", "elastic", "changeme", "success"],
]

def verify(target: str, session=None, **kwargs) -> Tuple[bool, str]:
    """
    验证目标是否使用默认凭据
    
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
    
    # 保存发现的默认凭据
    found_credentials = []
    
    # 遍历默认凭据列表进行测试
    for cred in DEFAULT_CREDENTIALS:
        app_name, login_path, method, data_format, user_field, pass_field, username, password, success_mark = cred
        
        # 构建完整的登录URL
        if login_path.startswith('/'):
            login_path = login_path[1:]
        login_url = target + login_path
        
        try:
            # 根据不同的认证类型发送请求
            if data_format == "basic":
                # HTTP基本认证
                response = session.request(
                    method=method,
                    url=login_url,
                    auth=(username, password),
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
            elif data_format == "form":
                # 表单数据
                data = {user_field: username, pass_field: password}
                response = session.request(
                    method=method,
                    url=login_url,
                    data=data,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
            elif data_format == "json":
                # JSON数据
                json_data = {user_field: username, pass_field: password}
                response = session.request(
                    method=method,
                    url=login_url,
                    json=json_data,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
            else:
                continue
            
            # 检查响应是否表明登录成功
            login_success = False
            
            # 检查状态码
            if response.status_code == 200:
                # 检查常见的登录成功标志
                login_failure_indicators = [
                    "login failed", "incorrect password", "invalid credentials", 
                    "认证失败", "密码错误", "用户名或密码不正确"
                ]
                
                login_success = True
                for indicator in login_failure_indicators:
                    if indicator.lower() in response.text.lower():
                        login_success = False
                        break
                
                # 特定的成功标记检查
                if success_mark and success_mark.lower() not in response.text.lower():
                    login_success = False
                
                # 检查是否存在登录后才有的页面元素
                success_indicators = ["logout", "dashboard", "控制面板", "退出", "安全退出"]
                for indicator in success_indicators:
                    if indicator.lower() in response.text.lower():
                        login_success = True
                        break
            
            # 如果登录成功，记录凭据
            if login_success:
                found_credentials.append({
                    "app_name": app_name,
                    "login_url": login_url,
                    "username": username,
                    "password": password
                })
                
                # 为安全起见，尝试退出登录
                try:
                    logout_paths = ["/logout", "/signout", "/login?logout=true", "/exit"]
                    for logout_path in logout_paths:
                        try:
                            session.get(target + logout_path, timeout=2, verify=verify_ssl)
                        except:
                            pass
                except:
                    pass
            
            # 避免请求过快
            time.sleep(0.5)
            
        except requests.RequestException as e:
            # 请求异常，继续检查下一个
            continue
        except Exception as e:
            # 其他异常，继续检查下一个
            continue
    
    # 处理结果
    if found_credentials:
        vuln_details = f"发现{len(found_credentials)}组默认凭据:\n"
        for i, cred in enumerate(found_credentials):
            vuln_details += f"{i+1}. {cred['app_name']} - {cred['login_url']} - 用户名: {cred['username']}, 密码: {cred['password']}\n"
        
        return True, vuln_details
    else:
        return False, "未发现默认凭据" 