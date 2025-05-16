#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF检测插件
用于检测Web应用是否受到Web应用防火墙(WAF)保护
"""

import re
import requests
from typing import Dict, List, Any, Optional

from plugins.base_plugin import WebRiskPlugin

class WAFDetector(WebRiskPlugin):
    """WAF检测插件"""
    
    NAME = "WAF检测"
    DESCRIPTION = "检测Web应用是否受到Web应用防火墙(WAF)保护"
    VERSION = "1.0.0"
    AUTHOR = "ss0t-scna"
    CATEGORY = "信息收集"
    
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
    
    # 测试用的攻击负载
    TEST_PAYLOADS = [
        "<script>alert(1)</script>",  # XSS
        "1' OR '1'='1",               # SQL注入
        "../../../etc/passwd",        # 目录遍历
        "/bin/cat /etc/passwd",       # 命令注入
        "' UNION SELECT 1,2,3 --"     # SQL注入
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化WAF检测插件"""
        super().__init__(config)
        
        # 从配置中加载自定义WAF签名
        self.waf_signatures = self.DEFAULT_WAF_SIGNATURES.copy()
        if config and 'custom_signatures' in config:
            custom_signatures = config['custom_signatures']
            if isinstance(custom_signatures, dict):
                self.waf_signatures.update(custom_signatures)
    
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行WAF检测
        
        Args:
            target: 目标URL
            session: 请求会话对象
            **kwargs: 其他参数
            
        Returns:
            检测结果列表
        """
        results = []
        
        # 确保target不以/结尾
        if target.endswith('/'):
            target = target[:-1]
        
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
        
        detected_waf = None
        waf_evidence = ""
        
        try:
            # 先发送普通请求获取基础响应
            normal_response = session.get(
                target,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=follow_redirects
            )
            
            # 尝试触发WAF
            for payload in self.TEST_PAYLOADS:
                # 构造带攻击负载的URL
                test_url = f"{target}?test={payload}"
                
                try:
                    # 发送测试请求
                    attack_response = session.get(
                        test_url,
                        timeout=timeout,
                        verify=verify_ssl,
                        allow_redirects=follow_redirects
                    )
                    
                    # 分析响应头和Cookie
                    all_headers = str(attack_response.headers).lower()
                    cookies = str(attack_response.cookies).lower()
                    
                    # 检查是否有WAF特征
                    for waf_name, signatures in self.waf_signatures.items():
                        for signature in signatures:
                            if signature.lower() in all_headers or signature.lower() in cookies:
                                detected_waf = waf_name
                                waf_evidence = f"发现特征: {signature}"
                                break
                        
                        if detected_waf:
                            break
                    
                    # 检查响应状态码
                    if not detected_waf:
                        if (normal_response.status_code != attack_response.status_code and 
                            attack_response.status_code in [403, 406, 501, 502]):
                            detected_waf = "Unknown WAF"
                            waf_evidence = f"异常状态码: {attack_response.status_code}"
                    
                    # 检查响应内容是否包含WAF特征词
                    if not detected_waf and hasattr(attack_response, 'text'):
                        text = attack_response.text.lower()
                        waf_keywords = [
                            "waf", "firewall", "protection", "block", "security",
                            "blocked", "forbidden", "detected", "attack", "malicious"
                        ]
                        
                        for keyword in waf_keywords:
                            if keyword in text and keyword not in normal_response.text.lower():
                                detected_waf = "Unknown WAF"
                                waf_evidence = f"响应包含特征词: {keyword}"
                                break
                    
                    # 如果已检测到WAF，跳出循环
                    if detected_waf:
                        break
                
                except (requests.RequestException, ConnectionError, TimeoutError) as e:
                    # 如果请求异常，可能也是WAF的特征
                    if "timeout" in str(e).lower() and normal_response:
                        detected_waf = "Possible WAF (Request Timeout)"
                        waf_evidence = f"请求超时: {str(e)}"
                        break
                    continue
            
            # 生成结果
            if detected_waf:
                results.append({
                    "check_type": "waf",
                    "url": target,
                    "waf_name": detected_waf,
                    "status": "detected",
                    "details": f"检测到WAF: {detected_waf}",
                    "evidence": waf_evidence,
                    "recommendation": "Web应用防火墙提供了基本的安全保护，但不应完全依赖它。建议配合其他安全措施使用。"
                })
            else:
                results.append({
                    "check_type": "waf",
                    "url": target,
                    "waf_name": "无",
                    "status": "not_detected",
                    "details": "未检测到WAF",
                    "recommendation": "考虑部署Web应用防火墙以提高应用安全性。"
                })
        
        except Exception as e:
            self.logger.warning(f"WAF检测失败: {str(e)}")
            results.append({
                "check_type": "waf",
                "url": target,
                "status": "error",
                "details": f"WAF检测过程出错: {str(e)}"
            })
        
        return results
    
    def validate_config(self) -> tuple:
        """验证配置"""
        # 如果配置中包含custom_signatures，确保它是一个字典
        if 'custom_signatures' in self.config:
            custom_signatures = self.config['custom_signatures']
            if not isinstance(custom_signatures, dict):
                return False, "custom_signatures必须是一个字典"
                
            # 确保每个值是一个列表
            for waf_name, signatures in custom_signatures.items():
                if not isinstance(signatures, list):
                    return False, f"WAF '{waf_name}' 的签名必须是一个列表"
        
        return True, None 