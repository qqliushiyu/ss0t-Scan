#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web指纹识别插件
用于检测Web服务器、框架、CMS等技术栈信息
"""

import re
import json
import logging
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin
from pathlib import Path

from plugins.base_plugin import WebRiskPlugin

class FingerprintScanner(WebRiskPlugin):
    """
    Web指纹识别插件
    检测网站使用的Web服务器、框架、CMS等技术栈
    """
    
    # 插件元数据
    NAME = "Web指纹识别"
    DESCRIPTION = "检测网站使用的Web服务器、框架、CMS等技术栈"
    VERSION = "1.0.0"
    AUTHOR = "ss0t-scna"
    CATEGORY = "指纹识别"  # 指纹识别类别
    
    # 默认指纹库
    DEFAULT_FINGERPRINTS = {
        "WordPress": [
            {"path": "/wp-login.php", "pattern": "WordPress"},
            {"path": "/wp-content/", "pattern": "WordPress"}
        ],
        "Joomla": [
            {"path": "/administrator/", "pattern": "Joomla"},
            {"path": "/media/system/js/", "pattern": "Joomla"}
        ],
        "Drupal": [
            {"path": "/misc/drupal.js", "pattern": "Drupal"},
            {"path": "/sites/default/", "pattern": "Drupal"}
        ],
        "Magento": [
            {"path": "/skin/frontend/", "pattern": "Magento"},
            {"path": "/js/mage/", "pattern": "Magento"}
        ],
        "Laravel": [
            {"path": "/", "pattern": "Laravel", "header": "Set-Cookie", "regex": "laravel_session"}
        ],
        "Django": [
            {"path": "/admin/", "pattern": "Django"},
            {"path": "/static/admin/", "pattern": "Django"}
        ],
        "Flask": [
            {"path": "/", "pattern": "Flask", "header": "Server", "regex": "Werkzeug"}
        ],
        "Express.js": [
            {"path": "/", "pattern": "Express", "header": "X-Powered-By", "regex": "Express"}
        ],
        "Spring Boot": [
            {"path": "/error", "pattern": "Spring Boot"},
            {"path": "/actuator", "pattern": "Spring Boot"}
        ],
        "ASP.NET": [
            {"path": "/", "pattern": "ASP.NET", "header": "X-AspNet-Version"},
            {"path": "/", "pattern": "ASP.NET", "header": "X-Powered-By", "regex": "ASP\.NET"}
        ],
        "PHP": [
            {"path": "/", "pattern": "PHP", "header": "X-Powered-By", "regex": "PHP"}
        ],
        "Nginx": [
            {"path": "/", "pattern": "Nginx", "header": "Server", "regex": "nginx"}
        ],
        "Apache": [
            {"path": "/", "pattern": "Apache", "header": "Server", "regex": "Apache"}
        ],
        "IIS": [
            {"path": "/", "pattern": "IIS", "header": "Server", "regex": "IIS"}
        ],
        "Tomcat": [
            {"path": "/", "pattern": "Tomcat", "header": "Server", "regex": "Tomcat"},
            {"path": "/manager/html", "pattern": "Tomcat"}
        ],
        "jQuery": [
            {"path": "/", "pattern": "jQuery", "content": "jquery"}
        ],
        "Bootstrap": [
            {"path": "/", "pattern": "Bootstrap", "content": "bootstrap"}
        ],
        "React": [
            {"path": "/", "pattern": "React", "content": "reactjs|react.js|react-dom"}
        ],
        "Vue.js": [
            {"path": "/", "pattern": "Vue.js", "content": "vue.js|vue.min.js"}
        ],
        "Angular": [
            {"path": "/", "pattern": "Angular", "content": "angular.js|angular.min.js|ng-app"}
        ]
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化插件
        
        Args:
            config: 插件配置
        """
        super().__init__(config)
        self.logger = logging.getLogger(f"plugins.web_risk.{self.__class__.__name__}")
        
        # 加载指纹库
        self.fingerprints = self.load_fingerprints()
        
        self.logger.info(f"已加载 {sum(len(fps) for fps in self.fingerprints.values())} 条Web指纹")
    
    def load_fingerprints(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        加载指纹库
        
        Returns:
            指纹库字典
        """
        # 首先复制默认指纹库
        fingerprints = self.DEFAULT_FINGERPRINTS.copy()
        
        # 从配置中获取自定义指纹
        custom_fingerprints = self.config.get("custom_fingerprints", {})
        if custom_fingerprints:
            # 遍历自定义指纹并合并
            for tech_name, patterns in custom_fingerprints.items():
                if tech_name in fingerprints:
                    # 如果技术已存在，则合并指纹
                    fingerprints[tech_name].extend(patterns)
                else:
                    # 否则添加新技术
                    fingerprints[tech_name] = patterns
            
            self.logger.info(f"从配置加载了 {sum(len(fps) for tech, fps in custom_fingerprints.items())} 条自定义指纹")
        
        # 检查是否有自定义指纹文件路径
        custom_fingerprint_file = self.config.get("fingerprint_file", "")
        if custom_fingerprint_file:
            # 加载指定文件中的指纹
            file_fingerprints = self.load_fingerprints_from_file(custom_fingerprint_file)
            
            # 合并指纹
            for tech_name, patterns in file_fingerprints.items():
                if tech_name in fingerprints:
                    fingerprints[tech_name].extend(patterns)
                else:
                    fingerprints[tech_name] = patterns
        
        return fingerprints
    
    def load_fingerprints_from_file(self, file_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        从文件加载指纹
        
        Args:
            file_path: 文件路径
            
        Returns:
            指纹字典
        """
        fingerprints = {}
        
        # 判断文件是否存在
        path = Path(file_path)
        if not path.exists():
            self.logger.warning(f"指纹文件 {file_path} 不存在")
            return fingerprints
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # 根据文件扩展名决定加载方式
                if file_path.endswith('.json'):
                    # JSON格式
                    loaded_data = json.load(f)
                    fingerprints = loaded_data
                elif file_path.endswith('.txt'):
                    # 文本格式，每行一个指纹
                    # 格式: 技术名:路径:匹配模式[:header[:regex]]
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                            
                        parts = line.split(':', 4)
                        if len(parts) < 3:
                            self.logger.warning(f"忽略格式不正确的指纹: {line}")
                            continue
                            
                        tech_name = parts[0].strip()
                        path = parts[1].strip()
                        pattern = parts[2].strip()
                        
                        # 创建指纹
                        fingerprint = {"path": path, "pattern": pattern}
                        
                        # 添加HTTP头
                        if len(parts) > 3:
                            header = parts[3].strip()
                            if header:
                                fingerprint["header"] = header
                                
                            # 添加正则表达式
                            if len(parts) > 4:
                                regex = parts[4].strip()
                                if regex:
                                    fingerprint["regex"] = regex
                        
                        # 添加到指纹库
                        if tech_name not in fingerprints:
                            fingerprints[tech_name] = []
                        fingerprints[tech_name].append(fingerprint)
                else:
                    self.logger.warning(f"不支持的指纹文件格式: {file_path}")
            
            self.logger.info(f"从文件 {file_path} 加载了 {sum(len(fps) for tech, fps in fingerprints.items())} 条指纹")
        except Exception as e:
            self.logger.error(f"加载指纹文件 {file_path} 失败: {str(e)}")
        
        return fingerprints
    
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行Web指纹检测
        
        Args:
            target: 目标URL
            session: 可选的HTTP会话对象
            **kwargs: 其他参数
            
        Returns:
            检查结果列表
        """
        results = []
        
        if not session:
            session = requests.Session()
            # 设置默认超时
            timeout = self.config.get("timeout", 10)
            session.timeout = timeout
        
        # 设置User-Agent
        user_agent = self.config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36")
        default_headers = {"User-Agent": user_agent}
        
        # 是否验证SSL证书
        verify_ssl = self.config.get("verify_ssl", False)
        
        # 获取首页内容
        try:
            response = session.get(target, headers=default_headers, verify=verify_ssl, allow_redirects=True)
            main_page_content = response.text.lower()
            main_page_headers = response.headers
            
            # 添加首页基本信息
            results.append({
                "check_type": "basic_info",
                "url": target,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "server": response.headers.get("Server", "未知")
            })
            
            # 检测到的技术列表
            detected_technologies = []
            
            # 检查响应头中的常见技术标识
            server = response.headers.get("Server", "")
            if server:
                if "nginx" in server.lower():
                    detected_technologies.append("Nginx")
                if "apache" in server.lower():
                    detected_technologies.append("Apache")
                if "iis" in server.lower():
                    detected_technologies.append("IIS")
                if "tomcat" in server.lower():
                    detected_technologies.append("Tomcat")
                    
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                if "php" in powered_by.lower():
                    detected_technologies.append("PHP")
                if "asp.net" in powered_by.lower():
                    detected_technologies.append("ASP.NET")
                if "express" in powered_by.lower():
                    detected_technologies.append("Express.js")
            
            # 检查页面内容中的技术标识
            for tech_name, fingerprints in self.fingerprints.items():
                for fp in fingerprints:
                    # 检查是否需要检测HTTP头
                    if "header" in fp:
                        header_name = fp["header"]
                        header_value = main_page_headers.get(header_name, "")
                        
                        if header_value:
                            if "regex" in fp:
                                pattern = fp["regex"]
                                if re.search(pattern, header_value, re.IGNORECASE):
                                    if tech_name not in detected_technologies:
                                        detected_technologies.append(tech_name)
                                        break
                            else:
                                if fp["pattern"].lower() in header_value.lower():
                                    if tech_name not in detected_technologies:
                                        detected_technologies.append(tech_name)
                                        break
                    
                    # 检查页面内容
                    elif "content" in fp:
                        pattern = fp["content"]
                        if re.search(pattern, main_page_content, re.IGNORECASE):
                            if tech_name not in detected_technologies:
                                detected_technologies.append(tech_name)
                                break
                    
                    # 检查特定路径
                    else:
                        path = fp["path"]
                        full_url = urljoin(target, path)
                        
                        try:
                            path_response = session.get(
                                full_url, 
                                headers=default_headers,
                                verify=verify_ssl,
                                allow_redirects=True,
                                timeout=session.timeout
                            )
                            
                            if path_response.status_code == 200:
                                if fp["pattern"].lower() in path_response.text.lower():
                                    if tech_name not in detected_technologies:
                                        detected_technologies.append(tech_name)
                                        break
                        except Exception as e:
                            self.logger.debug(f"访问 {full_url} 时出错: {str(e)}")
            
            # 添加指纹识别结果
            results.append({
                "check_type": "server_info",
                "url": target,
                "server": server,
                "powered_by": powered_by,
                "technologies": detected_technologies
            })
            
        except Exception as e:
            self.logger.error(f"扫描 {target} 时出错: {str(e)}")
            results.append({
                "check_type": "error",
                "url": target,
                "error": str(e)
            })
        
        return results 