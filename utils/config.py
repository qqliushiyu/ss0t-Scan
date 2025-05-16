#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置管理模块
负责加载、保存和管理配置信息
"""

import configparser
import json
import os
import logging
from typing import Dict, Any, Optional, Union, List

# 配置日志
logger = logging.getLogger("scanner.config")

class ConfigManager:
    """配置管理器类"""
    
    DEFAULT_CONFIG_FILE = "config/settings.ini"
    
    # 默认配置
    DEFAULT_CONFIG = {
        "general": {
            "log_level": "INFO",
            "output_dir": "results",
            "default_export_format": "csv"
        },
        "network": {
            "timeout": "1.0",
            "max_threads": "50",
            "default_ports": "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,8080"
        },
        "host_scan": {
            "ping_count": "1",
            "ping_timeout": "1.0",
            "default_range": "192.168.1.1/24",
            "detect_os": "true",
            "get_mac": "true"
        },
        "port_scan": {
            "port_timeout": "0.5",
            "common_ports": "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,8080,8443",
            "port_threads": "100",
            "get_service": "true",
            "get_banner": "true"
        },
        "dns_check": {
            "dns_servers": "8.8.8.8,8.8.4.4,1.1.1.1",
            "record_types": "A,AAAA,CNAME,MX,NS,TXT,SOA",
            "timeout": "2.0"
        },
        "traceroute": {
            "max_hops": "30",
            "timeout": "1.0",
            "probe_count": "3"
        },
        "web_scan": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "timeout": "10.0",
            "follow_redirects": "true",
            "verify_ssl": "false",
            "detect_waf": "true",
            "threads": "10"
        },
        "web_dir_scan": {
            "timeout": "10.0",
            "threads": "10",
            "status_codes": "200,201,301,302,403",
            "extensions": "php,asp,aspx,jsp,html,txt,bak,zip,rar,sql",
            "follow_redirects": "true",
            "scan_delay": "0",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        }
    }
    
    def __init__(self, config_file: str = None):
        """
        初始化配置管理器
        
        Args:
            config_file: 配置文件路径，若为 None 则使用默认路径
        """
        self.config_file = config_file or self.DEFAULT_CONFIG_FILE
        self.config = configparser.ConfigParser(interpolation=None)
        
        # 加载配置
        self.load_config()
    
    def load_config(self) -> bool:
        """
        加载配置文件
        
        Returns:
            是否成功加载
        """
        # 设置默认配置
        for section, options in self.DEFAULT_CONFIG.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
            for option, value in options.items():
                if not self.config.has_option(section, option):
                    self.config.set(section, option, value)
        
        # 如果配置文件存在，则从文件加载
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file, encoding='utf-8')
                logger.info(f"配置已从 {self.config_file} 加载")
                return True
            except (configparser.Error, IOError) as e:
                logger.error(f"加载配置文件失败: {str(e)}")
        else:
            logger.warning(f"配置文件 {self.config_file} 不存在，使用默认配置")
            # 确保目录存在
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            # 保存默认配置
            self.save_config()
        
        return False
    
    def save_config(self) -> bool:
        """
        保存配置到文件
        
        Returns:
            是否成功保存
        """
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                self.config.write(f)
            
            logger.info(f"配置已保存到 {self.config_file}")
            return True
        except IOError as e:
            logger.error(f"保存配置文件失败: {str(e)}")
            return False
    
    def get(self, section: str, option: str, fallback: Any = None) -> str:
        """
        获取配置值
        
        Args:
            section: 配置节
            option: 配置项
            fallback: 默认值
        
        Returns:
            配置值
        """
        return self.config.get(section, option, fallback=fallback)
    
    def get_int(self, section: str, option: str, fallback: int = 0) -> int:
        """获取整数配置值"""
        return self.config.getint(section, option, fallback=fallback)
    
    def get_float(self, section: str, option: str, fallback: float = 0.0) -> float:
        """获取浮点数配置值"""
        return self.config.getfloat(section, option, fallback=fallback)
    
    def get_boolean(self, section: str, option: str, fallback: bool = False) -> bool:
        """获取布尔配置值"""
        return self.config.getboolean(section, option, fallback=fallback)
    
    def get_list(self, section: str, option: str, fallback: List = None, 
                delimiter: str = ',') -> List[str]:
        """
        获取列表配置值（以逗号分隔的字符串）
        
        Args:
            section: 配置节
            option: 配置项
            fallback: 默认值
            delimiter: 分隔符
        
        Returns:
            字符串列表
        """
        if fallback is None:
            fallback = []
        
        value = self.get(section, option)
        if value is None:
            return fallback
        
        return [item.strip() for item in value.split(delimiter) if item.strip()]
    
    def set(self, section: str, option: str, value: str) -> None:
        """
        设置配置值
        
        Args:
            section: 配置节
            option: 配置项
            value: 配置值
        """
        if not self.config.has_section(section):
            self.config.add_section(section)
        
        self.config.set(section, option, str(value))
    
    def get_section(self, section: str) -> Dict[str, str]:
        """
        获取整个配置节
        
        Args:
            section: 配置节
        
        Returns:
            配置项字典
        """
        if not self.config.has_section(section):
            return {}
        
        return dict(self.config[section])
    
    def load_module_config(self, module_name: str) -> Dict[str, Any]:
        """
        加载模块配置
        
        Args:
            module_name: 模块名称
        
        Returns:
            模块配置字典
        """
        # 先获取模块通用配置
        module_config = self.get_section(module_name)
        
        # 添加网络通用配置
        network_config = self.get_section("network")
        for key, value in network_config.items():
            if key not in module_config:
                module_config[key] = value
        
        # 将字符串配置值转换为适当的类型
        typed_config = {}
        for key, value in module_config.items():
            # 尝试转换为合适的类型
            if value.lower() in ('true', 'false'):
                typed_config[key] = value.lower() == 'true'
            else:
                try:
                    if '.' in value:
                        typed_config[key] = float(value)
                    else:
                        typed_config[key] = int(value)
                except ValueError:
                    typed_config[key] = value
        
        return typed_config
    
    def load_json_config(self, json_file: str) -> Dict[str, Any]:
        """
        从 JSON 文件加载配置
        
        Args:
            json_file: JSON 配置文件路径
        
        Returns:
            配置字典
        """
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"加载 JSON 配置文件失败: {str(e)}")
            return {}


# 全局配置管理器实例
config_manager = ConfigManager() 