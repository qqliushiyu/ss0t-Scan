#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件配置管理器
用于读取和管理各个插件的配置文件
"""

import os
import json
import yaml
import logging
import importlib.resources as pkg_resources
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

# 配置日志
logger = logging.getLogger("plugins.config_manager")

class PluginConfigManager:
    """
    插件配置管理器
    负责读取和管理各个插件的配置文件
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        初始化配置管理器
        
        Args:
            config_dir: 配置文件目录，默认为./configs/plugins/
        """
        # 默认配置目录
        if config_dir is None:
            # 获取当前工作目录
            cwd = os.getcwd()
            config_dir = os.path.join(cwd, "configs", "plugins")
        
        self.config_dir = config_dir
        self.configs: Dict[str, Dict[str, Any]] = {}
        self._ensure_config_dir()
        
    def _ensure_config_dir(self) -> None:
        """确保配置目录存在"""
        if not os.path.exists(self.config_dir):
            try:
                os.makedirs(self.config_dir, exist_ok=True)
                logger.info(f"创建配置目录: {self.config_dir}")
            except Exception as e:
                logger.error(f"创建配置目录失败: {str(e)}")
                
    def _get_config_path(self, plugin_id: str, file_format: str = "json") -> str:
        """
        获取插件配置文件路径
        
        Args:
            plugin_id: 插件ID
            file_format: 文件格式 (json 或 yaml)
            
        Returns:
            配置文件路径
        """
        return os.path.join(self.config_dir, f"{plugin_id}.{file_format}")
    
    def load_config(self, plugin_id: str, default_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        加载插件配置
        
        Args:
            plugin_id: 插件ID
            default_config: 默认配置
            
        Returns:
            插件配置
        """
        # 先尝试从缓存中获取
        if plugin_id in self.configs:
            return self.configs[plugin_id]
        
        # 初始化为默认配置
        config = default_config or {}
        
        # 尝试读取JSON配置
        json_path = self._get_config_path(plugin_id, "json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    config.update(loaded_config)
                logger.info(f"从 {json_path} 加载了插件配置")
                self.configs[plugin_id] = config
                return config
            except Exception as e:
                logger.error(f"读取配置文件 {json_path} 出错: {str(e)}")
        
        # 尝试读取YAML配置
        yaml_path = self._get_config_path(plugin_id, "yaml")
        if os.path.exists(yaml_path):
            try:
                with open(yaml_path, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f)
                    config.update(loaded_config)
                logger.info(f"从 {yaml_path} 加载了插件配置")
                self.configs[plugin_id] = config
                return config
            except Exception as e:
                logger.error(f"读取配置文件 {yaml_path} 出错: {str(e)}")
        
        # 如果找不到配置文件，尝试创建一个默认的
        if default_config:
            self.save_config(plugin_id, default_config)
        
        # 缓存配置
        self.configs[plugin_id] = config
        return config
    
    def save_config(self, plugin_id: str, config: Dict[str, Any], file_format: str = "json") -> bool:
        """
        保存插件配置
        
        Args:
            plugin_id: 插件ID
            config: 插件配置
            file_format: 文件格式 (json 或 yaml)
            
        Returns:
            是否成功保存
        """
        self._ensure_config_dir()
        
        config_path = self._get_config_path(plugin_id, file_format)
        try:
            if file_format == "json":
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=4, ensure_ascii=False)
            elif file_format == "yaml":
                with open(config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            else:
                logger.error(f"不支持的配置文件格式: {file_format}")
                return False
            
            # 更新缓存
            self.configs[plugin_id] = config
            logger.info(f"保存插件配置到 {config_path}")
            return True
        except Exception as e:
            logger.error(f"保存配置文件 {config_path} 出错: {str(e)}")
            return False
    
    def get_all_plugin_configs(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有插件配置
        
        Returns:
            所有插件配置的字典
        """
        # 扫描配置目录，加载所有配置文件
        self._ensure_config_dir()
        
        # 找出所有的配置文件
        config_files = []
        for extension in ["json", "yaml", "yml"]:
            config_files.extend(list(Path(self.config_dir).glob(f"*.{extension}")))
        
        for config_file in config_files:
            plugin_id = config_file.stem  # 获取不带扩展名的文件名
            if plugin_id not in self.configs:
                self.load_config(plugin_id)
        
        return self.configs
    
    def get_plugin_config_files(self) -> List[str]:
        """
        获取所有插件配置文件列表
        
        Returns:
            配置文件路径列表
        """
        self._ensure_config_dir()
        
        config_files = []
        for extension in ["json", "yaml", "yml"]:
            for file_path in Path(self.config_dir).glob(f"*.{extension}"):
                config_files.append(str(file_path))
        
        return config_files
    
    def create_default_configs(self, plugin_info_list: List[Dict[str, Any]]) -> None:
        """
        为所有插件创建默认配置文件
        
        Args:
            plugin_info_list: 插件信息列表
        """
        for plugin_info in plugin_info_list:
            plugin_id = plugin_info.get("id", "").lower()
            if not plugin_id:
                continue
                
            # 根据插件类别生成默认配置
            default_config = self._generate_default_config(plugin_info)
            
            # 检查配置文件是否已存在
            json_path = self._get_config_path(plugin_id, "json")
            yaml_path = self._get_config_path(plugin_id, "yaml")
            
            if not os.path.exists(json_path) and not os.path.exists(yaml_path):
                self.save_config(plugin_id, default_config)
    
    def _generate_default_config(self, plugin_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据插件信息生成默认配置
        
        Args:
            plugin_info: 插件信息
            
        Returns:
            默认配置
        """
        plugin_id = plugin_info.get("id", "").lower()
        category = plugin_info.get("category", "")
        
        # 基本配置
        config = {
            "enabled": True,
            "name": plugin_info.get("name", ""),
            "description": plugin_info.get("description", ""),
            "version": plugin_info.get("version", "1.0.0"),
            "timeout": 10,  # 默认超时10秒
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            "verify_ssl": False  # 默认不验证SSL证书
        }
        
        # 根据插件类别添加特定配置
        if category == "指纹识别":
            # 指纹识别插件配置
            if plugin_id == "fingerprintscanner":
                # 添加默认的自定义指纹
                config["custom_fingerprints"] = {
                    "Custom CMS": [
                        {"path": "/custom-path", "pattern": "CustomPattern"}
                    ]
                }
        elif category == "漏洞检测":
            # 漏洞检测插件配置
            if plugin_id == "vulnscanner":
                # 添加默认的自定义漏洞路径
                config["custom_paths"] = {
                    "SQL注入": ["/custom-sql.php", "/custom-inject"],
                    "XSS": ["/custom-xss.php", "/custom-reflect"],
                    "敏感文件": ["/custom-backup.zip", "/custom-config.bak"]
                }
            elif plugin_id == "xssscanner":
                # XSS扫描器配置
                config["detection_payloads"] = [
                    "<script>alert(1)</script>",
                    "\"><script>alert(1)</script>",
                    "javascript:alert(1)"
                ]
            elif plugin_id == "sqlinjectionscanner":
                # SQL注入扫描器配置
                config["detection_payloads"] = [
                    "' OR 1=1 --",
                    "\" OR 1=1 --",
                    "1' AND '1'='1"
                ]
        elif category == "安全配置":
            # 安全配置检查插件配置
            if plugin_id == "securityheaderscheck":
                # 安全头部检查器配置
                config["required_headers"] = [
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options"
                ]
        
        return config

# 单例模式实现
_instance = None

def get_config_manager(config_dir: Optional[str] = None) -> PluginConfigManager:
    """
    获取配置管理器实例
    
    Args:
        config_dir: 配置文件目录
        
    Returns:
        配置管理器实例
    """
    global _instance
    if _instance is None:
        _instance = PluginConfigManager(config_dir)
    elif config_dir is not None and _instance.config_dir != config_dir:
        _instance = PluginConfigManager(config_dir)
    return _instance

# 导出单例
plugin_config_manager = get_config_manager() 