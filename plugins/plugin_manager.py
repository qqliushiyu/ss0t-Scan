#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件管理器
用于发现、加载和管理Web风险扫描插件
"""

import importlib
import inspect
import logging
import os
import pkgutil
import sys
from typing import Dict, List, Any, Type, Optional, Set

from plugins.base_plugin import WebRiskPlugin
from plugins.config_manager import plugin_config_manager

# 配置日志
logger = logging.getLogger("plugins.manager")

class PluginManager:
    """
    插件管理器
    负责发现、加载和管理Web风险扫描插件
    """
    
    def __init__(self, plugin_dirs: List[str] = None):
        """
        初始化插件管理器
        
        Args:
            plugin_dirs: 插件目录列表，默认为['plugins/web_risk']
        """
        if plugin_dirs is None:
            plugin_dirs = ['plugins/web_risk']
        
        self.plugin_dirs = plugin_dirs
        self._plugins: Dict[str, Type[WebRiskPlugin]] = {}  # 类型: {插件ID: 插件类}
        self._instances: Dict[str, WebRiskPlugin] = {}  # 类型: {插件ID: 插件实例}
        self._disabled_plugins: Set[str] = set()  # 存储禁用的插件ID
        self._initialized = False
    
    def discover_plugins(self) -> None:
        """发现并加载所有可用的插件"""
        # 确保只初始化一次
        if self._initialized:
            return
        
        self._initialized = True
        
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                logger.warning(f"插件目录 {plugin_dir} 不存在，跳过")
                continue
            
            logger.info(f"从 {plugin_dir} 中发现插件")
            
            # 确保模块能够被导入
            package_path = plugin_dir.replace('/', '.')
            
            # 遍历目录中的所有模块
            for _, name, is_pkg in pkgutil.iter_modules([plugin_dir]):
                if is_pkg:
                    continue  # 跳过包，只处理模块
                
                # 跳过以_开头的模块
                if name.startswith('_'):
                    continue
                
                try:
                    # 导入模块
                    module_path = f"{package_path}.{name}"
                    module = importlib.import_module(module_path)
                    
                    # 查找模块中的插件类 (继承自WebRiskPlugin)
                    for item_name, item in inspect.getmembers(module, inspect.isclass):
                        if (issubclass(item, WebRiskPlugin) and 
                            item != WebRiskPlugin and
                            not item_name.startswith('_')):
                            
                            plugin_id = item_name.lower()
                            self._plugins[plugin_id] = item
                            logger.info(f"注册插件: {item_name} ({item.NAME} v{item.VERSION})")
                
                except (ImportError, AttributeError) as e:
                    logger.error(f"导入模块 {name} 出错: {str(e)}")
        
        logger.info(f"共注册 {len(self._plugins)} 个插件")
        
        # 为所有插件创建默认配置文件
        self._create_default_configs()
    
    def _create_default_configs(self) -> None:
        """为所有已注册的插件创建默认配置文件"""
        try:
            plugin_info_list = self.get_plugin_info_list()
            plugin_config_manager.create_default_configs(plugin_info_list)
        except Exception as e:
            logger.error(f"创建默认配置文件失败: {str(e)}")
    
    def register_plugin(self, plugin_class: Type[WebRiskPlugin]) -> None:
        """
        手动注册插件
        
        Args:
            plugin_class: 插件类，必须继承自WebRiskPlugin
        """
        if not issubclass(plugin_class, WebRiskPlugin):
            raise TypeError("插件类必须继承自WebRiskPlugin")
        
        plugin_id = plugin_class.__name__.lower()
        self._plugins[plugin_id] = plugin_class
        logger.info(f"手动注册插件: {plugin_class.__name__} ({plugin_class.NAME} v{plugin_class.VERSION})")
    
    def get_plugin_class(self, plugin_id: str) -> Optional[Type[WebRiskPlugin]]:
        """
        获取插件类
        
        Args:
            plugin_id: 插件ID (类名的小写形式)
        
        Returns:
            插件类或者None (如果未找到)
        """
        return self._plugins.get(plugin_id.lower())
    
    def get_plugin(self, plugin_id: str, config: Dict[str, Any] = None) -> Optional[WebRiskPlugin]:
        """
        获取或创建插件实例
        
        Args:
            plugin_id: 插件ID (类名的小写形式)
            config: 插件配置
        
        Returns:
            插件实例或者None (如果未找到)
        """
        plugin_id = plugin_id.lower()
        
        # 如果已有实例，直接返回
        if plugin_id in self._instances:
            instance = self._instances[plugin_id]
            if config is not None:
                # 更新配置
                instance.config.update(config)
            return instance
        
        # 否则创建新实例
        plugin_class = self.get_plugin_class(plugin_id)
        if plugin_class:
            # 加载配置文件
            file_config = self._load_plugin_config(plugin_id)
            
            # 合并配置
            merged_config = {}
            if file_config:
                merged_config.update(file_config)
            if config:
                merged_config.update(config)
            
            # 创建实例
            instance = plugin_class(merged_config or {})
            
            # 设置启用状态
            if plugin_id in self._disabled_plugins:
                instance.enabled = False
            
            self._instances[plugin_id] = instance
            return instance
        
        return None
    
    def _load_plugin_config(self, plugin_id: str) -> Dict[str, Any]:
        """
        从配置文件加载插件配置
        
        Args:
            plugin_id: 插件ID
            
        Returns:
            插件配置
        """
        try:
            # 获取插件的默认配置
            plugin_class = self.get_plugin_class(plugin_id)
            default_config = {}
            
            if plugin_class:
                # 构造基础默认配置
                plugin_info = {
                    "id": plugin_id,
                    "name": plugin_class.NAME,
                    "description": plugin_class.DESCRIPTION,
                    "version": plugin_class.VERSION,
                    "category": plugin_class.CATEGORY
                }
                
                # 加载配置文件
                config = plugin_config_manager.load_config(plugin_id, default_config)
                return config
            
            return {}
        except Exception as e:
            logger.error(f"加载插件 {plugin_id} 配置文件失败: {str(e)}")
            return {}
    
    def disable_plugin(self, plugin_id: str) -> bool:
        """
        禁用插件
        
        Args:
            plugin_id: 插件ID
        
        Returns:
            是否成功禁用
        """
        plugin_id = plugin_id.lower()
        if plugin_id not in self._plugins:
            logger.warning(f"尝试禁用不存在的插件: {plugin_id}")
            return False
        
        self._disabled_plugins.add(plugin_id)
        
        # 如果有实例，设置为禁用状态
        if plugin_id in self._instances:
            self._instances[plugin_id].enabled = False
        
        # 更新配置文件
        try:
            config = plugin_config_manager.load_config(plugin_id, {})
            config["enabled"] = False
            plugin_config_manager.save_config(plugin_id, config)
        except Exception as e:
            logger.error(f"保存插件 {plugin_id} 禁用状态到配置文件失败: {str(e)}")
        
        logger.info(f"禁用插件: {plugin_id}")
        return True
    
    def enable_plugin(self, plugin_id: str) -> bool:
        """
        启用插件
        
        Args:
            plugin_id: 插件ID
        
        Returns:
            是否成功启用
        """
        plugin_id = plugin_id.lower()
        if plugin_id not in self._plugins:
            logger.warning(f"尝试启用不存在的插件: {plugin_id}")
            return False
        
        if plugin_id in self._disabled_plugins:
            self._disabled_plugins.remove(plugin_id)
        
        # 如果有实例，设置为启用状态
        if plugin_id in self._instances:
            self._instances[plugin_id].enabled = True
        
        # 更新配置文件
        try:
            config = plugin_config_manager.load_config(plugin_id, {})
            config["enabled"] = True
            plugin_config_manager.save_config(plugin_id, config)
        except Exception as e:
            logger.error(f"保存插件 {plugin_id} 启用状态到配置文件失败: {str(e)}")
        
        logger.info(f"启用插件: {plugin_id}")
        return True
    
    def is_plugin_enabled(self, plugin_id: str) -> bool:
        """
        检查插件是否启用
        
        Args:
            plugin_id: 插件ID
        
        Returns:
            是否启用
        """
        plugin_id = plugin_id.lower()
        
        # 先检查是否在禁用列表中
        if plugin_id in self._disabled_plugins:
            return False
        
        # 然后检查配置文件中的enabled状态
        try:
            config = plugin_config_manager.load_config(plugin_id, {})
            if "enabled" in config:
                return config["enabled"]
        except Exception:
            pass
        
        # 默认为启用状态
        return True
    
    def get_all_plugins(self) -> Dict[str, Type[WebRiskPlugin]]:
        """
        获取所有插件
        
        Returns:
            所有插件的字典
        """
        return self._plugins.copy()
    
    def get_enabled_plugins(self) -> Dict[str, Type[WebRiskPlugin]]:
        """
        获取所有启用的插件
        
        Returns:
            所有启用插件的字典
        """
        return {
            pid: plugin 
            for pid, plugin in self._plugins.items() 
            if pid not in self._disabled_plugins
        }
    
    def get_plugin_info_list(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """
        获取插件信息列表
        
        Args:
            enabled_only: 是否只返回启用的插件
            
        Returns:
            插件信息列表
        """
        plugin_info_list = []
        
        for plugin_id, plugin_class in self._plugins.items():
            # 判断插件是否启用
            is_enabled = self.is_plugin_enabled(plugin_id)
            
            # 如果只要已启用的插件，但当前插件已禁用，则跳过
            if enabled_only and not is_enabled:
                continue
            
            # 获取插件实例以获取更多信息
            instance = None
            try:
                instance = self.get_plugin(plugin_id)
            except Exception:
                pass
            
            # 插件信息
            plugin_info = {
                "id": plugin_id,
                "name": plugin_class.NAME,
                "description": plugin_class.DESCRIPTION,
                "version": plugin_class.VERSION,
                "category": plugin_class.CATEGORY,
                "author": plugin_class.AUTHOR,
                "enabled": is_enabled,
                "class_name": plugin_class.__name__
            }
            
            # 添加到列表
            plugin_info_list.append(plugin_info)
        
        return plugin_info_list
    
    def init_plugins(self) -> int:
        """
        初始化所有插件
        
        Returns:
            成功初始化的插件数量
        """
        if not self._initialized:
            self.discover_plugins()
        
        # 加载配置文件，更新禁用插件列表
        self._load_disabled_plugins_from_config()
        
        # 预初始化所有插件
        init_count = 0
        for plugin_id, plugin_class in self._plugins.items():
            try:
                # 检查插件是否启用
                if plugin_id in self._disabled_plugins:
                    logger.info(f"跳过禁用的插件: {plugin_id}")
                    continue
                
                # 创建插件实例
                _ = self.get_plugin(plugin_id)
                
                init_count += 1
            except Exception as e:
                logger.error(f"初始化插件 {plugin_id} 失败: {str(e)}")
        
        logger.info(f"成功初始化 {init_count} 个插件")
        return init_count
    
    def _load_disabled_plugins_from_config(self) -> None:
        """从配置文件加载禁用的插件列表"""
        try:
            # 获取所有配置
            all_configs = plugin_config_manager.get_all_plugin_configs()
            
            # 清空禁用列表
            self._disabled_plugins.clear()
            
            # 添加配置中标记为禁用的插件
            for plugin_id, config in all_configs.items():
                if config.get("enabled") is False:
                    self._disabled_plugins.add(plugin_id.lower())
                    logger.info(f"从配置文件中加载禁用的插件: {plugin_id}")
        except Exception as e:
            logger.error(f"从配置文件加载禁用插件列表失败: {str(e)}")
    
    def clear_instances(self) -> None:
        """清除所有插件实例"""
        self._instances.clear()
    
    def reload_plugins(self) -> None:
        """重新加载所有插件"""
        self._initialized = False
        self._plugins.clear()
        self._instances.clear()
        self._disabled_plugins.clear()
        self.discover_plugins()


# 创建插件管理器实例
plugin_manager = PluginManager() 