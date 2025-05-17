#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件配置数据模型模块
提供配置数据的加载、解析和保存功能
"""

import os
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path

from plugins.config_manager import plugin_config_manager

# 配置日志
logger = logging.getLogger("nettools.plugin_config_editor.model")

class PluginConfigModel:
    """插件配置数据模型"""
    
    def __init__(self):
        """初始化配置数据模型"""
        self.current_config_file = None
        self.current_config_data = None
        self.modified = False
        
    def get_plugin_config_files(self) -> List[Dict[str, Any]]:
        """
        获取所有插件配置文件列表
        
        Returns:
            配置文件信息列表，每个元素是包含file、name和access的字典
        """
        configs = []
        config_files = plugin_config_manager.get_plugin_config_files()
        
        # 按字母排序
        config_files.sort()
        
        for config_file in config_files:
            file_name = os.path.basename(config_file)
            plugin_id = os.path.splitext(file_name)[0]
            
            # 检查是否有读取权限
            has_read_access = os.access(config_file, os.R_OK)
            if not has_read_access:
                configs.append({
                    'file': config_file,
                    'name': f"{file_name} (无读取权限)",
                    'access': False
                })
                continue
            
            # 检查是否有写入权限
            has_write_access = os.access(config_file, os.W_OK)
            
            # 尝试加载配置获取插件名称
            try:
                config = self.load_config_file(config_file)
                
                name = config.get("name", plugin_id) if config else plugin_id
                
                display_name = name
                if not has_write_access:
                    display_name = f"{name} ({file_name}) [只读]"
                else:
                    display_name = f"{name} ({file_name})"
                    
                configs.append({
                    'file': config_file, 
                    'name': display_name,
                    'access': has_write_access
                })
            except Exception as e:
                logger.warning(f"加载插件配置 {file_name} 失败: {str(e)}")
                if not has_write_access:
                    configs.append({
                        'file': config_file,
                        'name': f"{file_name} [只读]",
                        'access': False
                    })
                else:
                    configs.append({
                        'file': config_file,
                        'name': file_name,
                        'access': True
                    })
                    
        return configs
    
    def load_config_file(self, config_file: str) -> Optional[Dict[str, Any]]:
        """
        加载配置文件
        
        Args:
            config_file: 配置文件路径
            
        Returns:
            配置数据，加载失败则返回None
        """
        try:
            if not os.path.exists(config_file):
                return None
                
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 根据文件类型解析配置
            config = None
            if config_file.lower().endswith('.json'):
                config = json.loads(content)
            elif config_file.lower().endswith(('.yaml', '.yml')):
                config = yaml.safe_load(content)
            else:
                logger.warning(f"不支持的配置文件类型: {config_file}")
                return None
                
            self.current_config_file = config_file
            self.current_config_data = config
            self.modified = False
            
            return config
        except Exception as e:
            logger.error(f"加载配置文件失败: {str(e)}")
            return None
    
    def create_default_config(self, plugin_id: str) -> Tuple[bool, str]:
        """
        创建默认配置
        
        Args:
            plugin_id: 插件ID
            
        Returns:
            (成功标志, 文件路径或错误信息)
        """
        try:
            # 创建默认配置
            default_config = {
                "enabled": True,
                "name": plugin_id,
                "description": "插件描述",
                "version": "1.0.0",
                "timeout": 10,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                "verify_ssl": False
            }
            
            # 保存配置
            json_path = os.path.join(plugin_config_manager.config_dir, f"{plugin_id}.json")
            
            # 使用插件配置管理器保存
            if plugin_config_manager.save_config(plugin_id, default_config):
                self.current_config_file = json_path
                self.current_config_data = default_config
                self.modified = False
                return True, json_path
            else:
                return False, "保存配置失败"
                
        except Exception as e:
            logger.error(f"创建默认配置失败: {str(e)}")
            return False, str(e)
    
    def save_config(self, content: str) -> Tuple[bool, str]:
        """
        保存配置文件
        
        Args:
            content: 配置文件内容
            
        Returns:
            (成功标志, 成功信息或错误信息)
        """
        if not self.current_config_file:
            return False, "未选择配置文件"
            
        try:
            # 验证JSON/YAML格式
            if self.current_config_file.lower().endswith('.json'):
                # 验证JSON
                config_data = json.loads(content)
            elif self.current_config_file.lower().endswith(('.yaml', '.yml')):
                # 验证YAML
                config_data = yaml.safe_load(content)
            else:
                return False, "不支持的配置文件格式"
                
            # 保存到文件
            with open(self.current_config_file, 'w', encoding='utf-8') as f:
                f.write(content)
                
            # 更新当前数据
            self.current_config_data = config_data
            self.modified = False
            
            # 更新配置管理器缓存
            plugin_id = os.path.splitext(os.path.basename(self.current_config_file))[0]
            if plugin_id in plugin_config_manager.configs:
                del plugin_config_manager.configs[plugin_id]
                plugin_config_manager.load_config(plugin_id)
                
            return True, f"配置已保存: {os.path.basename(self.current_config_file)}"
            
        except json.JSONDecodeError as e:
            return False, f"JSON格式错误: {str(e)}"
        except yaml.YAMLError as e:
            return False, f"YAML格式错误: {str(e)}"
        except Exception as e:
            logger.error(f"保存配置失败: {str(e)}")
            return False, f"保存配置失败: {str(e)}"
    
    def parse_tree_structure(self, data: Any, max_nodes: int = 1500) -> Tuple[Any, int, bool]:
        """
        解析树结构
        
        Args:
            data: 配置数据
            max_nodes: 最大节点数
            
        Returns:
            (树结构数据, 节点数, 是否截断)
        """
        node_count = 0
        truncated = False
        
        def _process_data(data, parent_path=""):
            nonlocal node_count, truncated
            
            # 检查是否达到节点限制
            if node_count >= max_nodes:
                truncated = True
                return None
                
            if isinstance(data, dict):
                result = {}
                # 对于字典，处理每个键值对
                for k, v in list(data.items())[:100]:  # 限制最多100个子项
                    node_count += 1
                    if node_count >= max_nodes:
                        truncated = True
                        break
                    
                    # 递归处理值
                    child_path = f"{parent_path}.{k}" if parent_path else k
                    result[k] = _process_data(v, child_path)
                    
                return result
                
            elif isinstance(data, list):
                result = []
                # 对于列表，处理每个元素
                for i, item in enumerate(data[:100]):  # 限制最多100个子项
                    node_count += 1
                    if node_count >= max_nodes:
                        truncated = True
                        break
                    
                    # 递归处理元素
                    child_path = f"{parent_path}[{i}]"
                    result.append(_process_data(item, child_path))
                    
                return result
                
            else:
                # 基本类型直接返回
                node_count += 1
                return data
                
        # 处理数据
        result = _process_data(data)
        return result, node_count, truncated 