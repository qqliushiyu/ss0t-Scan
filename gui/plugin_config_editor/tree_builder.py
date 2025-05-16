#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置树构建模块
负责将配置数据构建为树形控件
"""

from typing import Any, Dict, List, Tuple, Optional
from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

class ConfigTreeBuilder:
    """配置数据树构建器"""
    
    def __init__(self, tree_widget: QTreeWidget):
        """
        初始化树构建器
        
        Args:
            tree_widget: 树控件
        """
        self.tree_widget = tree_widget
    
    def build_tree(self, config_data: Any, max_nodes: int = 1500, is_sampled: bool = False) -> Tuple[int, bool]:
        """
        构建配置树结构
        
        Args:
            config_data: 配置数据
            max_nodes: 最大节点数
            is_sampled: 是否为采样解析结果
            
        Returns:
            (节点数, 是否截断)
        """
        # 清空树控件
        self.tree_widget.clear()
        
        # 创建根节点
        root_item = QTreeWidgetItem(self.tree_widget, ["插件配置"])
        if is_sampled:
            root_item.setText(0, "插件配置 (采样解析)")
            root_item.setForeground(0, QColor(0, 0, 255))  # 蓝色提示采样解析
        
        # 记录节点数
        node_count = [0]
        
        # 递归构建树
        truncated = self._build_json_tree(root_item, config_data, node_count=node_count, max_nodes=max_nodes)
        
        # 如果达到了节点限制，显示提示
        if truncated:
            warning_item = QTreeWidgetItem(root_item, [f"... (配置结构过大，仅显示前{max_nodes}个节点)"])
            warning_item.setForeground(0, QColor(255, 0, 0))  # 红色提示
        
        # 展开根节点
        self.tree_widget.expandItem(root_item)
        
        return node_count[0], truncated
    
    def _build_json_tree(self, parent_item: QTreeWidgetItem, data: Any, key: str = None, 
                       node_count: List[int] = None, max_nodes: int = 1500) -> bool:
        """
        递归构建JSON/YAML树
        
        Args:
            parent_item: 父树项
            data: 数据
            key: 键名
            node_count: 当前节点计数
            max_nodes: 最大节点数
            
        Returns:
            是否达到节点限制
        """
        # 检查是否达到节点限制
        if node_count is not None and max_nodes is not None:
            if node_count[0] >= max_nodes:
                return True
            node_count[0] += 1
        
        if isinstance(data, dict):
            # 对于字典，添加每个键值对
            items = list(data.items())
            
            # 如果数据项过多，只处理前100项
            if len(items) > 100:
                items = items[:100]
                truncated = True
            else:
                truncated = False
            
            for k, v in items:
                if isinstance(v, (dict, list)):
                    # 对于复杂类型，创建子节点
                    child = QTreeWidgetItem(parent_item, [k])
                    child.setData(0, Qt.UserRole, ('key', k))
                    if self._build_json_tree(child, v, k, node_count, max_nodes):
                        return True
                else:
                    # 对于简单类型，显示键值对
                    value_str = str(v)
                    # 限制值的长度
                    if len(value_str) > 100:
                        value_str = value_str[:100] + "..."
                    child = QTreeWidgetItem(parent_item, [f"{k}: {value_str}"])
                    child.setData(0, Qt.UserRole, ('value', k))
                    
                    if node_count is not None:
                        node_count[0] += 1
                        if node_count[0] >= max_nodes:
                            return True
            
            # 如果数据被截断，添加提示
            if truncated:
                more_item = QTreeWidgetItem(parent_item, ["... (更多项已省略)"])
                more_item.setForeground(0, QColor(128, 128, 128))  # 灰色
                
                if node_count is not None:
                    node_count[0] += 1
                    if node_count[0] >= max_nodes:
                        return True
        
        elif isinstance(data, list):
            # 对于列表，添加每个元素
            # 如果列表过长，只显示前100项
            if len(data) > 100:
                display_items = data[:100]
                truncated = True
            else:
                display_items = data
                truncated = False
            
            for i, item in enumerate(display_items):
                if isinstance(item, (dict, list)):
                    # 对于复杂类型，创建子节点
                    child = QTreeWidgetItem(parent_item, [f"[{i}]"])
                    child.setData(0, Qt.UserRole, ('index', i))
                    if self._build_json_tree(child, item, node_count=node_count, max_nodes=max_nodes):
                        return True
                else:
                    # 对于简单类型，直接显示值
                    value_str = str(item)
                    # 限制值的长度
                    if len(value_str) > 100:
                        value_str = value_str[:100] + "..."
                    child = QTreeWidgetItem(parent_item, [f"[{i}]: {value_str}"])
                    child.setData(0, Qt.UserRole, ('item', i))
                    
                    if node_count is not None:
                        node_count[0] += 1
                        if node_count[0] >= max_nodes:
                            return True
            
            # 如果数据被截断，添加提示
            if truncated:
                more_item = QTreeWidgetItem(parent_item, [f"... (更多 {len(data) - 100} 项已省略)"])
                more_item.setForeground(0, QColor(128, 128, 128))  # 灰色
                
                if node_count is not None:
                    node_count[0] += 1
                    if node_count[0] >= max_nodes:
                        return True
        
        return False
    
    def set_error(self, error_message: str):
        """
        设置错误信息
        
        Args:
            error_message: 错误信息
        """
        self.tree_widget.clear()
        error_item = QTreeWidgetItem(self.tree_widget, [f"解析错误: {error_message}"])
        error_item.setForeground(0, QColor(255, 0, 0))  # 红色错误提示
    
    def set_loading(self):
        """设置加载中状态"""
        self.tree_widget.clear()
        loading_item = QTreeWidgetItem(self.tree_widget, ["正在解析文件结构..."])
    
    def add_warning(self, warning_message: str):
        """
        添加警告信息
        
        Args:
            warning_message: 警告信息
        """
        warning_item = QTreeWidgetItem(self.tree_widget, [warning_message])
        warning_item.setForeground(0, QColor(128, 0, 0))  # 暗红色警告
    
    def locate_node(self, item, text_edit):
        """
        定位节点在文本中的位置
        
        Args:
            item: 树节点
            text_edit: 文本编辑器组件
            
        Returns:
            是否成功定位
        """
        try:
            # 获取项目数据
            item_data = item.data(0, Qt.UserRole)
            if not item_data:
                return False
                
            data_type, key = item_data
            
            # 获取文本内容
            text = text_edit.toPlainText()
            
            # 判断文件类型是否为JSON
            is_json = text.lstrip().startswith('{') or text.lstrip().startswith('[')
            
            # 构建需要查找的模式
            if data_type == 'key':
                if is_json:
                    pattern = f'"{key}"\\s*:'
                else:  # YAML
                    pattern = f'^\\s*{key}\\s*:'
            elif data_type == 'value':
                if is_json:
                    pattern = f'"{key}"\\s*:'
                else:  # YAML
                    pattern = f'^\\s*{key}\\s*:'
            elif data_type == 'index':
                # 列表索引定位比较困难，可以尝试通过父节点名称和索引定位
                return False
            elif data_type == 'item':
                # 列表项定位
                return False
            else:
                return False
                
            # 使用正则表达式查找
            import re
            match = re.search(pattern, text, re.MULTILINE)
            
            if match:
                # 计算位置
                start = match.start()
                
                # 设置光标位置
                cursor = text_edit.textCursor()
                cursor.setPosition(start)
                text_edit.setTextCursor(cursor)
                
                # 滚动到可见区域
                text_edit.ensureCursorVisible()
                return True
        except Exception as e:
            return False
            
        return False 