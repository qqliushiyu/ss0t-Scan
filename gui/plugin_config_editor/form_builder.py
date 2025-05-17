#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置表单构建模块
负责将配置数据构建为表单控件
"""

import json
from typing import Dict, Any, List, Tuple, Optional, Callable
from PyQt5.QtWidgets import (
    QFormLayout, QWidget, QLineEdit, QTextEdit, QCheckBox, 
    QSpinBox, QDoubleSpinBox, QGroupBox, QVBoxLayout, QComboBox
)
from PyQt5.QtCore import Qt

class ConfigFormBuilder:
    """配置表单构建器"""
    
    def __init__(self, parent_widget: QWidget, on_field_changed: Callable):
        """
        初始化表单构建器
        
        Args:
            parent_widget: 父控件
            on_field_changed: 字段变更回调
        """
        self.parent_widget = parent_widget
        self.on_field_changed = on_field_changed
        self.form_fields = {}
        self.current_config_data = None
    
    def build_form(self, config_data: Dict[str, Any]) -> QWidget:
        """
        根据配置数据构建表单
        
        Args:
            config_data: 配置数据
            
        Returns:
            表单容器控件
        """
        # 保存当前配置数据
        self.current_config_data = config_data
        
        # 清空表单字段
        self.form_fields = {}
        
        # 创建表单布局
        form_layout = QFormLayout()
        form_layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form_layout.setLabelAlignment(Qt.AlignRight)
        
        # 处理配置项
        self._add_config_to_form("", config_data, form_layout)
        
        # 创建表单容器
        form_container = QWidget()
        form_container.setLayout(form_layout)
        
        return form_container
    
    def _add_config_to_form(self, prefix: str, config_data: Any, layout: QFormLayout, parent_level: int = 0):
        """
        递归添加配置项到表单
        
        Args:
            prefix: 键前缀
            config_data: 配置数据
            layout: 表单布局
            parent_level: 父级嵌套层级
        """
        if isinstance(config_data, dict):
            # 对于字典，创建分组
            for key, value in config_data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, dict) and parent_level < 1:
                    # 为子字典创建分组框
                    group_box = QGroupBox(key)
                    group_layout = QFormLayout(group_box)
                    group_layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
                    
                    # 递归添加子项
                    self._add_config_to_form(full_key, value, group_layout, parent_level + 1)
                    
                    # 将分组添加到主布局
                    layout.addRow(group_box)
                else:
                    # 为基本类型创建表单字段
                    if isinstance(value, dict):
                        # 如果是嵌套字典但超过层级限制，转为文本框
                        field = QTextEdit()
                        field.setMaximumHeight(120)
                        field.setText(json.dumps(value, indent=2, ensure_ascii=False))
                        field.textChanged.connect(self.on_field_changed)
                        layout.addRow(f"{key}:", field)
                        self.form_fields[full_key] = (field, "object")
                    elif isinstance(value, list):
                        # 列表转为文本框
                        field = QTextEdit()
                        field.setMaximumHeight(120)
                        field.setText(json.dumps(value, indent=2, ensure_ascii=False))
                        field.textChanged.connect(self.on_field_changed)
                        layout.addRow(f"{key}:", field)
                        self.form_fields[full_key] = (field, "list")
                    elif isinstance(value, bool):
                        # 布尔值转为复选框
                        field = QCheckBox()
                        field.setChecked(value)
                        field.stateChanged.connect(self.on_field_changed)
                        layout.addRow(f"{key}:", field)
                        self.form_fields[full_key] = (field, "bool")
                    elif isinstance(value, int):
                        # 整数转为数字输入框
                        field = QSpinBox()
                        field.setRange(-999999999, 999999999)  # 设置一个很大的范围
                        field.setValue(value)
                        field.valueChanged.connect(self.on_field_changed)
                        layout.addRow(f"{key}:", field)
                        self.form_fields[full_key] = (field, "int")
                    elif isinstance(value, float):
                        # 浮点数转为数字输入框
                        field = QDoubleSpinBox()
                        field.setRange(-999999999, 999999999)  # 设置一个很大的范围
                        field.setDecimals(6)  # 最多6位小数
                        field.setValue(value)
                        field.valueChanged.connect(self.on_field_changed)
                        layout.addRow(f"{key}:", field)
                        self.form_fields[full_key] = (field, "float")
                    else:
                        # 其他类型转为文本框
                        field = QLineEdit()
                        field.setText(str(value))
                        field.textChanged.connect(self.on_field_changed)
                        layout.addRow(f"{key}:", field)
                        self.form_fields[full_key] = (field, "str")
        elif isinstance(config_data, list):
            # 对于列表，创建文本编辑器
            field = QTextEdit()
            field.setText(json.dumps(config_data, indent=2, ensure_ascii=False))
            field.textChanged.connect(self.on_field_changed)
            layout.addRow(prefix, field)
            self.form_fields[prefix] = (field, "list")
        else:
            # 基本类型处理（字符串等）
            field = QLineEdit()
            field.setText(str(config_data))
            field.textChanged.connect(self.on_field_changed)
            layout.addRow(prefix, field)
            self.form_fields[prefix] = (field, "str")
    
    def get_form_data(self) -> Dict[str, Any]:
        """
        从表单中获取配置数据
        
        Returns:
            配置数据
        """
        result = {}
        
        # 使用深拷贝避免修改原始数据
        import copy
        if self.current_config_data:
            result = copy.deepcopy(self.current_config_data)
        
        # 从表单字段中更新数据
        for key, (field, field_type) in self.form_fields.items():
            parts = key.split(".")
            target = result
            
            # 遍历嵌套层级直到最后一个键
            for i, part in enumerate(parts[:-1]):
                if part not in target:
                    target[part] = {}
                target = target[part]
            
            # 最后一个键是我们要设置的值
            last_key = parts[-1]
            
            # 根据字段类型获取值
            if field_type == "bool":
                target[last_key] = field.isChecked()
            elif field_type == "int":
                target[last_key] = field.value()
            elif field_type == "float":
                target[last_key] = field.value()
            elif field_type == "list" or field_type == "object":
                try:
                    # 尝试解析JSON
                    value = json.loads(field.toPlainText())
                    target[last_key] = value
                except json.JSONDecodeError:
                    # 如果无法解析，保持原值
                    pass
            else:
                # 字符串类型
                target[last_key] = field.text()
        
        return result 