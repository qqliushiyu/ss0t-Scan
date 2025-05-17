#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件配置编辑器模块
提供插件配置文件的图形化编辑功能
"""

import os
import sys
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# 将父目录添加到模块搜索路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTabWidget,
    QWidget, QLabel, QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem,
    QMessageBox, QFileDialog, QInputDialog, QLineEdit, QMenu, QAction,
    QComboBox, QFormLayout, QGroupBox, QCheckBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QToolButton, QApplication, QProgressDialog
)
from PyQt5.QtCore import Qt, QPoint, QSize
from PyQt5.QtGui import QFont, QIcon, QColor, QSyntaxHighlighter, QTextCharFormat

from plugins.config_manager import plugin_config_manager
from gui.config_editor import IniSyntaxHighlighter

# 配置日志
logger = logging.getLogger("nettools.plugin_config_editor")

class JsonSyntaxHighlighter(QSyntaxHighlighter):
    """JSON语法高亮器"""
    
    def __init__(self, parent=None):
        """初始化语法高亮器"""
        super().__init__(parent)
        
        # 语法高亮规则
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor(0, 0, 255))  # 蓝色
        self.keyword_format.setFontWeight(QFont.Bold)
        
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor(0, 128, 0))  # 绿色
        
        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor(128, 0, 128))  # 紫色
        
        self.boolean_format = QTextCharFormat()
        self.boolean_format.setForeground(QColor(255, 0, 0))  # 红色
        self.boolean_format.setFontWeight(QFont.Bold)
        
        self.bracket_format = QTextCharFormat()
        self.bracket_format.setForeground(QColor(128, 128, 128))  # 灰色
        self.bracket_format.setFontWeight(QFont.Bold)
        
        # 简单的JSON语法高亮规则
        # 完整的JSON解析需要更复杂的状态机，这里只做简单处理
        self.string_regex = r'"[^"\\]*(\\.[^"\\]*)*"'
        self.number_regex = r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b'
        self.keyword_regex = r'\b(true|false|null)\b'
        self.bracket_regex = r'[\{\}\[\],:]'
    
    def highlightBlock(self, text: str):
        """
        对文本块进行高亮处理
        
        Args:
            text: 文本块内容
        """
        # 字符串
        import re
        for match in re.finditer(self.string_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.string_format)
        
        # 数字
        for match in re.finditer(self.number_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.number_format)
        
        # 关键字
        for match in re.finditer(self.keyword_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.boolean_format)
        
        # 括号和冒号
        for match in re.finditer(self.bracket_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.bracket_format)

class PluginConfigEditorDialog(QDialog):
    """插件配置编辑器对话框"""
    
    def __init__(self, parent=None):
        """
        初始化插件配置编辑器对话框
        
        Args:
            parent: 父窗口
        """
        super().__init__(parent)
        
        self.setWindowTitle(f"插件配置编辑器")
        self.setMinimumSize(900, 700)
        
        # 当前正在编辑的配置文件
        self.current_config_file = None
        
        # 初始化UI
        self.init_ui()
        
        # 加载插件配置列表
        self.load_plugin_config_list()
    
    def init_ui(self):
        """初始化用户界面"""
        layout = QVBoxLayout(self)
        
        # 顶部工具栏
        toolbar_layout = QHBoxLayout()
        
        # 添加插件选择下拉框
        self.plugin_combo = QComboBox()
        self.plugin_combo.setMinimumWidth(300)
        self.plugin_combo.currentIndexChanged.connect(self.on_plugin_selected)
        toolbar_layout.addWidget(QLabel("选择插件:"))
        toolbar_layout.addWidget(self.plugin_combo)
        
        # 添加新建按钮
        new_btn = QPushButton("新建")
        new_btn.clicked.connect(self.on_new_plugin_config)
        toolbar_layout.addWidget(new_btn)
        
        # 右侧空白
        toolbar_layout.addStretch()
        
        layout.addLayout(toolbar_layout)
        
        # 创建分割器
        self.splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(self.splitter)
        
        # 左侧面板 - 配置文件结构树
        self.left_panel = QWidget()
        left_layout = QVBoxLayout(self.left_panel)
        
        # 创建树控件
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabel("配置结构")
        self.tree_widget.setMinimumWidth(200)
        self.tree_widget.itemClicked.connect(self.on_tree_item_clicked)
        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_tree_context_menu)
        left_layout.addWidget(self.tree_widget)
        
        # 右侧面板 - 文本编辑器
        self.right_panel = QWidget()
        right_layout = QVBoxLayout(self.right_panel)
        
        # 文件路径标签
        self.path_label = QLabel("未选择文件")
        right_layout.addWidget(self.path_label)
        
        # 创建选项卡控件
        self.tab_widget = QTabWidget()
        right_layout.addWidget(self.tab_widget)
        
        # 文本编辑选项卡
        self.text_edit_tab = QWidget()
        text_edit_layout = QVBoxLayout(self.text_edit_tab)
        
        # 创建文本编辑器
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Courier New", 10))
        text_edit_layout.addWidget(self.text_edit)
        
        # 表单编辑选项卡
        self.form_edit_tab = QWidget()
        self.form_layout = QVBoxLayout(self.form_edit_tab)
        self.form_scroll_area = QWidget()
        self.form_scroll_layout = QFormLayout(self.form_scroll_area)
        self.form_layout.addWidget(self.form_scroll_area)
        
        # 添加选项卡
        self.tab_widget.addTab(self.text_edit_tab, "原始编辑")
        self.tab_widget.addTab(self.form_edit_tab, "表单编辑")
        
        # 添加到分割器
        self.splitter.addWidget(self.left_panel)
        self.splitter.addWidget(self.right_panel)
        self.splitter.setStretchFactor(1, 3)  # 右侧区域更大
        
        # 创建按钮布局
        btn_layout = QHBoxLayout()
        
        # 保存按钮
        self.save_btn = QPushButton("保存")
        self.save_btn.clicked.connect(self.save_config)
        self.save_btn.setEnabled(False)
        btn_layout.addWidget(self.save_btn)
        
        # 重新加载按钮
        self.reload_btn = QPushButton("重新加载")
        self.reload_btn.clicked.connect(self.reload_current_config)
        self.reload_btn.setEnabled(False)
        btn_layout.addWidget(self.reload_btn)
        
        # 取消按钮
        self.cancel_btn = QPushButton("关闭")
        self.cancel_btn.clicked.connect(self.close)
        btn_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(btn_layout)
    
    def load_plugin_config_list(self):
        """加载插件配置文件列表"""
        progress_dialog = None
        try:
            # 显示进度对话框 - 确保在主线程中创建
            progress_dialog = QProgressDialog("正在加载插件配置...", "取消", 0, 100, self)
            progress_dialog.setWindowTitle("加载中")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)  # 立即显示
            progress_dialog.setValue(0)
            
            # 立即处理事件，确保对话框显示
            QApplication.processEvents()
            
            self.plugin_combo.clear()
            
            # 添加一个空选项
            self.plugin_combo.addItem("-- 选择插件配置 --", None)
            
            # 确保配置目录存在且有权限访问
            if not os.path.exists(plugin_config_manager.config_dir):
                raise FileNotFoundError(f"配置目录不存在: {plugin_config_manager.config_dir}")
            
            if not os.access(plugin_config_manager.config_dir, os.R_OK):
                raise PermissionError(f"无权限访问配置目录: {plugin_config_manager.config_dir}")
            
            # 获取所有配置文件路径
            config_files = plugin_config_manager.get_plugin_config_files()
            
            # 按字母排序
            config_files.sort()
            
            # 添加到下拉框
            total_files = len(config_files)
            for i, config_file in enumerate(config_files):
                # 检查是否取消操作
                if progress_dialog and progress_dialog.wasCanceled():
                    break
                
                # 更新进度
                progress = int((i / total_files) * 100) if total_files > 0 else 0
                if progress_dialog:
                    progress_dialog.setValue(progress)
                
                file_name = os.path.basename(config_file)
                plugin_id = os.path.splitext(file_name)[0]
                
                # 检查是否有读取权限
                if not os.access(config_file, os.R_OK):
                    logger.warning(f"无权限读取配置文件: {config_file}")
                    self.plugin_combo.addItem(f"{file_name} (无读取权限)", None)
                    continue
                
                # 检查是否有写入权限
                has_write_access = os.access(config_file, os.W_OK)
                
                # 尝试加载配置获取插件名称
                try:
                    config = plugin_config_manager.load_config(plugin_id)
                    name = config.get("name", plugin_id)
                    if not has_write_access:
                        self.plugin_combo.addItem(f"{name} ({file_name}) [只读]", config_file)
                    else:
                        self.plugin_combo.addItem(f"{name} ({file_name})", config_file)
                except Exception as e:
                    logger.warning(f"加载插件配置 {file_name} 失败: {str(e)}")
                    if not has_write_access:
                        self.plugin_combo.addItem(f"{file_name} [只读]", config_file)
                    else:
                        self.plugin_combo.addItem(file_name, config_file)
                
                # 处理事件，使界面保持响应
                QApplication.processEvents()
            
            # 添加新建选项
            self.plugin_combo.addItem("+ 创建新插件配置...", "new")
            
            # 完成进度
            if progress_dialog:
                progress_dialog.setValue(100)
                # 给UI一点时间来更新
                QApplication.processEvents()
        
        except Exception as e:
            logger.error(f"加载插件配置列表失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"加载插件配置列表失败: {str(e)}")
        finally:
            # 确保进度对话框被关闭
            if progress_dialog:
                progress_dialog.close()
    
    def on_plugin_selected(self, index: int):
        """
        处理插件选择事件
        
        Args:
            index: 所选索引
        """
        if index <= 0:
            # 清空当前视图
            self.text_edit.clear()
            self.tree_widget.clear()
            self.path_label.setText("未选择文件")
            self.current_config_file = None
            self.save_btn.setEnabled(False)
            self.reload_btn.setEnabled(False)
            return
        
        # 获取所选配置文件路径
        config_file = self.plugin_combo.itemData(index)
        
        if config_file == "new":
            # 重置选择
            self.plugin_combo.setCurrentIndex(0)
            # 创建新配置
            self.on_new_plugin_config()
            return
        
        # 加载配置文件
        self.load_config_file(config_file)
    
    def load_config_file(self, config_file: str):
        """
        加载配置文件
        
        Args:
            config_file: 配置文件路径
        """
        progress_dialog = None
        try:
            # 检查文件大小
            file_size = os.path.getsize(config_file)
            large_file = file_size > 1024 * 1024  # 大于1MB的文件
            
            if large_file:
                # 显示进度对话框 - 在主线程中创建
                progress_dialog = QProgressDialog("正在加载大文件...", "取消", 0, 100, self)
                progress_dialog.setWindowTitle("加载中")
                progress_dialog.setWindowModality(Qt.WindowModal)
                progress_dialog.setMinimumDuration(0)  # 立即显示
                progress_dialog.setValue(0)
                # 立即处理事件，确保对话框显示
                QApplication.processEvents()
            
            # 读取文件内容
            content = ""
            with open(config_file, 'r', encoding='utf-8') as f:
                if large_file:
                    # 对于大文件，分块读取
                    chunk_size = 102400  # 100KB 每块
                    total_size = file_size
                    read_size = 0
                    
                    while True:
                        # 检查是否取消操作
                        if progress_dialog and progress_dialog.wasCanceled():
                            return
                        
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        
                        content += chunk
                        read_size += len(chunk.encode('utf-8'))
                        progress = int((read_size / total_size) * 100)
                        
                        if progress_dialog:
                            progress_dialog.setValue(progress)
                        # 立即处理事件，确保对话框更新
                        QApplication.processEvents()
                else:
                    # 对于小文件，直接读取
                    content = f.read()
            
            # 关闭进度对话框
            if progress_dialog:
                progress_dialog.setValue(100)
                # 确保UI更新
                QApplication.processEvents()
                progress_dialog.close()
                progress_dialog = None
            
            # 设置文本编辑器内容
            self.text_edit.setPlainText(content)
            
            # 应用语法高亮
            if config_file.lower().endswith('.json'):
                self.highlighter = JsonSyntaxHighlighter(self.text_edit.document())
            elif config_file.lower().endswith(('.yaml', '.yml')):
                # 可以添加YAML的语法高亮器
                pass
            
            # 解析配置结构并填充树控件
            # 对于大文件，提示用户可能会比较慢
            if large_file:
                parse_warning = QMessageBox(self)
                parse_warning.setWindowTitle("警告")
                parse_warning.setText("文件较大，解析可能需要一些时间。是否继续解析结构?")
                parse_warning.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
                parse_warning.setDefaultButton(QMessageBox.Yes)
                
                if parse_warning.exec_() == QMessageBox.Yes:
                    # 显示进度对话框
                    struct_progress = QProgressDialog("正在解析文件结构...", "取消", 0, 100, self)
                    struct_progress.setWindowTitle("解析中")
                    struct_progress.setWindowModality(Qt.WindowModal)
                    struct_progress.setMinimumDuration(0)
                    struct_progress.setValue(10)  # 起始进度
                    QApplication.processEvents()
                    
                    # 解析结构
                    try:
                        self.parse_config_structure(content, config_file)
                        struct_progress.setValue(100)
                        # 确保UI更新
                        QApplication.processEvents()
                    finally:
                        struct_progress.close()
                else:
                    # 清空树控件
                    self.tree_widget.clear()
                    root_item = QTreeWidgetItem(self.tree_widget, ["文件较大，已跳过解析"])
            else:
                # 小文件直接解析
                self.parse_config_structure(content, config_file)
            
            # 更新UI状态
            self.path_label.setText(f"文件: {config_file}")
            self.current_config_file = config_file
            self.save_btn.setEnabled(True)
            self.reload_btn.setEnabled(True)
            
            logger.info(f"已加载插件配置文件: {config_file}")
        
        except Exception as e:
            error_msg = f"读取配置文件失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, "错误", error_msg)
        finally:
            # 确保进度对话框被关闭
            if progress_dialog:
                progress_dialog.close()
    
    def parse_config_structure(self, content: str, config_file: str):
        """
        解析配置文件结构并填充树控件
        
        Args:
            content: 配置文件内容
            config_file: 配置文件路径
        """
        try:
            # 禁用树控件更新以提高性能
            self.tree_widget.setUpdatesEnabled(False)
            self.tree_widget.clear()
            
            # 根据文件类型解析内容
            config = None
            try:
                if config_file.lower().endswith('.json'):
                    config = json.loads(content)
                elif config_file.lower().endswith(('.yaml', '.yml')):
                    config = yaml.safe_load(content)
                else:
                    # 对于不支持的文件类型，只显示文件名
                    root_item = QTreeWidgetItem(self.tree_widget, [os.path.basename(config_file)])
                    self.tree_widget.setUpdatesEnabled(True)
                    return
            except json.JSONDecodeError as e:
                error_item = QTreeWidgetItem(self.tree_widget, [f"JSON解析错误: {str(e)}"])
                self.tree_widget.setUpdatesEnabled(True)
                return
            except yaml.YAMLError as e:
                error_item = QTreeWidgetItem(self.tree_widget, [f"YAML解析错误: {str(e)}"])
                self.tree_widget.setUpdatesEnabled(True)
                return
            
            if config is not None:
                root_item = QTreeWidgetItem(self.tree_widget, ["插件配置"])
                
                # 限制处理的最大节点数，防止过大的配置文件导致界面卡死
                max_nodes = 1000
                node_count = [0]  # 使用列表以便在递归中修改
                
                # 递归构建树
                self.build_json_tree(root_item, config, node_count=node_count, max_nodes=max_nodes)
                
                # 如果达到了节点限制，显示提示
                if node_count[0] >= max_nodes:
                    warning_item = QTreeWidgetItem(root_item, [f"... (配置结构过大，已省略部分内容)"])
                    warning_item.setForeground(0, QColor(255, 0, 0))  # 红色提示
            
            # 展开树
            self.tree_widget.expandAll()
        
        except Exception as e:
            logger.error(f"解析配置文件结构失败: {str(e)}")
            error_item = QTreeWidgetItem(self.tree_widget, [f"错误: {str(e)}"])
        finally:
            # 重新启用树控件更新
            self.tree_widget.setUpdatesEnabled(True)
    
    def build_json_tree(self, parent_item: QTreeWidgetItem, data: Any, key: str = None, 
                       node_count: List[int] = None, max_nodes: int = None):
        """
        递归构建JSON/YAML树
        
        Args:
            parent_item: 父树项
            data: 数据
            key: 键名
            node_count: 当前节点计数
            max_nodes: 最大节点数
        """
        # 检查是否达到节点限制
        if node_count is not None and max_nodes is not None:
            if node_count[0] >= max_nodes:
                return
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
                    self.build_json_tree(child, v, k, node_count, max_nodes)
                else:
                    # 对于简单类型，显示键值对
                    value_str = str(v)
                    # 限制值的长度
                    if len(value_str) > 100:
                        value_str = value_str[:100] + "..."
                    child = QTreeWidgetItem(parent_item, [f"{k}: {value_str}"])
                    child.setData(0, Qt.UserRole, ('value', k))
            
            # 如果数据被截断，添加提示
            if truncated:
                more_item = QTreeWidgetItem(parent_item, ["... (更多项已省略)"])
                more_item.setForeground(0, QColor(128, 128, 128))  # 灰色
        
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
                    self.build_json_tree(child, item, node_count=node_count, max_nodes=max_nodes)
                else:
                    # 对于简单类型，直接显示值
                    value_str = str(item)
                    # 限制值的长度
                    if len(value_str) > 100:
                        value_str = value_str[:100] + "..."
                    child = QTreeWidgetItem(parent_item, [f"[{i}]: {value_str}"])
                    child.setData(0, Qt.UserRole, ('item', i))
            
            # 如果数据被截断，添加提示
            if truncated:
                more_item = QTreeWidgetItem(parent_item, [f"... (更多 {len(data) - 100} 项已省略)"])
                more_item.setForeground(0, QColor(128, 128, 128))  # 灰色
    
    def on_tree_item_clicked(self, item, column):
        """
        处理树项目点击事件
        
        Args:
            item: 被点击的树项目
            column: 列索引
        """
        # 点击树节点时的处理
        pass
    
    def show_tree_context_menu(self, position: QPoint):
        """
        显示树控件上下文菜单
        
        Args:
            position: 鼠标位置
        """
        # 右键菜单
        pass
    
    def on_new_plugin_config(self):
        """创建新的插件配置"""
        # 获取插件ID
        plugin_id, ok = QInputDialog.getText(
            self, "创建新插件配置", 
            "请输入插件ID (英文字母、数字和下划线):",
            QLineEdit.Normal
        )
        
        if not ok or not plugin_id:
            return
        
        # 验证插件ID
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', plugin_id):
            QMessageBox.warning(self, "无效的插件ID", "插件ID只能包含英文字母、数字和下划线")
            return
        
        # 检查是否已存在
        json_path = os.path.join(plugin_config_manager.config_dir, f"{plugin_id}.json")
        if os.path.exists(json_path):
            reply = QMessageBox.question(
                self, "确认覆盖", 
                f"插件配置 '{plugin_id}.json' 已存在，是否覆盖?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
        
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
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=4, ensure_ascii=False)
            
            logger.info(f"已创建新插件配置: {json_path}")
            
            # 刷新插件列表
            self.load_plugin_config_list()
            
            # 定位到新创建的插件
            for i in range(self.plugin_combo.count()):
                if self.plugin_combo.itemData(i) == json_path:
                    self.plugin_combo.setCurrentIndex(i)
                    break
            
            QMessageBox.information(self, "成功", f"已创建新插件配置: {plugin_id}.json")
        
        except Exception as e:
            error_msg = f"创建插件配置失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, "错误", error_msg)
    
    def reload_current_config(self):
        """重新加载当前配置文件"""
        if self.current_config_file:
            self.load_config_file(self.current_config_file)
    
    def save_config(self):
        """保存配置文件"""
        if not self.current_config_file:
            return
        
        try:
            # 获取文本编辑器内容
            content = self.text_edit.toPlainText()
            
            # 验证JSON/YAML格式
            if self.current_config_file.lower().endswith('.json'):
                # 验证JSON
                try:
                    json.loads(content)
                except json.JSONDecodeError as e:
                    QMessageBox.critical(self, "无效的JSON", f"JSON格式错误: {str(e)}")
                    return
            elif self.current_config_file.lower().endswith(('.yaml', '.yml')):
                # 验证YAML
                try:
                    yaml.safe_load(content)
                except yaml.YAMLError as e:
                    QMessageBox.critical(self, "无效的YAML", f"YAML格式错误: {str(e)}")
                    return
            
            # 保存文件
            with open(self.current_config_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 重新加载配置到内存
            plugin_id = os.path.splitext(os.path.basename(self.current_config_file))[0]
            if plugin_id in plugin_config_manager.configs:
                del plugin_config_manager.configs[plugin_id]
                plugin_config_manager.load_config(plugin_id)
            
            logger.info(f"已保存插件配置: {self.current_config_file}")
            QMessageBox.information(self, "成功", f"配置已保存: {os.path.basename(self.current_config_file)}")
            
            # 重新解析配置结构
            self.parse_config_structure(content, self.current_config_file)
        
        except Exception as e:
            error_msg = f"保存配置失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, "错误", error_msg)

def show_plugin_config_editor(parent=None):
    """
    显示插件配置编辑器对话框
    
    Args:
        parent: 父窗口
    
    Returns:
        对话框接受/拒绝状态
    """
    dialog = PluginConfigEditorDialog(parent)
    return dialog.exec_()

if __name__ == "__main__":
    # 独立运行时的测试代码
    import sys
    from PyQt5.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    dialog = PluginConfigEditorDialog()
    dialog.exec_()
    
    sys.exit() 