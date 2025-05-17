#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置编辑器模块
提供图形化配置文件编辑功能
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional, Tuple

# 将父目录添加到模块搜索路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTabWidget,
    QWidget, QLabel, QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem,
    QMessageBox, QFileDialog, QInputDialog, QLineEdit, QMenu, QAction
)
from PyQt5.QtCore import Qt, QPoint, QRegExp
from PyQt5.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat, QTextDocument

from utils.config import ConfigManager, config_manager

# 配置日志
logger = logging.getLogger("nettools.config_editor")

class IniSyntaxHighlighter(QSyntaxHighlighter):
    """INI语法高亮器"""
    
    def __init__(self, parent=None):
        """初始化语法高亮器"""
        super().__init__(parent)
        
        # 语法高亮规则
        self.section_format = QTextCharFormat()
        self.section_format.setForeground(QColor(0, 0, 255))  # 蓝色
        self.section_format.setFontWeight(QFont.Bold)
        
        self.key_format = QTextCharFormat()
        self.key_format.setForeground(QColor(128, 0, 128))  # 紫色
        
        self.value_format = QTextCharFormat()
        self.value_format.setForeground(QColor(0, 128, 0))  # 绿色
        
        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor(128, 128, 128))  # 灰色
        self.comment_format.setFontItalic(True)
    
    def highlightBlock(self, text: str):
        """
        对文本块进行高亮处理
        
        Args:
            text: 文本块内容
        """
        text = text.strip()
        
        # 注释
        if text.startswith('#') or text.startswith(';'):
            self.setFormat(0, len(text), self.comment_format)
            return
        
        # 段落
        if text.startswith('[') and text.endswith(']'):
            self.setFormat(0, len(text), self.section_format)
            return
        
        # 键值对
        if '=' in text:
            key_end = text.find('=')
            self.setFormat(0, key_end, self.key_format)
            self.setFormat(key_end, 1, QTextCharFormat())  # 等号使用默认格式
            self.setFormat(key_end + 1, len(text) - key_end - 1, self.value_format)

class ConfigEditorDialog(QDialog):
    """配置编辑器对话框"""
    
    def __init__(self, config_file: str, parent=None, config_manager: Optional[ConfigManager] = None):
        """
        初始化配置编辑器对话框
        
        Args:
            config_file: 配置文件路径
            parent: 父窗口
            config_manager: 配置管理器实例，如果为None则使用默认实例
        """
        super().__init__(parent)
        self.config_file = config_file
        self.config_manager = config_manager or globals().get('config_manager')
        
        self.setWindowTitle(f"配置编辑器 - {os.path.basename(config_file)}")
        self.setMinimumSize(900, 700)
        
        # 初始化UI
        self.init_ui()
        
        # 加载配置文件内容
        self.load_config_content()
    
    def init_ui(self):
        """初始化用户界面"""
        layout = QVBoxLayout(self)
        
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
        self.path_label = QLabel(f"文件: {self.config_file}")
        right_layout.addWidget(self.path_label)
        
        # 创建文本编辑器
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Courier New", 10))
        self.text_edit.textChanged.connect(self.on_text_changed)
        right_layout.addWidget(self.text_edit)
        
        # 为INI文件添加语法高亮
        if self.config_file.lower().endswith('.ini'):
            self.highlighter = IniSyntaxHighlighter(self.text_edit.document())
        
        # 添加到分割器
        self.splitter.addWidget(self.left_panel)
        self.splitter.addWidget(self.right_panel)
        self.splitter.setStretchFactor(1, 3)  # 文本编辑器区域更大
        
        # 创建按钮布局
        btn_layout = QHBoxLayout()
        
        # 保存按钮
        self.save_btn = QPushButton("保存")
        self.save_btn.clicked.connect(self.save_config)
        btn_layout.addWidget(self.save_btn)
        
        # 重新加载按钮
        self.reload_btn = QPushButton("重新加载")
        self.reload_btn.clicked.connect(self.load_config_content)
        btn_layout.addWidget(self.reload_btn)
        
        # 取消按钮
        self.cancel_btn = QPushButton("关闭")
        self.cancel_btn.clicked.connect(self.close)
        btn_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(btn_layout)
    
    def load_config_content(self):
        """加载配置文件内容并解析结构"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.text_edit.setPlainText(content)
            
            # 解析配置文件结构并填充树控件
            self.parse_config_structure(content)
            
            logger.info(f"已加载配置文件内容: {self.config_file}")
        except Exception as e:
            error_msg = f"读取配置文件失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, "错误", error_msg)
    
    def parse_config_structure(self, content: str):
        """
        解析配置文件结构并填充树控件
        
        Args:
            content: 配置文件内容
        """
        self.tree_widget.clear()
        
        # 如果是INI文件，解析其节和键值对
        if self.config_file.lower().endswith('.ini'):
            current_section = None
            section_item = None
            
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(('#', ';')):
                    continue
                
                if line.startswith('[') and line.endswith(']'):
                    # 新节
                    section_name = line[1:-1]
                    section_item = QTreeWidgetItem(self.tree_widget, [section_name])
                    section_item.setData(0, Qt.UserRole, ('section', section_name))
                    current_section = section_item
                elif '=' in line and current_section:
                    # 键值对
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    key_item = QTreeWidgetItem(current_section, [f"{key} = {value}"])
                    key_item.setData(0, Qt.UserRole, ('key', key))
        
        # 对于其他类型的文件，可以根据需要添加解析逻辑
        elif self.config_file.lower().endswith(('.json', '.yaml', '.yml')):
            root_item = QTreeWidgetItem(self.tree_widget, ["文件内容"])
        else:
            # 对于不支持结构解析的文件，只显示文件名
            root_item = QTreeWidgetItem(self.tree_widget, [os.path.basename(self.config_file)])
        
        # 展开树
        self.tree_widget.expandAll()
    
    def on_tree_item_clicked(self, item, column):
        """
        处理树项目点击事件
        
        Args:
            item: 被点击的树项目
            column: 列索引
        """
        item_data = item.data(0, Qt.UserRole)
        if not item_data:
            return
        
        item_type, item_value = item_data
        
        # 如果点击的是节，定位到对应节
        if item_type == 'section':
            self.locate_section(item_value)
        # 如果点击的是键，定位到对应键
        elif item_type == 'key':
            self.locate_key(item_value)
    
    def locate_section(self, section_name: str):
        """
        在文本编辑器中定位到指定节
        
        Args:
            section_name: 节名称
        """
        section_pattern = f"[{section_name}]"
        self.locate_text(section_pattern)
    
    def locate_key(self, key_name: str):
        """
        在文本编辑器中定位到指定键
        
        Args:
            key_name: 键名称
        """
        # 查找形如 "key = value" 或 "key=value" 的模式
        key_pattern = f"{key_name}\\s*="
        self.locate_text(key_pattern, use_regex=True)
    
    def locate_text(self, text: str, use_regex: bool = False):
        """
        在文本编辑器中定位指定文本
        
        Args:
            text: 要定位的文本
            use_regex: 是否使用正则表达式
        """
        cursor = self.text_edit.textCursor()
        cursor.movePosition(cursor.Start)
        self.text_edit.setTextCursor(cursor)
        
        # 由于PyQt5不同版本中QTextEdit的查找API不一致，
        # 这里简化实现，直接使用正则表达式查找
        if use_regex:
            regex = QRegExp(text)
            regex.setCaseSensitivity(Qt.CaseSensitive)
            found = self.text_edit.find(regex)
        else:
            found = self.text_edit.find(text)
        
        # 如果没找到，尝试不区分大小写再查找一次
        if not found:
            cursor.movePosition(cursor.Start)
            self.text_edit.setTextCursor(cursor)
            
            if use_regex:
                regex = QRegExp(text)
                regex.setCaseSensitivity(Qt.CaseInsensitive)
                self.text_edit.find(regex)
            else:
                # 不区分大小写查找
                self.text_edit.find(text)
    
    def on_text_changed(self):
        """处理文本变更事件"""
        # 这里可以添加未保存提示等逻辑
        pass
    
    def show_tree_context_menu(self, position: QPoint):
        """
        显示树控件上下文菜单
        
        Args:
            position: 鼠标位置
        """
        item = self.tree_widget.itemAt(position)
        if not item:
            return
        
        item_data = item.data(0, Qt.UserRole)
        if not item_data:
            return
        
        item_type, item_value = item_data
        
        menu = QMenu(self)
        
        if item_type == 'section':
            # 节菜单选项
            add_key_action = QAction("添加新键", self)
            add_key_action.triggered.connect(lambda: self.add_new_key(item_value))
            menu.addAction(add_key_action)
            
            rename_action = QAction("重命名节", self)
            rename_action.triggered.connect(lambda: self.rename_section(item_value))
            menu.addAction(rename_action)
            
            delete_action = QAction("删除节", self)
            delete_action.triggered.connect(lambda: self.delete_section(item_value))
            menu.addAction(delete_action)
        
        elif item_type == 'key':
            # 键菜单选项
            edit_action = QAction("编辑值", self)
            edit_action.triggered.connect(lambda: self.edit_key_value(item_value))
            menu.addAction(edit_action)
            
            delete_action = QAction("删除键", self)
            delete_action.triggered.connect(lambda: self.delete_key(item_value))
            menu.addAction(delete_action)
        
        menu.exec_(self.tree_widget.mapToGlobal(position))
    
    def add_new_key(self, section_name: str):
        """
        添加新键
        
        Args:
            section_name: 节名称
        """
        key, ok = QInputDialog.getText(self, "添加新键", "键名:", QLineEdit.Normal)
        if ok and key:
            value, ok = QInputDialog.getText(self, "设置值", f"'{key}'的值:", QLineEdit.Normal)
            if ok:
                # 在配置文件中添加新键
                if self.config_manager:
                    self.config_manager.set(section_name, key, value)
                    self.config_manager.save_config()
                
                # 更新编辑器内容
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.text_edit.setPlainText(content)
                
                # 重新解析结构
                self.parse_config_structure(content)
    
    def rename_section(self, section_name: str):
        """
        重命名节
        
        Args:
            section_name: 原节名称
        """
        new_name, ok = QInputDialog.getText(
            self, "重命名节", "新节名:", QLineEdit.Normal, section_name
        )
        if ok and new_name and new_name != section_name:
            # 重命名节需要手动编辑文本
            content = self.text_edit.toPlainText()
            new_content = content.replace(f"[{section_name}]", f"[{new_name}]")
            
            if new_content != content:
                self.text_edit.setPlainText(new_content)
                self.parse_config_structure(new_content)
    
    def delete_section(self, section_name: str):
        """
        删除节
        
        Args:
            section_name: 节名称
        """
        reply = QMessageBox.question(
            self, "确认删除", 
            f"确定要删除节 '{section_name}' 及其所有设置吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # 这里需要手动编辑文本来删除整个节
            content = self.text_edit.toPlainText()
            lines = content.splitlines()
            
            new_lines = []
            skip_section = False
            
            for line in lines:
                if line.strip() == f"[{section_name}]":
                    skip_section = True
                    continue
                elif line.strip().startswith('[') and line.strip().endswith(']') and skip_section:
                    skip_section = False
                
                if not skip_section:
                    new_lines.append(line)
            
            new_content = '\n'.join(new_lines)
            self.text_edit.setPlainText(new_content)
            self.parse_config_structure(new_content)
    
    def edit_key_value(self, key_name: str):
        """
        编辑键值
        
        Args:
            key_name: 键名称
        """
        # 定位到键
        self.locate_key(key_name)
        
        # 获取当前值
        cursor = self.text_edit.textCursor()
        cursor.select(cursor.LineUnderCursor)
        line = cursor.selectedText()
        
        # 解析当前值
        if '=' in line:
            current_value = line.split('=', 1)[1].strip()
        else:
            current_value = ""
        
        # 获取新值
        new_value, ok = QInputDialog.getText(
            self, "编辑值", f"'{key_name}'的新值:", QLineEdit.Normal, current_value
        )
        
        if ok:
            # 更新值
            new_line = f"{key_name} = {new_value}"
            cursor.insertText(new_line)
            
            # 重新解析结构
            self.parse_config_structure(self.text_edit.toPlainText())
    
    def delete_key(self, key_name: str):
        """
        删除键
        
        Args:
            key_name: 键名称
        """
        reply = QMessageBox.question(
            self, "确认删除", 
            f"确定要删除键 '{key_name}' 吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # 定位到键
            self.locate_key(key_name)
            
            # 删除当前行
            cursor = self.text_edit.textCursor()
            cursor.select(cursor.LineUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()  # 删除换行符
            
            # 重新解析结构
            self.parse_config_structure(self.text_edit.toPlainText())
    
    def save_config(self):
        """保存配置文件内容"""
        try:
            content = self.text_edit.toPlainText()
            with open(self.config_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"已保存配置文件: {self.config_file}")
            QMessageBox.information(self, "成功", f"配置文件已保存到 {self.config_file}")
            
            # 重新加载配置
            if self.config_manager and self.config_file == self.config_manager.config_file:
                # 重新加载配置管理器
                self.config_manager.load_config()
                QMessageBox.information(self, "成功", "配置已重新加载")
            
            # 重新解析结构
            self.parse_config_structure(content)
            
            # 发出配置已更新的信号
            self.accept()
        except Exception as e:
            error_msg = f"保存配置文件失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, "错误", error_msg)

def show_config_editor(config_file: str, parent=None):
    """
    显示配置编辑器对话框
    
    Args:
        config_file: 配置文件路径
        parent: 父窗口
    
    Returns:
        对话框接受/拒绝状态
    """
    dialog = ConfigEditorDialog(config_file, parent)
    return dialog.exec_()

if __name__ == "__main__":
    # 独立运行时的测试代码
    import sys
    from PyQt5.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    # 如果提供了命令行参数，则使用它作为配置文件路径
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config/settings.ini"
    
    dialog = ConfigEditorDialog(config_file)
    dialog.exec_()
    
    sys.exit() 