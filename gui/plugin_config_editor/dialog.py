#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件配置编辑器对话框模块
提供插件配置文件的图形化编辑对话框
"""

import os
import sys
import json
import yaml
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTabWidget,
    QWidget, QLabel, QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem,
    QMessageBox, QFileDialog, QInputDialog, QLineEdit, QMenu, QAction,
    QComboBox, QFormLayout, QGroupBox, QCheckBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QToolButton, QApplication, QProgressDialog,
    QScrollArea
)
from PyQt5.QtCore import (
    Qt, QPoint, QSize, QThread, pyqtSignal, QEventLoop, QTimer
)
from PyQt5.QtGui import QFont, QIcon, QColor

from plugins.config_manager import plugin_config_manager
from gui.plugin_config_editor.highlighters import JsonSyntaxHighlighter, YamlSyntaxHighlighter
from gui.plugin_config_editor.model import PluginConfigModel
from gui.plugin_config_editor.tree_builder import ConfigTreeBuilder
from gui.plugin_config_editor.form_builder import ConfigFormBuilder
from gui.plugin_config_editor.threads import (
    LoadConfigListThread, LoadFileThread, ParseConfigThread, SaveConfigThread
)

# 配置日志
logger = logging.getLogger("ss0t-scna.plugin_config_editor")

class PluginConfigEditorDialog(QDialog):
    """插件配置编辑器对话框"""
    
    def __init__(self, parent=None):
        """
        初始化插件配置编辑器对话框
        
        Args:
            parent: 父窗口
        """
        super().__init__(parent)
        
        self.setWindowTitle("插件配置编辑器")
        self.setMinimumSize(900, 700)
        
        # 创建数据模型
        self.model = PluginConfigModel()
        
        # 当前正在编辑的配置文件
        self.current_config_file = None
        
        # 文件内容是否已修改
        self.modified = False
        
        # 保存上次有效的JSON/YAML内容，用于在验证失败时恢复
        self.last_valid_content = ""
        
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
        
        # 树构建器
        self.tree_builder = ConfigTreeBuilder(self.tree_widget)
        
        # 右侧面板 - 文本编辑器
        self.right_panel = QWidget()
        right_layout = QVBoxLayout(self.right_panel)
        
        # 文件路径标签
        self.path_label = QLabel("未选择文件")
        right_layout.addWidget(self.path_label)
        
        # 创建选项卡控件
        self.tab_widget = QTabWidget()
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        right_layout.addWidget(self.tab_widget)
        
        # 文本编辑选项卡
        self.text_edit_tab = QWidget()
        text_edit_layout = QVBoxLayout(self.text_edit_tab)
        
        # 创建文本编辑器
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Courier New", 10))
        self.text_edit.textChanged.connect(self.on_text_changed)
        text_edit_layout.addWidget(self.text_edit)
        
        # 表单编辑选项卡
        self.form_edit_tab = QWidget()
        self.form_layout = QVBoxLayout(self.form_edit_tab)
        
        # 添加滚动区域来放置表单
        self.form_scroll_area = QScrollArea()
        self.form_scroll_area.setWidgetResizable(True)
        self.form_scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.form_scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        # 创建一个内容窗口放置表单
        self.form_content = QWidget()
        self.form_content_layout = QVBoxLayout(self.form_content)
        self.form_content_layout.setAlignment(Qt.AlignTop)
        self.form_scroll_area.setWidget(self.form_content)
        
        # 添加应用修改按钮
        self.apply_form_btn = QPushButton("应用表单修改")
        self.apply_form_btn.setEnabled(False)
        self.apply_form_btn.clicked.connect(self.apply_form_changes)
        
        # 添加到布局
        self.form_layout.addWidget(self.form_scroll_area)
        self.form_layout.addWidget(self.apply_form_btn)
        
        # 创建表单构建器
        self.form_builder = ConfigFormBuilder(self.form_content, self.on_form_field_changed)
        
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
        # 显示正在加载的提示，让界面保持响应
        self.plugin_combo.clear()
        self.plugin_combo.addItem("正在加载插件配置...", None)
        self.plugin_combo.setEnabled(False)
        
        # 使用QTimer延迟执行，让界面先有响应
        QTimer.singleShot(100, self._async_load_plugin_list)
    
    def _async_load_plugin_list(self):
        """异步加载插件配置列表"""
        # 创建和显示进度对话框
        progress_dialog = QProgressDialog("正在加载插件配置...", "取消", 0, 100, self)
        progress_dialog.setWindowTitle("加载中")
        progress_dialog.setWindowModality(Qt.WindowModal)
        progress_dialog.setMinimumDuration(500)  # 500ms后才显示
        progress_dialog.setValue(0)
        
        # 创建加载线程
        load_thread = LoadConfigListThread(plugin_config_manager)
        
        # 连接进度信号
        load_thread.progress_update.connect(progress_dialog.setValue)
        
        # 创建事件循环，用于等待加载完成
        loop = QEventLoop()
        
        # 加载完成处理
        def on_load_complete(configs, error):
            progress_dialog.close()
            
            # 清空下拉框并重新填充
            self.plugin_combo.clear()
            self.plugin_combo.setEnabled(True)
            
            # 添加一个空选项
            self.plugin_combo.addItem("-- 选择插件配置 --", None)
            
            if error:
                QMessageBox.critical(self, "错误", f"加载插件配置列表失败: {error}")
            elif not configs:
                QMessageBox.warning(self, "警告", "未找到任何插件配置文件")
            else:
                # 添加所有配置
                for config in configs:
                    self.plugin_combo.addItem(config['name'], config['file'])
            
            # 添加新建选项
            self.plugin_combo.addItem("+ 创建新插件配置...", "new")
            
            # 退出事件循环
            loop.quit()
        
        load_thread.load_complete.connect(on_load_complete)
        
        # 取消处理
        progress_dialog.canceled.connect(loop.quit)
        
        # 启动线程
        load_thread.start()
        
        # 等待加载完成或用户取消
        loop.exec_()
    
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
        success, result = self.model.create_default_config(plugin_id)
        
        if success:
            # 刷新插件列表
            self.load_plugin_config_list()
            
            # 加载新创建的配置文件
            self.load_config_file(result)
            
            QMessageBox.information(self, "成功", f"已创建新插件配置: {plugin_id}.json")
        else:
            QMessageBox.critical(self, "错误", f"创建插件配置失败: {result}")

    def load_config_file(self, config_file: str):
        """
        加载配置文件
        
        Args:
            config_file: 配置文件路径
        """
        # 先显示正在加载的提示
        self.path_label.setText(f"正在加载文件: {config_file}...")
        self.text_edit.setReadOnly(True)
        self.text_edit.blockSignals(True)
        self.text_edit.setPlainText("正在加载文件内容，请稍候...")
        self.text_edit.blockSignals(False)
        
        # 使用QTimer延迟执行，让界面先有响应
        QTimer.singleShot(100, lambda: self._async_load_file(config_file))
    
    def _async_load_file(self, config_file):
        """异步加载文件
        
        Args:
            config_file: 配置文件路径
        """
        # 创建进度对话框
        progress_dialog = QProgressDialog("正在加载文件...", "取消", 0, 100, self)
        progress_dialog.setWindowTitle("加载中")
        progress_dialog.setWindowModality(Qt.WindowModal)
        progress_dialog.setMinimumDuration(500)  # 500ms后才显示
        progress_dialog.setValue(0)
        
        # 创建加载线程
        load_thread = LoadFileThread(config_file)
        
        # 连接进度信号
        load_thread.progress_update.connect(progress_dialog.setValue)
        
        # 创建事件循环，用于等待加载完成
        loop = QEventLoop()
        
        # 加载完成处理
        def on_load_complete(content, is_error, error_msg):
            progress_dialog.close()
            
            if is_error:
                error_msg = f"读取配置文件失败: {error_msg}"
                logger.error(error_msg)
                QMessageBox.critical(self, "错误", error_msg)
                
                # 重置UI状态
                self.path_label.setText("未选择文件")
                self.text_edit.setReadOnly(False)
                self.text_edit.blockSignals(True)
                self.text_edit.setPlainText("")
                self.text_edit.blockSignals(False)
                self.tree_widget.clear()
                self.current_config_file = None
            else:
                # 保存当前有效的内容
                self.last_valid_content = content
                
                # 更新UI状态
                self.path_label.setText(f"文件: {config_file}")
                self.current_config_file = config_file
                self.save_btn.setEnabled(False)
                self.reload_btn.setEnabled(True)
                self.text_edit.setReadOnly(False)
                
                # 设置文本编辑器内容
                self.text_edit.blockSignals(True)  # 防止触发textChanged信号
                self.text_edit.setPlainText(content)
                self.text_edit.blockSignals(False)
                self.modified = False
                
                # 应用语法高亮
                if config_file.lower().endswith('.json'):
                    self.highlighter = JsonSyntaxHighlighter(self.text_edit.document())
                elif config_file.lower().endswith(('.yaml', '.yml')):
                    self.highlighter = YamlSyntaxHighlighter(self.text_edit.document())
                
                # 大型文件异步解析配置结构
                self.tree_builder.set_loading()
                
                # 延迟解析，让UI先有响应
                QTimer.singleShot(200, lambda: self.delayed_parse_structure(content, config_file))
                
                logger.info(f"已加载插件配置文件: {config_file}")
            
            # 退出事件循环
            loop.quit()
        
        load_thread.load_complete.connect(on_load_complete)
        
        # 取消处理
        progress_dialog.canceled.connect(loop.quit)
        
        # 启动线程
        load_thread.start()
        
        # 等待加载完成或用户取消
        loop.exec_()
    
    def delayed_parse_structure(self, content, config_file):
        """在单独的线程中延迟解析结构，防止UI卡死
        
        Args:
            content: 配置文件内容
            config_file: 配置文件路径
        """
        try:
            # 初始化取消标志和解析完成标志
            self.parse_canceled = False
            self.parsing_completed = False  # 标记解析是否已完成
            logger.info(f"开始解析配置文件: {config_file}")
            
            # 创建进度对话框
            progress_dialog = QProgressDialog("正在解析...", "取消", 0, 100, self)
            progress_dialog.setWindowTitle("解析配置")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)  # 立即显示进度
            progress_dialog.setAttribute(Qt.WA_DeleteOnClose, True)  # 完成时自动删除
            progress_dialog.setAutoClose(True)  # 完成时自动关闭
            progress_dialog.setAutoReset(False)  # 不自动重置
            progress_dialog.setValue(10)
            
            # 创建并启动解析线程
            is_json = config_file.lower().endswith('.json')
            self.parse_thread = ParseConfigThread(content, is_json)
            
            # 连接进度信号
            def update_progress(value, message):
                if progress_dialog and not progress_dialog.wasCanceled():
                    progress_dialog.setValue(value)
                    progress_dialog.setLabelText(f"正在解析... {message}")
                    # 确保UI事件得到处理
                    QApplication.processEvents()
            
            self.parse_thread.progress_update.connect(update_progress)
            
            # 创建事件循环，用于等待解析完成
            loop = QEventLoop()
            
            # 连接完成信号
            def on_parse_complete(result, is_error, error_info):
                logger.info(f"解析完成: is_error={is_error}, error_info='{error_info}', parse_canceled={self.parse_canceled}")
                
                # 标记解析已完成，防止之后的取消操作影响显示
                self.parsing_completed = True
                
                # 如果进度对话框存在，关闭它
                if progress_dialog:
                    if progress_dialog.isVisible():
                        # 在进度对话框中禁用取消按钮
                        cancel_button = progress_dialog.findChild(QPushButton)
                        if cancel_button:
                            cancel_button.setEnabled(False)
                            cancel_button.setText("已完成")
                    
                    progress_dialog.setValue(100)
                    progress_dialog.close()
                
                # 如果解析已被用户取消
                if self.parse_canceled:
                    logger.info("用户取消了解析，显示取消消息")
                    self.tree_widget.clear()
                    message_item = QTreeWidgetItem(self.tree_widget, ["解析已取消 - 可直接手动编辑配置文件"])
                    QTimer.singleShot(100, loop.quit)
                    return
                
                # 如果解析结果是取消的，显示取消消息
                if isinstance(result, dict) and result.get("status") == "canceled":
                    logger.info("解析结果是取消的，显示取消消息")
                    self.tree_widget.clear()
                    message_item = QTreeWidgetItem(self.tree_widget, ["解析已取消 - 可直接手动编辑配置文件"])
                    QTimer.singleShot(100, loop.quit)
                    return
                
                # 如果解析出错
                if is_error:
                    logger.info(f"解析出错: {result}")
                    self.tree_builder.set_error(result)
                    
                    # 如果这是一个大文件，提供提示
                    if len(content) > 1024 * 1024:
                        self.tree_builder.add_warning("提示: 文件过大，可能无法正常解析。可以尝试手动编辑配置文件。")
                else:  # 解析成功
                    logger.info("解析成功，构建树视图")
                    # 判断是否是采样解析结果
                    is_sampled = error_info == "采样解析" or error_info == "简化解析"
                    
                    # 使用树构建器构建树
                    try:
                        node_count, truncated = self.tree_builder.build_tree(result, 1500, is_sampled)
                        logger.info(f"树构建完成: {node_count} 节点, 是否截断: {truncated}")
                        
                        # 如果这是一个采样解析结果，添加警告
                        if is_sampled:
                            self.tree_builder.add_warning("注意: 文件较大，可能意味着解析结果是采样解析，可能不完全")
                        
                        # 更新当前配置数据
                        self.model.current_config_data = result
                        
                        # 如果当前在表单编辑选项卡，创建表单
                        if self.tab_widget.currentIndex() == 1:
                            QTimer.singleShot(100, self.create_form_from_config)
                    except Exception as tree_error:
                        logger.error(f"树构建失败: {str(tree_error)}")
                        self.tree_builder.set_error(f"树构建失败: {str(tree_error)}")
                
                # 解析完成，退出事件循环
                QTimer.singleShot(200, loop.quit)
            
            self.parse_thread.parse_complete.connect(on_parse_complete)
            
            # 取消处理
            def on_canceled():
                logger.info("用户点击了取消按钮")
                
                # 如果解析已完成，不要处理取消操作
                if hasattr(self, 'parsing_completed') and self.parsing_completed:
                    logger.info("解析已完成，不要处理取消操作")
                    return
                
                # 设置取消标志
                self.parse_canceled = True
                
                # 尝试中止解析线程
                if hasattr(self, 'parse_thread') and self.parse_thread.isRunning():
                    logger.info("调用线程的取消方法")
                    
                    # 调用解析线程的取消方法
                    if hasattr(self.parse_thread, 'cancel'):
                        self.parse_thread.cancel()
                    
                    # 不要等待线程结束，让它继续运行
                    # 解析线程会检测到取消状态并发送结果
                    logger.info("线程将在检测到取消标志后自行结束")
                
                # 不要在这里修改树视图或退出事件循环
                # 让on_parse_complete接收到取消消息后处理
            
            progress_dialog.canceled.connect(on_canceled)
            
            # 启动线程
            self.parse_thread.start()
            
            # 等待解析完成或用户取消
            loop.exec_()
            logger.info("解析事件循环完成")
            
        except Exception as e:
            logger.error(f"解析线程失败: {str(e)}")
            self.tree_widget.clear()
            error_item = QTreeWidgetItem(self.tree_widget, [f"解析失败: {str(e)}"])
            error_item.setForeground(0, QColor(255, 0, 0))  # 红色错误提示
    
    def on_text_changed(self):
        """处理文本编辑器内容变更"""
        self.modified = True
        self.save_btn.setEnabled(True)
    
    def on_tree_item_clicked(self, item, column):
        """
        处理树项目点击事件
        
        Args:
            item: 被点击的树项目
            column: 列索引
        """
        # 只有在编辑文本模式下才定位光标
        if not self.current_config_file or self.tab_widget.currentIndex() != 0:
            return
            
        # 使用树构建器进行定位
        self.tree_builder.locate_node(item, self.text_edit)
    
    def show_tree_context_menu(self, position: QPoint):
        """
        显示树控件上下文菜单
        
        Args:
            position: 鼠标位置
        """
        # 获取当前选中的项目
        item = self.tree_widget.itemAt(position)
        if not item:
            return
            
        # 创建上下文菜单
        menu = QMenu()
        
        # 添加复制键名操作
        copy_key_action = QAction("复制键名", self)
        menu.addAction(copy_key_action)
        
        # 添加复制值操作
        copy_value_action = QAction("复制值", self)
        menu.addAction(copy_value_action)
        
        # 添加复制路径操作
        copy_path_action = QAction("复制完整路径", self)
        menu.addAction(copy_path_action)
        
        # 显示菜单
        action = menu.exec_(self.tree_widget.mapToGlobal(position))
        
        if action == copy_key_action:
            # 复制键名
            item_data = item.data(0, Qt.UserRole)
            if item_data:
                data_type, key = item_data
                QApplication.clipboard().setText(key)
        elif action == copy_value_action:
            # 复制值
            text = item.text(0)
            # 如果是键值对，提取值部分
            if ': ' in text:
                value = text.split(': ', 1)[1]
                QApplication.clipboard().setText(value)
        elif action == copy_path_action:
            # 生成并复制完整路径
            path = []
            current = item
            while current:
                text = current.text(0)
                if ': ' in text:
                    key = text.split(': ', 1)[0]
                    path.insert(0, key)
                else:
                    path.insert(0, text)
                current = current.parent()
            
            QApplication.clipboard().setText('.'.join(path))
    
    def on_tab_changed(self, index):
        """处理选项卡切换事件"""
        if index == 1:  # 表单编辑选项卡
            # 如果当前有配置文件，创建表单
            if self.current_config_file and self.model.current_config_data:
                self.create_form_from_config()
        elif index == 0:  # 原始编辑选项卡
            # 如果表单有修改，提示用户是否应用修改
            if self.apply_form_btn.isEnabled():
                reply = QMessageBox.question(
                    self, "应用修改", 
                    "表单中有未应用的修改，是否应用到原始编辑器?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                if reply == QMessageBox.Yes:
                    self.apply_form_changes()
    
    def create_form_from_config(self):
        """根据当前配置创建表单界面"""
        try:
            # 显示正在创建表单的状态
            self.status_bar.showMessage("正在创建表单...", 2000) if hasattr(self, 'status_bar') else None
            
            # 清空当前表单内容前先禁用更新
            self.form_content.setUpdatesEnabled(False)
            
            # 清空当前表单
            while self.form_content_layout.count():
                item = self.form_content_layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
            
            if not self.model.current_config_data:
                self.form_content.setUpdatesEnabled(True)
                return
                
            # 使用定时器延迟创建表单，让界面保持响应
            QTimer.singleShot(50, self._delayed_create_form)
        except Exception as e:
            logger.error(f"创建表单失败: {str(e)}")
            self.form_content.setUpdatesEnabled(True)
            
            # 在界面上显示错误
            error_label = QLabel(f"创建表单失败: {str(e)}")
            error_label.setStyleSheet("color: red;")
            self.form_content_layout.addWidget(error_label)
            
    def _delayed_create_form(self):
        """延迟创建表单，避免UI卡死"""
        try:
            # 创建进度对话框用于长时间操作
            if len(str(self.model.current_config_data)) > 10000:  # 对于大型配置显示进度
                progress_dialog = QProgressDialog("正在构建表单...", "取消", 0, 100, self)
                progress_dialog.setWindowModality(Qt.WindowModal)
                progress_dialog.setMinimumDuration(500)
                progress_dialog.setValue(10)
                
                # 定期更新，确保UI响应
                def update_progress():
                    if progress_dialog and not progress_dialog.wasCanceled():
                        current = progress_dialog.value()
                        if current < 90:
                            progress_dialog.setValue(current + 10)
                            QTimer.singleShot(200, update_progress)
                    
                # 启动进度更新
                update_progress()
            else:
                progress_dialog = None
                
            # 创建表单
            form_widget = self.form_builder.build_form(self.model.current_config_data)
            
            # 添加到表单内容
            self.form_content_layout.addWidget(form_widget)
            
            # 重置修改标志
            self.apply_form_btn.setEnabled(False)
            
            # 恢复更新
            self.form_content.setUpdatesEnabled(True)
            
            # 关闭进度对话框
            if progress_dialog:
                progress_dialog.setValue(100)
                QTimer.singleShot(200, progress_dialog.close)
                
        except Exception as e:
            logger.error(f"构建表单失败: {str(e)}")
            self.form_content.setUpdatesEnabled(True)
            
            # 在界面上显示错误
            error_label = QLabel(f"构建表单失败: {str(e)}")
            error_label.setStyleSheet("color: red;")
            self.form_content_layout.addWidget(error_label)
    
    def on_form_field_changed(self):
        """处理表单字段变更"""
        self.apply_form_btn.setEnabled(True)
    
    def apply_form_changes(self):
        """应用表单更改到文本编辑器"""
        if not self.model.current_config_data:
            return
            
        # 从表单获取配置数据
        config_data = self.form_builder.get_form_data()
        
        try:
            # 更新JSON文本
            json_text = json.dumps(config_data, indent=4, ensure_ascii=False)
            
            # 更新到文本编辑器
            self.text_edit.blockSignals(True)
            self.text_edit.setPlainText(json_text)
            self.text_edit.blockSignals(False)
            
            # 更新当前配置数据
            self.model.current_config_data = config_data
            
            # 标记为已修改
            self.modified = True
            self.save_btn.setEnabled(True)
            
            # 重置应用按钮
            self.apply_form_btn.setEnabled(False)
            
            # 通知用户
            QMessageBox.information(self, "已应用", "表单修改已应用到编辑器")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"应用表单修改失败: {str(e)}")
    
    def reload_current_config(self):
        """重新加载当前配置文件"""
        if self.current_config_file:
            if self.modified:
                reply = QMessageBox.question(
                    self, "确认重新加载", 
                    "当前有未保存的修改，重新加载将丢失这些修改。是否继续?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return
            
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
            
            # 创建进度对话框
            progress_dialog = QProgressDialog("正在保存...", "取消", 0, 100, self)
            progress_dialog.setWindowTitle("保存中")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)  # 立即显示
            progress_dialog.setValue(10)
            
            # 创建保存线程
            save_thread = SaveConfigThread(self.current_config_file, content)
            
            # 连接信号
            save_thread.progress_update.connect(progress_dialog.setValue)
            
            # 创建事件循环，用于等待保存完成
            loop = QEventLoop()
            
            # 保存完成时执行进一步操作
            def on_save_complete(success, error_msg):
                progress_dialog.setValue(100)
                
                if success:
                    # 更新上次有效内容
                    self.last_valid_content = content
                    self.modified = False
                    self.save_btn.setEnabled(False)
                    
                    # 重新加载配置到内存
                    plugin_id = os.path.splitext(os.path.basename(self.current_config_file))[0]
                    if plugin_id in plugin_config_manager.configs:
                        del plugin_config_manager.configs[plugin_id]
                        plugin_config_manager.load_config(plugin_id)
                    
                    # 重新解析配置结构
                    # 确保QTimer已导入
                    QTimer.singleShot(100, lambda: self.delayed_parse_structure(content, self.current_config_file))
                    
                    logger.info(f"已保存插件配置: {self.current_config_file}")
                    QMessageBox.information(self, "成功", f"配置已保存: {os.path.basename(self.current_config_file)}")
                else:
                    logger.error(f"保存配置失败: {error_msg}")
                    QMessageBox.critical(self, "错误", f"保存配置失败: {error_msg}")
                
                # 退出事件循环
                loop.quit()
            
            save_thread.save_complete.connect(on_save_complete)
            
            # 取消操作
            progress_dialog.canceled.connect(loop.quit)
            
            # 启动线程
            save_thread.start()
            
            # 等待保存完成或用户取消
            loop.exec_()
            
        except Exception as e:
            error_msg = f"保存配置失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, "错误", error_msg)
    
    def closeEvent(self, event):
        """
        窗口关闭前检查是否有未保存的修改
        
        Args:
            event: 关闭事件
        """
        if self.modified:
            reply = QMessageBox.question(
                self, "确认", "有未保存的修改，是否保存?",
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                QMessageBox.Save
            )
            
            if reply == QMessageBox.Save:
                # 保存配置
                self.save_config()
                event.accept()
            elif reply == QMessageBox.Discard:
                # 丢弃更改
                event.accept()
            else:
                # 取消关闭
                event.ignore()
        else:
            event.accept()


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