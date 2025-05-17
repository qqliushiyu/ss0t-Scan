#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC扫描界面模块
提供基于POC的漏洞验证框架界面
"""

import os
import time
import logging
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QLineEdit, QTextEdit, QComboBox, QSpinBox, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QTabWidget, QGroupBox, QFormLayout, QMessageBox, QSplitter,
    QProgressBar, QToolButton, QMenu, QAction, QDialog, QDialogButtonBox,
    QGridLayout, QRadioButton, QProgressDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QSize, QSortFilterProxyModel
from PyQt5.QtGui import QIcon, QColor, QStandardItemModel, QStandardItem

from core.poc_scan import POCScanner
from core.base_scanner import ScanResult

class POCManagerDialog(QDialog):
    """POC管理对话框"""
    
    pocSelectionChanged = pyqtSignal(list)  # 发送选中的POC ID列表
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger("gui.dialogs.poc_manager")
        self.setWindowTitle("POC管理")
        self.resize(800, 600)
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint | Qt.WindowMinMaxButtonsHint)
        
        # 保存POC列表
        self.poc_list = []
        self.selected_pocs = []
        
        # 初始化界面
        self.setup_ui()
        
        # 加载POC列表
        self.reload_poc_list()
    
    def setup_ui(self):
        """初始化UI"""
        # 主布局
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)
        
        # 顶部过滤区
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(10)
        
        # 搜索框
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索POC...")
        self.search_input.textChanged.connect(self.filter_pocs)
        filter_layout.addWidget(QLabel("搜索:"))
        filter_layout.addWidget(self.search_input)
        
        # 严重性筛选
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("所有级别", "all")
        self.severity_combo.addItem("严重", "critical")
        self.severity_combo.addItem("高危", "high")
        self.severity_combo.addItem("中危", "medium")
        self.severity_combo.addItem("低危", "low")
        self.severity_combo.currentIndexChanged.connect(self.filter_pocs)
        filter_layout.addWidget(QLabel("严重性:"))
        filter_layout.addWidget(self.severity_combo)
        
        # 类型筛选
        self.type_combo = QComboBox()
        self.type_combo.addItem("所有类型", "all")
        self.type_combo.currentIndexChanged.connect(self.filter_pocs)
        filter_layout.addWidget(QLabel("类型:"))
        filter_layout.addWidget(self.type_combo)
        
        main_layout.addLayout(filter_layout)
        
        # 中间POC列表表格
        # 使用标准模型和代理模型实现过滤
        self.poc_model = QStandardItemModel()
        self.poc_model.setHorizontalHeaderLabels(["名称", "类型", "严重性", "选择"])
        
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.poc_model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        
        self.poc_table = QTableWidget()
        self.poc_table.setColumnCount(4)
        self.poc_table.setHorizontalHeaderLabels(["名称", "类型", "严重性", "选择"])
        self.poc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.poc_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.poc_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.poc_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.poc_table.verticalHeader().setDefaultSectionSize(22)
        
        main_layout.addWidget(self.poc_table)
        
        # 底部按钮区
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        self.select_all_btn = QPushButton("全选")
        self.select_all_btn.clicked.connect(self.select_all_pocs)
        self.select_none_btn = QPushButton("取消全选")
        self.select_none_btn.clicked.connect(self.select_none_pocs)
        self.add_poc_btn = QPushButton("添加POC")
        self.add_poc_btn.clicked.connect(self.add_poc)
        self.reload_btn = QPushButton("刷新列表")
        self.reload_btn.clicked.connect(self.reload_poc_list)
        self.apply_btn = QPushButton("应用选择")
        self.apply_btn.clicked.connect(self.apply_selection)
        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.close)
        
        btn_layout.addWidget(self.select_all_btn)
        btn_layout.addWidget(self.select_none_btn)
        btn_layout.addWidget(self.add_poc_btn)
        btn_layout.addWidget(self.reload_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.apply_btn)
        btn_layout.addWidget(self.cancel_btn)
        
        main_layout.addLayout(btn_layout)
        
        # 状态标签
        self.status_label = QLabel("就绪")
        main_layout.addWidget(self.status_label)
    
    def reload_poc_list(self):
        """重新加载POC列表"""
        try:
            # 获取POC列表
            from core.poc_scan import POCScanner
            scanner = POCScanner()
            self.poc_list = scanner.get_available_pocs()
            
            # 填充表格
            self.populate_poc_table()
            
            # 更新POC类型下拉列表
            self.update_type_filter()
            
            # 更新状态
            self.status_label.setText(f"已加载 {len(self.poc_list)} 个POC")
            
        except Exception as e:
            self.logger.error(f"加载POC列表失败: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            
            # 显示错误信息
            QMessageBox.critical(
                self, "加载失败", 
                f"加载POC列表时出错: {str(e)}\n请检查POC目录和日志。"
            )
            
            # 保持列表为空
            self.poc_list = []
            self.populate_poc_table()
    
    def update_type_filter(self):
        """更新POC类型筛选下拉列表"""
        self.type_combo.clear()
        self.type_combo.addItem("所有类型", "all")
        
        # 收集所有不同的POC类型
        poc_types = set()
        for poc in self.poc_list:
            poc_type = poc.get('type', '未分类')
            poc_types.add(poc_type)
        
        # 添加到下拉列表
        for poc_type in sorted(poc_types):
            self.type_combo.addItem(poc_type, poc_type)
    
    def populate_poc_table(self):
        """填充POC表格"""
        self.poc_table.setRowCount(0)  # 清空表格
        
        for i, poc in enumerate(self.poc_list):
            self.poc_table.insertRow(i)
            
            # 名称
            name_item = QTableWidgetItem(poc.get('name', '未知'))
            name_item.setData(Qt.UserRole, poc.get('id'))
            self.poc_table.setItem(i, 0, name_item)
            
            # 类型
            self.poc_table.setItem(i, 1, QTableWidgetItem(poc.get('type', '未分类')))
            
            # 严重性
            severity = poc.get('severity', 'medium')
            severity_item = QTableWidgetItem(self.format_severity(severity))
            severity_item.setTextAlignment(Qt.AlignCenter)
            # 设置颜色
            if severity == 'critical':
                severity_item.setBackground(QColor(255, 0, 0, 50))
            elif severity == 'high':
                severity_item.setBackground(QColor(255, 165, 0, 50))
            elif severity == 'medium':
                severity_item.setBackground(QColor(255, 255, 0, 50))
            elif severity == 'low':
                severity_item.setBackground(QColor(0, 128, 0, 50))
            
            self.poc_table.setItem(i, 2, severity_item)
            
            # 选择
            checkbox = QCheckBox()
            # 如果POC ID在已选择列表中，标记为选中
            if poc.get('id') in self.selected_pocs:
                checkbox.setChecked(True)
            self.poc_table.setCellWidget(i, 3, self.create_checkbox_widget(checkbox))
            
    def format_severity(self, severity):
        """格式化严重性"""
        if severity == 'critical':
            return '严重'
        elif severity == 'high':
            return '高危'
        elif severity == 'medium':
            return '中危'
        elif severity == 'low':
            return '低危'
        elif severity == 'info':
            return '信息'
        else:
            return '未知'
    
    def filter_pocs(self):
        """根据筛选条件过滤POC列表"""
        search_text = self.search_input.text().lower()
        severity = self.severity_combo.currentData()
        poc_type = self.type_combo.currentData()
        
        # 隐藏所有行
        for row in range(self.poc_table.rowCount()):
            self.poc_table.setRowHidden(row, True)
        
        # 根据筛选条件显示行
        for row in range(self.poc_table.rowCount()):
            name_item = self.poc_table.item(row, 0)
            if not name_item:
                continue
                
            name = name_item.text().lower()
            
            type_item = self.poc_table.item(row, 1)
            if not type_item:
                continue
                
            type_text = type_item.text()
            
            severity_item = self.poc_table.item(row, 2)
            if not severity_item:
                continue
                
            severity_text = severity_item.text()
            poc_severity = self.get_severity_value(severity_text)
            
            # 搜索文本匹配
            if search_text and search_text not in name:
                continue
            
            # 严重性匹配
            if severity != "all" and poc_severity != severity:
                continue
            
            # 类型匹配
            if poc_type != "all" and type_text != poc_type:
                continue
            
            # 显示匹配的行
            self.poc_table.setRowHidden(row, False)
    
    def get_severity_value(self, severity_text):
        """将中文严重性转换为英文值 - 不再使用，保留作为辅助方法"""
        if severity_text == "严重":
            return "critical"
        elif severity_text == "高危":
            return "high"
        elif severity_text == "中危":
            return "medium"
        elif severity_text == "低危":
            return "low"
        elif severity_text == "信息":
            return "info"
        else:
            return "medium"  # 默认
    
    def create_checkbox_widget(self, checkbox):
        """创建一个居中的复选框小部件"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.addWidget(checkbox)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(0, 0, 0, 0)
        widget.setLayout(layout)
        return widget
    
    def select_all_pocs(self):
        """全选所有POC - 不再使用，已移至POC管理器"""
        pass
    
    def select_none_pocs(self):
        """取消全选POC - 不再使用，已移至POC管理器"""
        pass
    
    def get_selected_pocs(self):
        """获取选中的POC ID列表 - 不再从表格获取，而是使用saved属性"""
        return self.selected_pocs
    
    def set_selected_pocs(self, poc_ids):
        """设置已选中的POC"""
        self.selected_pocs = poc_ids
        self.populate_poc_table()
    
    def apply_selection(self):
        """应用当前选择并关闭窗口"""
        selected_pocs = self.get_selected_pocs()
        self.pocSelectionChanged.emit(selected_pocs)
        self.accept()  # 使用accept代替close，表示用户接受结果
    
    def add_poc(self):
        """添加新POC"""
        dialog = QDialog(self)
        dialog.setWindowTitle("添加POC")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(500)
        
        layout = QVBoxLayout(dialog)
        
        # POC名称
        name_layout = QHBoxLayout()
        name_label = QLabel("POC名称:")
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("输入POC名称，例如: CVE-2023-12345")
        name_layout.addWidget(name_label)
        name_layout.addWidget(name_edit)
        layout.addLayout(name_layout)
        
        # POC格式选择
        format_layout = QHBoxLayout()
        format_label = QLabel("POC格式:")
        format_combo = QComboBox()
        format_combo.addItem("Python", "python")
        format_combo.addItem("JSON", "json")
        format_layout.addWidget(format_label)
        format_layout.addWidget(format_combo)
        format_layout.addStretch()
        layout.addLayout(format_layout)
        
        # POC内容
        content_label = QLabel("POC内容:")
        layout.addWidget(content_label)
        
        content_edit = QTextEdit()
        content_edit.setMinimumHeight(300)
        
        # 添加模板内容
        def update_template():
            if format_combo.currentData() == "python":
                template = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# POC描述信息
# 此处编写对此POC的详细描述

import requests
from typing import Tuple, Dict, Any, Optional

# POC信息
name = "漏洞名称"
description = "漏洞详细描述"
author = "作者"
type = "漏洞类型"
severity = "high"  # 严重程度: critical, high, medium, low, info

def verify(target: str, session=None, **kwargs) -> Tuple[bool, str]:
    """
    验证目标是否存在漏洞
    
    Args:
        target: 目标URL
        session: 请求会话对象
        **kwargs: 其他参数
        
    Returns:
        (是否存在漏洞, 详细信息)
    """
    # 使用提供的会话或创建新会话
    if session is None:
        session = requests.Session()
    
    # 设置请求超时
    timeout = kwargs.get('timeout', 10)
    verify_ssl = kwargs.get('verify', False)
    
    try:
        # 发送请求
        response = session.get(
            target,
            timeout=timeout,
            verify=verify_ssl
        )
        
        # 检查漏洞条件
        if "vulnerable_string" in response.text:
            return True, "发现漏洞，详细信息..."
        
        return False, "未发现漏洞"
        
    except Exception as e:
        return False, f"验证过程中发生错误: {str(e)}"
'''
                content_edit.setText(template)
            else:
                template = '''{
    "name": "漏洞名称",
    "id": "CVE-XXXX-XXXXX",
    "description": "漏洞详细描述",
    "author": "作者",
    "type": "漏洞类型",
    "severity": "high",
    "references": [
        "https://example.com/reference1",
        "https://example.com/reference2"
    ],
    "request": {
        "method": "GET",
        "path": "/vulnerable_path",
        "headers": {
            "User-Agent": "Mozilla/5.0"
        }
    },
    "matchers": [
        {
            "type": "word",
            "part": "body",
            "words": [
                "vulnerable_string1",
                "vulnerable_string2"
            ],
            "condition": "or"
        },
        {
            "type": "status",
            "status": [200, 302]
        }
    ]
}'''
                content_edit.setText(template)
        
        format_combo.currentIndexChanged.connect(update_template)
        update_template()
        
        layout.addWidget(content_edit)
        
        # 按钮
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(lambda: self.save_new_poc(name_edit.text(), content_edit.toPlainText(), format_combo.currentData(), dialog))
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.exec_()
    
    def save_new_poc(self, name, content, poc_format, dialog):
        """保存新的POC"""
        if not name or not content:
            QMessageBox.warning(dialog, "输入错误", "请输入POC名称和内容")
            return
        
        # 确保文件名正确
        if not name.lower().endswith(f'.{poc_format}'):
            name = f"{name}.{poc_format}"
        
        try:
            # 获取POC扫描器实例
            from plugins.plugin_manager import plugin_manager
            plugin = plugin_manager.get_plugin('pocscanner')
            
            if not plugin:
                QMessageBox.warning(dialog, "错误", "无法获取POC扫描插件实例")
                return
            
            # 添加POC
            if hasattr(plugin, 'add_poc'):
                success = plugin.add_poc(content, name, poc_format)
                if success:
                    QMessageBox.information(dialog, "添加成功", f"POC '{name}' 已成功添加")
                    # 刷新POC列表
                    self.reload_poc_list()
                    dialog.accept()
                else:
                    QMessageBox.warning(dialog, "添加失败", "无法添加POC，请检查内容格式")
            else:
                QMessageBox.warning(dialog, "功能不可用", "当前插件不支持添加POC功能")
        except Exception as e:
            QMessageBox.critical(dialog, "错误", f"添加POC时出错: {str(e)}")
            import traceback
            self.logger.error(f"添加POC时出错: {str(e)}")
            self.logger.debug(traceback.format_exc())

class POCScanPanel(QWidget):
    """POC扫描面板"""
    
    # 添加自定义信号用于线程安全的UI更新
    update_progress_signal = pyqtSignal(int, str)
    add_result_signal = pyqtSignal(dict)
    scan_finished_signal = pyqtSignal(object)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger("gui.panels.poc_scan")
        
        # 上次扫描结果
        self.last_scan_result = None
        
        # 加载POC列表
        self.poc_list = []
        self.selected_pocs = []
        
        # 初始化UI
        self.setup_ui()
        
        # 加载POC列表
        self.reload_poc_list()
        
        # 创建POC管理对话框
        self.poc_manager = None
        
        # 连接信号和槽
        self.setup_connections()
    
    def setup_ui(self):
        """初始化UI组件"""
        # 创建主布局
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(1, 1, 1, 1)  # 进一步减小边距
        main_layout.setSpacing(1)  # 进一步减小间距
        
        # 创建顶部控制区域和结果区域的分割器
        splitter = QSplitter(Qt.Vertical)
        
        # === 顶部控制区域 ===
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(2)  # 减小间距
        
        # 创建左右布局，左侧为基本参数，右侧为POC选择
        params_layout = QHBoxLayout()
        params_layout.setSpacing(2)  # 减小间距
        
        # --- 左侧：基本参数和扫描设置 ---
        basic_params_group = QGroupBox("基本参数")
        basic_form_layout = QFormLayout(basic_params_group)
        basic_form_layout.setContentsMargins(3, 5, 3, 3)  # 减小内边距
        basic_form_layout.setVerticalSpacing(2)  # 减小垂直间距
        basic_form_layout.setHorizontalSpacing(3)  # 减小水平间距
        basic_form_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)  # 允许字段扩展
        
        # 目标输入和文件加载按钮在同一行
        target_layout = QHBoxLayout()
        target_layout.setSpacing(2)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("输入目标URL，多个目标用逗号分隔")
        self.target_input.setMinimumHeight(22)  # 设置最小高度
        target_layout.addWidget(self.target_input)
        
        self.load_file_btn = QPushButton("文件")
        self.load_file_btn.setFixedWidth(35)  # 减小按钮宽度
        self.load_file_btn.setFixedHeight(22)  # 设置固定高度
        self.load_file_btn.setToolTip("从文件加载目标")
        target_layout.addWidget(self.load_file_btn)
        
        basic_form_layout.addRow("目标:", target_layout)
        
        # 线程与超时设置
        thread_timeout_widget = QWidget()
        thread_timeout_layout = QHBoxLayout(thread_timeout_widget)
        thread_timeout_layout.setContentsMargins(0, 0, 0, 0)
        
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("线程数:"))
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 50)
        self.threads_input.setValue(10)
        self.threads_input.setFixedWidth(45)  # 减小宽度
        self.threads_input.setFixedHeight(22)  # 设置固定高度
        thread_layout.addWidget(self.threads_input)
        thread_timeout_layout.addLayout(thread_layout)
        
        thread_timeout_layout.addSpacing(10)  # 添加间距分隔
        
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("超时:"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 60)
        self.timeout_input.setValue(10)
        self.timeout_input.setSuffix(" 秒")
        self.timeout_input.setFixedWidth(55)  # 减小宽度
        self.timeout_input.setFixedHeight(22)  # 设置固定高度
        timeout_layout.addWidget(self.timeout_input)
        thread_timeout_layout.addLayout(timeout_layout)
        
        basic_form_layout.addRow("", thread_timeout_widget)
        
        # 扫描深度与SSL验证选项
        scan_options_widget = QWidget()
        scan_options_layout = QHBoxLayout(scan_options_widget)
        scan_options_layout.setContentsMargins(0, 0, 0, 0)
        
        # 扫描深度
        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("扫描深度:"))
        self.scan_depth_combo = QComboBox()
        self.scan_depth_combo.addItem("基本", 0)
        self.scan_depth_combo.addItem("标准", 1)
        self.scan_depth_combo.addItem("深度", 2)
        self.scan_depth_combo.setCurrentIndex(1)  # 默认标准扫描
        self.scan_depth_combo.setFixedWidth(50)  # 减小宽度
        self.scan_depth_combo.setFixedHeight(22)  # 设置固定高度
        depth_layout.addWidget(self.scan_depth_combo)
        scan_options_layout.addLayout(depth_layout)
        
        scan_options_layout.addSpacing(10)  # 添加间距
        
        # SSL验证
        self.verify_ssl_check = QCheckBox("验证SSL证书")
        self.verify_ssl_check.setChecked(False)
        scan_options_layout.addWidget(self.verify_ssl_check)
        
        scan_options_layout.addStretch()
        basic_form_layout.addRow("", scan_options_widget)
        
        # --- 右侧：POC 选择区域 ---
        poc_group = QGroupBox("POC选择")
        poc_layout = QVBoxLayout(poc_group)
        poc_layout.setContentsMargins(3, 5, 3, 3)  # 减小内边距
        poc_layout.setSpacing(2)  # 减小间距
        
        # POC选择摘要
        self.poc_summary_label = QLabel("请选择POC")
        poc_layout.addWidget(self.poc_summary_label)
        
        # POC管理按钮
        poc_btn_layout = QHBoxLayout()
        poc_btn_layout.setSpacing(2)  # 减小按钮间距
        
        self.manage_poc_btn = QPushButton("管理POC")
        self.manage_poc_btn.setFixedHeight(22)  # 设置固定高度
        self.manage_poc_btn.clicked.connect(self.show_poc_manager)
        
        self.reload_poc_btn = QPushButton("刷新")
        self.reload_poc_btn.setFixedWidth(40)
        self.reload_poc_btn.setFixedHeight(22)  # 设置固定高度
        
        poc_btn_layout.addWidget(self.manage_poc_btn)
        poc_btn_layout.addWidget(self.reload_poc_btn)
        poc_btn_layout.addStretch()
        
        poc_layout.addLayout(poc_btn_layout)
        
        # 将左右区域添加到参数布局，并调整比例
        params_layout.addWidget(basic_params_group, 2)  # 基本参数组占比更大
        params_layout.addWidget(poc_group, 1)  # POC组占比更小
        
        # 添加参数布局到顶部布局
        top_layout.addLayout(params_layout)
        
        # 操作按钮行
        control_layout = QHBoxLayout()
        control_layout.setSpacing(3)
        
        self.start_btn = QPushButton("开始扫描")
        self.start_btn.setFixedHeight(25)  # 按钮稍微高一点以便操作
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setFixedHeight(25)
        control_layout.addWidget(self.stop_btn)
        
        self.export_btn = QPushButton("导出报告")
        self.export_btn.setEnabled(False)
        self.export_btn.setFixedHeight(25)
        control_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("清空")
        self.clear_btn.setFixedHeight(25)
        control_layout.addWidget(self.clear_btn)
        
        control_layout.addStretch()
        
        top_layout.addLayout(control_layout)
        
        # 进度条和状态标签
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        top_layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("就绪")
        top_layout.addWidget(self.progress_label)
        
        # === 结果区域 ===
        result_widget = QWidget()
        result_layout = QVBoxLayout(result_widget)
        result_layout.setContentsMargins(0, 0, 0, 0)
        result_layout.setSpacing(1)  # 进一步减小间距
        
        # 结果标签页
        self.result_tabs = QTabWidget()
        self.result_tabs.setDocumentMode(True)  # 使用更紧凑的文档模式
        
        # 漏洞表格
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["目标", "漏洞", "严重性", "状态", "详情"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.vuln_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.vuln_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.vuln_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.vuln_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        # 设置紧凑的行高
        self.vuln_table.verticalHeader().setDefaultSectionSize(20)  # 减小默认行高
        self.vuln_table.verticalHeader().setVisible(False)  # 隐藏行号，节省空间
        
        # 详情文本框
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        
        # 添加选项卡
        self.result_tabs.addTab(self.vuln_table, "漏洞列表")
        self.result_tabs.addTab(self.detail_text, "详细信息")
        
        result_layout.addWidget(self.result_tabs)
        
        # 添加控制区域和结果区域到分割器
        splitter.addWidget(top_widget)
        splitter.addWidget(result_widget)
        
        # 设置分割器的初始大小比例
        splitter.setSizes([200, 500])  # 控制区域更紧凑
        
        # 添加分割器到主布局
        main_layout.addWidget(splitter)
        
        # 初始化POC摘要信息
        self.update_poc_summary()
    
    def setup_connections(self):
        """连接信号和槽"""
        # 按钮事件
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_btn.clicked.connect(self.export_results)
        self.clear_btn.clicked.connect(self.clear_results)
        
        # POC管理
        self.reload_poc_btn.clicked.connect(self.reload_poc_list)
        
        # 目标文件加载
        self.load_file_btn.clicked.connect(self.load_targets_from_file)
        
        # 漏洞表格选择
        self.vuln_table.itemSelectionChanged.connect(self.update_detail_view)
        
        # 连接自定义信号到对应的槽函数，用于线程安全的UI更新
        self.update_progress_signal.connect(self._update_progress_ui)
        self.add_result_signal.connect(self._add_result_to_table)
        self.scan_finished_signal.connect(self._update_ui_after_scan)
    
    def reload_poc_list(self):
        """重新加载POC列表"""
        try:
            # 获取POC列表
            from core.poc_scan import POCScanner
            scanner = POCScanner()
            self.poc_list = scanner.get_available_pocs()
            
            # 更新摘要信息
            self.update_poc_summary()
            
            # 更新状态
            self.logger.info(f"已加载 {len(self.poc_list)} 个POC")
            
        except Exception as e:
            self.logger.error(f"加载POC列表失败: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            
            # 显示错误信息
            QMessageBox.critical(
                self, "加载失败", 
                f"加载POC列表时出错: {str(e)}\n请检查POC目录和日志。"
            )
            
            # 保持列表为空
            self.poc_list = []
            self.update_poc_summary()
    
    def update_poc_summary(self):
        """更新POC选择摘要信息"""
        if not self.poc_list:
            self.poc_summary_label.setText("未找到可用POC")
            return
        
        # 计算不同级别的POC数量
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for poc in self.poc_list:
            severity = poc.get("severity", "medium")
            if severity in severity_count:
                severity_count[severity] += 1
        
        # 计算选中的POC数量
        if not self.selected_pocs:  # 初始默认全选
            self.selected_pocs = [poc.get("id") for poc in self.poc_list]
        
        selected_count = len(self.selected_pocs)
        total_count = len(self.poc_list)
        
        # 更新摘要文本
        summary_text = f"已选择 {selected_count}/{total_count} 个POC"
        summary_text += f" (严重: {severity_count['critical']}, 高危: {severity_count['high']}, "
        summary_text += f"中危: {severity_count['medium']}, 低危: {severity_count['low']})"
        
        self.poc_summary_label.setText(summary_text)
    
    def show_poc_manager(self):
        """显示POC管理对话框"""
        if not self.poc_manager:
            self.poc_manager = POCManagerDialog(self)
            self.poc_manager.pocSelectionChanged.connect(self.on_poc_selection_changed)
        
        # 设置当前选中的POC
        self.poc_manager.set_selected_pocs(self.selected_pocs)
        
        # 显示对话框并等待结果
        self.poc_manager.exec_()
    
    def on_poc_selection_changed(self, selected_pocs):
        """POC选择变更事件"""
        self.selected_pocs = selected_pocs
        self.update_poc_summary()
    
    def get_scan_config(self):
        """获取扫描配置"""
        return {
            'targets': self.target_input.text().strip(),
            'threads': self.threads_input.value(),
            'timeout': self.timeout_input.value(),
            'verify_ssl': self.verify_ssl_check.isChecked(),
            'scan_depth': self.scan_depth_combo.currentData(),
            'selected_pocs': self.selected_pocs
        }
    
    def load_targets_from_file(self):
        """从文件加载目标"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                targets = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
            
            if targets:
                self.target_input.setText(','.join(targets))
                QMessageBox.information(
                    self, "加载成功", f"成功从文件加载了 {len(targets)} 个目标"
                )
            else:
                QMessageBox.warning(
                    self, "加载失败", "文件中没有有效的目标"
                )
                
        except Exception as e:
            QMessageBox.critical(
                self, "加载错误", f"加载目标文件时出错: {str(e)}"
            )
    
    def start_scan(self):
        """开始扫描"""
        # 获取扫描配置
        config = self.get_scan_config()
        
        if not config['targets']:
            QMessageBox.warning(self, "参数错误", "请输入扫描目标")
            return
        
        if not config['selected_pocs']:
            QMessageBox.warning(self, "参数错误", "请至少选择一个POC")
            return
        
        # 清空结果
        self.clear_results()
        
        # 更新UI状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        
        # 记录开始时间
        self.progress_label.setText("正在准备扫描...")
        self.progress_bar.setValue(5)
        
        try:
            # 创建扫描器
            from core.poc_scan import POCScanner
            
            # 确保目标格式正确
            targets = config['targets']
            if isinstance(targets, str):
                # 分割并清理目标URL
                targets = [t.strip() for t in targets.split(',') if t.strip()]
            
            # 更新配置
            scan_config = {
                'targets': targets,
                'threads': config['threads'],
                'timeout': config['timeout'],
                'verify_ssl': config['verify_ssl'],
                'scan_depth': config['scan_depth'],
                'selected_pocs': config['selected_pocs']
            }
            
            # 创建扫描器
            self.scanner = POCScanner(scan_config)
            self.scanner.set_progress_callback(self.update_progress)
            
            # 创建扫描线程
            self.scan_thread = ScanThread(self.scanner)
            self.scan_thread.scan_finished.connect(self.on_scan_finished)
            self.scan_thread.scan_result.connect(self.on_result_received)
            
            # 开始扫描
            self.scan_thread.start()
            
        except Exception as e:
            # 处理初始化错误
            import traceback
            error_detail = traceback.format_exc()
            
            self.progress_label.setText("扫描初始化失败")
            self.progress_bar.setValue(0)
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            QMessageBox.critical(
                self, "扫描错误", 
                f"初始化POC扫描器时出错: {str(e)}\n\n请检查配置和日志文件。"
            )
            self.logger.error(f"初始化POC扫描器失败: {str(e)}\n{error_detail}")
    
    def stop_scan(self):
        """停止扫描"""
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.scanner.stop()
            self.scan_thread.wait()
            self.update_progress(100, "扫描已停止")
            
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            # 如果有结果，启用导出按钮
            if self.vuln_table.rowCount() > 0:
                self.export_btn.setEnabled(True)
    
    def on_scan_finished(self, result):
        """扫描完成回调"""
        # 保存结果引用
        self.last_scan_result = result
        
        # 通过信号发送扫描完成通知，确保在主线程中安全更新UI
        self.scan_finished_signal.emit(result)
    
    def _update_ui_after_scan(self, result):
        """在主线程中安全地更新扫描完成后的UI
        
        Args:
            result: 扫描结果对象
        """
        try:
            # 更新UI状态
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            # 如果有结果，启用导出按钮
            if self.vuln_table.rowCount() > 0:
                self.export_btn.setEnabled(True)
            
            # 更新进度条和标签
            if result.success:
                self.progress_bar.setValue(100)
                self.progress_label.setText("扫描完成")
            else:
                self.progress_bar.setValue(0)
                self.progress_label.setText("扫描失败")
            
            # 显示扫描统计
            vuln_count = len([r for r in result.data if r.get("status") == "vulnerable"])
            total_count = len(result.data)
            
            if result.success:
                # 成功情况
                message = f"POC扫描完成，共检查了 {total_count} 个结果，发现 {vuln_count} 个漏洞。\n"
                message += f"用时: {result.duration:.2f} 秒"
                
                # 显示摘要信息
                summary = next((r for r in result.data if r.get("check_type") == "poc_scan_summary"), None)
                if summary:
                    vuln_targets = summary.get("vulnerable_targets", 0)
                    total_targets = summary.get("total_targets", 0)
                    message += f"\n发现 {vuln_targets}/{total_targets} 个目标存在漏洞"
                
                QMessageBox.information(self, "扫描完成", message)
            else:
                # 失败情况
                error_msg = result.error_msg if result.error_msg else "未知错误"
                QMessageBox.warning(
                    self, "扫描异常", 
                    f"POC扫描过程中发生错误: {error_msg}"
                )
        except Exception as e:
            self.logger.error(f"更新扫描完成UI时出错: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
    
    def update_progress(self, percent, message):
        """更新进度
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        # 使用信号发送进度更新，确保在主线程中安全更新UI
        self.update_progress_signal.emit(percent, message)
    
    def _update_progress_ui(self, percent, message):
        """在主线程中安全地更新进度UI
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        try:
            self.progress_bar.setValue(percent)
            self.progress_label.setText(message)
        except Exception as e:
            self.logger.error(f"更新进度UI时出错: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
    
    def on_result_received(self, result):
        """接收扫描结果"""
        try:
            # 跳过摘要信息
            if result.get("check_type") == "poc_scan_summary":
                return
            
            # 只处理漏洞检查结果
            if result.get("check_type") != "vulnerability":
                return
            
            # 通过信号发送结果，确保在主线程中安全更新UI
            self.add_result_signal.emit(result)
            
        except Exception as e:
            # 处理结果解析错误
            self.logger.error(f"处理扫描结果时出错: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
    
    def _add_result_to_table(self, result):
        """在主线程中安全地添加结果到表格
        
        Args:
            result: 扫描结果字典
        """
        try:
            # 添加新行
            row = self.vuln_table.rowCount()
            self.vuln_table.insertRow(row)
            
            # 目标
            url = result.get("url", "")
            self.vuln_table.setItem(row, 0, QTableWidgetItem(url))
            
            # 漏洞名称
            vuln_name = result.get("vulnerability", "未知漏洞")
            self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln_name))
            
            # 严重性
            severity = result.get("severity", "medium")
            severity_item = QTableWidgetItem(self.format_severity(severity))
            severity_item.setTextAlignment(Qt.AlignCenter)
            # 设置颜色
            if severity == 'critical':
                severity_item.setBackground(QColor(255, 0, 0, 50))
            elif severity == 'high':
                severity_item.setBackground(QColor(255, 165, 0, 50))
            elif severity == 'medium':
                severity_item.setBackground(QColor(255, 255, 0, 50))
            elif severity == 'low':
                severity_item.setBackground(QColor(0, 128, 0, 50))
            
            self.vuln_table.setItem(row, 2, severity_item)
            
            # 状态
            status = result.get("status", "")
            status_item = QTableWidgetItem(self.format_status(status))
            status_item.setTextAlignment(Qt.AlignCenter)
            # 设置颜色
            if status == "vulnerable":
                status_item.setBackground(QColor(255, 0, 0, 50))
            elif status == "safe":
                status_item.setBackground(QColor(0, 255, 0, 50))
            elif status == "info":
                status_item.setBackground(QColor(0, 0, 255, 50))
            elif status == "error":
                status_item.setBackground(QColor(255, 165, 0, 50))
            
            self.vuln_table.setItem(row, 3, status_item)
            
            # 详情
            details = result.get("details", "")
            if details:
                self.vuln_table.setItem(row, 4, QTableWidgetItem(details))
            
            # 存储完整结果
            self.vuln_table.item(row, 0).setData(Qt.UserRole, result)
            
            # 自动调整行高
            self.vuln_table.resizeRowToContents(row)
            
        except Exception as e:
            # 处理结果解析错误
            self.logger.error(f"添加结果到表格时出错: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
    
    def format_status(self, status):
        """格式化状态"""
        if status == "vulnerable":
            return "存在漏洞"
        elif status == "safe":
            return "安全"
        elif status == "info":
            return "信息"
        elif status == "error":
            return "错误"
        elif status == "skipped":
            return "已跳过"
        else:
            return status
    
    def format_severity(self, severity):
        """格式化严重性"""
        if severity == 'critical':
            return '严重'
        elif severity == 'high':
            return '高危'
        elif severity == 'medium':
            return '中危'
        elif severity == 'low':
            return '低危'
        elif severity == 'info':
            return '信息'
        else:
            return '未知'
    
    def update_detail_view(self):
        """更新详情视图"""
        selected_items = self.vuln_table.selectedItems()
        if not selected_items:
            return
        
        # 获取选中行
        row = selected_items[0].row()
        
        # 获取完整结果
        result = self.vuln_table.item(row, 0).data(Qt.UserRole)
        if not result:
            return
        
        # 格式化详情
        details = f"## 漏洞信息\n\n"
        details += f"**目标:** {result.get('url', '')}\n\n"
        details += f"**漏洞:** {result.get('vulnerability', '')}\n\n"
        details += f"**严重性:** {self.format_severity(result.get('severity', ''))}\n\n"
        details += f"**状态:** {self.format_status(result.get('status', ''))}\n\n"
        
        if "poc_id" in result:
            details += f"**POC ID:** {result.get('poc_id', '')}\n\n"
        
        details += f"**详情:**\n{result.get('details', '')}\n\n"
        
        if "recommendation" in result:
            details += f"**建议:**\n{result.get('recommendation', '')}\n\n"
        
        # 设置详情文本
        self.detail_text.setPlainText(details)
        
        # 切换到详情选项卡
        self.result_tabs.setCurrentIndex(1)
    
    def clear_results(self):
        """清空结果"""
        self.vuln_table.setRowCount(0)
        self.detail_text.clear()
        self.progress_bar.setValue(0)
        self.progress_label.setText("就绪")
        self.export_btn.setEnabled(False)
        self.last_scan_result = None
    
    def export_results(self):
        """导出结果"""
        if not self.last_scan_result or self.vuln_table.rowCount() == 0:
            QMessageBox.warning(self, "导出错误", "没有可导出的扫描结果")
            return
        
        # 创建格式选择对话框
        format_dialog = QDialog(self)
        format_dialog.setWindowTitle("选择报告格式")
        format_dialog.setMinimumWidth(300)
        
        layout = QVBoxLayout(format_dialog)
        
        # 添加说明标签
        label = QLabel("请选择要生成的报告格式:")
        layout.addWidget(label)
        
        # 添加格式选择单选按钮
        html_radio = QRadioButton("HTML格式")
        html_radio.setChecked(True)  # 默认选中HTML
        layout.addWidget(html_radio)
        
        pdf_radio = QRadioButton("PDF格式")
        layout.addWidget(pdf_radio)
        
        html_desc = QLabel("HTML格式: 浏览器友好，包含完整样式和交互功能")
        html_desc.setStyleSheet("color: gray; font-size: 15px;")
        layout.addWidget(html_desc)
        
        pdf_desc = QLabel("PDF格式: 适合打印和分享，需要额外依赖")
        pdf_desc.setStyleSheet("color: gray; font-size: 15px;")
        layout.addWidget(pdf_desc)
        
        # 添加按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(format_dialog.accept)
        button_box.rejected.connect(format_dialog.reject)
        layout.addWidget(button_box)
        
        # 显示对话框
        if format_dialog.exec_() == QDialog.Accepted:
            # 根据用户选择的格式生成报告
            format_type = "pdf" if pdf_radio.isChecked() else "html"
            self.generate_scan_report(self.last_scan_result, "poc_vulnerability_scan", format_type)
        
    def generate_scan_report(self, result, report_name, format_type="html"):
        """生成扫描报告
        
        Args:
            result: ScanResult对象
            report_name: 报告名称
            format_type: 报告格式，"html"或"pdf"
        """
        try:
            from utils.report_generator import generate_report
            import os
            
            # 显示进度对话框
            progress_dialog = QProgressDialog("正在生成报告...", "取消", 0, 100, self)
            progress_dialog.setWindowTitle("生成报告")
            progress_dialog.setMinimumDuration(500)  # 显示对话框前的最小延迟
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setValue(10)
            
            # 确保报告目录存在
            reports_dir = os.path.join(os.getcwd(), "reports")
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
            
            # 更新进度
            progress_dialog.setValue(20)
            
            # 准备元数据
            metadata = {}
            
            # 生成标识
            scan_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            
            # 获取目标URL
            targets = self.target_input.text().strip().split(',')
            
            # 提取所有URL作为alive_urls
            alive_urls = []
            for result_item in result.data:
                if isinstance(result_item, dict) and "url" in result_item:
                    url = result_item.get("url")
                    if url and url not in alive_urls:
                        alive_urls.append(url)
            
            # 统一元数据格式
            metadata = {
                "module": "POC漏洞扫描",
                "scan_time": scan_time,
                "target_urls": targets,  # 使用统一的字段名
                "alive_urls": alive_urls,
                "scan_config": {  # 使用统一的字段名
                    "threads": self.threads_input.value(),
                    "timeout": self.timeout_input.value(),
                    "scan_depth": self.scan_depth_combo.currentIndex(),
                    "verify_ssl": self.verify_ssl_check.isChecked()
                }
            }
            
            # 更新进度
            progress_dialog.setValue(30)
            
            # 调用报告生成函数
            self.logger.info(f"开始生成{format_type}格式POC扫描报告...")
            report_path = generate_report(
                data=result.data,
                metadata=metadata,
                output_dir=reports_dir,
                format_type=format_type
            )
            
            # 更新进度
            progress_dialog.setValue(90)
            
            # 检查报告是否生成成功
            if report_path and os.path.exists(report_path):
                # 关闭进度对话框
                progress_dialog.setValue(100)
                
                # 创建更详细的成功消息
                msg = f"报告已成功生成: {os.path.basename(report_path)}\n位置: {os.path.dirname(report_path)}"
                
                # 如果是PDF格式且文件较小，可能是简化版
                if format_type.lower() == "pdf":
                    html_path = report_path.replace(".pdf", ".html")
                    if os.path.exists(html_path):
                        pdf_size = os.path.getsize(report_path)
                        html_size = os.path.getsize(html_path)
                        if pdf_size < html_size * 0.5:
                            msg += "\n\n注意: 生成的是简化版PDF。如需更完整的PDF，请安装wkhtmltopdf。"
                
                # 询问用户是否打开报告
                reply = QMessageBox.question(
                    self, 
                    "报告生成成功", 
                    f"{msg}\n\n是否立即打开?",
                    QMessageBox.Yes | QMessageBox.No, 
                    QMessageBox.Yes
                )
                
                if reply == QMessageBox.Yes:
                    # 使用系统默认程序打开报告
                    import webbrowser
                    self.logger.info(f"正在打开报告: {report_path}")
                    webbrowser.open('file://' + os.path.abspath(report_path))
                    
                self.logger.info(f"报告生成完成: {report_path}")
                return report_path
            else:
                progress_dialog.close()
                self.logger.error("报告生成失败")
                QMessageBox.warning(self, "警告", "报告生成失败，请检查日志")
                return None
                
        except ImportError as e:
            self.logger.error(f"导入report_generator模块失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"导入报告生成模块失败: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"生成报告时出错: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "错误", f"生成报告时出错: {str(e)}")
            return None

    def show_add_poc_dialog(self):
        """显示添加POC对话框 - 为兼容性保留"""
        # 如果已有POC管理器，直接使用
        if self.poc_manager:
            self.poc_manager.add_poc()
        else:
            # 简化实现，实际应该创建一个更复杂的对话框
            QMessageBox.information(
                self, "功能开发中", 
                "此功能正在开发中，请手动添加POC文件到plugins/web_risk/pocs目录"
            )

class ScanThread(QThread):
    """POC扫描线程"""
    
    scan_finished = pyqtSignal(object)
    scan_result = pyqtSignal(object)
    
    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
    
    def run(self):
        """执行扫描"""
        try:
            # 执行扫描
            result = self.scanner.execute()
            
            # 发送每个扫描结果
            for item in result.data:
                self.scan_result.emit(item)
            
            # 发送扫描完成信号
            self.scan_finished.emit(result)
        except Exception as e:
            # 处理任何异常，防止应用闪退
            import traceback
            error_detail = traceback.format_exc()
            
            # 创建错误结果
            from core.base_scanner import ScanResult
            error_result = ScanResult(
                success=False,
                data=[{
                    "check_type": "vulnerability",
                    "vulnerability": "扫描错误",
                    "status": "error",
                    "details": f"扫描过程中出现错误: {str(e)}\n\n{error_detail}"
                }],
                error_msg=str(e)
            )
            
            # 发送错误结果
            self.scan_result.emit(error_result.data[0])
            self.scan_finished.emit(error_result) 