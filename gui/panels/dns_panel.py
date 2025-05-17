#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS检测面板
用于图形化操作DNS检测模块
"""

import logging
import socket
from typing import Dict, List, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QPushButton, QLabel, QLineEdit, QCheckBox, QSpinBox, 
    QDoubleSpinBox, QComboBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QListWidget, QGridLayout,
    QToolButton, QSizePolicy, QProgressBar, QFileDialog, QSplitter
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QIcon

from gui.panels.base_panel import BasePanel, ScanThread


class DnsPanel(BasePanel):
    """DNS检测面板"""
    
    MODULE_ID = "dnschecker"
    MODULE_NAME = "DNS检测"
    
    # DNS记录类型
    DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV"]
    
    def __init__(self, parent=None):
        """初始化DNS检测面板"""
        super().__init__(parent)
    
    def create_param_group(self):
        """创建参数组"""
        self.param_group = QGroupBox("扫描参数")
        param_layout = QVBoxLayout()
        param_layout.setSpacing(5)
        param_layout.setContentsMargins(5, 5, 5, 5)
        
        # 创建水平布局用于域名和DNS服务器
        basic_params_layout = QHBoxLayout()
        
        # 创建域名布局
        domain_layout = QVBoxLayout()
        domain_label = QLabel("域名:")
        domain_layout.addWidget(domain_label)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        domain_layout.addWidget(self.domain_input)
        basic_params_layout.addLayout(domain_layout, 3)
        
        # 创建DNS服务器布局
        nameservers_layout = QVBoxLayout()
        nameservers_label = QLabel("DNS服务器:")
        nameservers_layout.addWidget(nameservers_label)
        self.nameservers_input = QLineEdit()
        self.nameservers_input.setPlaceholderText("8.8.8.8,8.8.4.4,1.1.1.1")
        nameservers_layout.addWidget(self.nameservers_input)
        basic_params_layout.addLayout(nameservers_layout, 4)
        
        # 创建超时时间布局
        timeout_layout = QVBoxLayout()
        timeout_label = QLabel("超时:")
        timeout_layout.addWidget(timeout_label)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.5, 30.0)
        self.timeout_spin.setSingleStep(0.5)
        self.timeout_spin.setValue(2.0)
        self.timeout_spin.setSuffix(" 秒")
        timeout_layout.addWidget(self.timeout_spin)
        basic_params_layout.addLayout(timeout_layout, 1)
        
        param_layout.addLayout(basic_params_layout)
        
        # 水平分隔记录类型和高级选项
        options_layout = QHBoxLayout()
        
        # 记录类型 - 使用网格布局优化
        record_types_group = QGroupBox("记录类型")
        record_types_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        record_types_layout = QVBoxLayout()
        record_types_layout.setSpacing(3)
        record_types_layout.setContentsMargins(5, 5, 5, 5)
        
        # 创建网格布局用于放置记录类型复选框
        grid_layout = QGridLayout()
        grid_layout.setSpacing(5)
        grid_layout.setVerticalSpacing(2)
        
        # 创建记录类型复选框并放置到网格中
        self.record_type_checks = {}
        common_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
        cols = 3  # 设置为3列
        
        for i, record_type in enumerate(self.DNS_RECORD_TYPES):
            check = QCheckBox(record_type)
            check.setChecked(record_type in common_types)
            
            # 计算行列位置
            row = i // cols
            col = i % cols
            
            grid_layout.addWidget(check, row, col)
            self.record_type_checks[record_type] = check
        
        # 添加网格布局
        record_types_layout.addLayout(grid_layout)
        
        # 全选/取消全选按钮 - 使用小型按钮
        select_buttons_layout = QHBoxLayout()
        
        select_all_button = QPushButton("全选")
        select_all_button.setMaximumWidth(60)
        select_all_button.setFixedHeight(22)
        select_all_button.clicked.connect(self.select_all_record_types)
        select_buttons_layout.addWidget(select_all_button)
        
        deselect_all_button = QPushButton("取消全选")
        deselect_all_button.setMaximumWidth(60)
        deselect_all_button.setFixedHeight(22)
        deselect_all_button.clicked.connect(self.deselect_all_record_types)
        select_buttons_layout.addWidget(deselect_all_button)
        
        select_buttons_layout.addStretch(1)  # 添加弹性空间
        
        record_types_layout.addLayout(select_buttons_layout)
        record_types_group.setLayout(record_types_layout)
        options_layout.addWidget(record_types_group)
        
        # 高级选项
        advanced_group = QGroupBox("高级选项")
        advanced_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        advanced_layout = QVBoxLayout()
        advanced_layout.setSpacing(3)
        advanced_layout.setContentsMargins(5, 5, 5, 5)
        
        # 区域传送选项
        self.zone_transfer_check = QCheckBox("尝试区域传送")
        self.zone_transfer_check.setChecked(True)
        advanced_layout.addWidget(self.zone_transfer_check)
        
        # 子域名扫描选项
        self.subdomain_scan_check = QCheckBox("扫描子域名")
        self.subdomain_scan_check.setChecked(False)
        self.subdomain_scan_check.stateChanged.connect(self.on_subdomain_scan_changed)
        advanced_layout.addWidget(self.subdomain_scan_check)
        
        # 子域名字典 - 精简布局
        subdomain_dict_layout = QHBoxLayout()
        self.subdomain_dict_input = QLineEdit()
        self.subdomain_dict_input.setPlaceholderText("子域名字典文件路径")
        self.subdomain_dict_input.setEnabled(False)  # 默认禁用
        subdomain_dict_layout.addWidget(self.subdomain_dict_input)
        
        self.browse_button = QToolButton()
        self.browse_button.setText("...")
        self.browse_button.setToolTip("浏览子域名字典文件")
        self.browse_button.clicked.connect(self.browse_subdomain_dict)
        self.browse_button.setEnabled(False)  # 默认禁用
        subdomain_dict_layout.addWidget(self.browse_button)
        
        advanced_layout.addLayout(subdomain_dict_layout)
        advanced_group.setLayout(advanced_layout)
        options_layout.addWidget(advanced_group)
        
        param_layout.addLayout(options_layout)
        
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
    
    def select_all_record_types(self):
        """选择所有记录类型"""
        for check in self.record_type_checks.values():
            check.setChecked(True)
    
    def deselect_all_record_types(self):
        """取消选择所有记录类型"""
        for check in self.record_type_checks.values():
            check.setChecked(False)
    
    def on_subdomain_scan_changed(self, state):
        """子域名扫描选项变更处理"""
        enabled = state == Qt.Checked
        self.subdomain_dict_input.setEnabled(enabled)
        self.browse_button.setEnabled(enabled)
    
    def browse_subdomain_dict(self):
        """浏览子域名字典文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择子域名字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self.subdomain_dict_input.setText(file_path)
    
    def get_scan_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        # 获取选中的记录类型
        record_types = [
            rt for rt, check in self.record_type_checks.items() 
            if check.isChecked()
        ]
        
        # 处理DNS服务器列表
        nameservers_str = self.nameservers_input.text().strip()
        nameservers = []
        if nameservers_str:
            nameservers = [ns.strip() for ns in nameservers_str.split(",") if ns.strip()]
        
        return {
            "domain": self.domain_input.text().strip(),
            "record_types": record_types,
            "nameservers": nameservers,
            "timeout": self.timeout_spin.value(),
            "subdomain_scan": self.subdomain_scan_check.isChecked(),
            "subdomain_dict": self.subdomain_dict_input.text().strip() if self.subdomain_scan_check.isChecked() else None,
            "zone_transfer": self.zone_transfer_check.isChecked()
        }
    
    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """设置扫描配置到UI控件"""
        if "domain" in config:
            self.domain_input.setText(str(config["domain"]))
        
        if "nameservers" in config:
            nameservers = config["nameservers"]
            if isinstance(nameservers, list):
                self.nameservers_input.setText(",".join(nameservers))
            elif isinstance(nameservers, str):
                self.nameservers_input.setText(nameservers)
        
        if "record_types" in config:
            record_types = config["record_types"]
            # 清除所有选中
            self.deselect_all_record_types()
            # 选中配置中的记录类型
            if isinstance(record_types, list):
                for rt in record_types:
                    if rt in self.record_type_checks:
                        self.record_type_checks[rt].setChecked(True)
            elif isinstance(record_types, str):
                for rt in record_types.split(","):
                    rt = rt.strip().upper()
                    if rt in self.record_type_checks:
                        self.record_type_checks[rt].setChecked(True)
        
        if "timeout" in config:
            self.timeout_spin.setValue(float(config["timeout"]))
        
        if "subdomain_scan" in config:
            self.subdomain_scan_check.setChecked(config["subdomain_scan"])
        
        if "subdomain_dict" in config and config["subdomain_dict"]:
            self.subdomain_dict_input.setText(str(config["subdomain_dict"]))
        
        if "zone_transfer" in config:
            self.zone_transfer_check.setChecked(config["zone_transfer"])
    
    def validate_params(self, config: Dict[str, Any]) -> bool:
        """验证扫描参数"""
        # 检查域名
        domain = config.get("domain", "")
        if not domain:
            QMessageBox.warning(self, "参数错误", "请输入目标域名")
            return False
        
        # 简单验证域名格式
        if "." not in domain:
            QMessageBox.warning(self, "参数错误", "无效的域名格式")
            return False
        
        # 检查记录类型
        record_types = config.get("record_types", [])
        if not record_types:
            QMessageBox.warning(self, "参数错误", "请至少选择一种记录类型")
            return False
        
        # 检查子域名字典文件
        if config.get("subdomain_scan") and config.get("subdomain_dict"):
            import os
            if not os.path.exists(config["subdomain_dict"]):
                QMessageBox.warning(self, "参数错误", "子域名字典文件不存在")
                return False
        
        # 检查DNS服务器
        nameservers = config.get("nameservers", [])
        if nameservers:
            for ns in nameservers:
                try:
                    socket.inet_aton(ns)  # 验证IP地址格式
                except socket.error:
                    # 尝试解析主机名
                    try:
                        socket.gethostbyname(ns)
                    except socket.gaierror:
                        QMessageBox.warning(self, "参数错误", f"无效的DNS服务器地址: {ns}")
                        return False
        
        return True
    
    def display_results(self, result):
        """显示扫描结果"""
        # 先调用基类方法清空表格
        super().display_results(result)
        
        if not result.success or not result.data:
            return
        
        # 提取数据
        data = result.data
        
        # 为DNS检测结果设置自定义列
        columns = ["domain", "type", "data", "ttl", "source"]
        column_names = ["域名", "记录类型", "记录内容", "TTL", "来源"]
        
        # 设置表格列
        self.result_table.setColumnCount(len(columns))
        self.result_table.setHorizontalHeaderLabels(column_names)
        
        # 设置表格行高
        self.result_table.verticalHeader().setDefaultSectionSize(22)
        # 启用交替行颜色
        self.result_table.setAlternatingRowColors(True)
        
        # 添加行
        self.result_table.setRowCount(len(data))
        
        # 填充数据
        for row, record in enumerate(data):
            for col, key in enumerate(columns):
                value = record.get(key, "")
                
                # 特殊处理
                if key == "source" and not value:
                    value = "查询"
                
                # 正常处理
                item = QTableWidgetItem(str(value) if value is not None else "")
                self.result_table.setItem(row, col, item)
        
        # 调整列宽
        self.result_table.resizeColumnsToContents()
        
        # 优化各列宽度
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # 域名列
        header.setSectionResizeMode(1, QHeaderView.Fixed)  # 记录类型列
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # 记录内容列
        header.setSectionResizeMode(3, QHeaderView.Fixed)  # TTL列
        header.setSectionResizeMode(4, QHeaderView.Fixed)  # 来源列
        
        # 设置固定列宽
        self.result_table.setColumnWidth(1, 80)   # 记录类型
        self.result_table.setColumnWidth(3, 60)   # TTL
        self.result_table.setColumnWidth(4, 70)   # 来源
        
        # 统计结果
        record_counts = {}
        for record in data:
            record_type = record.get("type", "未知")
            record_counts[record_type] = record_counts.get(record_type, 0) + 1
        
        total_records = len(data)
        type_counts = ", ".join([f"{t}: {c}" for t, c in record_counts.items()])
        
        # 更新状态栏
        self.status_label.setText(
            f"查询完成: {total_records}条记录 ({type_counts}), 用时{result.duration:.2f}秒"
        )
    
    def create_action_group(self):
        """创建操作按钮组"""
        self.action_group = QGroupBox("操作")
        # 减小内边距，使内容更紧凑
        action_layout = QHBoxLayout()
        action_layout.setSpacing(5)
        action_layout.setContentsMargins(5, 5, 5, 5)
        
        # 设置所有按钮的固定高度以减少垂直空间
        button_height = 28
        
        # 开始扫描按钮
        self.scan_button = QPushButton("开始扫描")
        self.scan_button.setFixedHeight(button_height)
        self.scan_button.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_button)
        
        # 停止扫描按钮
        self.stop_button = QPushButton("停止扫描")
        self.stop_button.setFixedHeight(button_height)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        action_layout.addWidget(self.stop_button)
        
        # 清除结果按钮
        self.clear_button = QPushButton("清除结果")
        self.clear_button.setFixedHeight(button_height)
        self.clear_button.clicked.connect(self.clear_results)
        action_layout.addWidget(self.clear_button)
        
        # 导出结果按钮
        self.export_button = QPushButton("导出结果")
        self.export_button.setFixedHeight(button_height)
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        action_layout.addWidget(self.export_button)
        
        # 保存配置按钮
        self.save_config_button = QPushButton("保存配置")
        self.save_config_button.setFixedHeight(button_height)
        self.save_config_button.clicked.connect(self.save_config)
        action_layout.addWidget(self.save_config_button)
        
        self.action_group.setLayout(action_layout)
        self.config_layout.addWidget(self.action_group)
    
    def create_status_bar(self):
        """创建状态栏"""
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(2, 0, 2, 0)
        status_layout.setSpacing(5)
        
        # 状态标签
        self.status_label = QLabel("就绪")
        self.status_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        status_layout.addWidget(self.status_label, 1)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(16)
        status_layout.addWidget(self.progress_bar, 2)
        
        self.layout.addLayout(status_layout)
    
    def init_ui(self):
        """初始化用户界面"""
        # 调用父类的init_ui方法
        super().init_ui()
        
        # 调整分割器初始大小，减小参数区域比例，增大结果区域比例
        self.splitter.setSizes([160, 440]) 