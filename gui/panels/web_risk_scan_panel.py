#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web风险扫描面板
用于Web安全风险检测的图形界面模块
"""

import os
import sys
import time
import logging
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

from PyQt5.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox, QLabel, 
    QLineEdit, QPushButton, QRadioButton, QButtonGroup, QProgressBar,
    QWidget, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QCheckBox, QSpinBox, QMessageBox, QDialog, QDialogButtonBox,
    QTextEdit, QSplitter, QComboBox, QFileDialog, QProgressDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QIcon, QColor, QBrush

from core.web_risk_scan import WebRiskScanner
from gui.panels.base_panel import BasePanel, ScanThread
from utils.config import ConfigManager
from plugins import plugin_manager
from core.scanner_manager import scanner_manager

# 配置日志记录器
logger = logging.getLogger("ss0t-scna.gui.web_risk_scan_panel")

class WebRiskScanPanel(BasePanel):
    """
    Web风险扫描面板
    提供Web安全检测功能的图形界面
    """
    
    # 设置模块ID
    MODULE_ID = "webriskscanner"
    MODULE_NAME = "Web风险扫描"
    
    def __init__(self, parent=None):
        """初始化面板"""
        # 初始化配置字典
        self.config = {}
        
        # 初始化logger（先于父类初始化）
        self.logger = logging.getLogger(f"ss0t-scna.gui.{self.MODULE_ID}")
        self.logger.info("初始化Web风险扫描面板")
        
        # URL列表，用于存储从文件加载的URL
        self.url_list = []
        
        # 原始Wappalyzer技术指纹数据
        self.raw_wappalyzer_data = {}
        
        # 恢复初始化禁用插件列表
        self.disabled_plugins = []
        self.plugin_checkboxes = {}
        
        # 调用父类的__init__，这样会初始化基本的UI组件，也会调用load_config
        super().__init__(parent)
        
        # 注册QVector<int>类型，用于Qt信号槽机制
        try:
            # 尝试使用qRegisterMetaType
            from PyQt5.QtCore import qRegisterMetaType
            try:
                qRegisterMetaType("QVector<int>")
            except Exception:
                pass  # 忽略错误，不会影响主要功能
        except Exception as e:
            self.logger.warning(f"注册信号类型失败: {str(e)}")
            # 继续执行，不影响主要功能
        
        # 移除父类的布局，避免冲突
        if self.layout():
            # 清空父类添加的所有小部件
            while self.layout().count():
                item = self.layout().takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
            # 删除父类布局
            old_layout = self.layout()
            QWidget().setLayout(old_layout)
        
        # 插件管理器初始化
        plugin_manager.init_plugins()
        
        # 初始化WebRiskScanPanel特定的UI组件
        self.setup_ui()
        
        # 建立信号连接
        self.setup_connections()
        
        # 恢复初始化插件信息
        self.init_plugin_info()
        
        # 加载配置
        try:
            self.load_config()
        except Exception as e:
            self.logger.error(f"加载配置失败: {str(e)}")
            
    def init_plugin_info(self):
        """初始化插件信息，但不在UI中显示插件选项"""
        # 发现可用插件
        plugin_manager.discover_plugins()
        
        # 获取所有插件信息
        all_plugins = plugin_manager.get_plugin_info_list()
        
        # 使用所有插件，不再过滤POC扫描插件（已独立出来）
        self.all_plugins = all_plugins
        
        if self.all_plugins:
            self.logger.info(f"发现 {len(self.all_plugins)} 个Web风险扫描插件")
        else:
            self.logger.warning("未发现任何Web风险扫描插件")
    
    def init_ui(self):
        """初始化UI组件"""
        # 主布局
        layout = QVBoxLayout(self)
        
        # 创建上下分隔布局
        splitter = QSplitter(Qt.Vertical)
        
        # 上部分 - 参数设置
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        # 创建左右布局，左侧为基本参数，右侧为选项
        params_layout = QHBoxLayout()
        
        # === 左侧基本参数 ===
        basic_params_group = QGroupBox("基本参数")
        basic_form_layout = QFormLayout(basic_params_group)
        
        # 目标输入类型：手动输入或从文件导入
        target_type_layout = QHBoxLayout()
        self.target_type_group = QButtonGroup(self)
        
        self.manual_radio = QRadioButton("手动输入")
        self.manual_radio.setChecked(True)
        self.target_type_group.addButton(self.manual_radio)
        
        self.file_radio = QRadioButton("从文件导入")
        self.target_type_group.addButton(self.file_radio)
        
        target_type_layout.addWidget(self.manual_radio)
        target_type_layout.addWidget(self.file_radio)
        target_type_layout.addStretch()
        
        basic_form_layout.addRow("输入类型:", target_type_layout)
        
        # 目标输入框
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("输入URL, IP或IP段 (例如: http://example.com, 192.168.1.1, 192.168.1.0/24)")
        basic_form_layout.addRow("目标:", self.target_input)
        
        # 文件选择（默认隐藏）
        self.file_select_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("选择包含URL列表的文件")
        self.file_select_layout.addWidget(self.file_path_input)
        
        self.browse_button = QPushButton("浏览...")
        self.file_select_layout.addWidget(self.browse_button)
        
        file_layout_widget = QWidget()
        file_layout_widget.setLayout(self.file_select_layout)
        file_layout_widget.setVisible(False)
        self.file_widget = file_layout_widget
        basic_form_layout.addRow("", file_layout_widget)
        
        # URL计数标签（默认隐藏）
        self.url_count_label = QLabel("已加载 0 个URL")
        self.url_count_label.setVisible(False)
        basic_form_layout.addRow("", self.url_count_label)
        
        # 端口
        self.port_input = QLineEdit("80,443")
        basic_form_layout.addRow("端口:", self.port_input)
        
        params_layout.addWidget(basic_params_group, 1)
        
        # === 扫描参数组 ===
        scan_params_group = QGroupBox("扫描参数")
        scan_params_layout = QFormLayout(scan_params_group)
        scan_params_layout.setVerticalSpacing(6)  # 减少垂直间距
        
        # 线程与超时设置
        thread_timeout_widget = QWidget()
        thread_timeout_layout = QHBoxLayout(thread_timeout_widget)
        thread_timeout_layout.setContentsMargins(0, 0, 0, 0)
        
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("线程数:"))
        self.thread_input = QSpinBox()
        self.thread_input.setRange(1, 200)
        self.thread_input.setValue(10)
        thread_layout.addWidget(self.thread_input)
        thread_timeout_layout.addLayout(thread_layout)
        
        thread_timeout_layout.addSpacing(20)  # 添加一些间距分隔
        
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("超时:"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 60)
        self.timeout_input.setValue(10)
        self.timeout_input.setSuffix(" 秒")
        timeout_layout.addWidget(self.timeout_input)
        thread_timeout_layout.addLayout(timeout_layout)
        
        scan_params_layout.addRow("", thread_timeout_widget)
        
        # 扫描深度选择器
        depth_widget = QWidget()
        depth_layout = QHBoxLayout(depth_widget)
        depth_layout.setContentsMargins(0, 0, 0, 0)
        depth_layout.addWidget(QLabel("扫描深度:"))
        self.scan_depth_combo = QComboBox()
        self.scan_depth_combo.addItem("基本检查", 0)
        self.scan_depth_combo.addItem("标准检查", 1)
        self.scan_depth_combo.addItem("深入检查", 2)
        self.scan_depth_combo.setCurrentIndex(1)  # 默认使用标准检查
        depth_layout.addWidget(self.scan_depth_combo)
        depth_layout.addStretch()
        scan_params_layout.addRow("", depth_widget)
        
        # 检查选项
        options_widget = QWidget()
        options_layout = QHBoxLayout(options_widget)
        options_layout.setContentsMargins(0, 0, 0, 0)
        
        # 验证SSL证书
        self.verify_ssl_check = QCheckBox("验证SSL证书")
        self.verify_ssl_check.setChecked(False)
        options_layout.addWidget(self.verify_ssl_check)
        
        options_layout.addSpacing(20)  # 添加一些间距分隔
        
        # 跟随重定向
        self.follow_redirect_check = QCheckBox("跟随重定向")
        self.follow_redirect_check.setChecked(True)
        options_layout.addWidget(self.follow_redirect_check)
        
        options_layout.addStretch()
        scan_params_layout.addRow("", options_widget)
        
        params_layout.addWidget(scan_params_group, 1)
        
        # === 右侧选项 ===
        options_group = QGroupBox("插件选项")
        options_layout = QVBoxLayout(options_group)
        
        # 插件管理按钮
        plugin_management_layout = QHBoxLayout()
        
        # 恢复插件管理按钮
        self.manage_plugins_button = QPushButton("管理扫描插件")
        plugin_management_layout.addWidget(self.manage_plugins_button)
        
        # 恢复插件配置按钮
        self.config_plugins_button = QPushButton("配置插件参数")
        plugin_management_layout.addWidget(self.config_plugins_button)
        
        options_layout.addLayout(plugin_management_layout)
        
        params_layout.addWidget(options_group, 1)
        
        top_layout.addLayout(params_layout)
        
        # 控制按钮
        control_layout = QHBoxLayout()
        
        self.start_button = QPushButton("开始扫描")
        self.start_button.setIcon(QIcon.fromTheme("system-run"))
        control_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("停止")
        self.stop_button.setIcon(QIcon.fromTheme("process-stop"))
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        self.report_button = QPushButton("生成报告")
        self.report_button.setIcon(QIcon.fromTheme("text-x-generic"))
        self.report_button.setEnabled(False)
        control_layout.addWidget(self.report_button)
        
        top_layout.addLayout(control_layout)
        
        # 添加进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        top_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("就绪")
        top_layout.addWidget(self.status_label)
        
        # 下部分 - 结果显示
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        
        # 创建标签页容器
        self.result_tabs = QTabWidget()
        
        # 创建各个标签页
        # 总览标签页
        self.overview_table = self.create_overview_table()
        self.result_tabs.addTab(self.overview_table, "总览")
        
        # 漏洞标签页
        self.vuln_table = self.create_vuln_table()
        self.result_tabs.addTab(self.vuln_table, "漏洞")
        
        # 服务信息标签页
        self.service_table = self.create_service_table()
        self.result_tabs.addTab(self.service_table, "服务信息")
        
        # 安全响应头标签页
        self.headers_table = self.create_headers_table()
        self.result_tabs.addTab(self.headers_table, "安全响应头")
        
        bottom_layout.addWidget(self.result_tabs)
        
        # 添加到分隔布局
        splitter.addWidget(top_widget)
        splitter.addWidget(bottom_widget)
        
        # 设置分隔比例
        splitter.setSizes([300, 700])
        
        layout.addWidget(splitter)
        
        # 创建扫描线程
        self.scan_thread = None
        
        # 当前结果
        self.current_result = None
    
    def setup_connections(self):
        """连接信号和槽"""
        # 目标类型切换
        self.manual_radio.toggled.connect(self.toggle_target_type)
        self.file_radio.toggled.connect(self.toggle_target_type)
        
        # 文件浏览
        self.browse_button.clicked.connect(self.browse_file)
        
        # 控制按钮
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.report_button.clicked.connect(self.generate_report)
        
        # 恢复插件管理按钮的连接
        self.manage_plugins_button.clicked.connect(self.show_plugin_manager)
        self.config_plugins_button.clicked.connect(self.show_plugin_config)

    def toggle_target_type(self):
        """切换目标输入模式"""
        is_manual = self.manual_radio.isChecked()
        
        # 手动输入模式
        self.target_input.setEnabled(is_manual)
        
        # 文件导入模式
        self.file_path_input.setEnabled(not is_manual)
        self.browse_button.setEnabled(not is_manual)
        self.url_count_label.setVisible(not is_manual)
        
        # 更新状态信息
        if not is_manual:
            if self.url_list:
                self.url_count_label.setText(f"已加载 {len(self.url_list)} 个URL")
            else:
                self.url_count_label.setText("请选择URL文件")

    def browse_file(self):
        """浏览并选择URL文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择URL文件", "", "文本文件 (*.txt);;所有文件 (*.*)"
        )
        
        if file_path:
            self.file_path_input.setText(file_path)
            self.load_url_list(file_path)

    def load_url_list(self, file_path):
        """从文件加载URL列表"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.url_list = []
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        # 确保URL以http://或https://开头
                        if not url.startswith(('http://', 'https://')):
                            url = 'http://' + url
                        self.url_list.append(url)
            
            # 更新URL计数标签
            self.url_count_label.setText(f"已加载 {len(self.url_list)} 个URL")
            self.logger.info(f"从文件 {file_path} 加载了 {len(self.url_list)} 个URL")
            
            if not self.url_list:
                QMessageBox.warning(self, "警告", "URL文件为空或格式不正确")
                return False
            return True
        except Exception as e:
            self.logger.error(f"加载URL文件失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"加载URL文件失败: {str(e)}")
            self.url_list = []
            self.url_count_label.setText("加载失败")
            return False

    def clear_tables(self):
        """清空所有表格"""
        for table in [self.overview_table, self.vuln_table, self.service_table, self.headers_table]:
            table.setRowCount(0)

    def start_scan(self):
        """开始扫描"""
        # 清空表格
        self.clear_tables()
        
        # 获取参数
        params = self.get_scan_config()
        
        # 验证输入
        if not params["targets"]:
            if self.file_radio.isChecked():
                self.show_error("请选择有效的URL文件")
            else:
                self.show_error("请输入目标URL或IP")
            return
        
        # 创建并启动扫描线程
        self.scan_thread = self.create_scan_thread("webriskscanner", params)
        
        # 设置结果回调函数
        if hasattr(self.scan_thread.scanner, 'set_result_callback'):
            self.scan_thread.scanner.set_result_callback(self.on_result_received)
        
        self.start_scan_thread()
    
    def on_result_received(self, result):
        """
        处理实时结果
        
        Args:
            result: 单条扫描结果
        """
        # 根据结果类型更新不同的表格
        check_type = result.get("check_type", "")
        
        if check_type == "basic_info":
            self.add_overview_row(result)
        elif check_type == "vulnerability":
            self.add_vuln_row(result)
        elif check_type == "server_info":
            self.add_server_row(result)
        elif check_type == "security_header":
            self.add_header_row(result)
        elif check_type == "ssl":
            self.update_server_ssl_info(result)
        elif check_type == "waf":
            self.update_overview_waf(result)
    
    def add_overview_row(self, result):
        """添加总览表格行"""
        url = result.get("url", "")
        status_code = result.get("status_code", "")
        
        # 检查是否已存在该URL的行
        for row in range(self.overview_table.rowCount()):
            if self.overview_table.item(row, 0).text() == url:
                # 更新已存在的行
                self.overview_table.item(row, 1).setText(str(status_code))
                return
        
        # 添加新行
        row = self.overview_table.rowCount()
        self.overview_table.insertRow(row)
        
        # 填充基本数据
        self.overview_table.setItem(row, 0, QTableWidgetItem(url))
        self.overview_table.setItem(row, 1, QTableWidgetItem(str(status_code)))
        self.overview_table.setItem(row, 2, QTableWidgetItem(""))  # 服务器
        self.overview_table.setItem(row, 3, QTableWidgetItem(""))  # 技术
        self.overview_table.setItem(row, 4, QTableWidgetItem("无"))  # WAF
        self.overview_table.setItem(row, 5, QTableWidgetItem("待评估"))  # 安全评分
        self.overview_table.setItem(row, 6, QTableWidgetItem("0"))  # 漏洞数
    
    def update_overview_waf(self, result):
        """更新总览表格中的WAF信息"""
        url = result.get("url", "")
        waf_name = result.get("waf_name", "未知")
        
        # 查找URL对应的行
        for row in range(self.overview_table.rowCount()):
            if self.overview_table.item(row, 0).text() == url:
                self.overview_table.item(row, 4).setText(waf_name)
                break
    
    def add_vuln_row(self, result):
        """添加漏洞表格行"""
        url = result.get("url", "")
        vuln_type = result.get("vulnerability", "")
        details = result.get("details", "")
        recommendation = result.get("recommendation", "")
        
        # 添加新行
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        
        # 填充数据
        self.vuln_table.setItem(row, 0, QTableWidgetItem(url))
        self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln_type))
        self.vuln_table.setItem(row, 2, QTableWidgetItem(details))
        
        # 根据漏洞类型设置严重性
        severity = "高"
        if vuln_type in ["XSS", "SQL注入"]:
            severity = "高"
        elif vuln_type in ["目录遍历", "文件包含"]:
            severity = "高"
        elif vuln_type == "敏感文件":
            severity = "中"
        
        self.vuln_table.setItem(row, 3, QTableWidgetItem(severity))
        self.vuln_table.setItem(row, 4, QTableWidgetItem(recommendation))
        
        # 更新总览表格中的漏洞计数
        self.update_overview_vuln_count(url)
    
    def update_overview_vuln_count(self, url):
        """更新总览表格中的漏洞计数"""
        # 统计该URL的漏洞数
        vuln_count = 0
        for row in range(self.vuln_table.rowCount()):
            if self.vuln_table.item(row, 0).text() == url:
                vuln_count += 1
        
        # 更新总览表格
        for row in range(self.overview_table.rowCount()):
            if self.overview_table.item(row, 0).text() == url:
                self.overview_table.item(row, 6).setText(str(vuln_count))
                
                # 计算安全评分
                score = 100
                if vuln_count > 0:
                    score -= min(80, vuln_count * 20)  # 最低20分
                
                self.overview_table.item(row, 5).setText(f"{score}分")
                break
    
    def add_server_row(self, result):
        """添加服务器信息表格行"""
        url = result.get("url", "")
        server = result.get("server", "")
        powered_by = result.get("powered_by", "")
        technologies = ", ".join(result.get("technologies", []))
        
        # 添加新行
        row = self.service_table.rowCount()
        self.service_table.insertRow(row)
        
        # 填充数据
        self.service_table.setItem(row, 0, QTableWidgetItem(url))
        self.service_table.setItem(row, 1, QTableWidgetItem(server))
        self.service_table.setItem(row, 2, QTableWidgetItem(technologies))
        self.service_table.setItem(row, 3, QTableWidgetItem(powered_by))
        self.service_table.setItem(row, 4, QTableWidgetItem(""))  # TLS版本
        self.service_table.setItem(row, 5, QTableWidgetItem(""))  # 证书信息
        
        # 更新总览表格
        for row in range(self.overview_table.rowCount()):
            if self.overview_table.item(row, 0).text() == url:
                self.overview_table.item(row, 2).setText(server)
                self.overview_table.item(row, 3).setText(technologies)
                break
    
    def update_server_ssl_info(self, result):
        """更新服务器表格中的SSL信息"""
        url = result.get("url", "")
        tls_version = result.get("tls_version", "")
        
        # 构建证书信息
        issuer = result.get("issuer", {})
        subject = result.get("subject", {})
        not_after = result.get("not_after", "")
        
        issuer_name = issuer.get("commonName", "")
        subject_name = subject.get("commonName", "")
        
        cert_info = f"发行: {issuer_name}, 主题: {subject_name}, 到期: {not_after}"
        
        # 更新服务器表格
        for row in range(self.service_table.rowCount()):
            if self.service_table.item(row, 0).text() == url:
                self.service_table.item(row, 4).setText(str(tls_version))
                self.service_table.item(row, 5).setText(cert_info)
                break
    
    def add_header_row(self, result):
        """添加安全响应头表格行"""
        url = result.get("url", "")
        header = result.get("header", "")
        status = result.get("status", "")
        description = result.get("description", "")
        recommendation = result.get("recommendation", "")
        
        # 添加新行
        row = self.headers_table.rowCount()
        self.headers_table.insertRow(row)
        
        # 填充数据
        self.headers_table.setItem(row, 0, QTableWidgetItem(url))
        self.headers_table.setItem(row, 1, QTableWidgetItem(header))
        self.headers_table.setItem(row, 2, QTableWidgetItem(status))
        self.headers_table.setItem(row, 3, QTableWidgetItem(description))
        self.headers_table.setItem(row, 4, QTableWidgetItem(recommendation))
    
    def display_results(self, results):
        """
        扫描完成后显示结果
        
        Args:
            results: 扫描结果列表
        """
        # 实际上可能已经通过实时回调添加了大部分结果
        # 这里只需要计算和更新最终的统计数据
        
        # 更新统计信息
        total_urls = len(set([r.get("url", "") for r in results if "url" in r]))
        total_vulns = len([r for r in results if r.get("check_type") == "vulnerability" and r.get("status") == "vulnerable"])
        total_issues = len([r for r in results if r.get("check_type") == "security_header" and r.get("status") == "missing"])
        
        # 更新状态
        self.status_label.setText(f"扫描完成: {total_urls}个URL, {total_vulns}个漏洞, {total_issues}个配置问题")
        
        # 启用导出按钮
        self.report_button.setEnabled(True)
    
    def export_results(self):
        """导出扫描结果"""
        if self.last_scan_result:
            self.export_scan_result(self.last_scan_result, "web_risk_scan")
    
    def handle_scan_error(self, error_msg):
        """
        处理扫描错误
        
        Args:
            error_msg: 错误信息
        """
        self.show_error(f"扫描出错: {error_msg}")
        self.reset_ui()
    
    def reset_ui(self):
        """重置UI状态"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("就绪")
        
    def create_scan_thread(self, module_id, params):
        """
        创建扫描线程
        
        Args:
            module_id: 模块ID
            params: 扫描参数
            
        Returns:
            扫描线程实例
        """
        # 获取扫描器类
        scanner_class = scanner_manager.get_scanner(module_id)
        if not scanner_class:
            self.show_error(f"模块 {module_id} 未找到")
            return None
            
        # 创建扫描器实例
        scanner = scanner_class(params)
        
        # 创建并配置扫描线程
        scan_thread = ScanThread(scanner, self)
        scan_thread.scan_complete.connect(self.on_scan_complete)
        scan_thread.scan_progress.connect(self.on_scan_progress)
        scan_thread.scan_error.connect(self.on_scan_error)
        
        self.last_scan_result = None
        return scan_thread
        
    def add_result(self, result_item):
        """
        添加单条结果
        
        Args:
            result_item: 结果项
        """
        # 处理实时结果
        self.on_result_received(result_item)
        
    def start_scan_thread(self):
        """启动扫描线程"""
        if not self.scan_thread:
            return
            
        # 更新UI状态
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.report_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("正在扫描...")
        
        # 启动线程
        self.scan_thread.start()
        
    def on_scan_complete(self, result):
        """
        扫描完成回调
        
        Args:
            result: 扫描结果
        """
        # 保存结果
        self.last_scan_result = result
        
        # 更新UI状态
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.report_button.setEnabled(result.success and len(result.data) > 0)
        self.progress_bar.setValue(100)
        
        if result.success:
            # 显示所有结果
            self.display_results(result.data)
            
            # 处理结果中的每一条数据
            for item in result.data:
                self.on_result_received(item)
        else:
            error_msg = result.error_msg or "未知错误"
            self.status_label.setText(f"扫描失败: {error_msg}")
            self.show_error(f"扫描失败: {error_msg}")
    
    def on_scan_progress(self, percent, message):
        """
        扫描进度更新回调
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)
    
    def on_scan_error(self, error_msg):
        """
        扫描错误回调
        
        Args:
            error_msg: 错误信息
        """
        self.handle_scan_error(error_msg)
    
    def show_error(self, message):
        """
        显示错误消息
        
        Args:
            message: 错误消息
        """
        QMessageBox.critical(self, "错误", message)
    
    def stop_scan(self):
        """停止扫描"""
        if self.scan_thread and self.scan_thread.isRunning():
            # 停止扫描器
            self.scan_thread.scanner.stop()
            
            # 更新UI状态先行，避免用户感觉界面卡顿
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("正在停止扫描...")
            self.progress_bar.setValue(0)
            
            # 使用定时器非阻塞检查线程状态
            self.check_thread_timer = QTimer()
            self.check_thread_timer.setSingleShot(True)
            self.check_thread_timer.timeout.connect(self.check_thread_stopped)
            self.check_thread_timer.start(100)  # 100毫秒后检查
            
            self.logger.info("正在停止扫描...")
    
    def check_thread_stopped(self):
        """检查线程是否已停止，并处理超时情况"""
        if self.scan_thread and self.scan_thread.isRunning():
            # 线程仍在运行，再次启动定时器
            elapsed_time = getattr(self, 'stop_elapsed_time', 0) + 100
            self.stop_elapsed_time = elapsed_time
            
            if elapsed_time > 5000:  # 超过5秒
                # 强制终止线程
                self.logger.warning("扫描线程未能在预期时间内停止，尝试强制终止")
                # 先再次尝试停止扫描器
                if hasattr(self.scan_thread, 'scanner') and hasattr(self.scan_thread.scanner, 'stop'):
                    self.scan_thread.scanner.stop()
                # 终止线程
                self.scan_thread.terminate()
                self.scan_thread.wait(500)  # 再等待500毫秒
                self.status_label.setText("扫描已强制停止")
                self.stop_elapsed_time = 0
                self.logger.info("扫描已停止")
            else:
                # 更新UI提示并继续等待
                self.status_label.setText(f"正在停止扫描...({elapsed_time/1000:.1f}秒)")
                self.check_thread_timer.start(100)  # 再等待100毫秒
        else:
            # 线程已停止
            self.status_label.setText("扫描已停止")
            self.stop_elapsed_time = 0
            self.logger.info("扫描已停止")
    
    def closeEvent(self, event):
        """
        窗口关闭时的事件处理
        
        Args:
            event: 关闭事件
        """
        # 停止任何正在运行的扫描
        if self.scan_thread and self.scan_thread.isRunning():
            self.logger.info("面板关闭时停止正在运行的扫描")
            self.scan_thread.scanner.stop()
            self.scan_thread.wait(1000)  # 等待最多1秒
            
            # 如果线程仍在运行，则终止它
            if self.scan_thread.isRunning():
                self.logger.warning("强制终止扫描线程")
                self.scan_thread.terminate()
                self.scan_thread.wait()
        
        # 调用父类方法
        QWidget.closeEvent(self, event)

    def create_overview_table(self):
        """设置总览表格"""
        headers = ["URL", "状态码", "服务器", "技术", "WAF", "安全评分", "漏洞数"]
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        return table

    def create_vuln_table(self):
        """设置漏洞表格"""
        headers = ["URL", "漏洞类型", "详情", "严重性", "建议"]
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        return table

    def create_service_table(self):
        """设置服务器信息表格"""
        headers = ["URL", "服务器", "技术", "X-Powered-By", "TLS版本", "证书信息"]
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        return table

    def create_headers_table(self):
        """设置安全头表格"""
        headers = ["URL", "响应头", "状态", "描述", "建议"]
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        return table

    def generate_report(self):
        """生成扫描报告"""
        if self.last_scan_result:
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
                self.generate_scan_report(self.last_scan_result, "web_risk_scan", format_type)
        else:
            QMessageBox.warning(self, "警告", "没有可用的扫描结果，请先执行扫描")
    
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
            metadata = result.metadata.copy() if result.metadata else {}
            
            # 获取目标URL
            target_urls = []
            for item in result.data:
                url = item.get("url", "")
                if url and url not in target_urls:
                    target_urls.append(url)
            
            # 获取存活URL（有服务器信息的URL）
            alive_urls = []
            for item in result.data:
                if item.get("check_type") == "server_info":
                    url = item.get("url", "")
                    if url and url not in alive_urls:
                        alive_urls.append(url)
            
            # 更新元数据
            metadata["target_urls"] = target_urls
            metadata["alive_urls"] = alive_urls
            metadata["scan_config"] = result.metadata.get("scan_config", {})
            
            # 获取插件信息
            plugin_info = []
            if hasattr(self, "all_plugins") and self.all_plugins:
                for plugin in self.all_plugins:
                    # 只包含启用的插件
                    if plugin.get("id") not in self.disabled_plugins:
                        plugin_info.append(plugin)
            metadata["plugin_info"] = plugin_info
            
            # 更新进度
            progress_dialog.setValue(30)
            
            # 调用报告生成函数
            self.logger.info(f"开始生成{format_type}格式报告...")
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

    def display_overview_vuln_count(self, url):
        """更新总览表格中的漏洞计数"""
        # 统计该URL的漏洞数
        vuln_count = 0
        for row in range(self.vuln_table.rowCount()):
            if self.vuln_table.item(row, 0).text() == url:
                vuln_count += 1
        
        # 更新总览表格
        for row in range(self.overview_table.rowCount()):
            if self.overview_table.item(row, 0).text() == url:
                self.overview_table.item(row, 6).setText(str(vuln_count))
                
                # 计算安全评分
                score = 100
                if vuln_count > 0:
                    score -= min(80, vuln_count * 20)  # 最低20分
                
                self.overview_table.item(row, 5).setText(f"{score}分")
                break
    
    def display_server_row(self, result):
        """显示服务器信息表格行"""
        url = result.get("url", "")
        server = result.get("server", "")
        powered_by = result.get("powered_by", "")
        technologies = ", ".join(result.get("technologies", []))
        
        # 添加新行
        row = self.service_table.rowCount()
        self.service_table.insertRow(row)
        
        # 填充数据
        self.service_table.setItem(row, 0, QTableWidgetItem(url))
        self.service_table.setItem(row, 1, QTableWidgetItem(server))
        self.service_table.setItem(row, 2, QTableWidgetItem(technologies))
        self.service_table.setItem(row, 3, QTableWidgetItem(powered_by))
        self.service_table.setItem(row, 4, QTableWidgetItem(""))  # TLS版本
        self.service_table.setItem(row, 5, QTableWidgetItem(""))  # 证书信息
        
        # 更新总览表格
        for row in range(self.overview_table.rowCount()):
            if self.overview_table.item(row, 0).text() == url:
                self.overview_table.item(row, 2).setText(server)
                self.overview_table.item(row, 3).setText(technologies)
                break
    
    def display_server_ssl_info(self, result):
        """显示服务器表格中的SSL信息"""
        url = result.get("url", "")
        tls_version = result.get("tls_version", "")
        
        # 构建证书信息
        issuer = result.get("issuer", {})
        subject = result.get("subject", {})
        not_after = result.get("not_after", "")
        
        issuer_name = issuer.get("commonName", "")
        subject_name = subject.get("commonName", "")
        
        cert_info = f"发行: {issuer_name}, 主题: {subject_name}, 到期: {not_after}"
        
        # 更新服务器表格
        for row in range(self.service_table.rowCount()):
            if self.service_table.item(row, 0).text() == url:
                self.service_table.item(row, 4).setText(str(tls_version))
                self.service_table.item(row, 5).setText(cert_info)
                break
    
    def display_header_row(self, result):
        """显示安全响应头表格行"""
        url = result.get("url", "")
        header = result.get("header", "")
        status = result.get("status", "")
        description = result.get("description", "")
        recommendation = result.get("recommendation", "")
        
        # 添加新行
        row = self.headers_table.rowCount()
        self.headers_table.insertRow(row)
        
        # 填充数据
        self.headers_table.setItem(row, 0, QTableWidgetItem(url))
        self.headers_table.setItem(row, 1, QTableWidgetItem(header))
        self.headers_table.setItem(row, 2, QTableWidgetItem(status))
        self.headers_table.setItem(row, 3, QTableWidgetItem(description))
        self.headers_table.setItem(row, 4, QTableWidgetItem(recommendation))
    
    def create_action_group(self):
        """创建操作按钮组"""
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("开始扫描")
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("停止")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        # 导出按钮
        self.export_button = QPushButton("导出结果")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        button_layout.addWidget(self.export_button)
        
        # 添加编辑配置按钮
        self.edit_config_button = QPushButton("编辑扫描配置")
        self.edit_config_button.setToolTip("编辑漏洞路径、Web指纹和WAF签名")
        self.edit_config_button.clicked.connect(self.edit_scan_config)
        button_layout.addWidget(self.edit_config_button)
        
        return button_layout

    def edit_scan_config(self):
        """编辑自定义扫描配置"""
        try:
            # 直接调用配置编辑器
            from utils.config import ConfigManager
            from gui.config_editor import show_config_editor
            
            # 获取配置文件路径
            config = ConfigManager()
            config_file = config.get_config_file_path()
            
            # 打开配置编辑器
            if show_config_editor(config_file, self):
                # 配置已更新，重新加载
                self.load_config()
                QMessageBox.information(self, "配置已保存", "Web风险扫描配置已更新，将在下次扫描时生效。")
        except Exception as e:
            self.logger.error(f"打开配置编辑器时出错: {str(e)}")
            QMessageBox.critical(self, "错误", f"无法打开配置编辑器: {str(e)}")

    def show_plugin_config(self):
        """显示插件配置对话框"""
        try:
            # 使用新的插件配置编辑器路径
            from gui.plugin_config_editor.dialog import show_plugin_config_editor
            show_plugin_config_editor(self)
            
            # 提示用户配置已更新
            QMessageBox.information(self, "配置已更新", "插件配置已更新，将在下次扫描时生效。")
            
            # 重新加载插件配置
            self.load_config()
        except Exception as e:
            self.logger.error(f"显示插件配置编辑器时出错: {str(e)}")
            QMessageBox.critical(self, "错误", f"无法打开插件配置编辑器: {str(e)}")

    def show_plugin_manager(self):
        """显示插件管理对话框"""
        # 检查是否有可用插件
        if not self.all_plugins:
            QMessageBox.warning(self, "警告", "没有可用的插件可管理")
            return
        
        # 创建对话框
        dialog = QDialog(self)
        dialog.setWindowTitle("插件管理")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)
        
        # 创建布局
        layout = QVBoxLayout(dialog)
        
        # 创建插件表格
        table = QTableWidget()
        table.setColumnCount(4)  # 复选框、名称、描述、版本
        table.setHorizontalHeaderLabels(["启用", "名称", "描述", "版本"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        table.verticalHeader().setVisible(False)
        
        # 填充插件表格
        table.setRowCount(len(self.all_plugins))
        for i, plugin_info in enumerate(self.all_plugins):
            plugin_id = plugin_info.get('id')
            plugin_name = plugin_info.get('name')
            plugin_desc = plugin_info.get('description', '')
            plugin_version = plugin_info.get('version', '')
            
            # 创建复选框
            checkbox_item = QTableWidgetItem()
            checkbox_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            checkbox_item.setCheckState(
                Qt.Unchecked if plugin_id in self.disabled_plugins else Qt.Checked
            )
            
            # 设置表格内容
            table.setItem(i, 0, checkbox_item)
            table.setItem(i, 1, QTableWidgetItem(plugin_name))
            table.setItem(i, 2, QTableWidgetItem(plugin_desc))
            table.setItem(i, 3, QTableWidgetItem(plugin_version))
        
        layout.addWidget(table)
        
        # 添加操作按钮
        buttons_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("全部选择")
        select_all_btn.clicked.connect(lambda: self.set_all_plugin_state(table, Qt.Checked))
        buttons_layout.addWidget(select_all_btn)
        
        select_none_btn = QPushButton("全部取消")
        select_none_btn.clicked.connect(lambda: self.set_all_plugin_state(table, Qt.Unchecked))
        buttons_layout.addWidget(select_none_btn)
        
        invert_btn = QPushButton("反选")
        invert_btn.clicked.connect(lambda: self.invert_plugin_selection(table))
        buttons_layout.addWidget(invert_btn)
        
        layout.addLayout(buttons_layout)
        
        # 添加确定和取消按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(lambda: self.save_plugin_selection(table, dialog))
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        # 显示对话框
        dialog.exec_()

    def load_config(self):
        """加载配置"""
        try:
            # 确保self.config已初始化
            if not hasattr(self, 'config'):
                self.config = {}
                
            from utils.config import ConfigManager
            config = ConfigManager()
            
            # 加载目标
            target = config.get("web_risk_scan", "target", fallback="")
            if hasattr(self, 'target_input'):
                self.target_input.setText(target)
            
            # 加载端口
            ports = config.get("web_risk_scan", "ports", fallback="80,443")
            if hasattr(self, 'port_input'):
                self.port_input.setText(ports)
            
            # 加载线程数
            threads = config.get_int("web_risk_scan", "threads", fallback=10)
            if hasattr(self, 'thread_input'):
                self.thread_input.setValue(threads)
            
            # 加载超时
            timeout = config.get_int("web_risk_scan", "timeout", fallback=10)
            if hasattr(self, 'timeout_input'):
                self.timeout_input.setValue(timeout)
            
            # 加载扫描深度
            scan_depth = config.get_int("web_risk_scan", "scan_depth", fallback=1)
            if hasattr(self, 'scan_depth_combo'):
                self.scan_depth_combo.setCurrentIndex(scan_depth)
            
            # 加载基本选项
            if hasattr(self, 'verify_ssl_check'):
                verify_ssl = config.get_boolean("web_risk_scan", "verify_ssl", fallback=False)
                self.verify_ssl_check.setChecked(verify_ssl)
            
            if hasattr(self, 'follow_redirect_check'):
                follow_redirect = config.get_boolean("web_risk_scan", "follow_redirect", fallback=True)
                self.follow_redirect_check.setChecked(follow_redirect)
            
            # 加载禁用插件的代码
            disabled_plugins_str = config.get("web_risk_scan", "disabled_plugins", fallback="")
            disabled_plugins = [p.strip() for p in disabled_plugins_str.split(",") if p.strip()]
            
            # 清空已有的禁用插件列表
            self.disabled_plugins = []
            
            # 设置禁用插件
            for plugin_id in disabled_plugins:
                self.disabled_plugins.append(plugin_id)
                plugin_manager.disable_plugin(plugin_id)
            
            self.logger.info(f"已从配置加载 {len(disabled_plugins)} 个禁用插件")
            
            # 加载插件配置
            import json
            plugins_config_json = config.get("web_risk_scan", "plugins_config", fallback="{}")
            try:
                plugins_config = json.loads(plugins_config_json)
                self.config['plugins_config'] = plugins_config
                self.logger.info(f"已从配置加载插件配置，包含 {len(plugins_config)} 个插件的配置")
            except json.JSONDecodeError as e:
                self.logger.warning(f"解析插件配置JSON失败: {str(e)}，将使用默认配置")
                self.config['plugins_config'] = {}
            
            self.logger.info("已加载Web风险扫描配置")
        except Exception as e:
            self.logger.error(f"加载Web风险扫描配置失败: {str(e)}")
            raise
    
    def save_config(self):
        """保存配置"""
        try:
            # 确保self.config已初始化
            if not hasattr(self, 'config'):
                self.config = {}
                
            from utils.config import ConfigManager
            config = ConfigManager()
            
            # 保存目标
            if self.manual_radio.isChecked():
                config.set("web_risk_scan", "target", self.target_input.text())
            
            # 保存端口
            config.set("web_risk_scan", "ports", self.port_input.text())
            
            # 保存线程数
            config.set("web_risk_scan", "threads", str(self.thread_input.value()))
            
            # 保存超时
            config.set("web_risk_scan", "timeout", str(self.timeout_input.value()))
            
            # 保存扫描深度
            config.set("web_risk_scan", "scan_depth", str(self.scan_depth_combo.currentIndex()))
            
            # 保存基本选项
            config.set("web_risk_scan", "verify_ssl", str(self.verify_ssl_check.isChecked()))
            config.set("web_risk_scan", "follow_redirect", str(self.follow_redirect_check.isChecked()))
            
            # 保存禁用插件的代码
            config.set("web_risk_scan", "disabled_plugins", ",".join(self.disabled_plugins))
            
            # 保存插件配置
            import json
            if 'plugins_config' in self.config:
                plugins_config_json = json.dumps(self.config['plugins_config'])
                config.set("web_risk_scan", "plugins_config", plugins_config_json)
            
            # 保存配置
            config.save()
            
            self.logger.info("已保存Web风险扫描配置")
            
        except Exception as e:
            self.logger.error(f"保存配置失败: {str(e)}")
    
    def setup_ui(self):
        """初始化UI组件"""
        # 主布局
        layout = QVBoxLayout(self)
        
        # 创建上下分隔布局
        splitter = QSplitter(Qt.Vertical)
        
        # 上部分 - 参数设置
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        # 创建左右布局，左侧为基本参数，右侧为选项
        params_layout = QHBoxLayout()
        
        # === 左侧基本参数 ===
        basic_params_group = QGroupBox("基本参数")
        basic_form_layout = QFormLayout(basic_params_group)
        
        # 目标输入类型：手动输入或从文件导入
        target_type_layout = QHBoxLayout()
        self.target_type_group = QButtonGroup(self)
        
        self.manual_radio = QRadioButton("手动输入")
        self.manual_radio.setChecked(True)
        self.target_type_group.addButton(self.manual_radio)
        
        self.file_radio = QRadioButton("从文件导入")
        self.target_type_group.addButton(self.file_radio)
        
        target_type_layout.addWidget(self.manual_radio)
        target_type_layout.addWidget(self.file_radio)
        target_type_layout.addStretch()
        
        basic_form_layout.addRow("输入类型:", target_type_layout)
        
        # 目标输入框
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("输入URL, IP或IP段 (例如: http://example.com, 192.168.1.1, 192.168.1.0/24)")
        basic_form_layout.addRow("目标:", self.target_input)
        
        # 文件选择（默认隐藏）
        self.file_select_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("选择包含URL列表的文件")
        self.file_select_layout.addWidget(self.file_path_input)
        
        self.browse_button = QPushButton("浏览...")
        self.file_select_layout.addWidget(self.browse_button)
        
        file_layout_widget = QWidget()
        file_layout_widget.setLayout(self.file_select_layout)
        file_layout_widget.setVisible(False)
        self.file_widget = file_layout_widget
        basic_form_layout.addRow("", file_layout_widget)
        
        # URL计数标签（默认隐藏）
        self.url_count_label = QLabel("已加载 0 个URL")
        self.url_count_label.setVisible(False)
        basic_form_layout.addRow("", self.url_count_label)
        
        # 端口
        self.port_input = QLineEdit("80,443")
        basic_form_layout.addRow("端口:", self.port_input)
        
        params_layout.addWidget(basic_params_group, 1)
        
        # === 扫描参数组 ===
        scan_params_group = QGroupBox("扫描参数")
        scan_params_layout = QFormLayout(scan_params_group)
        scan_params_layout.setVerticalSpacing(6)  # 减少垂直间距
        
        # 线程与超时设置
        thread_timeout_widget = QWidget()
        thread_timeout_layout = QHBoxLayout(thread_timeout_widget)
        thread_timeout_layout.setContentsMargins(0, 0, 0, 0)
        
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("线程数:"))
        self.thread_input = QSpinBox()
        self.thread_input.setRange(1, 200)
        self.thread_input.setValue(10)
        thread_layout.addWidget(self.thread_input)
        thread_timeout_layout.addLayout(thread_layout)
        
        thread_timeout_layout.addSpacing(20)  # 添加一些间距分隔
        
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("超时:"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 60)
        self.timeout_input.setValue(10)
        self.timeout_input.setSuffix(" 秒")
        timeout_layout.addWidget(self.timeout_input)
        thread_timeout_layout.addLayout(timeout_layout)
        
        scan_params_layout.addRow("", thread_timeout_widget)
        
        # 扫描深度选择器
        depth_widget = QWidget()
        depth_layout = QHBoxLayout(depth_widget)
        depth_layout.setContentsMargins(0, 0, 0, 0)
        depth_layout.addWidget(QLabel("扫描深度:"))
        self.scan_depth_combo = QComboBox()
        self.scan_depth_combo.addItem("基本检查", 0)
        self.scan_depth_combo.addItem("标准检查", 1)
        self.scan_depth_combo.addItem("深入检查", 2)
        self.scan_depth_combo.setCurrentIndex(1)  # 默认使用标准检查
        depth_layout.addWidget(self.scan_depth_combo)
        depth_layout.addStretch()
        scan_params_layout.addRow("", depth_widget)
        
        # 检查选项
        options_widget = QWidget()
        options_layout = QHBoxLayout(options_widget)
        options_layout.setContentsMargins(0, 0, 0, 0)
        
        # 验证SSL证书
        self.verify_ssl_check = QCheckBox("验证SSL证书")
        self.verify_ssl_check.setChecked(False)
        options_layout.addWidget(self.verify_ssl_check)
        
        options_layout.addSpacing(20)  # 添加一些间距分隔
        
        # 跟随重定向
        self.follow_redirect_check = QCheckBox("跟随重定向")
        self.follow_redirect_check.setChecked(True)
        options_layout.addWidget(self.follow_redirect_check)
        
        options_layout.addStretch()
        scan_params_layout.addRow("", options_widget)
        
        params_layout.addWidget(scan_params_group, 1)
        
        # === 右侧选项 ===
        options_group = QGroupBox("插件选项")
        options_layout = QVBoxLayout(options_group)
        
        # 插件管理按钮
        plugin_management_layout = QHBoxLayout()
        
        # 恢复插件管理按钮
        self.manage_plugins_button = QPushButton("管理扫描插件")
        plugin_management_layout.addWidget(self.manage_plugins_button)
        
        # 恢复插件配置按钮
        self.config_plugins_button = QPushButton("配置插件参数")
        plugin_management_layout.addWidget(self.config_plugins_button)
        
        options_layout.addLayout(plugin_management_layout)
        
        params_layout.addWidget(options_group, 1)
        
        top_layout.addLayout(params_layout)
        
        # 控制按钮
        control_layout = QHBoxLayout()
        
        self.start_button = QPushButton("开始扫描")
        self.start_button.setIcon(QIcon.fromTheme("system-run"))
        control_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("停止")
        self.stop_button.setIcon(QIcon.fromTheme("process-stop"))
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.stop_button)
        
        self.report_button = QPushButton("生成报告")
        self.report_button.setIcon(QIcon.fromTheme("text-x-generic"))
        self.report_button.setEnabled(False)
        control_layout.addWidget(self.report_button)
        
        top_layout.addLayout(control_layout)
        
        # 添加进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        top_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("就绪")
        top_layout.addWidget(self.status_label)
        
        # 下部分 - 结果显示
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        
        # 创建标签页容器
        self.result_tabs = QTabWidget()
        
        # 创建各个标签页
        # 总览标签页
        self.overview_table = self.create_overview_table()
        self.result_tabs.addTab(self.overview_table, "总览")
        
        # 漏洞标签页
        self.vuln_table = self.create_vuln_table()
        self.result_tabs.addTab(self.vuln_table, "漏洞")
        
        # 服务信息标签页
        self.service_table = self.create_service_table()
        self.result_tabs.addTab(self.service_table, "服务信息")
        
        # 安全响应头标签页
        self.headers_table = self.create_headers_table()
        self.result_tabs.addTab(self.headers_table, "安全响应头")
        
        bottom_layout.addWidget(self.result_tabs)
        
        # 添加到分隔布局
        splitter.addWidget(top_widget)
        splitter.addWidget(bottom_widget)
        
        # 设置分隔比例
        splitter.setSizes([300, 700])
        
        layout.addWidget(splitter)
        
        # 创建扫描线程
        self.scan_thread = None
        
        # 当前结果
        self.current_result = None

    def set_all_plugin_state(self, table, state):
        """设置所有插件状态
        
        Args:
            table: 插件表格
            state: 复选框状态 (Qt.Checked 或 Qt.Unchecked)
        """
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item:
                item.setCheckState(state)
    
    def invert_plugin_selection(self, table):
        """反选插件
        
        Args:
            table: 插件表格
        """
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item:
                current_state = item.checkState()
                new_state = Qt.Unchecked if current_state == Qt.Checked else Qt.Checked
                item.setCheckState(new_state)
    
    def save_plugin_selection(self, table, dialog):
        """保存插件选择结果
        
        Args:
            table: 插件表格
            dialog: 对话框
        """
        try:
            # 清空禁用插件列表
            self.disabled_plugins = []
            
            for row in range(table.rowCount()):
                plugin_id = self.all_plugins[row]['id']
                checked = table.item(row, 0).checkState() == Qt.Checked
                
                # 更新插件管理器状态
                if not checked:
                    plugin_manager.disable_plugin(plugin_id)
                    self.disabled_plugins.append(plugin_id)
                else:
                    plugin_manager.enable_plugin(plugin_id)
            
            disabled_count = sum(1 for row in range(table.rowCount()) 
                                if table.item(row, 0).checkState() != Qt.Checked)
            
            # 保存配置
            self.save_config()
            
            # 显示结果
            QMessageBox.information(
                dialog, "插件设置已保存", 
                f"已启用 {table.rowCount() - disabled_count} 个插件，禁用 {disabled_count} 个插件"
            )
            
            # 关闭对话框
            dialog.accept()
            
        except Exception as e:
            self.logger.error(f"保存插件选择失败: {str(e)}")
            QMessageBox.critical(dialog, "保存失败", f"保存插件选择时出错: {str(e)}")

    def get_scan_config(self):
        """获取扫描配置参数
        
        Returns:
            扫描参数字典
        """
        params = {}
        
        # 设置目标
        if self.manual_radio.isChecked():
            # 手动输入模式
            params["targets"] = self.target_input.text().strip()
        else:
            # 文件导入模式
            if not self.url_list:
                params["targets"] = ""
            else:
                params["targets"] = ",".join(self.url_list)
        
        # 端口
        params["ports"] = self.port_input.text().strip()
        
        # 线程数
        params["threads"] = self.thread_input.value()
        
        # 超时
        params["timeout"] = self.timeout_input.value()
        
        # 验证SSL
        params["verify_ssl"] = self.verify_ssl_check.isChecked()
        
        # 跟随重定向
        params["follow_redirects"] = self.follow_redirect_check.isChecked()
        
        # 扫描深度
        params["scan_depth"] = self.scan_depth_combo.currentIndex()
        
        # 禁用插件
        params["disabled_plugins"] = self.disabled_plugins
        
        # 插件配置
        params["plugins_config"] = self.config.get("plugins_config", {})
        
        # 用户代理
        params["user_agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        
        self.logger.info(f"扫描配置: 目标={params['targets']}, 端口={params['ports']}, 线程数={params['threads']}, 扫描深度={params['scan_depth']}")
        
        return params