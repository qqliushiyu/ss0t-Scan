#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
爆破扫描界面模块
提供对常见服务进行密码爆破的界面
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
    QProgressBar, QToolButton, QMenu, QAction, QInputDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QSize
from PyQt5.QtGui import QIcon, QColor

from core.bruteforce_scan import BruteforceScanner
from core.base_scanner import ScanResult

class BruteforcePanel(QWidget):
    """爆破扫描面板"""
    
    MODULE_ID = "bruteforce"
    MODULE_NAME = "爆破扫描"
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger("gui.panels.bruteforce")
        
        # 上次扫描结果
        self.last_scan_result = None
        
        # 初始化UI
        self.setup_ui()
        
        # 加载支持的服务类型
        self.load_service_types()
        
        # 连接信号和槽
        self.setup_connections()
    
    def setup_ui(self):
        """初始化UI组件"""
        # 创建主布局
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(2, 2, 2, 2)  # 减小边距
        main_layout.setSpacing(2)  # 减小间距
        
        # 创建顶部控制区域和结果区域的分割器
        splitter = QSplitter(Qt.Vertical)
        
        # === 顶部控制区域 ===
        control_widget = QWidget()
        control_layout = QVBoxLayout(control_widget)
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(3)  # 减小间距
        
        # 创建左右布局来放置基本参数和高级设置
        params_layout = QHBoxLayout()
        params_layout.setSpacing(2)  # 减小组件间间距
        
        # --- 左侧：基本参数区域 ---
        basic_params_group = QGroupBox("基本参数")
        basic_params_layout = QVBoxLayout(basic_params_group)
        basic_params_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        basic_params_layout.setSpacing(3)  # 减小垂直间距
        
        # 扫描模式选择
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(3)
        
        mode_label = QLabel("模式:")
        mode_label.setFixedWidth(50)  # 统一标签宽度
        mode_layout.addWidget(mode_label)
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("单一目标爆破", "single")
        self.mode_combo.addItem("网段扫描爆破", "network")
        self.mode_combo.setMinimumHeight(22)  # 统一控件高度
        mode_layout.addWidget(self.mode_combo)
        
        basic_params_layout.addLayout(mode_layout)
        
        # 目标输入和文件加载按钮在同一行
        target_layout = QHBoxLayout()
        target_layout.setSpacing(3)
        
        target_label = QLabel("目标:")
        target_label.setFixedWidth(50)  # 统一标签宽度
        target_layout.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("输入目标主机或网段，例如: 192.168.1.0/24")
        self.target_input.setMinimumHeight(22)  # 统一控件高度
        target_layout.addWidget(self.target_input)
        
        self.load_targets_btn = QPushButton("文件")
        self.load_targets_btn.setFixedWidth(40)  # 减小按钮宽度
        self.load_targets_btn.setFixedHeight(22)  # 统一按钮高度
        self.load_targets_btn.setToolTip("从文件加载目标")
        target_layout.addWidget(self.load_targets_btn)
        
        basic_params_layout.addLayout(target_layout)
        
        # 服务类型选择
        service_layout = QHBoxLayout()
        service_layout.setSpacing(3)
        
        service_label = QLabel("服务:")
        service_label.setFixedWidth(50)  # 统一标签宽度
        service_layout.addWidget(service_label)
        
        service_type_port_layout = QHBoxLayout()
        service_type_port_layout.setSpacing(5)
        
        self.service_combo = QComboBox()
        self.service_combo.setToolTip("选择要爆破的服务类型")
        self.service_combo.setMinimumHeight(22)  # 统一控件高度
        service_type_port_layout.addWidget(self.service_combo, 1)  # 让服务类型占据更多空间
        
        # 服务端口
        port_layout = QHBoxLayout()
        port_layout.setSpacing(2)
        port_layout.addWidget(QLabel("端口:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)  # 默认SSH端口
        self.port_input.setFixedWidth(60)
        self.port_input.setFixedHeight(22)  # 统一控件高度
        port_layout.addWidget(self.port_input)
        
        service_type_port_layout.addLayout(port_layout)
        service_layout.addLayout(service_type_port_layout)
        
        basic_params_layout.addLayout(service_layout)
        
        # 用户名输入
        username_layout = QHBoxLayout()
        username_layout.setSpacing(3)
        
        username_label = QLabel("用户名:")
        username_label.setFixedWidth(50)  # 统一标签宽度
        username_layout.addWidget(username_label)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("输入用户名，多个用逗号分隔")
        self.username_input.setMinimumHeight(22)  # 统一控件高度
        username_layout.addWidget(self.username_input)
        
        self.load_usernames_btn = QPushButton("文件")
        self.load_usernames_btn.setFixedWidth(40)
        self.load_usernames_btn.setFixedHeight(22)  # 统一按钮高度
        self.load_usernames_btn.setToolTip("从文件加载用户名列表")
        username_layout.addWidget(self.load_usernames_btn)
        
        basic_params_layout.addLayout(username_layout)
        
        # 密码输入
        password_layout = QHBoxLayout()
        password_layout.setSpacing(3)
        
        password_label = QLabel("密码:")
        password_label.setFixedWidth(50)  # 统一标签宽度
        password_layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("输入密码，多个用逗号分隔")
        self.password_input.setMinimumHeight(22)  # 统一控件高度
        password_layout.addWidget(self.password_input)
        
        self.load_passwords_btn = QPushButton("文件")
        self.load_passwords_btn.setFixedWidth(40)
        self.load_passwords_btn.setFixedHeight(22)  # 统一按钮高度
        self.load_passwords_btn.setToolTip("从文件加载密码列表")
        password_layout.addWidget(self.load_passwords_btn)
        
        basic_params_layout.addLayout(password_layout)
        
        # 添加弹性空间
        basic_params_layout.addStretch(1)
        
        # --- 右侧：高级设置区域 ---
        advanced_params_group = QGroupBox("高级设置")
        advanced_params_layout = QVBoxLayout(advanced_params_group)
        advanced_params_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        advanced_params_layout.setSpacing(3)  # 减小垂直间距
        
        # 线程数设置
        threads_layout = QHBoxLayout()
        threads_layout.setSpacing(3)
        
        threads_label = QLabel("线程数:")
        threads_label.setFixedWidth(45)  # 统一标签宽度
        threads_layout.addWidget(threads_label)
        
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 50)
        self.threads_input.setValue(10)
        self.threads_input.setFixedWidth(50)
        self.threads_input.setFixedHeight(22)  # 统一控件高度
        threads_layout.addWidget(self.threads_input)
        threads_layout.addStretch(1)
        
        advanced_params_layout.addLayout(threads_layout)
        
        # 超时设置
        timeout_layout = QHBoxLayout()
        timeout_layout.setSpacing(3)
        
        timeout_label = QLabel("超时:")
        timeout_label.setFixedWidth(45)  # 统一标签宽度
        timeout_layout.addWidget(timeout_label)
        
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 60)
        self.timeout_input.setValue(3)
        self.timeout_input.setSuffix(" 秒")
        self.timeout_input.setFixedWidth(70)
        self.timeout_input.setFixedHeight(22)  # 统一控件高度
        timeout_layout.addWidget(self.timeout_input)
        timeout_layout.addStretch(1)
        
        advanced_params_layout.addLayout(timeout_layout)

        # 扫描选项（网段扫描模式下的选项）
        self.scan_options_group = QGroupBox("扫描选项")
        self.scan_options_group.setVisible(False)  # 默认隐藏
        scan_options_layout = QVBoxLayout(self.scan_options_group)
        scan_options_layout.setContentsMargins(5, 8, 5, 5)
        scan_options_layout.setSpacing(3)
        
        # 服务检测选项
        self.service_detection_check = QCheckBox("扫描前检测服务是否开放")
        self.service_detection_check.setChecked(True)
        scan_options_layout.addWidget(self.service_detection_check)
        
        # 只对开放服务爆破选项
        self.only_brute_open_check = QCheckBox("只对开放的服务进行爆破")
        self.only_brute_open_check.setChecked(True)
        scan_options_layout.addWidget(self.only_brute_open_check)
        
        advanced_params_layout.addWidget(self.scan_options_group)
        
        # 停止条件
        stop_condition_layout = QHBoxLayout()
        stop_condition_layout.setSpacing(3)
        
        self.stop_on_success_check = QCheckBox("找到一个凭据即停止")
        self.stop_on_success_check.setChecked(True)
        stop_condition_layout.addWidget(self.stop_on_success_check)
        stop_condition_layout.addStretch(1)
        
        advanced_params_layout.addLayout(stop_condition_layout)
        
        # 添加弹性空间
        advanced_params_layout.addStretch(1)
        
        # 将左右参数组添加到参数布局
        params_layout.addWidget(basic_params_group, 3)  # 基本参数占比更大
        params_layout.addWidget(advanced_params_group, 2)  # 高级设置占比较小
        
        # 添加参数布局到控制布局
        control_layout.addLayout(params_layout)
        
        # --- 操作按钮区域 ---
        action_layout = QHBoxLayout()
        action_layout.setSpacing(5)
        
        # 统一按钮高度
        button_height = 25
        
        # 操作按钮
        self.start_btn = QPushButton("开始扫描")
        self.start_btn.setFixedHeight(button_height)
        action_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setFixedHeight(button_height)
        action_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("清除结果")
        self.clear_btn.setFixedHeight(button_height)
        action_layout.addWidget(self.clear_btn)
        
        self.export_btn = QPushButton("导出报告")
        self.export_btn.setEnabled(False)
        self.export_btn.setFixedHeight(button_height)
        action_layout.addWidget(self.export_btn)
        
        # 添加弹性空间，右对齐按钮
        action_layout.addStretch(1)
        
        control_layout.addLayout(action_layout)
        
        # --- 进度条区域 ---
        progress_layout = QVBoxLayout()
        progress_layout.setContentsMargins(0, 2, 0, 0)
        progress_layout.setSpacing(1)  # 进度条和标签之间的间距最小化
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(12)  # 设置进度条高度
        self.progress_bar.setMaximumHeight(12)  # 确保进度条不会太高
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("就绪")
        self.progress_label.setMinimumHeight(12)  # 设置状态标签高度
        self.progress_label.setMaximumHeight(12)  # 确保状态标签不会太高
        progress_layout.addWidget(self.progress_label)
        
        control_layout.addLayout(progress_layout)
        
        # 添加控制区域到分割器
        splitter.addWidget(control_widget)
        
        # === 结果显示区域 ===
        result_tabs = QTabWidget()
        
        # 表格视图标签页
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels(["目标", "服务", "端口", "状态", "成功凭据", "用时"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.result_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.result_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.result_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        # 设置更紧凑的行高
        self.result_table.verticalHeader().setDefaultSectionSize(22)
        self.result_table.verticalHeader().setVisible(False)  # 隐藏垂直表头以节省空间
        result_tabs.addTab(self.result_table, "扫描结果")
        
        # 详细信息标签页
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        result_tabs.addTab(self.detail_text, "详细信息")
        
        splitter.addWidget(result_tabs)
        
        # 设置分割比例
        splitter.setSizes([200, 500])  # 控制区域更紧凑，结果区域更大
        main_layout.addWidget(splitter)
    
    def setup_connections(self):
        """设置信号和槽连接"""
        # 按钮信号连接
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.clear_btn.clicked.connect(self.clear_results)
        self.export_btn.clicked.connect(self.export_results)
        
        # 文件加载按钮
        self.load_targets_btn.clicked.connect(self.load_targets_from_file)
        self.load_usernames_btn.clicked.connect(self.load_usernames_from_file)
        self.load_passwords_btn.clicked.connect(self.load_passwords_from_file)
        
        # 服务类型变化时更新端口
        self.service_combo.currentIndexChanged.connect(self.update_default_port)
        
        # 结果表格点击事件
        self.result_table.itemSelectionChanged.connect(self.update_detail_view)
        
        # 模式选择事件
        self.mode_combo.currentIndexChanged.connect(self.switch_mode)
    
    def load_service_types(self):
        """加载支持的服务类型到下拉框"""
        # 清空当前列表
        self.service_combo.clear()
        
        # 获取支持的服务
        services = BruteforceScanner.get_supported_services()
        
        # 添加到下拉框
        for service in services:
            service_id = service["id"]
            service_name = service["name"]
            service_available = service["available"]
            
            # 只显示可用的服务
            if service_available:
                self.service_combo.addItem(service_name, service_id)
            else:
                # 不可用的服务显示为灰色并标记为不可用
                self.service_combo.addItem(f"{service_name} (未安装依赖)", service_id)
                index = self.service_combo.count() - 1
                self.service_combo.model().item(index).setEnabled(False)
        
        # 默认选择第一个可用服务
        if self.service_combo.count() > 0:
            self.service_combo.setCurrentIndex(0)
            self.update_default_port()
    
    def update_default_port(self):
        """根据选择的服务类型更新默认端口"""
        current_service_id = self.service_combo.currentData()
        if not current_service_id:
            return
        
        # 获取默认端口
        services = BruteforceScanner.get_supported_services()
        for service in services:
            if service["id"] == current_service_id:
                self.port_input.setValue(service["default_port"])
                break

    def update_detail_view(self):
        """更新详细信息视图"""
        # 获取选中的行
        selected_rows = self.result_table.selectionModel().selectedRows()
        if not selected_rows:
            self.detail_text.setText("")
            return
        
        # 获取选中行的目标信息
        row = selected_rows[0].row()
        target = self.result_table.item(row, 0).text()
        service = self.result_table.item(row, 1).text()
        port = self.result_table.item(row, 2).text()
        status = self.result_table.item(row, 3).text()
        creds = self.result_table.item(row, 4).text()
        
        # 在结果数据中查找详细信息
        if not self.last_scan_result or not self.last_scan_result.data:
            self.detail_text.setText("无详细信息可用")
            return
        
        # 查找对应的目标数据
        target_data = None
        for item in self.last_scan_result.data:
            if item.get("target") == target:
                target_data = item
                break
        
        if not target_data:
            self.detail_text.setText("未找到目标详细信息")
            return
        
        # 构建详细信息文本
        detail_lines = [
            f"目标: {target}",
            f"服务: {service}",
            f"端口: {port}",
            f"状态: {status}",
            f"扫描时间: {target_data.get('duration', 0):.2f}秒",
            "",
            "成功凭据:"
        ]
        
        if target_data.get("credentials"):
            for idx, cred in enumerate(target_data["credentials"], 1):
                username = cred.get("username", "")
                password = cred.get("password", "")
                time_found = cred.get("time", 0)
                time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_found)) if time_found else ""
                
                detail_lines.append(f"{idx}. 用户名: {username}")
                detail_lines.append(f"   密码: {password}")
                detail_lines.append(f"   发现时间: {time_str}")
                detail_lines.append("")
        else:
            detail_lines.append("无成功凭据")
        
        # 更新详细信息文本框
        self.detail_text.setText("\n".join(detail_lines))

    def load_targets_from_file(self):
        """从文件加载目标列表"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            if targets:
                # 更新目标输入框
                self.target_input.setText(",".join(targets))
                QMessageBox.information(self, "加载成功", f"成功加载 {len(targets)} 个目标")
            else:
                QMessageBox.warning(self, "加载失败", "文件不包含有效目标")
        
        except Exception as e:
            QMessageBox.critical(self, "加载失败", f"加载目标文件时出错: {str(e)}")
    
    def load_usernames_from_file(self):
        """从文件加载用户名列表"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择用户名文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
            
            if usernames:
                # 更新用户名输入框
                self.username_input.setText(",".join(usernames))
                QMessageBox.information(self, "加载成功", f"成功加载 {len(usernames)} 个用户名")
            else:
                QMessageBox.warning(self, "加载失败", "文件不包含有效用户名")
        
        except Exception as e:
            QMessageBox.critical(self, "加载失败", f"加载用户名文件时出错: {str(e)}")
    
    def load_passwords_from_file(self):
        """从文件加载密码列表"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择密码文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if passwords:
                # 更新密码输入框
                current_text = self.password_input.text()
                if current_text:
                    # 如果已有密码，询问是覆盖还是追加
                    reply = QMessageBox.question(
                        self, 
                        "加载密码", 
                        "是否覆盖现有密码？选择'否'将追加到现有密码",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    
                    if reply == QMessageBox.Yes:
                        self.password_input.setText(",".join(passwords))
                    else:
                        self.password_input.setText(current_text + "," + ",".join(passwords))
                else:
                    self.password_input.setText(",".join(passwords))
                
                QMessageBox.information(self, "加载成功", f"成功加载 {len(passwords)} 个密码")
            else:
                QMessageBox.warning(self, "加载失败", "文件不包含有效密码")
        
        except Exception as e:
            QMessageBox.critical(self, "加载失败", f"加载密码文件时出错: {str(e)}")
    
    def switch_mode(self):
        """根据选择的模式切换UI"""
        mode = self.mode_combo.currentData()
        
        if mode == "network":
            # 网段扫描模式
            self.target_input.setPlaceholderText("输入网段，例如: 192.168.1.0/24, 10.0.0.1-10.0.0.100")
            self.scan_options_group.setVisible(True)
        else:
            # 单一目标模式
            self.target_input.setPlaceholderText("输入目标主机，多个目标用逗号分隔")
            self.scan_options_group.setVisible(False)

    def get_scan_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        # 扫描模式
        mode = self.mode_combo.currentData()
        
        # 解析目标
        targets = self.target_input.text().strip()
        
        # 获取服务类型
        service_type = self.service_combo.currentData()
        
        # 解析用户名列表
        username_text = self.username_input.text().strip()
        username_list = []
        if username_text:
            username_list = [u.strip() for u in username_text.split(',') if u.strip()]
        
        # 解析密码列表
        password_text = self.password_input.text().strip()
        password_list = []
        if password_text:
            password_list = [p.strip() for p in password_text.split(',') if p.strip()]
        
        # 构造配置
        config = {
            'mode': mode,
            'targets': targets,
            'service_type': service_type,
            'port': self.port_input.value(),
            'username_list': username_list,
            'password_list': password_list,
            'threads': self.threads_input.value(),
            'timeout': self.timeout_input.value(),
            'stop_on_success': self.stop_on_success_check.isChecked()
        }
        
        # 网段扫描模式的特殊配置
        if mode == "network":
            config['service_detection'] = self.service_detection_check.isChecked()
            config['only_brute_open'] = self.only_brute_open_check.isChecked()
        
        return config
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """验证扫描配置"""
        # 检查目标
        if not config['targets']:
            QMessageBox.warning(self, "配置错误", "请输入至少一个目标")
            return False
        
        # 检查用户名
        if not config['username_list']:
            QMessageBox.warning(self, "配置错误", "请输入至少一个用户名")
            return False
        
        # 检查密码
        if not config['password_list']:
            QMessageBox.warning(self, "配置错误", "请输入至少一个密码")
            return False
        
        # 检查服务类型
        services = BruteforceScanner.get_supported_services()
        service_available = False
        for service in services:
            if service["id"] == config['service_type'] and service["available"]:
                service_available = True
                break
        
        if not service_available:
            QMessageBox.warning(
                self, 
                "配置错误", 
                f"无法使用 {config['service_type']} 服务，可能缺少所需的依赖库"
            )
            return False
        
        return True
    
    def start_scan(self):
        """开始爆破扫描"""
        # 获取配置
        config = self.get_scan_config()
        
        # 验证配置
        if not self.validate_config(config):
            return
        
        # 如果是网段扫描模式，需要解析网段
        if config['mode'] == "network":
            # 导入网络工具模块
            from utils.network import parse_ip_range, is_port_open
            
            # 解析IP范围
            ip_list = parse_ip_range(config['targets'])
            if not ip_list:
                QMessageBox.warning(self, "配置错误", "无法解析网段，请检查输入格式")
                return
            
            total_ips = len(ip_list)
            
            # 显示扫描任务大小的警告信息
            if config['service_detection']:
                warning_text = f"您将扫描 {total_ips} 个IP地址，并对开放服务进行爆破。"
            else:
                task_size = total_ips * len(config['username_list']) * len(config['password_list'])
                warning_text = f"您将对 {total_ips} 个IP地址进行爆破，共 {task_size} 个凭据组合，可能需要较长时间。"
            
            reply = QMessageBox.question(
                self,
                "扫描任务确认",
                f"{warning_text}是否继续？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.No:
                return
            
            # 使用字符串形式的IP列表
            config['targets'] = ip_list
        else:
            # 单一目标模式，可能有多个目标（逗号分隔）
            if ',' in config['targets']:
                targets = [t.strip() for t in config['targets'].split(',') if t.strip()]
                config['targets'] = targets
                
                # 显示扫描任务大小的警告信息
                task_size = len(targets) * len(config['username_list']) * len(config['password_list'])
                if task_size > 10000:
                    reply = QMessageBox.question(
                        self,
                        "扫描任务确认",
                        f"您的扫描任务将尝试 {task_size} 个凭据组合，可能需要较长时间。是否继续？",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    
                    if reply == QMessageBox.No:
                        return
        
        # 清空结果
        self.clear_results()
        
        # 创建扫描器
        scanner = BruteforceScanner(config)
        
        # 创建并启动扫描线程
        self.scan_thread = ScanThread(scanner)
        self.scan_thread.scan_complete.connect(self.on_scan_finished)
        self.scan_thread.scan_progress.connect(self.update_progress)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        
        # 更新UI状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_label.setText("正在准备...")
        self.progress_bar.setValue(0)
        
        # 启动线程
        self.scan_thread.start()
        
        self.logger.info(f"开始{config['mode'] == 'network' and '网段' or ''}爆破扫描，目标数: {len(config['targets']) if isinstance(config['targets'], list) else 1}, 用户名数: {len(config['username_list'])}, 密码数: {len(config['password_list'])}")
    
    def stop_scan(self):
        """停止爆破扫描"""
        if self.scan_thread and self.scan_thread.isRunning():
            # 尝试安全停止扫描
            self.logger.info("用户请求停止爆破扫描")
            self.progress_label.setText("正在停止...")
            self.scan_thread.scanner.stop()
            
            # 禁用停止按钮，防止多次点击
            self.stop_btn.setEnabled(False)
    
    def on_scan_finished(self, result: ScanResult):
        """扫描完成回调"""
        # 更新UI状态
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if not result:
            self.logger.warning("扫描线程未返回结果")
            return
        
        self.last_scan_result = result
        
        # 更新UI
        if result.success:
            self.progress_label.setText(f"扫描完成，成功破解 {self.count_successful_targets(result.data)} 个目标")
            self.progress_bar.setValue(100)
            
            # 显示结果
            self.display_results(result)
            
            # 启用导出按钮
            self.export_btn.setEnabled(True)
        else:
            self.progress_label.setText(f"扫描失败: {result.error_msg}")
            self.progress_bar.setValue(0)
        
        self.logger.info(f"爆破扫描完成，用时: {result.duration:.2f}秒")
    
    def update_progress(self, percent: int, message: str):
        """更新扫描进度"""
        self.progress_bar.setValue(percent)
        self.progress_label.setText(message)
    
    def on_scan_error(self, error_msg: str):
        """扫描出错回调"""
        self.logger.error(f"扫描出错: {error_msg}")
        
        # 更新UI状态
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_label.setText(f"扫描错误: {error_msg}")
        self.progress_bar.setValue(0)
        
        # 显示错误消息
        QMessageBox.critical(self, "扫描错误", f"扫描过程中出错:\n{error_msg}")
    
    def count_successful_targets(self, data: List[Dict[str, Any]]) -> int:
        """计算成功破解的目标数量"""
        count = 0
        for item in data:
            if item.get("status") == "success" and item.get("credentials"):
                count += 1
        return count

    def clear_results(self):
        """清除扫描结果"""
        self.result_table.setRowCount(0)
        self.detail_text.setText("")
        self.last_scan_result = None
        self.export_btn.setEnabled(False)
        self.progress_label.setText("就绪")
        self.progress_bar.setValue(0)
    
    def export_results(self):
        """导出扫描结果"""
        if not self.last_scan_result or not self.last_scan_result.data:
            QMessageBox.warning(self, "导出错误", "没有可导出的结果")
            return
        
        # 选择导出格式和文件路径
        export_format, ok = QInputDialog.getItem(
            self, 
            "选择导出格式", 
            "请选择导出格式:", 
            ["CSV", "JSON", "TXT"], 
            0, 
            False
        )
        
        if not ok or not export_format:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "保存结果", 
            f"bruteforce_result.{export_format.lower()}", 
            f"{export_format} 文件 (*.{export_format.lower()});;所有文件 (*)"
        )
        
        if not file_path:
            return
        
        try:
            # 根据格式导出
            if export_format.upper() == "CSV":
                self.export_to_csv(file_path)
            elif export_format.upper() == "JSON":
                self.export_to_json(file_path)
            elif export_format.upper() == "TXT":
                self.export_to_txt(file_path)
            
            QMessageBox.information(self, "导出成功", f"结果已成功导出到:\n{file_path}")
        
        except Exception as e:
            QMessageBox.critical(self, "导出错误", f"导出结果时出错:\n{str(e)}")
    
    def export_to_csv(self, file_path: str):
        """导出为CSV格式"""
        import csv
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # 写入标题行
            writer.writerow(["目标", "服务", "端口", "状态", "用户名", "密码", "发现时间", "用时(秒)"])
            
            # 写入数据行
            for item in self.last_scan_result.data:
                target = item.get("target", "")
                service = item.get("service", "")
                port = item.get("port", "")
                status = item.get("status", "")
                duration = item.get("duration", 0)
                
                if item.get("credentials"):
                    for cred in item["credentials"]:
                        username = cred.get("username", "")
                        password = cred.get("password", "")
                        time_found = cred.get("time", 0)
                        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_found)) if time_found else ""
                        
                        writer.writerow([target, service, port, status, username, password, time_str, f"{duration:.2f}"])
                else:
                    writer.writerow([target, service, port, status, "", "", "", f"{duration:.2f}"])
    
    def export_to_json(self, file_path: str):
        """导出为JSON格式"""
        import json
        
        # 直接导出结果数据
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.last_scan_result.to_dict(), f, ensure_ascii=False, indent=2)
    
    def export_to_txt(self, file_path: str):
        """导出为TXT格式"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=== 爆破扫描结果 ===\n\n")
            
            # 写入基本信息
            f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            if self.last_scan_result.metadata:
                service_type = self.last_scan_result.metadata.get("service_type", "")
                f.write(f"服务类型: {service_type}\n")
                f.write(f"目标数量: {self.last_scan_result.metadata.get('target_count', 0)}\n")
                f.write(f"用户名数量: {self.last_scan_result.metadata.get('username_count', 0)}\n")
                f.write(f"密码数量: {self.last_scan_result.metadata.get('password_count', 0)}\n")
            
            f.write(f"扫描用时: {self.last_scan_result.duration:.2f}秒\n")
            f.write("\n")
            
            # 写入成功的目标
            successful_targets = [item for item in self.last_scan_result.data if item.get("status") == "success" and item.get("credentials")]
            
            f.write(f"成功破解的目标数量: {len(successful_targets)}\n\n")
            
            # 逐个写入目标信息
            for item in self.last_scan_result.data:
                target = item.get("target", "")
                service = item.get("service", "")
                port = item.get("port", "")
                status = self.format_status(item.get("status", ""))
                
                f.write(f"目标: {target}\n")
                f.write(f"服务: {service}\n")
                f.write(f"端口: {port}\n")
                f.write(f"状态: {status}\n")
                
                if item.get("credentials"):
                    f.write("成功凭据:\n")
                    for idx, cred in enumerate(item["credentials"], 1):
                        username = cred.get("username", "")
                        password = cred.get("password", "")
                        f.write(f"  {idx}. {username}:{password}\n")
                else:
                    f.write("无成功凭据\n")
                
                f.write("\n" + "-" * 50 + "\n\n")

    def format_status(self, status: str) -> str:
        """格式化状态文本"""
        if status == "success":
            return "成功"
        elif status == "failed":
            return "失败"
        elif status == "in_progress":
            return "进行中"
        return status

    def display_results(self, result: ScanResult):
        """显示扫描结果"""
        if not result or not result.data:
            return
        
        # 清空表格
        self.result_table.setRowCount(0)
        
        # 填充表格
        for row_idx, item in enumerate(result.data):
            target = item.get("target", "")
            service = item.get("service", "")
            port = item.get("port", 0)
            status = item.get("status", "unknown")
            credentials = item.get("credentials", [])
            duration = item.get("duration", 0)
            
            # 添加新行
            self.result_table.insertRow(row_idx)
            
            # 设置单元格内容
            self.result_table.setItem(row_idx, 0, QTableWidgetItem(target))
            self.result_table.setItem(row_idx, 1, QTableWidgetItem(service))
            self.result_table.setItem(row_idx, 2, QTableWidgetItem(str(port)))
            
            # 状态列，根据状态设置不同颜色
            status_item = QTableWidgetItem(self.format_status(status))
            if status == "success":
                status_item.setForeground(QColor("green"))
            elif status == "failed":
                status_item.setForeground(QColor("red"))
            elif status == "in_progress":
                status_item.setForeground(QColor("blue"))
            self.result_table.setItem(row_idx, 3, status_item)
            
            # 凭据列
            cred_text = ""
            if credentials:
                cred_list = []
                for cred in credentials:
                    username = cred.get("username", "")
                    password = cred.get("password", "")
                    cred_list.append(f"{username}:{password}")
                cred_text = ", ".join(cred_list)
            
            self.result_table.setItem(row_idx, 4, QTableWidgetItem(cred_text))
            
            # 用时列
            self.result_table.setItem(row_idx, 5, QTableWidgetItem(f"{duration:.2f}秒"))
        
        # 如果有结果，默认选中第一行
        if self.result_table.rowCount() > 0:
            self.result_table.selectRow(0)
            self.update_detail_view()

class ScanThread(QThread):
    """爆破扫描线程"""
    
    scan_complete = pyqtSignal(object)
    scan_progress = pyqtSignal(int, str)
    scan_error = pyqtSignal(str)
    
    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        self.scanner.set_progress_callback(self.update_progress)
    
    def run(self):
        try:
            result = self.scanner.execute()
            self.scan_complete.emit(result)
        except Exception as e:
            self.scan_error.emit(str(e))
    
    def update_progress(self, percent, message):
        self.scan_progress.emit(percent, message) 