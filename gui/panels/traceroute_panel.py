#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
路由追踪面板
用于图形化操作路由追踪模块
"""

import logging
import platform
from typing import Dict, List, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QPushButton, QLabel, QLineEdit, QCheckBox, QSpinBox, 
    QDoubleSpinBox, QComboBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QRadioButton, QButtonGroup,
    QToolButton, QSizePolicy, QProgressBar, QSplitter
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from gui.panels.base_panel import BasePanel
from utils.network import is_valid_ip


class TraceroutePanel(BasePanel):
    """路由追踪面板"""
    
    MODULE_ID = "traceroute"
    MODULE_NAME = "路由追踪"
    
    def __init__(self, parent=None):
        """初始化路由追踪面板"""
        super().__init__(parent)
    
    def create_param_group(self):
        """创建参数组"""
        self.param_group = QGroupBox("扫描参数")
        param_layout = QVBoxLayout()
        param_layout.setSpacing(5)
        param_layout.setContentsMargins(5, 5, 5, 5)
        
        # 顶部参数行 - 包含目标输入和最大跳数
        top_params_layout = QHBoxLayout()
        
        # 目标输入
        target_layout = QVBoxLayout()
        target_label = QLabel("目标:")
        target_layout.addWidget(target_label)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP地址或域名 (如: example.com 或 8.8.8.8)")
        target_layout.addWidget(self.target_input)
        top_params_layout.addLayout(target_layout, 4)
        
        # 添加一个垂直分隔器
        params_right_layout = QVBoxLayout()
        params_right_layout.setSpacing(5)
        
        # 最大跳数和超时设置放在一行
        hop_timeout_layout = QHBoxLayout()
        
        # 最大跳数
        hop_layout = QVBoxLayout()
        hop_label = QLabel("最大跳数:")
        hop_layout.addWidget(hop_label)
        self.max_hops_spin = QSpinBox()
        self.max_hops_spin.setRange(1, 100)
        self.max_hops_spin.setValue(30)
        hop_layout.addWidget(self.max_hops_spin)
        hop_timeout_layout.addLayout(hop_layout)
        
        # 超时设置
        timeout_layout = QVBoxLayout()
        timeout_label = QLabel("超时:")
        timeout_layout.addWidget(timeout_label)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setSingleStep(0.1)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSuffix(" 秒")
        timeout_layout.addWidget(self.timeout_spin)
        hop_timeout_layout.addLayout(timeout_layout)
        
        params_right_layout.addLayout(hop_timeout_layout)
        top_params_layout.addLayout(params_right_layout, 2)
        param_layout.addLayout(top_params_layout)
        
        # 下部选项布局 - 包含追踪方法和高级选项
        bottom_options_layout = QHBoxLayout()
        
        # 追踪方法
        method_group = QGroupBox("追踪方法")
        method_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        method_layout = QHBoxLayout()
        method_layout.setSpacing(5)
        method_layout.setContentsMargins(5, 5, 5, 5)
        
        self.method_button_group = QButtonGroup(self)
        
        # ICMP方法
        self.icmp_radio = QRadioButton("ICMP")
        self.method_button_group.addButton(self.icmp_radio, 1)
        method_layout.addWidget(self.icmp_radio)
        
        # UDP方法
        self.udp_radio = QRadioButton("UDP")
        self.method_button_group.addButton(self.udp_radio, 2)
        method_layout.addWidget(self.udp_radio)
        
        # 设置默认方法
        system = platform.system().lower()
        if system == "windows":
            self.icmp_radio.setChecked(True)
        else:
            self.udp_radio.setChecked(True)
        
        method_group.setLayout(method_layout)
        bottom_options_layout.addWidget(method_group)
        
        # 高级选项
        advanced_group = QGroupBox("高级选项")
        advanced_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        advanced_layout = QHBoxLayout()
        advanced_layout.setSpacing(5)
        advanced_layout.setContentsMargins(5, 5, 5, 5)
        
        # 探测次数
        probe_layout = QHBoxLayout()
        probe_layout.addWidget(QLabel("探测次数:"))
        self.probe_count_spin = QSpinBox()
        self.probe_count_spin.setRange(1, 10)
        self.probe_count_spin.setValue(3)
        probe_layout.addWidget(self.probe_count_spin)
        advanced_layout.addLayout(probe_layout)
        
        # 是否解析主机名
        self.resolve_check = QCheckBox("解析主机名")
        self.resolve_check.setChecked(True)
        advanced_layout.addWidget(self.resolve_check)
        
        # UDP端口设置
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("UDP端口:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(33434)  # traceroute默认端口
        port_layout.addWidget(self.port_spin)
        advanced_layout.addLayout(port_layout)
        
        advanced_group.setLayout(advanced_layout)
        bottom_options_layout.addWidget(advanced_group, 1)
        
        param_layout.addLayout(bottom_options_layout)
        
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
    
    def get_scan_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        return {
            "target": self.target_input.text().strip(),
            "method": "icmp" if self.icmp_radio.isChecked() else "udp",
            "max_hops": self.max_hops_spin.value(),
            "timeout": self.timeout_spin.value(),
            "probe_count": self.probe_count_spin.value(),
            "resolve": self.resolve_check.isChecked(),
            "port": self.port_spin.value()
        }
    
    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """设置扫描配置到UI控件"""
        if "target" in config:
            self.target_input.setText(str(config["target"]))
        
        if "method" in config:
            method = config["method"]
            if method == "icmp":
                self.icmp_radio.setChecked(True)
            elif method == "udp":
                self.udp_radio.setChecked(True)
        
        if "max_hops" in config:
            self.max_hops_spin.setValue(int(config["max_hops"]))
        
        if "timeout" in config:
            self.timeout_spin.setValue(float(config["timeout"]))
        
        if "probe_count" in config:
            self.probe_count_spin.setValue(int(config["probe_count"]))
        
        if "resolve" in config:
            self.resolve_check.setChecked(config["resolve"])
        
        if "port" in config:
            self.port_spin.setValue(int(config["port"]))
    
    def validate_params(self, config: Dict[str, Any]) -> bool:
        """验证扫描参数"""
        # 检查目标
        target = config.get("target", "")
        if not target:
            QMessageBox.warning(self, "参数错误", "请输入目标IP或域名")
            return False
        
        # 检查目标格式（简单验证）
        if not is_valid_ip(target) and "." not in target:
            QMessageBox.warning(self, "参数错误", "无效的目标IP或域名格式")
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
        
        # 为路由追踪结果设置自定义列
        columns = ["hop", "ip", "hostname", "avg_time", "loss_rate"]
        column_names = ["跳数", "IP地址", "主机名", "平均响应时间(ms)", "丢包率"]
        
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
        for row, hop in enumerate(data):
            for col, key in enumerate(columns):
                value = hop.get(key, "")
                
                # 特殊处理
                if key == "avg_time" and value:
                    value = f"{float(value):.2f}"
                elif key == "loss_rate" and value is not None:
                    value = f"{float(value) * 100:.0f}%"
                
                item = QTableWidgetItem(str(value) if value is not None else "")
                
                # 设置颜色 - 根据丢包率着色
                if key == "loss_rate":
                    try:
                        loss_rate = float(hop.get("loss_rate", 0))
                        if loss_rate == 0:
                            item.setBackground(QColor(144, 238, 144))  # 浅绿色
                        elif loss_rate < 0.5:
                            item.setBackground(QColor(255, 255, 150))  # 浅黄色
                        else:
                            item.setBackground(QColor(255, 200, 200))  # 浅红色
                    except (ValueError, TypeError):
                        pass
                
                # 设置目标行的字体为粗体
                if row == len(data) - 1:  # 最后一跳通常是目标
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                
                self.result_table.setItem(row, col, item)
        
        # 调整列宽
        self.result_table.resizeColumnsToContents()
        
        # 优化各列宽度
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)       # 跳数列
        header.setSectionResizeMode(1, QHeaderView.Interactive) # IP地址列
        header.setSectionResizeMode(2, QHeaderView.Stretch)     # 主机名列
        header.setSectionResizeMode(3, QHeaderView.Fixed)       # 平均响应时间列
        header.setSectionResizeMode(4, QHeaderView.Fixed)       # 丢包率列
        
        # 设置固定列宽
        self.result_table.setColumnWidth(0, 40)   # 跳数
        self.result_table.setColumnWidth(3, 90)   # 平均响应时间
        self.result_table.setColumnWidth(4, 60)   # 丢包率
        
        # 更新状态栏
        target_name = self.target_input.text().strip()
        total_hops = len(data)
        
        self.status_label.setText(
            f"追踪完成: {target_name}, {total_hops}跳, 用时{result.duration:.2f}秒"
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