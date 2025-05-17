#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ping监控面板
用于图形化操作Ping监控模块
"""

import logging
import time
from typing import Dict, List, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QPushButton, QLabel, QLineEdit, QCheckBox, QSpinBox, 
    QDoubleSpinBox, QComboBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QRadioButton, QButtonGroup,
    QDateTimeEdit, QProgressBar, QTabWidget, QSizePolicy, QSplitter
)
from PyQt5.QtCore import Qt, QDateTime, QTimer
from PyQt5.QtGui import QColor, QFont, QPainter, QBrush
from PyQt5.QtWidgets import QApplication

from gui.panels.base_panel import BasePanel, ScanThread
from utils.network import is_valid_ip, parse_ip_range
from core.base_scanner import ScanResult


class PingMonitorPanel(BasePanel):
    """Ping监控面板"""
    
    MODULE_ID = "pingmonitor"
    MODULE_NAME = "Ping监控"
    
    def __init__(self, parent=None):
        """初始化Ping监控面板"""
        super().__init__(parent)
        
        # 初始化监控状态
        self.monitoring = False
        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self.update_monitor_status)
        
        # 添加一个实时监控标签页
        self.add_realtime_monitor_tab()
        
        # 设置快捷键支持
        self.setFocusPolicy(Qt.StrongFocus)
        
        # 调整分割器初始大小，减小参数区域比例，增大结果区域比例
        self.splitter.setSizes([160, 440])
    
    def create_param_group(self):
        """创建参数组"""
        self.param_group = QGroupBox("监控参数")
        param_layout = QVBoxLayout()
        param_layout.setSpacing(5)
        param_layout.setContentsMargins(5, 5, 5, 5)
        
        # 顶部目标输入行
        top_layout = QHBoxLayout()
        
        # 目标输入
        target_layout = QVBoxLayout()
        target_label = QLabel("目标:")
        target_layout.addWidget(target_label)
        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText("IP/IP范围，如:8.8.8.8,114.114.114.114或192.168.1.1-5")
        target_layout.addWidget(self.targets_input)
        top_layout.addLayout(target_layout, 4)
        
        # 间隔和超时设置
        interval_timeout_layout = QVBoxLayout()
        interval_timeout_layout.setSpacing(5)
        
        # 间隔和超时水平布局
        interval_timeout_row = QHBoxLayout()
        
        # 监控间隔
        interval_layout = QVBoxLayout()
        interval_label = QLabel("间隔:")
        interval_layout.addWidget(interval_label)
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.5, 3600.0)
        self.interval_spin.setSingleStep(1.0)
        self.interval_spin.setValue(5.0)
        self.interval_spin.setSuffix(" 秒")
        interval_layout.addWidget(self.interval_spin)
        interval_timeout_row.addLayout(interval_layout)
        
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
        interval_timeout_row.addLayout(timeout_layout)
        
        interval_timeout_layout.addLayout(interval_timeout_row)
        top_layout.addLayout(interval_timeout_layout, 2)
        
        param_layout.addLayout(top_layout)
        
        # 中部选项行 - 包含监控模式和高级选项
        options_layout = QHBoxLayout()
        options_layout.setSpacing(10)
        
        # 监控模式
        mode_group = QGroupBox("监控模式")
        mode_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(5)
        mode_layout.setContentsMargins(5, 5, 5, 5)
        
        self.mode_button_group = QButtonGroup(self)
        
        # 持续监控模式
        mode_left_layout = QVBoxLayout()
        self.continuous_radio = QRadioButton("持续监控")
        self.mode_button_group.addButton(self.continuous_radio, 1)
        mode_left_layout.addWidget(self.continuous_radio)
        mode_layout.addLayout(mode_left_layout)
        
        # 有限次数模式
        mode_right_layout = QVBoxLayout()
        count_layout = QHBoxLayout()
        self.count_radio = QRadioButton("监控")
        self.mode_button_group.addButton(self.count_radio, 2)
        count_layout.addWidget(self.count_radio)
        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 1000)
        self.count_spin.setValue(10)
        count_layout.addWidget(self.count_spin)
        count_layout.addWidget(QLabel("次"))
        mode_right_layout.addLayout(count_layout)
        mode_layout.addLayout(mode_right_layout)
        
        # 设置默认模式
        self.continuous_radio.setChecked(True)
        
        mode_group.setLayout(mode_layout)
        options_layout.addWidget(mode_group)
        
        # 高级选项
        advanced_group = QGroupBox("高级选项")
        advanced_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        advanced_layout = QHBoxLayout()
        advanced_layout.setSpacing(5)
        advanced_layout.setContentsMargins(5, 5, 5, 5)
        
        # 高级选项的左侧部分
        adv_left_layout = QVBoxLayout()
        
        # 解析主机名
        self.resolve_check = QCheckBox("解析主机名")
        self.resolve_check.setChecked(True)
        adv_left_layout.addWidget(self.resolve_check)
        
        # 保存结果
        self.save_result_check = QCheckBox("保存结果")
        self.save_result_check.setChecked(True)
        adv_left_layout.addWidget(self.save_result_check)
        
        advanced_layout.addLayout(adv_left_layout)
        
        # 高级选项的右侧部分
        adv_right_layout = QVBoxLayout()
        
        # 响应时间阈值
        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel("响应阈值:"))
        self.threshold_spin = QDoubleSpinBox()
        self.threshold_spin.setRange(0, 1000.0)
        self.threshold_spin.setValue(200.0)
        self.threshold_spin.setSuffix(" ms")
        threshold_layout.addWidget(self.threshold_spin)
        adv_right_layout.addLayout(threshold_layout)
        
        # 丢包率阈值
        loss_layout = QHBoxLayout()
        loss_layout.addWidget(QLabel("丢包阈值:"))
        self.loss_threshold_spin = QDoubleSpinBox()
        self.loss_threshold_spin.setRange(0, 1.0)
        self.loss_threshold_spin.setSingleStep(0.05)
        self.loss_threshold_spin.setValue(0.2)
        self.loss_threshold_spin.setSuffix("")
        loss_layout.addWidget(self.loss_threshold_spin)
        adv_right_layout.addLayout(loss_layout)
        
        advanced_layout.addLayout(adv_right_layout)
        
        advanced_group.setLayout(advanced_layout)
        options_layout.addWidget(advanced_group, 1)
        
        param_layout.addLayout(options_layout)
        
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
    
    def create_action_group(self):
        """创建操作按钮组（覆盖基类方法）"""
        self.action_group = QGroupBox("操作")
        # 减小内边距，使内容更紧凑
        action_layout = QHBoxLayout()
        action_layout.setSpacing(5)
        action_layout.setContentsMargins(5, 5, 5, 5)
        
        # 设置所有按钮的固定高度以减少垂直空间
        button_height = 28
        
        # 开始监控按钮
        self.scan_button = QPushButton("开始监控")
        self.scan_button.setFixedHeight(button_height)
        self.scan_button.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_button)
        
        # 停止监控按钮
        self.stop_button = QPushButton("停止监控")
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
    
    def add_realtime_monitor_tab(self):
        """添加实时监控标签页"""
        self.realtime_tab = QWidget()
        realtime_layout = QVBoxLayout(self.realtime_tab)
        realtime_layout.setContentsMargins(5, 5, 5, 5)
        
        # 添加一个监控状态表格
        self.monitor_table = QTableWidget()
        self.monitor_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.monitor_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.monitor_table.setAlternatingRowColors(True)
        
        # 设置列
        columns = ["ip", "status", "response_time", "last_check", "up_count", "down_count", "availability"]
        column_names = ["IP地址", "状态", "响应时间(ms)", "最后检查", "在线次数", "离线次数", "可用性"]
        
        self.monitor_table.setColumnCount(len(columns))
        self.monitor_table.setHorizontalHeaderLabels(column_names)
        
        # 设置表格行高
        self.monitor_table.verticalHeader().setDefaultSectionSize(22)
        
        # 设置固定列宽和列宽调整模式
        header = self.monitor_table.horizontalHeader() 
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # IP地址列
        header.setSectionResizeMode(1, QHeaderView.Fixed)       # 状态列
        header.setSectionResizeMode(2, QHeaderView.Fixed)       # 响应时间列
        header.setSectionResizeMode(3, QHeaderView.Fixed)       # 最后检查时间列
        header.setSectionResizeMode(4, QHeaderView.Fixed)       # 在线次数列
        header.setSectionResizeMode(5, QHeaderView.Fixed)       # 离线次数列
        header.setSectionResizeMode(6, QHeaderView.Fixed)       # 可用性列
        
        realtime_layout.addWidget(self.monitor_table)
        
        # 添加到结果标签页
        self.result_tabs.addTab(self.realtime_tab, "实时监控")
    
    def get_scan_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        return {
            "targets": self.targets_input.text().strip(),
            "interval": self.interval_spin.value(),
            "count": 0 if self.continuous_radio.isChecked() else self.count_spin.value(),
            "timeout": self.timeout_spin.value(),
            "resolve": self.resolve_check.isChecked(),
            "threshold": self.threshold_spin.value(),
            "loss_threshold": self.loss_threshold_spin.value(),
            "save_result": self.save_result_check.isChecked(),
            "max_threads": 10  # 固定线程数
        }
    
    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """设置扫描配置到UI控件"""
        if "targets" in config:
            self.targets_input.setText(str(config["targets"]))
        
        if "interval" in config:
            self.interval_spin.setValue(float(config["interval"]))
        
        if "count" in config:
            count = int(config["count"])
            if count == 0:
                self.continuous_radio.setChecked(True)
            else:
                self.count_radio.setChecked(True)
                self.count_spin.setValue(count)
        
        if "timeout" in config:
            self.timeout_spin.setValue(float(config["timeout"]))
        
        if "resolve" in config:
            self.resolve_check.setChecked(config["resolve"])
        
        if "threshold" in config:
            self.threshold_spin.setValue(float(config["threshold"]))
        
        if "loss_threshold" in config:
            self.loss_threshold_spin.setValue(float(config["loss_threshold"]))
        
        if "save_result" in config:
            self.save_result_check.setChecked(config["save_result"])
    
    def validate_params(self, config: Dict[str, Any]) -> bool:
        """验证扫描参数"""
        # 检查目标
        targets = config.get("targets", "")
        if not targets:
            QMessageBox.warning(self, "参数错误", "请输入目标IP或IP范围")
            return False
        
        # 尝试解析目标
        ips = parse_ip_range(targets)
        
        # 检查IP数量，防止过多IP导致界面卡死
        if ips and len(ips) > 100:
            result = QMessageBox.question(
                self, "性能警告", 
                f"您尝试监控 {len(ips)} 个IP地址，这可能导致界面卡顿或无响应。\n\n"
                f"推荐的IP数量上限为100个，是否仍要继续？",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
            )
            if result != QMessageBox.Yes:
                return False
            
        if not ips:
            # 检查是否为逗号分隔的列表
            valid_targets = []
            for target in targets.split(","):
                target = target.strip()
                if not target:
                    continue
                
                if is_valid_ip(target):
                    valid_targets.append(target)
                else:
                    parsed = parse_ip_range(target)
                    if parsed:
                        valid_targets.extend(parsed)
            
            if not valid_targets:
                QMessageBox.warning(self, "参数错误", "无效的目标IP或IP范围")
                return False
            
            # 对于拆分后的列表也检查IP数量
            if len(valid_targets) > 100:
                result = QMessageBox.question(
                    self, "性能警告", 
                    f"您尝试监控 {len(valid_targets)} 个IP地址，这可能导致界面卡顿或无响应。\n\n"
                    f"推荐的IP数量上限为100个，是否仍要继续？",
                    QMessageBox.Yes | QMessageBox.No, 
                    QMessageBox.No
                )
                if result != QMessageBox.Yes:
                    return False
        
        return True
    
    def start_scan(self) -> None:
        """开始监控（覆盖基类方法）"""
        # 获取扫描配置
        config = self.get_scan_config()
        
        # 参数验证
        if not self.validate_params(config):
            return
        
        # 创建扫描器
        from core.scanner_manager import scanner_manager
        scanner_class = scanner_manager.get_scanner(self.MODULE_ID)
        if not scanner_class:
            QMessageBox.critical(self, "错误", f"模块 {self.MODULE_ID} 未找到")
            return
        
        scanner = scanner_class(config)
        
        # 更新UI状态
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("正在启动监控...")
        
        # 创建并启动扫描线程
        self.scan_thread = ScanThread(scanner)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.scan_progress.connect(self.on_scan_progress)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        self.scan_thread.start()
        
        # 设置监控状态
        self.monitoring = True
        
        # 启动定时器更新监控状态
        update_interval = min(1000, int(config["interval"] * 1000 / 2))
        self.monitor_timer.start(update_interval)
        
        self.logger.info(f"开始 {self.MODULE_NAME}")
    
    def stop_scan(self) -> None:
        """停止监控（覆盖基类方法）"""
        self.logger.info(f"UI 请求停止 {self.MODULE_NAME} 监控...")
        
        self.monitoring = False 
        self.monitor_timer.stop()

        self.status_label.setText("正在停止监控...")
        QApplication.processEvents() 

        self.stop_button.setEnabled(False)

        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.isRunning():
            self.logger.info(f"ScanThread (QThread) 仍在运行，请求其管理的scanner停止...")
            if self.scan_thread.scanner:
                self.scan_thread.scanner.stop() 
        else:
            self.logger.info(f"ScanThread (QThread) 未运行或已停止。可能已提前完成或被停止。")
            if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.scanner:
                self.logger.info("尝试直接停止核心扫描器 (以防万一)")
                self.scan_thread.scanner.stop()

            self.scan_button.setEnabled(True)
            self.clear_button.setEnabled(True)
            self.export_button.setEnabled(self.current_result and self.current_result.success and len(self.current_result.data) > 0)
            self.status_label.setText("监控已停止。")
        
        self.logger.info(f"{self.MODULE_NAME} stop_scan 方法执行完毕。等待 on_scan_complete 或 on_scan_error。")
    
    def update_monitor_status(self):
        """更新监控状态"""
        if not hasattr(self.scan_thread, 'scanner') or not self.monitoring:
            return
        
        try:
            # 获取监控状态
            scanner = self.scan_thread.scanner
            status = scanner.get_status()
            
            if not status.get('running', False):
                # 如果监控已经停止，更新UI状态
                self.monitor_timer.stop()
                self.monitoring = False
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.clear_button.setEnabled(True)
                self.status_label.setText("监控已完成")
                return
            
            # 获取最新结果
            results = scanner.get_results()
            
            # 如果有结果，更新监控表格
            if results:
                self.update_monitor_table(results)
                # 更新状态栏信息，显示当前监控的状态
                targets_count = status.get('targets', 0)
                interval = status.get('interval', 0)
                current_results = status.get('current_results', 0)
                self.status_label.setText(
                    f"正在监控 {targets_count} 个主机，"
                    f"间隔 {interval} 秒，"
                    f"已收集 {current_results} 条记录"
                )
                # 如果是持续监控模式，启用导出按钮
                if status.get('count', 0) == 0 and current_results > 0:
                    self.export_button.setEnabled(True)
        
        except Exception as e:
            self.logger.error(f"更新监控状态时出错: {str(e)}")
    
    def update_monitor_table(self, results):
        """更新监控表格"""
        # 记录当前结果数量，用于性能评估
        result_count = len(results)
        if result_count > 500:
            self.logger.warning(f"大量结果记录 ({result_count})，可能影响界面性能")
            
        # 最近更新的IP（最多显示100个）
        # 首先按时间戳排序，获取最新的IP
        recent_ips = {}
        for result in sorted(results, key=lambda r: r.get('timestamp', ''), reverse=True):
            ip = result.get('ip', '')
            if not ip or ip in recent_ips:
                continue
            recent_ips[ip] = result
            if len(recent_ips) >= 100:  # 限制最多显示100行
                break
                
        # 按IP分组结果
        hosts = {}
        for ip, result in recent_ips.items():
            # 统计该IP的所有结果
            ip_results = [r for r in results if r.get('ip') == ip]
            
            # 计算统计信息
            up_count = sum(1 for r in ip_results if r.get('status') == 'up')
            down_count = sum(1 for r in ip_results if r.get('status') == 'down')
            total_count = len(ip_results)
            
            hosts[ip] = {
                'ip': ip,
                'status': result.get('status', 'unknown'),
                'response_time': result.get('response_time', 0),
                'last_check': result.get('timestamp', ''),
                'up_count': up_count,
                'down_count': down_count,
                'total_count': total_count
            }
        
        # 计算可用性
        for ip, host in hosts.items():
            if host['total_count'] > 0:
                host['availability'] = host['up_count'] / host['total_count'] * 100
            else:
                host['availability'] = 0
        
        # 优化表格更新 - 暂停界面更新，避免频繁重绘
        self.monitor_table.setUpdatesEnabled(False)
        
        try:
            # 为了提高性能，仅当行数发生变化时才重设行数
            if self.monitor_table.rowCount() != len(hosts):
                self.monitor_table.setRowCount(len(hosts))
            
            # 填充数据
            for row, (ip, host) in enumerate(hosts.items()):
                # IP地址
                if self.monitor_table.item(row, 0) is None or self.monitor_table.item(row, 0).text() != ip:
                    self.monitor_table.setItem(row, 0, QTableWidgetItem(ip))
                
                # 状态
                status_text = "在线" if host['status'] == 'up' else "离线"
                if self.monitor_table.item(row, 1) is None or self.monitor_table.item(row, 1).text() != status_text:
                    status_item = QTableWidgetItem(status_text)
                    status_color = QColor(144, 238, 144) if host['status'] == 'up' else QColor(255, 200, 200)
                    status_item.setBackground(status_color)
                    self.monitor_table.setItem(row, 1, status_item)
                
                # 响应时间
                response_time = f"{host['response_time']:.2f}" if host['status'] == 'up' else "-"
                if self.monitor_table.item(row, 2) is None or self.monitor_table.item(row, 2).text() != response_time:
                    self.monitor_table.setItem(row, 2, QTableWidgetItem(response_time))
                
                # 最后检查时间
                last_check = host['last_check']
                if last_check:
                    # 简化时间显示
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(last_check)
                        last_check = dt.strftime("%H:%M:%S")
                    except:
                        pass
                
                if self.monitor_table.item(row, 3) is None or (last_check and self.monitor_table.item(row, 3).text() != last_check):
                    self.monitor_table.setItem(row, 3, QTableWidgetItem(str(last_check) if last_check else ""))
                
                # 在线次数
                up_count = str(host['up_count'])
                if self.monitor_table.item(row, 4) is None or self.monitor_table.item(row, 4).text() != up_count:
                    self.monitor_table.setItem(row, 4, QTableWidgetItem(up_count))
                
                # 离线次数
                down_count = str(host['down_count'])
                if self.monitor_table.item(row, 5) is None or self.monitor_table.item(row, 5).text() != down_count:
                    self.monitor_table.setItem(row, 5, QTableWidgetItem(down_count))
                
                # 可用性
                availability = f"{host['availability']:.1f}%"
                if self.monitor_table.item(row, 6) is None or self.monitor_table.item(row, 6).text() != availability:
                    avail_item = QTableWidgetItem(availability)
                    
                    # 根据可用性着色
                    avail_val = host['availability']
                    if avail_val >= 99:
                        avail_item.setBackground(QColor(144, 238, 144))  # 浅绿色
                    elif avail_val >= 90:
                        avail_item.setBackground(QColor(255, 255, 150))  # 浅黄色
                    else:
                        avail_item.setBackground(QColor(255, 200, 200))  # 浅红色
                    
                    self.monitor_table.setItem(row, 6, avail_item)
            
            # 设置固定列宽
            self.monitor_table.setColumnWidth(1, 60)  # 状态
            self.monitor_table.setColumnWidth(2, 80)  # 响应时间
            self.monitor_table.setColumnWidth(3, 80)  # 最后检查时间
            self.monitor_table.setColumnWidth(4, 60)  # 在线次数
            self.monitor_table.setColumnWidth(5, 60)  # 离线次数
            self.monitor_table.setColumnWidth(6, 70)  # 可用性
            
            # 仅在首次更新时调整IP地址列宽
            if result_count <= 10:
                self.monitor_table.resizeColumnToContents(0)  # IP地址列
        
        finally:
            # 恢复界面更新
            self.monitor_table.setUpdatesEnabled(True)
    
    def display_results(self, result):
        """显示扫描结果"""
        # 先调用基类方法清空表格
        super().display_results(result)
        
        if not result.success or not result.data:
            return
        
        # 提取数据
        data = result.data
        
        # 检查是否是启动消息
        if len(data) == 1 and "status" in data[0] and data[0]["status"] == "running":
            # 这是一个启动消息，更新状态栏信息
            targets = data[0].get("targets", 0)
            self.status_label.setText(f"监控中: {targets}个主机")
            
            # 确保定时器已启动
            if not self.monitor_timer.isActive():
                update_interval = min(1000, int(self.interval_spin.value() * 1000 / 2))
                self.monitor_timer.start(update_interval)
            
            # 确保停止按钮已启用
            self.stop_button.setEnabled(True)
            self.scan_button.setEnabled(False)
            self.monitoring = True
            return
        
        # 检查是否是分析报告
        if len(data) == 1 and "hosts" in data[0]:
            # 这是一个分析报告，显示监控结果
            self.display_monitor_results(data[0])
        else:
            # 这可能是原始监控记录，显示到表格
            self.display_monitor_records(data)
    
    def display_monitor_results(self, analysis):
        """显示监控分析结果"""
        hosts = analysis.get("hosts", {})
        
        if not hosts:
            return
        
        # 设置表格列
        columns = ["ip", "availability", "up", "down", "avg_time", "min_time", 
                  "max_time", "jitter", "last_status", "last_check"]
        column_names = ["IP地址", "可用性(%)", "在线次数", "离线次数", "平均响应时间(ms)", 
                       "最小响应时间(ms)", "最大响应时间(ms)", "抖动(ms)", "最后状态", "最后检查时间"]
        
        self.result_table.setColumnCount(len(columns))
        self.result_table.setHorizontalHeaderLabels(column_names)
        
        # 添加行
        self.result_table.setRowCount(len(hosts))
        
        # 填充数据
        for row, (ip, host) in enumerate(hosts.items()):
            # IP地址
            self.result_table.setItem(row, 0, QTableWidgetItem(ip))
            
            # 可用性
            availability = f"{host.get('availability', 0):.2f}"
            availability_item = QTableWidgetItem(availability)
            
            # 根据可用性着色
            avail_val = float(availability)
            if avail_val >= 99:
                availability_item.setBackground(QColor(144, 238, 144))  # 浅绿色
            elif avail_val >= 90:
                availability_item.setBackground(QColor(255, 255, 150))  # 浅黄色
            else:
                availability_item.setBackground(QColor(255, 200, 200))  # 浅红色
            
            self.result_table.setItem(row, 1, availability_item)
            
            # 在线次数
            self.result_table.setItem(row, 2, QTableWidgetItem(str(host.get('up', 0))))
            
            # 离线次数
            self.result_table.setItem(row, 3, QTableWidgetItem(str(host.get('down', 0))))
            
            # 平均响应时间
            avg_time = f"{host.get('avg_time', 0):.2f}"
            self.result_table.setItem(row, 4, QTableWidgetItem(avg_time))
            
            # 最小响应时间
            min_time = f"{host.get('min_time', 0):.2f}"
            self.result_table.setItem(row, 5, QTableWidgetItem(min_time))
            
            # 最大响应时间
            max_time = f"{host.get('max_time', 0):.2f}"
            self.result_table.setItem(row, 6, QTableWidgetItem(max_time))
            
            # 抖动
            jitter = f"{host.get('jitter', 0):.2f}"
            self.result_table.setItem(row, 7, QTableWidgetItem(jitter))
            
            # 最后状态
            last_status = "在线" if host.get('last_status') == 'up' else "离线"
            status_item = QTableWidgetItem(last_status)
            if host.get('last_status') == 'up':
                status_item.setBackground(QColor(144, 238, 144))  # 浅绿色
            else:
                status_item.setBackground(QColor(255, 200, 200))  # 浅红色
            self.result_table.setItem(row, 8, status_item)
            
            # 最后检查时间
            last_check = host.get('last_check', '')
            self.result_table.setItem(row, 9, QTableWidgetItem(str(last_check)))
        
        # 调整列宽
        self.result_table.resizeColumnsToContents()
        
        # 更新状态栏
        total_checks = analysis.get("total_checks", 0)
        host_count = len(hosts)
        
        self.status_label.setText(
            f"监控完成: 检查了 {host_count} 台主机，"
            f"共执行 {total_checks} 次检查，"
            f"用时 {self.current_result.duration:.2f} 秒"
        )
    
    def display_monitor_records(self, records):
        """显示监控记录"""
        # 设置表格列
        columns = ["ip", "status", "response_time", "timestamp", "is_slow"]
        column_names = ["IP地址", "状态", "响应时间(ms)", "检查时间", "是否缓慢"]
        
        self.result_table.setColumnCount(len(columns))
        self.result_table.setHorizontalHeaderLabels(column_names)
        
        # 添加行
        self.result_table.setRowCount(len(records))
        
        # 填充数据
        for row, record in enumerate(records):
            for col, key in enumerate(columns):
                value = record.get(key, "")
                
                # 特殊处理
                if key == "status":
                    value = "在线" if value == "up" else "离线"
                    
                    # 设置颜色
                    item = QTableWidgetItem(value)
                    if value == "在线":
                        item.setBackground(QColor(144, 238, 144))  # 浅绿色
                    else:
                        item.setBackground(QColor(255, 200, 200))  # 浅红色
                    
                    self.result_table.setItem(row, col, item)
                    continue
                elif key == "is_slow":
                    value = "是" if value else "否"
                    
                    # 设置颜色
                    item = QTableWidgetItem(value)
                    if value == "是":
                        item.setBackground(QColor(255, 255, 150))  # 浅黄色
                    
                    self.result_table.setItem(row, col, item)
                    continue
                
                # 正常处理
                item = QTableWidgetItem(str(value) if value is not None else "")
                self.result_table.setItem(row, col, item)
        
        # 调整列宽
        self.result_table.resizeColumnsToContents()
        
        # 更新状态栏
        self.status_label.setText(f"显示 {len(records)} 条监控记录")
    
    def clear_results(self) -> None:
        """清除结果（覆盖基类方法）"""
        super().clear_results()
        
        # 清除监控表格
        self.monitor_table.clearContents()
        self.monitor_table.setRowCount(0)
    
    def on_scan_complete(self, result: ScanResult) -> None:
        """
        扫描完成处理（覆盖基类方法）
        
        Args:
            result: 扫描结果
        """
        # 保存结果
        self.current_result = result
        
        # 检查是否是持续监控模式的启动消息
        is_continuous_mode = False
        if result.success and result.data:
            data = result.data
            if len(data) == 1 and isinstance(data[0], dict) and data[0].get("status") == "running":
                is_continuous_mode = True
                
                # 持续监控模式不更改界面状态，由display_results处理
                self.display_results(result)
                return
        
        # 对于其他情况，使用基类处理方式
        # Attempt to resolve Pylance "undefined 'result'" error by using an alias
        result_for_super = result
        super().on_scan_complete(result_for_super)

    def keyPressEvent(self, event):
        """
        键盘事件处理
        支持使用Escape键停止监控
        """
        if event.key() == Qt.Key_Escape:
            if self.monitoring and self.stop_button.isEnabled():
                self.stop_scan()
        else:
            super().keyPressEvent(event)

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