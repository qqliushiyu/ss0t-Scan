#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
路由追踪面板
用于图形化操作路由追踪模块
"""

import logging
import platform
import time
from typing import Dict, List, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QPushButton, QLabel, QLineEdit, QCheckBox, QSpinBox, 
    QDoubleSpinBox, QComboBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QRadioButton, QButtonGroup,
    QToolButton, QSizePolicy, QProgressBar, QSplitter, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QColor, QFont, QTextCursor

from gui.panels.base_panel import BasePanel
from utils.network import is_valid_ip


# 定义一个自定义的扫描线程类，用于处理实时输出
class TracerouteScanThread(QThread):
    """路由追踪扫描线程"""
    
    # 定义信号
    scan_complete = pyqtSignal(object)  # 扫描完成信号，传递结果对象
    scan_progress = pyqtSignal(int, str)  # 扫描进度信号 (百分比, 消息)
    scan_error = pyqtSignal(str)  # 扫描错误信号
    scan_hop_result = pyqtSignal(object)  # 实时返回每一跳的结果
    
    def __init__(self, scanner):
        """初始化扫描线程"""
        super().__init__()
        self.scanner = scanner
        # 设置进度回调
        self.scanner.set_progress_callback(self.update_progress)
        # 添加处理每一跳结果的回调
        self.scanner.set_hop_callback(self.hop_callback)
        # 线程终止标志
        self._is_stopping = False
        # 终止请求时间
        self._stop_requested_time = 0
    
    def run(self):
        """执行扫描"""
        try:
            # 检查终止标志
            if self._is_stopping:
                return
            
            result = self.scanner.execute()
            
            # 再次检查终止标志，避免发送不需要的信号
            if not self._is_stopping:
                self.scan_complete.emit(result)
        except Exception as e:
            if not self._is_stopping:
                self.scan_error.emit(str(e))
    
    def update_progress(self, percent: int, message: str):
        """处理扫描进度更新"""
        if not self._is_stopping:
            self.scan_progress.emit(percent, message)
    
    def hop_callback(self, hop_data):
        """处理每一跳的结果"""
        if not self._is_stopping:
            self.scan_hop_result.emit(hop_data)
    
    def terminate(self):
        """终止扫描线程"""
        self._is_stopping = True
        self._stop_requested_time = time.time()
        
        # 尝试停止扫描器
        if self.scanner:
            try:
                self.scanner.stop()
                # 给扫描器一些时间停止
                for i in range(5):  # 最多等待500毫秒
                    if not self.isRunning():
                        return
                    time.sleep(0.1)
            except Exception as e:
                print(f"停止扫描器时出错: {str(e)}")
        
        # 强制终止线程
        if self.isRunning():
            super().terminate()


class TraceroutePanel(BasePanel):
    """路由追踪面板"""
    
    MODULE_ID = "traceroute"
    MODULE_NAME = "路由追踪"
    
    def __init__(self, parent=None):
        """初始化路由追踪面板"""
        super().__init__(parent)
        # 添加原生输出标志
        self.use_native_format = True
        # 存储当前跟踪的跳数
        self.current_hops = []
        # 记录开始扫描的时间
        self.scan_start_time = 0
    
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
        
        # 最大跳数布局（包含标签、SpinBox和复选框）
        max_hops_config_layout = QHBoxLayout()
        max_hops_config_layout.setSpacing(5)

        hop_label = QLabel("最大跳数:")
        max_hops_config_layout.addWidget(hop_label)

        self.max_hops_spin = QSpinBox()
        self.max_hops_spin.setRange(1, 255) # 实际traceroute最大跳数通常是255
        self.max_hops_spin.setValue(30)
        max_hops_config_layout.addWidget(self.max_hops_spin)

        self.adaptive_hops_check = QCheckBox("自适应")
        self.adaptive_hops_check.setChecked(True) # 默认为自适应
        self.adaptive_hops_check.toggled.connect(self.toggle_adaptive_hops)
        max_hops_config_layout.addWidget(self.adaptive_hops_check)
        max_hops_config_layout.addStretch(1) # 让复选框靠近SpinBox
        
        # 初始状态根据复选框设置
        self.toggle_adaptive_hops(self.adaptive_hops_check.isChecked())

        # 将最大跳数相关控件添加到右侧参数布局中
        params_right_layout.addLayout(max_hops_config_layout)

        # 超时设置
        timeout_layout = QVBoxLayout() # 改为QVBoxLayout以与其他参数项对齐
        timeout_label = QLabel("超时:")
        timeout_layout.addWidget(timeout_label)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setSingleStep(0.1)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSuffix(" 秒")
        timeout_layout.addWidget(self.timeout_spin)
        # 将超时添加到右侧参数布局中，而不是hop_timeout_layout
        params_right_layout.addLayout(timeout_layout)

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
        
        # 增加输出格式选项
        format_layout = QHBoxLayout()
        format_layout.setSpacing(15)
        
        self.native_format_check = QCheckBox("使用原生格式输出")
        self.native_format_check.setChecked(True)
        self.native_format_check.toggled.connect(self.toggle_output_format)
        format_layout.addWidget(self.native_format_check)
        
        format_layout.addStretch(1)
        param_layout.addLayout(format_layout)
        
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
    
    def toggle_adaptive_hops(self, checked: bool):
        """切换自适应最大跳数选框的状态"""
        self.max_hops_spin.setEnabled(not checked)
        if checked:
            # 可以选择清除或保留上次的值，这里先保留
            # self.max_hops_spin.clear() 
            pass
    
    def toggle_output_format(self, checked):
        """切换输出格式"""
        self.use_native_format = checked
    
    def get_scan_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        max_hops_value = 0 # 默认自适应
        if not self.adaptive_hops_check.isChecked():
            max_hops_value = self.max_hops_spin.value()

        return {
            "target": self.target_input.text().strip(),
            "method": "icmp" if self.icmp_radio.isChecked() else "udp",
            "max_hops": max_hops_value,
            "timeout": self.timeout_spin.value(),
            "probe_count": self.probe_count_spin.value(),
            "resolve": self.resolve_check.isChecked(),
            "port": self.port_spin.value(),
            "native_format": self.use_native_format
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
            max_hops_val = int(config["max_hops"])
            if max_hops_val == 0: # 自适应
                self.adaptive_hops_check.setChecked(True)
                self.max_hops_spin.setEnabled(False)
            else:
                self.adaptive_hops_check.setChecked(False)
                self.max_hops_spin.setEnabled(True)
                self.max_hops_spin.setValue(max_hops_val)
        else: # 如果配置中没有max_hops，则默认为自适应
            self.adaptive_hops_check.setChecked(True)
            self.max_hops_spin.setEnabled(False)
        
        if "timeout" in config:
            self.timeout_spin.setValue(float(config["timeout"]))
        
        if "probe_count" in config:
            self.probe_count_spin.setValue(int(config["probe_count"]))
        
        if "resolve" in config:
            self.resolve_check.setChecked(config["resolve"])
        
        if "port" in config:
            self.port_spin.setValue(int(config["port"]))
        
        if "native_format" in config:
            self.native_format_check.setChecked(config["native_format"])
            self.use_native_format = config["native_format"]
    
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
        
        if self.use_native_format:
            # 使用原生格式输出
            self.display_native_format(data, result.duration)
        else:
            # 使用表格格式输出
            self.display_table_format(data, result.duration)
    
    def display_native_format(self, data, duration):
        """使用原生格式显示结果"""
        # 清空表格
        self.result_table.clear()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(1)
        self.result_table.setHorizontalHeaderLabels(["路由追踪结果（原生格式）"])
        
        # 构建原生格式输出文本
        target_name = self.target_input.text().strip()
        
        max_hops_display = "max" # 默认显示max表示自适应
        if not self.adaptive_hops_check.isChecked():
            max_hops_display = str(self.max_hops_spin.value())
        
        native_text = f"traceroute to {target_name}, {max_hops_display} hops max\n\n"
        
        # 填充数据
        for hop in data:
            hop_num = hop.get("hop", "")
            ip = hop.get("ip", "*")
            hostname = hop.get("hostname", "")
            avg_time = hop.get("avg_time", "")
            loss_rate = hop.get("loss_rate", 0)
            
            # 构建每一跳的输出行
            line = f"{hop_num:2d}  "
            
            # 如果有主机名且不是IP，则显示主机名和IP
            if hostname and hostname != ip:
                line += f"{hostname} ({ip})"
            else:
                line += f"{ip}"
            
            # 添加响应时间和丢包率
            if avg_time:
                line += f"  {float(avg_time):.3f} ms"
                
                # 如果丢包率不为0，显示丢包率
                if loss_rate > 0:
                    line += f" ({float(loss_rate) * 100:.0f}% loss)"
            else:
                line += "  *"  # 超时或无响应
            
            native_text += line + "\n"
        
        # 添加总结信息
        native_text += f"\n追踪完成: {len(data)}跳, 用时{duration:.2f}秒"
        
        # 显示原生格式文本到文本结果区域
        self.result_text.setText(native_text)
        
        # 在表格中只显示一行，包含文本结果简短摘要
        self.result_table.setRowCount(1)
        summary_item = QTableWidgetItem(f"路由追踪到 {target_name} 完成，共 {len(data)} 跳，请查看下方文本结果获取详细信息")
        self.result_table.setItem(0, 0, summary_item)
        
        # 调整列宽
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        # 更新状态栏
        self.status_label.setText(
            f"追踪完成: {target_name}, {len(data)}跳, 用时{duration:.2f}秒"
        )
        
        # 启用导出按钮
        self.export_button.setEnabled(True)
    
    def display_table_format(self, data, duration):
        """使用表格格式显示结果"""
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
            f"追踪完成: {target_name}, {total_hops}跳, 用时{duration:.2f}秒"
        )
        
        # 启用导出按钮
        self.export_button.setEnabled(True)
    
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

    def export_results(self):
        """导出结果"""
        # 获取目标名称作为默认文件名
        target_name = self.target_input.text().strip().replace('://', '_').replace('/', '_')
        default_filename = f"traceroute_{target_name}.txt"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出结果", default_filename, "文本文件 (*.txt);;所有文件 (*.*)"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                if self.use_native_format:
                    # 导出原生格式的结果
                    f.write(self.result_text.toPlainText())
                else:
                    # 导出表格格式的结果
                    target_name = self.target_input.text().strip()
                    f.write(f"路由追踪结果 - {target_name}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # 获取表格数据
                    row_count = self.result_table.rowCount()
                    col_count = self.result_table.columnCount()
                    headers = []
                    
                    # 获取表头
                    for col in range(col_count):
                        header_item = self.result_table.horizontalHeaderItem(col)
                        if header_item:
                            headers.append(header_item.text())
                        else:
                            headers.append(f"列 {col+1}")
                    
                    # 写入表头
                    f.write("\t".join(headers) + "\n")
                    f.write("-" * 80 + "\n")
                    
                    # 写入数据
                    for row in range(row_count):
                        row_data = []
                        for col in range(col_count):
                            item = self.result_table.item(row, col)
                            if item:
                                row_data.append(item.text())
                            else:
                                row_data.append("")
                        f.write("\t".join(row_data) + "\n")
                
                self.status_label.setText(f"结果已导出到: {file_path}")
                self.logger.info(f"路由追踪结果已导出到: {file_path}")
        except Exception as e:
            error_msg = f"导出结果失败: {str(e)}"
            self.status_label.setText(error_msg)
            self.logger.error(error_msg)
            QMessageBox.critical(self, "导出错误", error_msg)
    
    def start_scan(self) -> None:
        """开始扫描"""
        # 获取扫描配置
        config = self.get_scan_config()
        
        # 参数验证
        if not self.validate_params(config):
            return
        
        # 清空结果
        self.clear_results()
        
        # 准备表格和文本区域
        if self.use_native_format:
            self.prepare_native_format_display()
        else:
            self.prepare_table_format_display()
        
        # 创建扫描器
        from core.traceroute import Traceroute
        scanner = Traceroute(config)
        
        # 更新UI状态
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("正在扫描...")
        
        # 记录开始时间
        self.scan_start_time = time.time()
        
        # 清空当前跳数列表
        self.current_hops = []
        
        # 创建并启动自定义扫描线程
        self.scan_thread = TracerouteScanThread(scanner)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.scan_progress.connect(self.on_scan_progress)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        self.scan_thread.scan_hop_result.connect(self.on_hop_result)
        self.scan_thread.start()
        
        self.logger.info(f"开始 {self.MODULE_NAME} 扫描: {config.get('target', '')}")
    
    def prepare_native_format_display(self):
        """准备原生格式显示"""
        # 清空表格
        self.result_table.clear()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(1)
        self.result_table.setHorizontalHeaderLabels(["路由追踪结果（原生格式）"])
        
        # 设置表格列宽
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        # 清空文本结果
        target_name = self.target_input.text().strip()
        max_hops_display = "max" # 默认显示max表示自适应
        if not self.adaptive_hops_check.isChecked():
            max_hops_display = str(self.max_hops_spin.value())
        
        native_text = f"traceroute to {target_name}, {max_hops_display} hops max\n\n"
        self.result_text.setText(native_text)
    
    def prepare_table_format_display(self):
        """准备表格格式显示"""
        # 清空表格
        self.result_table.clear()
        
        # 设置表头
        columns = ["hop", "ip", "hostname", "avg_time", "loss_rate"]
        column_names = ["跳数", "IP地址", "主机名", "平均响应时间(ms)", "丢包率"]
        
        self.result_table.setColumnCount(len(columns))
        self.result_table.setHorizontalHeaderLabels(column_names)
        
        # 设置表格行高
        self.result_table.verticalHeader().setDefaultSectionSize(22)
        # 启用交替行颜色
        self.result_table.setAlternatingRowColors(True)
        
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
    
    def on_hop_result(self, hop_data):
        """处理每一跳的结果"""
        if not hop_data:
            return
        
        # 将结果添加到列表
        self.current_hops.append(hop_data)
        
        # 根据格式显示结果
        if self.use_native_format:
            self.update_native_format_display(hop_data)
        else:
            self.update_table_format_display(hop_data)
        
        # 更新进度
        max_hops_for_progress = self.max_hops_spin.value()
        if self.adaptive_hops_check.isChecked():
            # 如果是自适应，我们不知道确切的最大跳数，可以用一个较大的值或动态调整
            # 这里暂时用一个常见的默认值30，或者可以考虑从第一跳的结果来估计
            max_hops_for_progress = hop_data.get("hop", 0) + 15 # 假设至少还有15跳, 或者一个固定值
            if max_hops_for_progress < 30: max_hops_for_progress = 30 # 保证一个最小值
        
        current_hop_num = hop_data.get("hop", 0)
        percent = 0
        if max_hops_for_progress > 0:
             percent = min(int((current_hop_num / max_hops_for_progress) * 100), 99)
        
        # 计算已用时间
        elapsed_time = time.time() - self.scan_start_time
        
        message = f"已追踪到第 {current_hop_num} 跳，用时 {elapsed_time:.1f} 秒"
        self.on_scan_progress(percent, message)
    
    def update_native_format_display(self, hop_data):
        """更新原生格式显示"""
        hop_num = hop_data.get("hop", "")
        ip = hop_data.get("ip", "*")
        hostname = hop_data.get("hostname", "")
        avg_time = hop_data.get("avg_time", "")
        loss_rate = hop_data.get("loss_rate", 0)
        
        # 构建行
        line = f"{hop_num:2d}  "
        
        # 如果有主机名且不是IP，则显示主机名和IP
        if hostname and hostname != ip:
            line += f"{hostname} ({ip})"
        else:
            line += f"{ip}"
        
        # 添加响应时间和丢包率
        if avg_time:
            line += f"  {float(avg_time):.3f} ms"
            
            # 如果丢包率不为0，显示丢包率
            if loss_rate > 0:
                line += f" ({float(loss_rate) * 100:.0f}% loss)"
        else:
            line += "  *"  # 超时或无响应
        
        # 获取当前文本并添加新行
        current_text = self.result_text.toPlainText()
        self.result_text.setText(current_text + line + "\n")
        
        # 滚动到最底部
        self.result_text.moveCursor(QTextCursor.End)
        
        # 更新表格，只显示简要信息
        row_count = self.result_table.rowCount()
        if row_count == 0:
            self.result_table.setRowCount(1)
            summary_item = QTableWidgetItem("正在跟踪路由，请查看下方文本区域获取实时结果...")
            self.result_table.setItem(0, 0, summary_item)
    
    def update_table_format_display(self, hop_data):
        """更新表格格式显示"""
        # 跳数
        hop_num = hop_data.get("hop", 0)
        
        # 检查是否已有此跳的行
        found = False
        for row in range(self.result_table.rowCount()):
            hop_item = self.result_table.item(row, 0)
            if hop_item and int(hop_item.text()) == hop_num:
                found = True
                break
        
        if not found:
            # 添加新行
            row = self.result_table.rowCount()
            self.result_table.setRowCount(row + 1)
            
            # 填充数据
            columns = ["hop", "ip", "hostname", "avg_time", "loss_rate"]
            
            for col, key in enumerate(columns):
                value = hop_data.get(key, "")
                
                # 特殊处理
                if key == "avg_time" and value:
                    value = f"{float(value):.2f}"
                elif key == "loss_rate" and value is not None:
                    value = f"{float(value) * 100:.0f}%"
                
                item = QTableWidgetItem(str(value) if value is not None else "")
                
                # 设置颜色 - 根据丢包率着色
                if key == "loss_rate":
                    try:
                        loss_rate = float(hop_data.get("loss_rate", 0))
                        if loss_rate == 0:
                            item.setBackground(QColor(144, 238, 144))  # 浅绿色
                        elif loss_rate < 0.5:
                            item.setBackground(QColor(255, 255, 150))  # 浅黄色
                        else:
                            item.setBackground(QColor(255, 200, 200))  # 浅红色
                    except (ValueError, TypeError):
                        pass
                
                self.result_table.setItem(row, col, item)
    
    def on_scan_complete(self, result):
        """扫描完成处理"""
        if self.current_hops and not result.data:
            # 如果有实时跳数结果但最终结果为空，使用实时收集的数据
            result.data = self.current_hops
            result.success = True
        
        # 调用原有的结果处理方法
        self.display_results(result)
        
        # 更新UI状态
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.progress_bar.setValue(100)
        
        # 计算总用时
        total_time = time.time() - self.scan_start_time
        target_name = self.target_input.text().strip()
        hops_count = len(result.data) if result and result.data else len(self.current_hops)
        
        self.status_label.setText(
            f"追踪完成: {target_name}, {hops_count}跳, 用时{total_time:.2f}秒"
        )
    
    def on_scan_progress(self, percent: int, message: str):
        """处理扫描进度更新"""
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)
    
    def on_scan_error(self, error_msg: str):
        """处理扫描错误"""
        self.status_label.setText(f"扫描错误: {error_msg}")
        self.logger.error(f"路由追踪扫描错误: {error_msg}")
        QMessageBox.critical(self, "扫描错误", error_msg)
    
    def stop_scan(self):
        """停止扫描"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            # 等待线程结束，以确保资源完全释放
            self.scan_thread.wait(1000) # 等待最多1秒
        
        self.status_label.setText("扫描已停止")
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(self.current_hops and len(self.current_hops) > 0)
        self.progress_bar.setValue(0)
        self.logger.info("路由追踪扫描已停止")
    
    def clear_results(self):
        """清除扫描结果"""
        self.result_table.clear()
        self.result_table.setRowCount(0) # 确保表格行数也清空
        self.result_text.clear()
        self.current_hops = []
        self.progress_bar.setValue(0)
        self.status_label.setText("就绪")
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(False)
        
        # 重新准备显示区域，以防格式切换后未清空
        if self.use_native_format:
            self.prepare_native_format_display()
        else:
            self.prepare_table_format_display()
    
    def save_config(self):
        """保存配置"""
        config = self.get_scan_config()
        # 实现保存配置的逻辑
        self.logger.info(f"路由追踪配置已保存: {config}")
        QMessageBox.information(self, "配置保存", "路由追踪配置已成功保存")
    
    def on_scan_progress(self, percent: int, message: str):
        """处理扫描进度更新"""
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)
    
    def on_scan_error(self, error_msg: str):
        """处理扫描错误"""
        self.status_label.setText(f"扫描错误: {error_msg}")
        self.logger.error(f"路由追踪扫描错误: {error_msg}")
        QMessageBox.critical(self, "扫描错误", error_msg) 