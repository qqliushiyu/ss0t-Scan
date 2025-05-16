#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP Ping 面板
TCP Ping 模块的图形界面
"""

import logging
import threading
import time
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox, 
    QPushButton, QLabel, QLineEdit, QSpinBox, QDoubleSpinBox,
    QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QMessageBox, QGridLayout
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QBrush
from PyQt5.QtWidgets import QApplication

from gui.panels.base_panel import BasePanel
from core.tcp_ping import TcpPing
from core.scanner_manager import scanner_manager
from utils.network import parse_ip_range, parse_port_range

class TcpPingPanel(BasePanel):
    """TCP Ping 面板类"""
    
    # 模块ID（与扫描器类名小写对应）
    MODULE_ID = "tcpping"
    
    # 模块名称
    MODULE_NAME = "TCP Ping"
    
    # 自定义信号：结果更新信号
    results_updated = pyqtSignal(list)
    scan_complete = pyqtSignal(object)
    scan_progress = pyqtSignal(int, str)
    scan_error = pyqtSignal(str)
    
    def __init__(self, parent=None):
        """
        初始化 TCP Ping 面板
        
        Args:
            parent: 父窗口
        """
        super().__init__(parent)
        
        # 初始化参数
        self.scanning = False
        self.scanner = None
        self.scan_thread = None
        self.current_result = None
        self._stopped = False  # 添加内部停止标志
        
        # 设置结果表格的列
        self.result_headers = [
            "IP", "端口", "状态", "响应时间 (ms)", "时间戳"
        ]
        
        # 初始化计时器
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_results_display)
        
        # 初始化停止检查计时器
        self.stop_timer = QTimer(self)
        self.stop_timer.setSingleShot(True)
        self.stop_timer.timeout.connect(self._check_thread_stopped)
        self._stop_check_count = 0
        
        # 连接信号
        self.scan_complete.connect(self.on_scan_complete)
        self.scan_progress.connect(self.on_scan_progress)
        self.scan_error.connect(self.on_scan_error)
        self.results_updated.connect(self.on_results_updated)
        
        # 添加模块菜单项
        self.actions = []
        
        # 执行自定义初始化
        self.post_init()
    
    def post_init(self):
        """
        在初始化后执行的设置，需要在UI加载完成后调用
        """
        # 连接标签页切换信号，以便在切换标签页时调整表格
        self.result_tabs.currentChanged.connect(self.on_tab_changed)
    
    def on_tab_changed(self, index):
        """
        当标签页切换时调用
        
        Args:
            index: 新标签页的索引
        """
        # 调整当前标签页中的表格列宽
        self.adjust_table_columns()
    
    def showEvent(self, event):
        """
        当面板显示时调用
        
        Args:
            event: 显示事件
        """
        super().showEvent(event)
        
        # 面板显示时调整表格列宽
        QTimer.singleShot(100, self.adjust_table_columns)
        
        # 确保连接标签页切换信号（在UI完全加载后）
        QTimer.singleShot(200, self.post_init)
    
    def create_param_group(self):
        """创建参数组"""
        # 创建紧凑的参数组
        self.param_group = QGroupBox("TCP Ping 参数")
        
        # 使用网格布局减少垂直空间占用
        param_layout = QGridLayout()
        param_layout.setVerticalSpacing(6)  # 减少垂直间距
        param_layout.setHorizontalSpacing(10)
        
        # ===== 行1：目标和端口设置 =====
        # 目标 IP/IP段
        param_layout.addWidget(QLabel("目标主机:"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP地址，IP段 (192.168.1.1/24) 或范围 (192.168.1.1-10)")
        param_layout.addWidget(self.target_input, 0, 1, 1, 3)  # 跨3列
        
        # 端口
        param_layout.addWidget(QLabel("目标端口:"), 0, 4)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("单个端口 (80) 或范围 (80-100) 或列表 (80,443)")
        param_layout.addWidget(self.port_input, 0, 5, 1, 3)  # 跨3列
        
        # ===== 行2：执行参数 =====
        # 持续模式
        param_layout.addWidget(QLabel("运行模式:"), 1, 0)
        self.continuous_checkbox = QCheckBox("持续ping")
        self.continuous_checkbox.setToolTip("启用后将无限次数ping目标")
        self.continuous_checkbox.stateChanged.connect(self.toggle_continuous_mode)
        param_layout.addWidget(self.continuous_checkbox, 1, 1)
        
        # Ping 次数
        param_layout.addWidget(QLabel("Ping次数:"), 1, 2)
        self.count_spinbox = QSpinBox()
        self.count_spinbox.setRange(1, 1000)
        self.count_spinbox.setValue(4)
        self.count_spinbox.setToolTip("对每个主机端口重复Ping的次数")
        param_layout.addWidget(self.count_spinbox, 1, 3)
        
        # 间隔时间
        param_layout.addWidget(QLabel("间隔(秒):"), 1, 4)
        self.interval_spinbox = QDoubleSpinBox()
        self.interval_spinbox.setRange(0.1, 10.0)
        self.interval_spinbox.setSingleStep(0.1)
        self.interval_spinbox.setValue(1.0)
        self.interval_spinbox.setToolTip("每次Ping之间的间隔时间(秒)")
        param_layout.addWidget(self.interval_spinbox, 1, 5)
        
        # 超时时间
        param_layout.addWidget(QLabel("超时(秒):"), 1, 6)
        self.timeout_spinbox = QDoubleSpinBox()
        self.timeout_spinbox.setRange(0.1, 30.0)
        self.timeout_spinbox.setSingleStep(0.1)
        self.timeout_spinbox.setValue(2.0)
        self.timeout_spinbox.setToolTip("连接超时时间(秒)")
        param_layout.addWidget(self.timeout_spinbox, 1, 7)
        
        # ===== 行3：高级设置和显示选项 =====
        # 最大线程数
        param_layout.addWidget(QLabel("最大线程:"), 2, 0)
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 100)
        self.threads_spinbox.setValue(20)
        self.threads_spinbox.setToolTip("最大并发线程数")
        param_layout.addWidget(self.threads_spinbox, 2, 1)
        
        # 慢响应阈值
        param_layout.addWidget(QLabel("慢响应阈值(ms):"), 2, 2)
        self.threshold_spinbox = QDoubleSpinBox()
        self.threshold_spinbox.setRange(10, 5000)
        self.threshold_spinbox.setSingleStep(10)
        self.threshold_spinbox.setValue(200)
        self.threshold_spinbox.setToolTip("响应时间超过此值视为慢响应(毫秒)")
        param_layout.addWidget(self.threshold_spinbox, 2, 3)
        
        # 显示模式
        param_layout.addWidget(QLabel("显示筛选:"), 2, 4)
        self.display_mode = QComboBox()
        self.display_mode.addItem("所有结果")
        self.display_mode.addItem("仅开放端口")
        self.display_mode.addItem("仅关闭端口")
        self.display_mode.addItem("仅慢响应")
        self.display_mode.currentIndexChanged.connect(self.update_results_display)
        param_layout.addWidget(self.display_mode, 2, 5)
        
        # 自动刷新
        refresh_layout = QHBoxLayout()
        self.auto_refresh = QCheckBox("自动刷新")
        self.auto_refresh.setChecked(True)
        self.auto_refresh.toggled.connect(self.toggle_auto_refresh)
        refresh_layout.addWidget(self.auto_refresh)
        
        # 刷新间隔
        refresh_layout.addWidget(QLabel("间隔:"))
        self.refresh_interval = QSpinBox()
        self.refresh_interval.setRange(1, 10)
        self.refresh_interval.setValue(1)
        self.refresh_interval.setSuffix(" 秒")
        self.refresh_interval.setToolTip("自动刷新间隔时间(秒)")
        self.refresh_interval.valueChanged.connect(self.update_refresh_interval)
        refresh_layout.addWidget(self.refresh_interval)
        
        param_layout.addLayout(refresh_layout, 2, 6, 1, 2)  # 跨2列
        
        # 设置列的拉伸因子
        for col in range(8):
            param_layout.setColumnStretch(col, 1)
        
        # 设置主参数组布局
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
        
        # 初始状态
        self.toggle_continuous_mode(self.continuous_checkbox.isChecked())
    
    def get_scan_config(self) -> Dict[str, Any]:
        """
        获取扫描配置
        
        Returns:
            配置参数字典
        """
        # 获取持续模式状态
        continuous = self.continuous_checkbox.isChecked()
        
        return {
            "targets": self.target_input.text().strip(),
            "ports": self.port_input.text().strip(),
            "count": self.count_spinbox.value(),
            "interval": self.interval_spinbox.value(),
            "timeout": self.timeout_spinbox.value(),
            "max_threads": self.threads_spinbox.value(),
            "threshold": self.threshold_spinbox.value(),
            "continuous": continuous
        }
    
    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """
        设置扫描配置到UI控件
        
        Args:
            config: 配置参数字典
        """
        # 更新UI控件
        if "targets" in config:
            self.target_input.setText(str(config["targets"]))
        
        if "ports" in config:
            self.port_input.setText(str(config["ports"]))
        
        if "continuous" in config:
            self.continuous_checkbox.setChecked(config["continuous"])
        
        if "count" in config:
            try:
                value = int(config["count"])
                self.count_spinbox.setValue(value)
            except (ValueError, TypeError):
                pass
        
        if "interval" in config:
            try:
                value = float(config["interval"])
                self.interval_spinbox.setValue(value)
            except (ValueError, TypeError):
                pass
        
        if "timeout" in config:
            try:
                value = float(config["timeout"])
                self.timeout_spinbox.setValue(value)
            except (ValueError, TypeError):
                pass
        
        if "max_threads" in config:
            try:
                value = int(config["max_threads"])
                self.threads_spinbox.setValue(value)
            except (ValueError, TypeError):
                pass
        
        if "threshold" in config:
            try:
                value = float(config["threshold"])
                self.threshold_spinbox.setValue(value)
            except (ValueError, TypeError):
                pass
    
    def toggle_auto_refresh(self, enabled: bool) -> None:
        """
        切换自动刷新状态
        
        Args:
            enabled: 是否启用
        """
        if enabled and self.scanning:
            # 使用用户设置的刷新间隔
            refresh_interval = self.refresh_interval.value() * 1000  # 转换为毫秒
            self.update_timer.start(refresh_interval)
        else:
            self.update_timer.stop()
    
    def toggle_continuous_mode(self, enabled: bool) -> None:
        """
        切换持续ping模式
        
        Args:
            enabled: 是否启用
        """
        if enabled:
            # 持续模式下，count值将被忽略，禁用count输入框
            self.count_spinbox.setEnabled(False)
            self.count_spinbox.setToolTip("持续模式下此设置无效")
        else:
            # 非持续模式，启用count输入框
            self.count_spinbox.setEnabled(True)
            self.count_spinbox.setToolTip("对每个主机端口重复 Ping 的次数")
    
    def validate_params(self, config: Dict[str, Any]) -> bool:
        """
        验证扫描参数
        
        Args:
            config: 配置参数字典
        
        Returns:
            是否有效
        """
        # 检查目标
        targets = config.get("targets", "")
        if not targets:
            QMessageBox.warning(self, "参数错误", "请输入目标IP或IP范围")
            return False
        
        # 尝试解析目标
        try:
            target_list = parse_ip_range(targets)
            if not target_list:
                QMessageBox.warning(self, "参数错误", "无法解析目标IP范围")
                return False
            
            # 检查目标数量
            if len(target_list) > 500:
                result = QMessageBox.question(
                    self, 
                    "警告", 
                    f"您指定了 {len(target_list)} 个目标IP，这可能会导致扫描时间较长。\n是否继续？",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if result != QMessageBox.Yes:
                    return False
        except Exception as e:
            QMessageBox.warning(self, "参数错误", f"目标格式错误: {str(e)}")
            return False
        
        # 检查端口
        ports = config.get("ports", "")
        if not ports:
            QMessageBox.warning(self, "参数错误", "请输入端口或端口范围")
            return False
        
        # 尝试解析端口
        try:
            port_list = parse_port_range(ports)
            if not port_list:
                QMessageBox.warning(self, "参数错误", "无法解析端口范围")
                return False
            
            # 检查端口数量
            if len(port_list) > 100:
                result = QMessageBox.question(
                    self, 
                    "警告", 
                    f"您指定了 {len(port_list)} 个端口，这可能会导致扫描时间较长。\n是否继续？",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if result != QMessageBox.Yes:
                    return False
        except Exception as e:
            QMessageBox.warning(self, "参数错误", f"端口格式错误: {str(e)}")
            return False
        
        return True
    
    def start_scan(self) -> None:
        """开始扫描"""
        # 获取扫描配置
        config = self.get_scan_config()
        continuous = config.get("continuous", False)
        
        # 参数验证
        if not self.validate_params(config):
            return
        
        # 创建扫描器
        scanner_class = scanner_manager.get_scanner(self.MODULE_ID)
        if not scanner_class:
            QMessageBox.critical(self, "错误", f"模块 {self.MODULE_ID} 未找到")
            return
        
        # 记录操作到日志
        self.logger.info(f"开始扫描，持续模式: {continuous}")
        
        # 更新UI状态
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # 确保停止按钮可以点击，并在界面上清晰可见
        self.stop_button.setFocus()
        self.stop_button.raise_()
        
        self.clear_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
        
        # 如果是持续扫描模式，需要特殊处理
        if continuous:
            self.status_label.setText("正在持续 TCP Ping 扫描...")
            
            # 禁用相关设置控件
            self.continuous_checkbox.setEnabled(False)
            self.count_spinbox.setEnabled(False)
            self.target_input.setEnabled(False)
            self.port_input.setEnabled(False)
            
            # 在持续模式下确保停止按钮可用
            self.logger.info("持续模式: 确保停止按钮已启用")
            self.stop_button.setEnabled(True)
        else:
            self.status_label.setText("正在扫描...")
        
        # 设置扫描状态
        self.scanning = True
        self._stopped = False
        
        # 使用我们自定义的扫描方法
        self._run_scan(scanner_class, config)
        
        # 启动自动刷新
        if self.auto_refresh.isChecked():
            refresh_interval = self.refresh_interval.value() * 1000  # 转换为毫秒
            self.update_timer.start(refresh_interval)
        
        # 强制更新UI，确保按钮状态被及时刷新
        QApplication.processEvents()
        
        # 再次确认停止按钮状态
        if not self.stop_button.isEnabled():
            self.logger.warning("UI更新后停止按钮仍未启用，强制启用")
            self.stop_button.setEnabled(True)
            QApplication.processEvents()
        
        self.logger.info(f"开始 {self.MODULE_NAME} 扫描，停止按钮状态: {self.stop_button.isEnabled()}")
    
    def stop_scan(self) -> None:
        """
        停止扫描
        
        此方法解决了使用Python标准线程时停止按钮无法使用的问题：
        1. 检查扫描是否正在进行且扫描器实例存在
        2. 调用扫描器的stop()方法设置内部停止标志
        3. 立即更新UI状态以避免界面卡顿
        4. 使用计时器非阻塞方式检查线程状态
        5. 避免重复连接计时器信号，使用在初始化时创建的连接
        """
        # 直接记录操作到日志，用于调试
        self.logger.info("用户点击了停止按钮")
        
        # 立即禁用停止按钮，防止重复点击
        if hasattr(self, 'stop_button'):
            self.stop_button.setEnabled(False)
            # 强制立即处理UI事件
            QApplication.processEvents()
        
        try:
            if self.scanning:
                # 确保有扫描器实例存在
                if hasattr(self, 'scanner') and self.scanner:
                    try:
                        # 停止扫描器
                        self.scanner.stop()
                        
                        # 直接设置停止标志
                        self._stopped = True
                        self.scanning = False
                        
                        # 判断是否为持续模式
                        continuous_mode = False
                        if self.current_result and hasattr(self.current_result, 'metadata') and self.current_result.metadata:
                            continuous_mode = self.current_result.metadata.get('continuous', False)
                        
                        # 记录扫描状态
                        self.logger.info(f"停止扫描: 持续模式={continuous_mode}, 扫描状态={self.scanning}, 停止标志={self._stopped}")
                        
                        # 立即更新UI状态，避免界面卡顿
                        self.scan_button.setEnabled(False)  # 临时禁用，等待完全停止
                        self.status_label.setText("正在停止扫描...")
                        
                        # 停止自动刷新
                        if hasattr(self, 'update_timer'):
                            self.update_timer.stop()
                        
                        # 重置停止计时器相关变量
                        self._stop_check_count = 0
                        self._stop_start_time = time.time()
                        
                        # 启动计时器检查线程状态，使用已有的连接，不要重复连接
                        self.stop_timer.start(100)  # 缩短检查间隔到100毫秒，以便更快响应
                        
                        # 再次强制处理UI事件
                        QApplication.processEvents()
                        
                        self.logger.info("正在停止 TCP Ping 扫描...")
                    except Exception as e:
                        self.logger.error(f"停止扫描时出错: {str(e)}")
                        # 出错时恢复UI状态
                        self._handle_thread_stopped()
                else:
                    # 没有扫描器实例，直接恢复UI状态
                    self.logger.warning("尝试停止不存在的扫描")
                    self._handle_thread_stopped()
            else:
                # 没有正在进行的扫描，直接恢复UI状态
                self._handle_thread_stopped()
        except Exception as e:
            self.logger.error(f"执行stop_scan()方法时出错: {str(e)}")
            # 任何异常都恢复UI状态
            self._handle_thread_stopped()
    
    def _handle_thread_stopped(self):
        """处理线程已停止的情况，恢复UI状态"""
        # 清理资源
        self.scanning = False
        self._stopped = False
        self.scan_thread = None
        if hasattr(self, 'scanner'):
            self.scanner = None  # 清除扫描器引用
        
        # 清除停止检查相关变量
        if hasattr(self, '_stop_check_count'):
            self._stop_check_count = 0
        if hasattr(self, '_stop_start_time'):
            delattr(self, '_stop_start_time')
        
        # 更新界面，调用专用方法
        self._restore_ui_after_scan()
        
        # 更新额外的UI元素
        self.status_label.setText("扫描已停止")
        self.progress_bar.setValue(0)
        
        # 调整表格布局
        self.adjust_table_columns()
        
        # 显示持续扫描停止提示（如果适用）
        if self.current_result and hasattr(self.current_result, 'metadata') and \
           self.current_result.metadata and self.current_result.metadata.get('continuous', False):
            QMessageBox.information(self, "持续扫描已停止", "持续扫描已停止，当前结果已保存")
        
        self.logger.info(f"{self.MODULE_NAME} 扫描完成")
        
        # 强制处理UI事件，确保状态更新显示
        QApplication.processEvents()
    
    def on_scan_complete(self, result):
        """
        扫描完成处理
        
        Args:
            result: 扫描结果
        """
        super().on_scan_complete(result)
        
        # 获取持续模式状态
        continuous = False
        if hasattr(result, 'metadata') and result.metadata:
            continuous = result.metadata.get('continuous', False)
        
        # 记录调试信息
        self.logger.info(f"扫描完成回调，持续模式: {continuous}, 当前扫描状态: {self.scanning}")
        
        # 如果不是持续模式，则正常结束
        if not continuous:
            # 设置扫描状态
            self.scanning = False
            
            # 停止自动刷新
            self.update_timer.stop()
            
            # 恢复所有UI控件状态
            self.continuous_checkbox.setEnabled(True)
            self.count_spinbox.setEnabled(True)
            self.target_input.setEnabled(True)
            self.port_input.setEnabled(True)
            
            # 非持续模式扫描完成后启用扫描按钮
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
        else:
            # 持续模式下确保扫描按钮禁用，停止按钮可用
            self.scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.stop_button.raise_()
            QApplication.processEvents()
            self.logger.info(f"持续模式扫描完成后，按钮状态: 扫描={self.scan_button.isEnabled()}, 停止={self.stop_button.isEnabled()}")
        
        # 更新状态栏，区分持续模式和普通模式
        if continuous and self.scanning:
            self.status_label.setText("持续 TCP Ping 扫描进行中...")
        else:
            self.status_label.setText("扫描完成")
            
        # 调整表格列宽以适应当前窗口大小
        QTimer.singleShot(100, self.adjust_table_columns)
    
    def on_results_updated(self, results: List[Dict[str, Any]]) -> None:
        """
        结果更新处理
        
        Args:
            results: 更新的结果列表
        """
        # 可以在这里处理实时结果更新，如高亮显示新结果
        pass
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """
        在持续模式下获取实时统计信息
        
        Returns:
            统计信息字典
        """
        if not self.scanning or not hasattr(self, 'scanner') or not self.scanner:
            return {}
        
        # 获取scanner中的最新结果
        with self.scanner._lock:
            results = self.scanner._results.copy()
        
        if not results:
            return {}
        
        # 计算基本统计
        total_count = len(results)
        success_count = sum(1 for r in results if r.get("status") == "open")
        slow_count = sum(1 for r in results if r.get("is_slow", False))
        
        # 使用scanner的analyze_results方法获取详细统计
        stats = self.scanner.analyze_results(results)
        
        return {
            "total_count": total_count,
            "success_count": success_count,
            "slow_count": slow_count,
            "stats": stats
        }
    
    def update_results_display(self) -> None:
        """更新结果显示"""
        if not self.current_result:
            return
        
        # 检查是否为持续模式
        continuous_mode = False
        if hasattr(self.current_result, 'metadata') and self.current_result.metadata:
            continuous_mode = self.current_result.metadata.get('continuous', False)
        
        # 在持续模式下，从scanner获取实时结果
        if continuous_mode and self.scanning and hasattr(self, 'scanner') and self.scanner:
            # 获取scanner中的最新结果
            with self.scanner._lock:
                # 更新当前结果数据
                self.current_result.data = self.scanner._results.copy()
                
            # 获取实时统计信息并更新摘要标签页
            stats_data = self.get_real_time_stats()
            if stats_data and "stats" in stats_data:
                # 更新metadata中的stats数据
                if not hasattr(self.current_result, 'metadata'):
                    self.current_result.metadata = {}
                self.current_result.metadata["stats"] = stats_data["stats"]
                
                # 更新摘要表格
                hosts = stats_data["stats"].get("hosts", [])
                if hosts:
                    self.update_summary_tab(hosts)
        
        if not hasattr(self.current_result, 'data'):
            return
        
        # 获取显示模式
        mode = self.display_mode.currentText()
        
        # 过滤结果
        filtered_results = []
        for item in self.current_result.data:
            if mode == "所有结果":
                filtered_results.append(item)
            elif mode == "仅开放端口" and item.get("status") == "open":
                filtered_results.append(item)
            elif mode == "仅关闭端口" and item.get("status") == "closed":
                filtered_results.append(item)
            elif mode == "仅慢响应" and item.get("is_slow", False):
                filtered_results.append(item)
        
        # 显示过滤后的结果
        self.display_filtered_results(filtered_results)
        
        # 调整表格列宽以适应当前窗口大小
        self.adjust_table_columns()
        
        # 如果在持续模式下，更新状态栏
        if continuous_mode and self.scanning and hasattr(self, 'scanner') and self.scanner:
            stats_data = self.get_real_time_stats()
            if stats_data:
                # 更新状态栏
                self.status_label.setText(
                    f"持续TCP Ping扫描中: 已发送 {stats_data['total_count']} 次，"
                    f"{stats_data['success_count']} 次成功，{stats_data['slow_count']} 次响应慢"
                )
    
    def display_filtered_results(self, results: List[Dict[str, Any]]) -> None:
        """
        显示过滤后的结果
        
        Args:
            results: 过滤后的结果列表
        """
        # 设置表格列
        self.result_table.setColumnCount(len(self.result_headers))
        self.result_table.setHorizontalHeaderLabels(self.result_headers)
        
        # 限制结果数量以提高性能
        max_rows = 5000
        if len(results) > max_rows:
            self.status_label.setText(f"显示前 {max_rows} 条结果 (共 {len(results)} 条)")
            results = results[:max_rows]
        
        # 设置行数
        self.result_table.setRowCount(len(results))
        
        # 禁用排序以加快加载速度
        self.result_table.setSortingEnabled(False)
        
        # 填充数据
        for row, item in enumerate(results):
            # IP
            self.result_table.setItem(row, 0, QTableWidgetItem(item.get("ip", "")))
            
            # 端口
            port = item.get("port", "")
            self.result_table.setItem(row, 1, QTableWidgetItem(str(port)))
            
            # 状态
            status = item.get("status", "")
            status_item = QTableWidgetItem(status)
            if status == "open":
                status_item.setBackground(QBrush(QColor(200, 255, 200)))  # 浅绿色
            elif status == "closed":
                status_item.setBackground(QBrush(QColor(255, 200, 200)))  # 浅红色
            self.result_table.setItem(row, 2, status_item)
            
            # 响应时间
            response_time = item.get("response_time", 0)
            time_item = QTableWidgetItem(f"{response_time:.2f}")
            if item.get("is_slow", False):
                time_item.setBackground(QBrush(QColor(255, 255, 150)))  # 浅黄色
            self.result_table.setItem(row, 3, time_item)
            
            # 时间戳
            self.result_table.setItem(row, 4, QTableWidgetItem(item.get("timestamp", "")))
        
        # 恢复排序功能
        self.result_table.setSortingEnabled(True)
        
        # 适应列宽
        self.adjust_table_columns()
    
    def display_results(self, result) -> None:
        """
        显示扫描结果
        
        Args:
            result: 扫描结果
        """
        # 保存结果
        self.current_result = result
        
        # 更新结果显示
        self.update_results_display()
        
        # 检查是否为持续模式
        continuous_mode = False
        if hasattr(result, 'metadata') and result.metadata:
            continuous_mode = result.metadata.get('continuous', False)
        
        # 显示统计信息
        if hasattr(result, 'metadata') and result.metadata:
            stats = result.metadata.get('stats', {})
            hosts = stats.get('hosts', [])
            
            # 如果是持续模式但还没有数据，创建一个空的统计表
            if continuous_mode and not hosts:
                # 创建摘要表格
                summary_table = QTableWidget()
                summary_table.setSelectionBehavior(QTableWidget.SelectRows)
                summary_table.setEditTriggers(QTableWidget.NoEditTriggers)
                summary_table.setAlternatingRowColors(True)
                summary_table.setColumnCount(8)
                summary_table.setHorizontalHeaderLabels([
                    "IP:端口", "状态", "成功率", "平均响应(ms)",
                    "最小响应(ms)", "最大响应(ms)", "抖动", "慢响应数"
                ])
                
                # 设置适当的列宽
                summary_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
                summary_table.setColumnWidth(0, 140)  # IP:端口列
                summary_table.setColumnWidth(1, 60)   # 状态列
                summary_table.setColumnWidth(2, 70)   # 成功率列
                summary_table.setColumnWidth(3, 100)  # 平均响应时间列
                summary_table.setColumnWidth(4, 110)  # 最小响应时间列
                summary_table.setColumnWidth(5, 110)  # 最大响应时间列
                summary_table.setColumnWidth(6, 60)   # 抖动列
                summary_table.setColumnWidth(7, 80)   # 慢响应数列
                summary_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
                
                # 添加到结果标签页
                exists = False
                for i in range(self.result_tabs.count()):
                    if self.result_tabs.tabText(i) == "统计摘要":
                        self.result_tabs.removeTab(i)
                        exists = True
                        break
                
                self.result_tabs.addTab(summary_table, "统计摘要")
                
                # 如果是新添加的标签页，切换到这个标签页
                if not exists:
                    self.result_tabs.setCurrentIndex(self.result_tabs.count() - 1)
                    
                # 在持续模式下，设置提示信息
                self.status_label.setText("持续TCP Ping扫描中: 等待初始结果...")
                return
            
            if hosts:
                # 使用update_summary_tab方法更新摘要表格
                self.update_summary_tab(hosts)
                
                # 持续模式下的状态更新
                if continuous_mode and self.scanning:
                    total_count = len(result.data)
                    success_count = sum(1 for r in result.data if r.get("status") == "open")
                    slow_count = sum(1 for r in result.data if r.get("is_slow", False))
                    
                    # 更新状态栏
                    self.status_label.setText(
                        f"持续TCP Ping扫描中: 已发送 {total_count} 次，"
                        f"{success_count} 次成功，{slow_count} 次响应慢"
                    )
    
    def update_refresh_interval(self, value: int) -> None:
        """
        更新自动刷新间隔
        
        Args:
            value: 间隔时间(秒)
        """
        if self.auto_refresh.isChecked() and self.scanning:
            self.update_timer.start(value * 1000)

    def _run_scan(self, scanner_class, config):
        """
        运行扫描
        
        Args:
            scanner_class: 扫描器类
            config: 扫描配置
        """
        try:
            self.scanner = scanner_class(config)
            self._stopped = False  # 添加内部停止标志
            
            # 启动扫描
            self.scan_thread = threading.Thread(
                target=self._scan_thread_func,
                args=(self.scanner,)
            )
            self.scan_thread.daemon = True
            self.scan_thread.start()
            
            # 强制处理UI事件，确保按钮状态立即更新
            QApplication.processEvents()
            
            # 确保在线程启动后停止按钮可用
            self.stop_button.setEnabled(True)
            QApplication.processEvents()
            
            self.logger.info(f"扫描线程已启动，停止按钮状态: {self.stop_button.isEnabled()}")
        except Exception as e:
            self.scan_error.emit(str(e))

    def _scan_thread_func(self, scanner):
        """
        扫描线程函数
        
        Args:
            scanner: 扫描器实例
        """
        try:
            # 设置进度更新回调
            scanner.set_progress_callback(self.scan_progress.emit)
            
            # 运行扫描
            result = scanner.run_scan()
            
            # 发送完成信号
            self.scan_complete.emit(result)
        except Exception as e:
            self.scan_error.emit(str(e))
        finally:
            # 确保扫描结束时UI状态正确
            if hasattr(self, '_stopped') and self._stopped:
                # 如果是用户主动停止的扫描，确保在主线程中更新UI
                QTimer.singleShot(0, self._handle_thread_stopped)

    def on_scan_progress(self, percent: int, message: str) -> None:
        """
        扫描进度更新
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)

    def on_scan_error(self, error_msg: str) -> None:
        """
        扫描错误处理
        
        Args:
            error_msg: 错误消息
        """
        # 设置扫描状态
        self.scanning = False
        
        # 恢复UI控件状态
        self.continuous_checkbox.setEnabled(True)
        self.count_spinbox.setEnabled(True)
        
        # 更新UI状态
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"扫描错误: {error_msg}")
        
        # 停止自动刷新
        self.update_timer.stop()
        
        # 显示错误消息
        QMessageBox.critical(self, "扫描错误", error_msg)

    def update_summary_tab(self, hosts: List[Dict[str, Any]]) -> None:
        """
        更新摘要标签页
        
        Args:
            hosts: 主机统计信息
        """
        if not hosts:
            return
        
        # 查找是否存在摘要标签页
        summary_table = None
        summary_index = -1
        for i in range(self.result_tabs.count()):
            if self.result_tabs.tabText(i) == "统计摘要":
                summary_table = self.result_tabs.widget(i)
                summary_index = i
                break
        
        # 如果没有找到，创建新的标签页
        if not summary_table:
            summary_table = QTableWidget()
            summary_table.setSelectionBehavior(QTableWidget.SelectRows)
            summary_table.setEditTriggers(QTableWidget.NoEditTriggers)
            summary_table.setAlternatingRowColors(True)
            summary_table.setColumnCount(7)  # 减少列数，合并一些相关信息
            summary_table.setHorizontalHeaderLabels([
                "IP:端口", "状态", "成功率", "响应时间(ms)",
                "抖动", "慢响应数", "详情"
            ])
            
            summary_index = self.result_tabs.addTab(summary_table, "统计摘要")
        
        # 确保表格是QTableWidget类型
        if not isinstance(summary_table, QTableWidget):
            return
        
        # 设置行数
        summary_table.setRowCount(len(hosts))
        
        # 填充数据
        for row, host in enumerate(hosts):
            # IP:端口
            ip_port = f"{host.get('ip', '')}:{host.get('port', '')}"
            summary_table.setItem(row, 0, QTableWidgetItem(ip_port))
            
            # 状态
            last_status = host.get("last_status", "unknown")
            status_item = QTableWidgetItem(last_status)
            if last_status == "open":
                status_item.setBackground(QBrush(QColor(200, 255, 200)))  # 浅绿色
            elif last_status == "closed":
                status_item.setBackground(QBrush(QColor(255, 200, 200)))  # 浅红色
            summary_table.setItem(row, 1, status_item)
            
            # 成功率
            availability = host.get("availability", 0)
            summary_table.setItem(row, 2, QTableWidgetItem(f"{availability:.1f}%"))
            
            # 响应时间 (合并平均、最小和最大为一列)
            avg_time = host.get("avg_time", 0)
            min_time = host.get("min_time", 0)
            max_time = host.get("max_time", 0)
            time_info = f"{avg_time:.1f} (最小: {min_time:.1f}, 最大: {max_time:.1f})"
            summary_table.setItem(row, 3, QTableWidgetItem(time_info))
            
            # 抖动
            jitter = host.get("jitter", 0)
            summary_table.setItem(row, 4, QTableWidgetItem(f"{jitter:.1f}"))
            
            # 慢响应数
            slow_count = host.get("slow", 0)
            total = host.get("total", 1)
            slow_item = QTableWidgetItem(f"{slow_count} ({(slow_count/max(1,total))*100:.1f}%)")
            if slow_count > 0:
                slow_item.setBackground(QBrush(QColor(255, 255, 150)))  # 浅黄色
            summary_table.setItem(row, 5, slow_item)
            
            # 详情：添加更多有用信息
            up_count = host.get("up", 0) if "up" in host else host.get("open", 0)
            down_count = host.get("down", 0) if "down" in host else host.get("closed", 0)
            details = f"总次数: {total}, 成功: {up_count}, 失败: {down_count}"
            summary_table.setItem(row, 6, QTableWidgetItem(details))
        
        # 优化表格显示
        self.adjust_summary_columns(summary_table)
        
        # 如果这是第一次创建摘要表，切换到摘要标签页
        if summary_index >= 0 and self.result_tabs.currentIndex() != summary_index:
            self.result_tabs.setCurrentIndex(summary_index)
    
    def adjust_summary_columns(self, table):
        """调整摘要表格的列宽"""
        if not table:
            return
            
        # 根据窗口大小动态调整列宽
        width = table.width()
        
        # 优化摘要表格列宽
        if width > 700:  # 大窗口
            col_widths = [140, 60, 70, 160, 60, 100, 150]
        else:  # 小窗口
            col_widths = [120, 50, 60, 140, 50, 80, 120]
        
        # 应用列宽设置
        for i, width in enumerate(col_widths):
            if i < table.columnCount():
                table.setColumnWidth(i, width)
        
        # 使IP:端口列和详情列自动拉伸填充剩余空间
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        
        # 设置适当的行高
        table.verticalHeader().setDefaultSectionSize(22)  # 减小行高

    def adjust_table_columns(self):
        """调整表格列宽以适应当前窗口大小"""
        # 调整主结果表格
        if hasattr(self, 'result_table') and self.result_table:
            width = self.result_table.width()
            
            # 根据窗口大小动态调整列宽
            if width > 600:  # 大窗口
                col_widths = [120, 60, 60, 100, 160]
            else:  # 小窗口
                col_widths = [100, 50, 50, 80, 140]
            
            # 应用列宽设置
            for i, width in enumerate(col_widths):
                if i < self.result_table.columnCount():
                    self.result_table.setColumnWidth(i, width)
            
            # 设置行高
            self.result_table.verticalHeader().setDefaultSectionSize(22)  # 减小行高
        
        # 调整摘要表格
        summary_table = None
        for i in range(self.result_tabs.count()):
            if self.result_tabs.tabText(i) == "统计摘要":
                summary_table = self.result_tabs.widget(i)
                self.adjust_summary_columns(summary_table)
                break

    def _check_thread_stopped(self):
        """
        检查线程是否已停止
        
        此方法专门处理Python标准线程的停止检测，与QThread不同：
        1. 使用is_alive()方法检查Python标准线程是否已停止
        2. 确保线程存在并且已停止才恢复UI状态
        3. 清除扫描器和线程引用以释放资源
        4. 如果线程仍在运行，则持续检查直到线程停止
        5. 支持持续模式下的特殊处理
        
        注意：此方法通过计时器调用，避免了阻塞UI线程
        """
        try:
            # 记录当前线程状态以便调试
            thread_exists = hasattr(self, 'scan_thread') and self.scan_thread is not None
            thread_alive = thread_exists and hasattr(self.scan_thread, 'is_alive') and self.scan_thread.is_alive()
            scanner_exists = hasattr(self, 'scanner') and self.scanner is not None
            
            self.logger.debug(f"检查线程状态: 存在={thread_exists}, 活动={thread_alive}, 扫描器存在={scanner_exists}")
            
            # 首先检查scanner是否还存在，如果scanner已被手动设置为None，则表示已停止
            if not scanner_exists:
                self.logger.info("扫描器已移除，视为已停止")
                self._handle_thread_stopped()
                return
                
            # 如果扫描器存在但停止标志已设置，确保再次调用stop方法
            if scanner_exists and self._stopped and not self.scanner._stopped:
                self.logger.info("发现扫描器停止标志未正确设置，重新停止")
                self.scanner.stop()
            
            # 检查线程是否已停止
            if not thread_exists or not thread_alive:
                # 线程不存在或已停止，恢复UI状态
                self.logger.info("扫描线程已停止，恢复UI状态")
                self._handle_thread_stopped()
            else:
                # 线程仍在运行，继续等待并记录
                self.logger.debug("线程仍在运行，继续等待停止")
                self.stop_timer.start(100)  # 更快检查，100毫秒后再检查
                
                # 每400毫秒更新一次UI提示
                if not hasattr(self, '_stop_check_count'):
                    self._stop_check_count = 0
                self._stop_check_count += 1
                
                if self._stop_check_count >= 4:  # 约400毫秒
                    self._stop_check_count = 0
                    self.status_label.setText(f"正在停止扫描，请稍候...")
                    QApplication.processEvents()
                    
                # 如果等待超过5秒，尝试强制结束线程
                if hasattr(self, '_stop_start_time'):
                    elapsed = time.time() - self._stop_start_time
                    if elapsed > 5.0:
                        self.logger.warning(f"线程停止等待超时(5秒)，尝试强制清理资源")
                        self._handle_thread_stopped()
                        return
                else:
                    self._stop_start_time = time.time()
        except Exception as e:
            # 记录异常但不中断UI
            self.logger.error(f"检查线程状态时发生错误: {str(e)}")
            # 出错时也尝试恢复UI
            self._handle_thread_stopped()

    def create_action_group(self):
        """创建操作按钮组 - 覆盖父类方法"""
        self.action_group = QGroupBox("操作")
        action_layout = QHBoxLayout()
        action_layout.setSpacing(8)  # 减少按钮间距
        
        # 开始扫描按钮
        self.scan_button = QPushButton("开始扫描")
        self.scan_button.setToolTip("开始TCP Ping扫描")
        self.scan_button.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_button)
        
        # 停止扫描按钮
        self.stop_button = QPushButton("停止扫描")
        self.stop_button.setToolTip("停止正在进行的扫描")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)  # 初始禁用
        action_layout.addWidget(self.stop_button)
        
        # 清除结果按钮
        self.clear_button = QPushButton("清除结果")
        self.clear_button.setToolTip("清除所有扫描结果")
        self.clear_button.clicked.connect(self.clear_results)
        action_layout.addWidget(self.clear_button)
        
        # 导出结果按钮
        self.export_button = QPushButton("导出结果")
        self.export_button.setToolTip("将扫描结果导出到文件")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)  # 初始禁用
        action_layout.addWidget(self.export_button)
        
        # 保存配置按钮
        self.save_config_button = QPushButton("保存配置")
        self.save_config_button.setToolTip("保存当前配置为默认值")
        self.save_config_button.clicked.connect(self.save_config)
        action_layout.addWidget(self.save_config_button)
        
        self.action_group.setLayout(action_layout)
        self.config_layout.addWidget(self.action_group)

    def _restore_ui_after_scan(self):
        """恢复扫描后的UI状态"""
        # 恢复UI控件状态
        self.scanning = False
        self.scan_button.setEnabled(True)  # 确保扫描按钮始终可用
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.target_input.setEnabled(True)
        self.port_input.setEnabled(True)
        self.continuous_checkbox.setEnabled(True)
        self.count_spinbox.setEnabled(not self.continuous_checkbox.isChecked())
        self.status_label.setText("扫描已停止")
        self.export_button.setEnabled(self.current_result is not None)
        
        # 记录按钮状态
        self.logger.info(f"UI恢复后按钮状态: 扫描={self.scan_button.isEnabled()}, 停止={self.stop_button.isEnabled()}")
        
        # 强制处理UI事件，确保状态更新显示
        QApplication.processEvents()
        
        self.logger.info("扫描线程已停止，恢复UI状态")