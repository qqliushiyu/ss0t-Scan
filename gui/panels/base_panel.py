#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基础面板，提供所有扫描面板的共用基类和函数
"""

import os
import time
import logging
from typing import Dict, List, Any, Optional, Tuple, Callable

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QProgressBar,
    QLabel, QMessageBox, QTableWidget, QTableWidgetItem, QFileDialog,
    QApplication, QHeaderView, QSplitter, QTextEdit, QGroupBox, QFormLayout,
    QTabWidget
)

# 导入扫描管理器
from core.scanner_manager import scanner_manager
from core.base_scanner import BaseScanner, ScanResult
from utils.config import config_manager
from utils.export import export_result


class ScanThread(QThread):
    """扫描线程，用于执行后台扫描任务"""
    
    # 定义信号
    scan_complete = pyqtSignal(object)  # 扫描完成信号，传递结果对象
    scan_progress = pyqtSignal(int, str)  # 扫描进度信号 (百分比, 消息)
    scan_error = pyqtSignal(str)  # 扫描错误信号
    
    def __init__(self, scanner: BaseScanner, parent=None):
        """初始化扫描线程"""
        super().__init__(parent)
        self.scanner = scanner
        # 设置进度回调
        self.scanner.set_progress_callback(self.update_progress)
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
        """
        处理扫描进度更新
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        # 检查是否需要急切终止
        if self._is_stopping:
            # 如果停止请求超过2秒还在收到进度更新，可能需要强制终止
            if self._stop_requested_time > 0 and (time.time() - self._stop_requested_time) > 2:
                print("扫描器在2秒后仍在发送进度更新，考虑强制终止")
                self.terminate()
                return
        else:
            self.scan_progress.emit(percent, message)
    
    def terminate(self):
        """
        安全终止线程
        首先通知扫描器停止，然后等待一段时间，最后再强制终止
        """
        # 设置终止标志，阻止新的进度和结果信号
        self._is_stopping = True
        self._stop_requested_time = time.time()
        
        # 首先尝试优雅地停止扫描器
        if self.scanner:
            try:
                self.scanner.stop()
                # 给扫描器一定时间来停止
                for i in range(5):  # 最多等待500毫秒
                    if not self.isRunning():
                        return  # 如果线程已经停止，直接返回
                    time.sleep(0.1)
            except Exception as e:
                print(f"停止扫描器时出错: {str(e)}")
        
        # 最后调用父类的terminate，强制结束线程
        if self.isRunning():
            super().terminate()


class BasePanel(QWidget):
    """
    基础面板类
    所有扫描模块面板的父类，提供统一的布局和功能接口
    """
    
    # 模块ID，子类需要覆盖此属性
    MODULE_ID = ""
    
    # 模块名称，子类需要覆盖此属性
    MODULE_NAME = ""
    
    def __init__(self, parent=None):
        """初始化基础面板"""
        super().__init__(parent)
        
        # 获取日志记录器
        self.logger = logging.getLogger(f"nettools.gui.{self.MODULE_ID}")
        
        # 创建扫描线程
        self.scan_thread = None
        
        # 当前结果
        self.current_result = None
        
        # 初始化UI
        self.init_ui()
        
        # 加载配置
        self.load_config()
    
    def init_ui(self):
        """初始化用户界面"""
        # 主布局
        self.layout = QVBoxLayout(self)
        
        # 创建分割器
        self.splitter = QSplitter(Qt.Vertical)
        self.layout.addWidget(self.splitter)
        
        # 配置区域
        self.config_widget = QWidget()
        self.config_layout = QVBoxLayout(self.config_widget)
        
        # 参数组
        self.create_param_group()
        
        # 操作按钮组
        self.create_action_group()
        
        # 将配置区域添加到分割器
        self.splitter.addWidget(self.config_widget)
        
        # 结果区域
        self.result_tabs = QTabWidget()
        
        # 创建结果表格
        self.result_table = QTableWidget()
        self.result_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        
        # 创建结果文本框
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        
        # 添加到结果标签页
        self.result_tabs.addTab(self.result_table, "表格视图")
        self.result_tabs.addTab(self.result_text, "文本视图")
        
        # 将结果区域添加到分割器
        self.splitter.addWidget(self.result_tabs)
        
        # 设置分割器的初始大小
        self.splitter.setSizes([200, 400])
        
        # 底部状态栏
        self.create_status_bar()
    
    def create_param_group(self):
        """创建参数组"""
        self.param_group = QGroupBox("扫描参数")
        param_layout = QFormLayout()
        
        # 子类应该在此方法中添加特定的参数控件
        # 这里只创建一个空的布局
        
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
    
    def create_action_group(self):
        """创建操作按钮组"""
        self.action_group = QGroupBox("操作")
        action_layout = QHBoxLayout()
        
        # 开始扫描按钮
        self.scan_button = QPushButton("开始扫描")
        self.scan_button.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_button)
        
        # 停止扫描按钮
        self.stop_button = QPushButton("停止扫描")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        action_layout.addWidget(self.stop_button)
        
        # 清除结果按钮
        self.clear_button = QPushButton("清除结果")
        self.clear_button.clicked.connect(self.clear_results)
        action_layout.addWidget(self.clear_button)
        
        # 导出结果按钮
        self.export_button = QPushButton("导出结果")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        action_layout.addWidget(self.export_button)
        
        # 保存配置按钮
        self.save_config_button = QPushButton("保存配置")
        self.save_config_button.clicked.connect(self.save_config)
        action_layout.addWidget(self.save_config_button)
        
        self.action_group.setLayout(action_layout)
        self.config_layout.addWidget(self.action_group)
    
    def create_status_bar(self):
        """创建状态栏"""
        status_layout = QHBoxLayout()
        
        # 状态标签
        self.status_label = QLabel("就绪")
        status_layout.addWidget(self.status_label, 1)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar, 2)
        
        self.layout.addLayout(status_layout)
    
    def get_scan_config(self) -> Dict[str, Any]:
        """
        获取扫描配置
        子类应该覆盖此方法，从UI控件收集配置参数
        
        Returns:
            配置参数字典
        """
        # 基础实现返回空字典，子类应该覆盖此方法
        return {}
    
    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """
        设置扫描配置到UI控件
        子类应该覆盖此方法，将配置参数设置到UI控件
        
        Args:
            config: 配置参数字典
        """
        # 基础实现什么都不做，子类应该覆盖此方法
        pass
    
    def load_config(self) -> None:
        """从配置管理器加载模块配置"""
        if not self.MODULE_ID:
            return
        
        # 从配置管理器加载此模块的配置
        config = config_manager.load_module_config(self.MODULE_ID)
        
        # 设置到UI控件
        self.set_scan_config(config)
        
        self.logger.debug(f"已加载模块 {self.MODULE_ID} 的配置")
    
    def save_config(self) -> None:
        """保存当前配置到配置管理器"""
        if not self.MODULE_ID:
            return
        
        # 获取当前UI控件中的配置
        config = self.get_scan_config()
        
        # 保存到配置管理器
        for key, value in config.items():
            # 将值转换为字符串
            if isinstance(value, bool):
                str_value = "true" if value else "false"
            else:
                str_value = str(value)
            
            config_manager.set(self.MODULE_ID, key, str_value)
        
        # 保存配置文件
        config_manager.save_config()
        
        self.logger.debug(f"已保存模块 {self.MODULE_ID} 的配置")
        QMessageBox.information(self, "成功", "配置已保存")
    
    def start_scan(self) -> None:
        """开始扫描"""
        # 获取扫描配置
        config = self.get_scan_config()
        
        # 参数验证
        if not self.validate_params(config):
            return
        
        # 创建扫描器
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
        self.status_label.setText("正在扫描...")
        
        # 创建并启动扫描线程
        self.scan_thread = ScanThread(scanner)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.scan_progress.connect(self.on_scan_progress)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        self.scan_thread.start()
        
        self.logger.info(f"开始 {self.MODULE_NAME} 扫描")
    
    def stop_scan(self) -> None:
        """停止扫描"""
        if self.scan_thread and self.scan_thread.isRunning():
            # 停止扫描器
            self.scan_thread.scanner.stop()
            
            # 立即更新UI状态，避免界面卡顿
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.clear_button.setEnabled(True)
            self.status_label.setText("正在停止扫描...")
            
            # 使用计时器非阻塞检查线程状态
            self.stop_timer = QTimer()
            self.stop_timer.setSingleShot(True)
            self.stop_timer.timeout.connect(self._check_thread_stopped)
            self.stop_timer.start(100)  # 100毫秒后检查
            
            self.logger.info("正在停止扫描...")
    
    def _check_thread_stopped(self) -> None:
        """检查线程是否已停止，处理超时情况"""
        # 计算已等待时间
        self._stop_wait_time = getattr(self, "_stop_wait_time", 0) + 100
        
        if self.scan_thread and self.scan_thread.isRunning():
            if self._stop_wait_time > 3000:  # 超过3秒
                # 强制终止线程
                self.logger.warning("扫描线程未能在预期时间内停止，强制终止")
                self.scan_thread.terminate()
                self.scan_thread.wait(500)  # 再等500毫秒确保完全停止
                self.status_label.setText("扫描已强制停止")
                self._stop_wait_time = 0
            else:
                # 继续等待
                self.status_label.setText(f"正在停止扫描...({self._stop_wait_time/1000:.1f}秒)")
                self.stop_timer.start(100)
        else:
            # 线程已停止
            self.status_label.setText("扫描已停止")
            self._stop_wait_time = 0
            self.logger.info("扫描已停止")
    
    def on_scan_complete(self, result: ScanResult) -> None:
        """
        扫描完成处理
        
        Args:
            result: 扫描结果
        """
        # 保存结果
        self.current_result = result
        
        # 更新UI状态
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(result.success and len(result.data) > 0)
        self.progress_bar.setValue(100)
        
        if result.success:
            self.status_label.setText(f"扫描完成，获取到 {result.record_count} 条记录")
            
            # 显示结果
            self.display_results(result)
            
            self.logger.info(f"扫描完成，记录数: {result.record_count}")
        else:
            error_msg = result.error_msg or "未知错误"
            self.status_label.setText(f"扫描失败: {error_msg}")
            
            # 显示错误消息
            QMessageBox.warning(self, "扫描失败", error_msg)
            
            self.logger.error(f"扫描失败: {error_msg}")
    
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
        # 更新UI状态
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"扫描错误: {error_msg}")
        
        # 显示错误消息
        QMessageBox.critical(self, "扫描错误", error_msg)
        
        self.logger.error(f"扫描错误: {error_msg}")
    
    def display_results(self, result: ScanResult) -> None:
        """
        显示扫描结果
        子类应该覆盖此方法，将结果显示到UI控件
        
        Args:
            result: 扫描结果
        """
        # 基础实现，显示基本结果信息
        
        # 清空表格和文本
        self.result_table.clear()
        self.result_text.clear()
        
        if not result.success or not result.data:
            return
        
        # 文本视图显示
        import json
        result_json = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
        self.result_text.setPlainText(result_json)
        
        # 表格视图显示
        data = result.data
        
        # 检查数据格式，确保是列表
        if not isinstance(data, list):
            if isinstance(data, dict):
                data = [data]
            else:
                return
        
        # 设置表格列
        if data and isinstance(data[0], dict):
            headers = list(data[0].keys())
            self.result_table.setColumnCount(len(headers))
            self.result_table.setHorizontalHeaderLabels(headers)
            
            # 添加行
            self.result_table.setRowCount(len(data))
            
            for row, item in enumerate(data):
                for col, key in enumerate(headers):
                    value = item.get(key, "")
                    
                    # 处理不同类型的值
                    if isinstance(value, (list, dict)):
                        value = json.dumps(value, ensure_ascii=False)
                    elif value is None:
                        value = ""
                    else:
                        value = str(value)
                    
                    table_item = QTableWidgetItem(value)
                    self.result_table.setItem(row, col, table_item)
    
    def clear_results(self) -> None:
        """清除结果"""
        self.result_table.clear()
        self.result_text.clear()
        self.current_result = None
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("就绪")
        
        self.logger.debug("结果已清除")
    
    def export_results(self) -> None:
        """导出结果"""
        if not self.current_result or not self.current_result.success:
            QMessageBox.warning(self, "警告", "没有可导出的结果")
            return
        
        # 选择导出格式
        formats = [
            ("CSV 文件", "csv"),
            ("JSON 文件", "json"),
            ("Excel 文件", "xlsx")
        ]
        
        # 通过对话框选择格式
        format_dialog = QMessageBox(self)
        format_dialog.setWindowTitle("导出格式")
        format_dialog.setText("请选择导出格式：")
        format_dialog.setIcon(QMessageBox.Question)
        
        # 添加按钮
        csv_button = format_dialog.addButton("CSV 文件", QMessageBox.ActionRole)
        json_button = format_dialog.addButton("JSON 文件", QMessageBox.ActionRole)
        excel_button = format_dialog.addButton("Excel 文件", QMessageBox.ActionRole)
        cancel_button = format_dialog.addButton(QMessageBox.Cancel)
        
        # 显示对话框
        format_dialog.exec_()
        
        # 获取点击的按钮
        clicked_button = format_dialog.clickedButton()
        
        if clicked_button == cancel_button:
            return
        
        # 确定选择的格式
        if clicked_button == csv_button:
            format_type = "csv"
            format_name = "CSV 文件"
        elif clicked_button == json_button:
            format_type = "json"
            format_name = "JSON 文件"
        elif clicked_button == excel_button:
            format_type = "xlsx"
            format_name = "Excel 文件"
        else:
            return
        
        # 选择保存路径
        file_name = f"{self.MODULE_ID}_{int(time.time())}.{format_type}"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存文件", file_name, f"{format_name} (*.{format_type})"
        )
        
        if not file_path:
            return
        
        try:
            # 导出结果
            if format_type == "csv":
                from utils.export import export_to_csv
                output_file = export_to_csv(self.current_result.data, file_path)
            elif format_type == "json":
                from utils.export import export_to_json
                output_file = export_to_json(self.current_result.data, file_path)
            elif format_type == "xlsx":
                from utils.export import export_to_excel
                output_file = export_to_excel(self.current_result.data, file_path)
            
            if output_file:
                QMessageBox.information(self, "成功", f"结果已导出到：\n{output_file}")
                self.logger.info(f"结果已导出到: {output_file}")
            else:
                QMessageBox.warning(self, "警告", "结果导出失败")
                self.logger.warning("结果导出失败")
        
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出结果时发生错误：\n{str(e)}")
            self.logger.error(f"导出结果失败: {str(e)}", exc_info=True)
    
    def validate_params(self, config: Dict[str, Any]) -> bool:
        """
        验证扫描参数
        子类应该覆盖此方法，验证用户输入的参数
        
        Args:
            config: 配置参数字典
        
        Returns:
            是否有效
        """
        # 基础实现始终返回True，子类应该覆盖此方法
        return True


# 导入时间模块，用于生成时间戳
import time 