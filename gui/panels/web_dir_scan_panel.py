#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web目录扫描面板
提供Web目录扫描功能的图形界面
"""

import os
import json
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QComboBox, QCheckBox, QFileDialog, QLabel, QSpinBox,
    QRadioButton, QButtonGroup, QMessageBox, QHeaderView,
    QGridLayout, QWidget, QProgressBar
)

from gui.panels.base_panel import BasePanel, ScanThread
from core.web_dir_scan import WebDirScanner
from utils.config import config_manager

class WebDirScanPanel(BasePanel):
    """Web目录扫描面板"""
    
    MODULE_ID = "webdirscanner"
    MODULE_NAME = "Web目录扫描"
    
    def __init__(self, parent=None):
        """初始化面板"""
        super().__init__(parent)
        # 用于批量扫描的URL列表
        self.url_list = []
        self.current_url_index = 0
        
        # 初始化表格和表头
        self.setup_result_table()
    
    def create_param_group(self):
        """创建参数组"""
        # 创建水平布局来放置左右两个参数组
        params_layout = QHBoxLayout()
        params_layout.setSpacing(2)  # 减小组件间间距
        
        # === 左侧基本参数组 ===
        self.basic_params_group = QGroupBox("基本参数")
        basic_layout = QVBoxLayout(self.basic_params_group)
        basic_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        basic_layout.setSpacing(3)  # 减小垂直间距
        
        # ----- 第1行：目标类型和URL输入框 -----
        target_layout = QHBoxLayout()
        target_layout.setSpacing(2)  # 减小水平间距
        
        # 目标选择：单一URL或批量URL文件
        self.target_type_group = QButtonGroup(self)
        self.single_url_radio = QRadioButton("单一")
        self.single_url_radio.setChecked(True)
        self.single_url_radio.toggled.connect(self.toggle_target_type)
        self.target_type_group.addButton(self.single_url_radio)
        
        self.batch_url_radio = QRadioButton("批量")
        self.batch_url_radio.toggled.connect(self.toggle_target_type)
        self.target_type_group.addButton(self.batch_url_radio)
        
        target_type_container = QHBoxLayout()
        target_type_container.setSpacing(2)
        target_type_container.addWidget(QLabel("目标:"))
        target_type_container.addWidget(self.single_url_radio)
        target_type_container.addWidget(self.batch_url_radio)
        target_type_container.addStretch(1)
        
        target_layout.addLayout(target_type_container)
        
        # 目标URL输入
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("http://example.com")
        self.target_input.setMinimumHeight(22)  # 统一控件高度
        
        url_layout = QHBoxLayout()
        url_layout.setSpacing(0)
        url_layout.addWidget(self.target_input)
        
        basic_layout.addLayout(target_layout)
        basic_layout.addLayout(url_layout)
        
        # ----- 第2行：URL文件选择 -----
        url_file_layout = QHBoxLayout()
        url_file_layout.setSpacing(2)
        
        file_label = QLabel("文件:")
        file_label.setFixedWidth(30)  # 统一标签宽度
        url_file_layout.addWidget(file_label)
        
        self.url_file_input = QLineEdit()
        self.url_file_input.setPlaceholderText("URL列表文件")
        self.url_file_input.setEnabled(False)
        self.url_file_input.setMinimumHeight(22)  # 统一控件高度
        url_file_layout.addWidget(self.url_file_input)
        
        self.browse_url_button = QPushButton("浏览")
        self.browse_url_button.setFixedWidth(40)
        self.browse_url_button.setFixedHeight(22)  # 统一按钮高度
        self.browse_url_button.clicked.connect(self.browse_url_file)
        self.browse_url_button.setEnabled(False)
        url_file_layout.addWidget(self.browse_url_button)
        
        basic_layout.addLayout(url_file_layout)
        
        # ----- 第3行：字典文件选择 -----
        dict_file_layout = QHBoxLayout()
        dict_file_layout.setSpacing(2)
        
        dict_label = QLabel("字典:")
        dict_label.setFixedWidth(30)  # 统一标签宽度
        dict_file_layout.addWidget(dict_label)
        
        self.dict_file_input = QLineEdit()
        self.dict_file_input.setPlaceholderText("使用内置字典")
        self.dict_file_input.setMinimumHeight(22)  # 统一控件高度
        dict_file_layout.addWidget(self.dict_file_input)
        
        self.browse_button = QPushButton("浏览")
        self.browse_button.setFixedWidth(40)
        self.browse_button.setFixedHeight(22)  # 统一按钮高度
        self.browse_button.clicked.connect(self.browse_dict_file)
        dict_file_layout.addWidget(self.browse_button)
        
        basic_layout.addLayout(dict_file_layout)
        
        # ----- 第4行：线程数、超时和延迟 -----
        params_container = QHBoxLayout()
        params_container.setSpacing(8)  # 参数组之间保持一定间距
        
        # 线程数输入
        thread_layout = QHBoxLayout()
        thread_layout.setSpacing(2)
        thread_label = QLabel("线程:")
        thread_label.setFixedWidth(30)  # 统一标签宽度
        thread_layout.addWidget(thread_label)
        
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 50)
        self.threads_input.setValue(10)
        self.threads_input.setFixedWidth(45)
        self.threads_input.setFixedHeight(22)  # 统一控件高度
        thread_layout.addWidget(self.threads_input)
        params_container.addLayout(thread_layout)
        
        # 超时设置
        timeout_layout = QHBoxLayout()
        timeout_layout.setSpacing(2)
        timeout_label = QLabel("超时:")
        timeout_label.setFixedWidth(30)  # 统一标签宽度
        timeout_layout.addWidget(timeout_label)
        
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 60)
        self.timeout_input.setValue(10)
        self.timeout_input.setFixedWidth(45)
        self.timeout_input.setFixedHeight(22)  # 统一控件高度
        timeout_layout.addWidget(self.timeout_input)
        params_container.addLayout(timeout_layout)
        
        # 延迟设置
        delay_layout = QHBoxLayout()
        delay_layout.setSpacing(2)
        delay_label = QLabel("延迟:")
        delay_label.setFixedWidth(30)  # 统一标签宽度
        delay_layout.addWidget(delay_label)
        
        self.delay_input = QSpinBox()
        self.delay_input.setRange(0, 1000)
        self.delay_input.setValue(0)
        self.delay_input.setFixedWidth(45)
        self.delay_input.setFixedHeight(22)  # 统一控件高度
        delay_layout.addWidget(self.delay_input)
        params_container.addLayout(delay_layout)
        
        # 添加弹性空间
        params_container.addStretch(1)
        
        basic_layout.addLayout(params_container)
        
        # === 右侧扫描选项组 ===
        self.scan_options_group = QGroupBox("扫描选项")
        options_layout = QVBoxLayout(self.scan_options_group)
        options_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        options_layout.setSpacing(3)  # 减小垂直间距
        
        # ----- 扩展名 -----
        ext_layout = QHBoxLayout()
        ext_layout.setSpacing(2)
        
        ext_label = QLabel("扩展:")
        ext_label.setFixedWidth(36)  # 统一标签宽度
        ext_layout.addWidget(ext_label)
        
        self.extensions_input = QLineEdit()
        self.extensions_input.setPlaceholderText("php,asp,aspx,jsp")
        self.extensions_input.setMinimumHeight(22)  # 统一控件高度
        ext_layout.addWidget(self.extensions_input)
        
        options_layout.addLayout(ext_layout)
        
        # ----- 状态码过滤 -----
        status_layout = QHBoxLayout()
        status_layout.setSpacing(2)
        
        status_label = QLabel("状态:")
        status_label.setFixedWidth(36)  # 统一标签宽度
        status_layout.addWidget(status_label)
        
        # 创建状态码复选框网格
        status_grid = QGridLayout()
        status_grid.setSpacing(5)
        status_grid.setContentsMargins(0, 0, 0, 0)
        
        # 第一行状态码
        self.code200_checkbox = QCheckBox("200")
        self.code200_checkbox.setChecked(True)
        status_grid.addWidget(self.code200_checkbox, 0, 0)
        
        self.code201_checkbox = QCheckBox("201")
        self.code201_checkbox.setChecked(True)
        status_grid.addWidget(self.code201_checkbox, 0, 1)
        
        self.code301_checkbox = QCheckBox("301")
        self.code301_checkbox.setChecked(True)
        status_grid.addWidget(self.code301_checkbox, 0, 2)
        
        # 第二行状态码
        self.code302_checkbox = QCheckBox("302")
        self.code302_checkbox.setChecked(True)
        status_grid.addWidget(self.code302_checkbox, 1, 0)
        
        self.code403_checkbox = QCheckBox("403")
        status_grid.addWidget(self.code403_checkbox, 1, 1)
        
        self.code404_checkbox = QCheckBox("404")
        status_grid.addWidget(self.code404_checkbox, 1, 2)
        
        status_codes_container = QVBoxLayout()
        status_codes_container.addLayout(status_grid)
        status_layout.addLayout(status_codes_container)
        
        options_layout.addLayout(status_layout)
        
        # ----- 其他选项 -----
        other_options = QVBoxLayout()
        other_options.setSpacing(2)
        
        # 跟随重定向
        self.follow_redirects_checkbox = QCheckBox("跟随重定向")
        self.follow_redirects_checkbox.setChecked(True)
        other_options.addWidget(self.follow_redirects_checkbox)
        
        # 高级选项展开按钮
        advanced_btn_layout = QHBoxLayout()
        advanced_btn_layout.setSpacing(2)
        
        self.advanced_button = QPushButton("高级选项")
        self.advanced_button.setCheckable(True)
        self.advanced_button.setFixedHeight(22)  # 统一按钮高度
        self.advanced_button.clicked.connect(self.toggle_advanced_options)
        advanced_btn_layout.addWidget(self.advanced_button)
        advanced_btn_layout.addStretch(1)
        
        other_options.addLayout(advanced_btn_layout)
        
        options_layout.addLayout(other_options)
        
        # ----- 高级选项区域 -----
        self.advanced_widget = QWidget()
        advanced_layout = QFormLayout(self.advanced_widget)
        advanced_layout.setVerticalSpacing(3)
        advanced_layout.setContentsMargins(2, 2, 2, 2)
        
        # User-Agent
        self.user_agent_input = QLineEdit()
        self.user_agent_input.setText(config_manager.get("web_scan", "user_agent"))
        self.user_agent_input.setMinimumHeight(22)  # 统一控件高度
        advanced_layout.addRow("User-Agent:", self.user_agent_input)
        
        # Cookies
        self.cookies_input = QLineEdit()
        self.cookies_input.setPlaceholderText("name1=value1; name2=value2")
        self.cookies_input.setMinimumHeight(22)  # 统一控件高度
        advanced_layout.addRow("Cookies:", self.cookies_input)
        
        # 认证
        self.auth_input = QLineEdit()
        self.auth_input.setPlaceholderText("username:password")
        self.auth_input.setMinimumHeight(22)  # 统一控件高度
        advanced_layout.addRow("认证:", self.auth_input)
        
        # 默认隐藏高级选项
        self.advanced_widget.setVisible(False)
        
        options_layout.addWidget(self.advanced_widget)
        options_layout.addStretch(1)  # 添加弹性空间，保持紧凑
        
        # 将左右参数组添加到参数布局
        params_layout.addWidget(self.basic_params_group, 3)  # 基本参数占比更大
        params_layout.addWidget(self.scan_options_group, 2)  # 扫描选项占比较小
        
        # 将布局设置到配置区域
        self.config_layout.addLayout(params_layout)
    
    def toggle_target_type(self):
        """切换目标类型"""
        is_single = self.single_url_radio.isChecked()
        self.target_input.setEnabled(is_single)
        self.url_file_input.setEnabled(not is_single)
        self.browse_url_button.setEnabled(not is_single)
        
        # 更新UI状态提示
        if not is_single and not self.url_list:
            self.status_label.setText("请选择包含URL列表的文件")
        elif not is_single and self.url_list:
            self.status_label.setText(f"已加载 {len(self.url_list)} 个URL")
            
    def browse_url_file(self):
        """浏览并选择URL文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择URL文件", os.getcwd(), "文本文件 (*.txt);;所有文件 (*.*)"
        )
        
        if file_path:
            self.url_file_input.setText(file_path)
            if self.load_url_list(file_path):
                self.status_label.setText(f"已加载 {len(self.url_list)} 个URL")
    
    def load_url_list(self, file_path):
        """加载URL列表"""
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
            
            self.logger.info(f"从文件 {file_path} 加载了 {len(self.url_list)} 个URL")
            
            if not self.url_list:
                QMessageBox.warning(self, "警告", "URL文件为空或格式不正确")
                return False
            return True
        except Exception as e:
            self.logger.error(f"加载URL文件失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"加载URL文件失败: {str(e)}")
            self.url_list = []
            return False

    def browse_dict_file(self):
        """浏览并选择字典文件"""
        dict_dir = os.path.join(os.getcwd(), "config", "dicts")
        if not os.path.exists(dict_dir):
            dict_dir = os.getcwd()
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", dict_dir, "文本文件 (*.txt);;所有文件 (*.*)"
        )
        
        if file_path:
            self.dict_file_input.setText(file_path)
    
    def get_status_codes(self) -> list:
        """获取选中的状态码列表"""
        codes = []
        
        if self.code200_checkbox.isChecked():
            codes.append(200)
        
        if self.code201_checkbox.isChecked():
            codes.append(201)
        
        if self.code301_checkbox.isChecked():
            codes.append(301)
        
        if self.code302_checkbox.isChecked():
            codes.append(302)
        
        if self.code403_checkbox.isChecked():
            codes.append(403)
        
        if self.code404_checkbox.isChecked():
            codes.append(404)
        
        return codes
    
    def setup_result_table(self):
        """设置结果表格"""
        # 清空表格
        self.result_table.clear()
        
        # 设置表头
        headers = ["路径", "状态码", "状态", "内容长度", "标题", "重定向URL"]
        self.result_table.setColumnCount(len(headers))
        self.result_table.setHorizontalHeaderLabels(headers)
        
        # 调整表格属性
        self.result_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        
        # 设置紧凑的行高以减少空间占用
        self.result_table.verticalHeader().setDefaultSectionSize(22)
        
        # 设置表格的列宽
        header = self.result_table.horizontalHeader()
        
        # 路径列 (稍宽)
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.result_table.setColumnWidth(0, 250)
        
        # 状态码和状态列 (窄列)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        self.result_table.setColumnWidth(1, 60)
        
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        self.result_table.setColumnWidth(2, 60)
        
        # 内容长度列 (窄列)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        self.result_table.setColumnWidth(3, 80)
        
        # 标题列 (可伸缩)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        
        # 重定向URL列 (稍宽)
        header.setSectionResizeMode(5, QHeaderView.Interactive)
        self.result_table.setColumnWidth(5, 200)
        
        # 设置表头可见并使其突出显示
        header.setVisible(True)
        header.setHighlightSections(True)
        
        # 设置垂直表头不可见以节省空间
        self.result_table.verticalHeader().setVisible(False)
        
        # 清空行
        self.result_table.setRowCount(0)
    
    def get_scan_config(self) -> dict:
        """获取扫描配置"""
        config = {
            "target": self.target_input.text().strip(),
            "dict_file": self.dict_file_input.text().strip(),
            "threads": self.threads_input.value(),
            "timeout": self.timeout_input.value(),
            "scan_delay": self.delay_input.value(),
            "status_codes": self.get_status_codes(),
            "follow_redirects": self.follow_redirects_checkbox.isChecked(),
        }
        
        # 处理扩展名
        extensions = self.extensions_input.text().strip()
        if extensions:
            config["extensions"] = extensions
        
        # 高级选项
        if self.advanced_button.isChecked():
            user_agent = self.user_agent_input.text().strip()
            if user_agent:
                config["user_agent"] = user_agent
            
            cookies = self.cookies_input.text().strip()
            if cookies:
                config["cookies"] = cookies
            
            auth = self.auth_input.text().strip()
            if auth:
                config["auth"] = auth
        
        return config
    
    def set_scan_config(self, config: dict) -> None:
        """设置扫描配置"""
        if "target" in config:
            self.target_input.setText(config["target"])
        
        if "dict_file" in config:
            self.dict_file_input.setText(config["dict_file"])
        
        if "threads" in config:
            self.threads_input.setValue(int(config["threads"]))
        
        if "timeout" in config:
            self.timeout_input.setValue(float(config["timeout"]))
        
        if "scan_delay" in config:
            self.delay_input.setValue(int(config["scan_delay"]))
        
        if "extensions" in config:
            self.extensions_input.setText(config["extensions"])
        
        if "follow_redirects" in config:
            self.follow_redirects_checkbox.setChecked(config["follow_redirects"])
        
        if "user_agent" in config:
            self.user_agent_input.setText(config["user_agent"])
        
        if "cookies" in config:
            self.cookies_input.setText(config["cookies"])
        
        if "auth" in config:
            self.auth_input.setText(config["auth"])
    
    def start_scan(self) -> None:
        """开始扫描"""
        # 确保结果目录存在
        os.makedirs("results", exist_ok=True)
        
        if self.batch_url_radio.isChecked():
            # 批量URL模式
            if not self.url_list:
                # 尝试加载URL列表
                file_path = self.url_file_input.text().strip()
                if not file_path:
                    self.show_error("请选择URL文件")
                    return
                if not self.load_url_list(file_path):
                    return
            
            # 重置索引
            self.current_url_index = 0
            
            # 设置表格
            self.setup_result_table()
            self.clear_results()
            
            # 开始扫描第一个URL
            self.start_next_url_scan()
        else:
            # 单一URL模式
            self.start_single_scan()
    
    def start_single_scan(self):
        """开始单一URL扫描"""
        # 获取配置
        config = self.get_scan_config()
        
        # 验证参数
        if not self.validate_params(config):
            return
        
        # 设置表格
        self.setup_result_table()
        self.clear_results()
        
        # 确保表头设置正确
        headers = ["路径", "状态码", "状态", "内容长度", "标题", "重定向URL"]
        self.result_table.setHorizontalHeaderLabels(headers)
        
        # 创建扫描器
        scanner = WebDirScanner(config)
        
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
        
        self.logger.info(f"开始 {self.MODULE_NAME} 扫描: {config.get('target', '')}")
    
    def start_next_url_scan(self):
        """开始下一个URL扫描"""
        if self.current_url_index >= len(self.url_list):
            # 所有URL已扫描完成
            self.status_label.setText(f"批量扫描完成，共 {len(self.url_list)} 个URL")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.clear_button.setEnabled(True)
            self.export_button.setEnabled(True)
            return
        
        # 确保表头设置正确
        headers = ["路径", "状态码", "状态", "内容长度", "标题", "重定向URL"]
        self.result_table.setHorizontalHeaderLabels(headers)
        
        # 获取当前URL
        url = self.url_list[self.current_url_index]
        
        # 获取基本配置
        config = self.get_scan_config()
        
        # 覆盖目标URL
        config["target"] = url
        
        # 更新UI状态
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"正在扫描 ({self.current_url_index + 1}/{len(self.url_list)}): {url}")
        
        # 创建扫描器
        scanner = WebDirScanner(config)
        
        # 创建并启动扫描线程
        self.scan_thread = ScanThread(scanner)
        self.scan_thread.scan_complete.connect(self.on_batch_scan_complete)
        self.scan_thread.scan_progress.connect(self.on_scan_progress)
        self.scan_thread.scan_error.connect(self.on_batch_scan_error)
        self.scan_thread.start()
        
        self.logger.info(f"批量扫描 ({self.current_url_index + 1}/{len(self.url_list)}): {url}")
    
    def on_batch_scan_complete(self, result):
        """批量扫描单个URL完成后的处理"""
        # 记录结果
        if result.success and result.data:
            # 将结果添加到表格
            self.display_batch_results(result)
            
            # 更新状态
            completed = self.current_url_index + 1
            total = len(self.url_list)
            self.status_label.setText(f"已完成 {completed}/{total} 个URL，发现 {len(result.data)} 个路径")
        
        # 准备扫描下一个URL
        self.current_url_index += 1
        
        # 继续扫描下一个
        self.start_next_url_scan()
    
    def on_batch_scan_error(self, error_msg):
        """批量扫描错误处理"""
        # 记录错误
        current_url = self.url_list[self.current_url_index] if self.current_url_index < len(self.url_list) else "未知URL"
        error_message = f"批量扫描错误: URL={current_url}, 错误: {error_msg}"
        self.logger.error(error_message)
        self.status_label.setText(f"扫描 {current_url} 失败: {error_msg}")
        
        # 继续扫描下一个URL
        self.current_url_index += 1
        self.start_next_url_scan()
    
    def display_batch_results(self, result):
        """显示批量扫描结果"""
        if not result.success or not result.data:
            return
            
        # 确保表头正确
        headers = ["路径", "状态码", "状态", "内容长度", "标题", "重定向URL"]
        self.result_table.setHorizontalHeaderLabels(headers)
        
        # 获取当前行数
        current_row_count = self.result_table.rowCount()
        
        # 添加新结果
        self.result_table.setRowCount(current_row_count + len(result.data))
        
        # 获取当前URL
        current_url = self.url_list[self.current_url_index]
        
        # 禁用排序以加快表格加载速度
        self.result_table.setSortingEnabled(False)
        
        for i, data in enumerate(result.data):
            row = current_row_count + i
            
            # 使用完整路径显示
            path = data.get("path", "")
            if path:
                # 如果path已经包含完整URL，则使用它
                if path.startswith(("http://", "https://")):
                    full_path = path
                else:
                    # 否则，组合当前URL和相对路径
                    full_path = f"{current_url.rstrip('/')}/{path.lstrip('/')}"
            else:
                full_path = current_url
            
            self.result_table.setItem(row, 0, QTableWidgetItem(full_path))
            
            # 状态码 - 根据状态码设置颜色
            status_code = data.get("status_code", 0)
            status_code_item = QTableWidgetItem(str(status_code))
            
            # 根据状态码设置不同背景色
            if 200 <= status_code < 300:
                status_code_item.setBackground(Qt.green)
            elif status_code == 301 or status_code == 302:
                status_code_item.setBackground(Qt.yellow)
            elif status_code == 403:
                status_code_item.setBackground(Qt.cyan)
            elif status_code == 404:
                status_code_item.setBackground(Qt.lightGray)
            elif status_code >= 500:
                status_code_item.setBackground(Qt.red)
                
            self.result_table.setItem(row, 1, status_code_item)
            
            self.result_table.setItem(row, 2, QTableWidgetItem(data.get("status", "")))
            self.result_table.setItem(row, 3, QTableWidgetItem(str(data.get("content_length", ""))))
            self.result_table.setItem(row, 4, QTableWidgetItem(data.get("title", "")))
            self.result_table.setItem(row, 5, QTableWidgetItem(data.get("redirect_url", "")))
        
        # 启用排序功能
        self.result_table.setSortingEnabled(True)
        
        # 更新文本结果 - 创建更紧凑的格式
        current_text = self.result_text.toPlainText()
        
        text_result = f"\n\n--- URL: {current_url} ---\n"
        
        for data in result.data:
            path = data.get('path', '')
            text_result += f"路径: {path}\n"
            text_result += f"完整URL: {current_url.rstrip('/')}/{path.lstrip('/')}\n"
            text_result += f"状态码: {data.get('status_code', '')} ({data.get('status', '')})"
            text_result += f" | 内容长度: {data.get('content_length', '')}"
            
            if data.get("title"):
                text_result += f" | 标题: {data.get('title', '')}"
            
            if data.get("redirect_url"):
                text_result += f"\n重定向URL: {data.get('redirect_url', '')}"
            
            text_result += "\n" + "-" * 50 + "\n"
        
        self.result_text.setText(current_text + text_result)
    
    def validate_params(self, config: dict) -> bool:
        """验证参数"""
        # 检查目标URL
        if not config.get("target"):
            self.show_error("请输入目标URL")
            return False
        
        # 验证URL格式
        target = config["target"]
        if not target.startswith(("http://", "https://")):
            self.show_error("目标URL必须以http://或https://开头")
            return False
        
        # 验证状态码
        if not config.get("status_codes"):
            self.show_error("请至少选择一个状态码进行过滤")
            return False
        
        return True
    
    def display_results(self, result):
        """显示扫描结果"""
        self.clear_results()
        
        if not result.success:
            self.show_error(f"扫描失败: {result.error_msg}")
            return
        
        if not result.data:
            self.status_label.setText("扫描完成，未发现任何路径")
            return
        
        # 重新设置表头
        headers = ["路径", "状态码", "状态", "内容长度", "标题", "重定向URL"]
        self.result_table.setHorizontalHeaderLabels(headers)
        
        # 填充结果表格
        self.result_table.setRowCount(len(result.data))
        
        # 禁用排序以加快表格加载速度
        self.result_table.setSortingEnabled(False)
        
        for row, data in enumerate(result.data):
            # 路径
            path_item = QTableWidgetItem(data.get("path", ""))
            self.result_table.setItem(row, 0, path_item)
            
            # 状态码 - 根据状态码设置颜色
            status_code = data.get("status_code", 0)
            status_code_item = QTableWidgetItem(str(status_code))
            
            # 根据状态码设置不同背景色
            if 200 <= status_code < 300:
                status_code_item.setBackground(Qt.green)
            elif status_code == 301 or status_code == 302:
                status_code_item.setBackground(Qt.yellow)
            elif status_code == 403:
                status_code_item.setBackground(Qt.cyan)
            elif status_code == 404:
                status_code_item.setBackground(Qt.lightGray)
            elif status_code >= 500:
                status_code_item.setBackground(Qt.red)
                
            self.result_table.setItem(row, 1, status_code_item)
            
            # 状态
            self.result_table.setItem(row, 2, QTableWidgetItem(data.get("status", "")))
            
            # 内容长度
            self.result_table.setItem(row, 3, QTableWidgetItem(str(data.get("content_length", ""))))
            
            # 标题
            self.result_table.setItem(row, 4, QTableWidgetItem(data.get("title", "")))
            
            # 重定向URL
            self.result_table.setItem(row, 5, QTableWidgetItem(data.get("redirect_url", "")))
        
        # 启用排序功能
        self.result_table.setSortingEnabled(True)
        
        # 显示文本结果 (保持简洁以减少视觉干扰)
        target_url = ""
        if hasattr(result, "metadata") and result.metadata and "target" in result.metadata:
            target_url = result.metadata["target"]
        else:
            # 尝试从配置中获取目标URL
            config = self.get_scan_config()
            if "target" in config:
                target_url = config["target"]
        
        text_result = f"Web目录扫描结果"
        if target_url:
            text_result += f" - {target_url}"
        text_result += "\n" + "=" * 80 + "\n\n"
        
        # 为文本视图创建更紧凑的结果显示
        for data in result.data:
            text_result += f"路径: {data.get('path', '')}\n"
            text_result += f"状态码: {data.get('status_code', '')} ({data.get('status', '')})"
            
            # 将内容长度和标题放在同一行以节省空间
            text_result += f" | 内容长度: {data.get('content_length', '')}"
            
            if data.get("title"):
                text_result += f" | 标题: {data.get('title', '')}"
            
            if data.get("redirect_url"):
                text_result += f"\n重定向URL: {data.get('redirect_url', '')}"
            
            text_result += "\n" + "-" * 80 + "\n"
        
        self.result_text.setText(text_result)
        
        # 更新状态
        self.status_label.setText(f"扫描完成，发现 {len(result.data)} 个路径")
        
        # 启用导出按钮
        self.export_button.setEnabled(True)
        
        # 保存配置
        self.save_config()
    
    def show_error(self, message):
        """显示错误消息"""
        QMessageBox.critical(self, "错误", message)
        self.logger.error(message)
        self.status_label.setText(f"错误: {message}")
    
    def on_scan_error(self, error_msg):
        """单个URL扫描错误处理"""
        self.show_error(f"扫描失败: {error_msg}")
        self.status_label.setText(f"扫描失败: {error_msg}")
        
        # 启用扫描按钮
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(False)
        self.progress_bar.setValue(0)
    
    def on_scan_progress(self, percent, message):
        """更新扫描进度"""
        self.progress_bar.setValue(percent)
        if message:
            self.status_label.setText(message)
    
    def on_scan_complete(self, result):
        """单个URL扫描完成后的处理"""
        self.display_results(result)
        
        # 启用扫描按钮
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.progress_bar.setValue(100)
        self.status_label.setText("扫描完成")
        
        # 获取target信息
        target = ""
        if hasattr(result, "metadata") and result.metadata:
            target = result.metadata.get('target', '')
        else:
            # 尝试从配置中获取
            config = self.get_scan_config()
            if config and "target" in config:
                target = config["target"]
        
        self.logger.info(f"{self.MODULE_NAME} 扫描完成: {target}")
    
    def clear_results(self):
        """清空结果"""
        # 保存当前的列数和表头
        col_count = self.result_table.columnCount()
        headers = []
        for i in range(col_count):
            header_item = self.result_table.horizontalHeaderItem(i)
            if header_item:
                headers.append(header_item.text())
            else:
                headers.append(f"列 {i+1}")
        
        # 清空表格内容，但保留表头
        self.result_table.setRowCount(0)
        
        # 如果没有表头或表头被清除，重新设置
        if not headers or all(h.startswith("列 ") for h in headers):
            headers = ["路径", "状态码", "状态", "内容长度", "标题", "重定向URL"]
        
        # 重新设置表头
        self.result_table.setHorizontalHeaderLabels(headers)
        
        # 清空文本结果
        self.result_text.clear()
        
        # 禁用导出按钮
        self.export_button.setEnabled(False)
        
        # 更新状态
        self.status_label.setText("就绪")
    
    def toggle_advanced_options(self):
        """切换高级选项的可见性"""
        visible = self.advanced_button.isChecked()
        self.advanced_widget.setVisible(visible)
        
        # 更新按钮文本
        if visible:
            self.advanced_button.setText("隐藏高级选项")
        else:
            self.advanced_button.setText("高级选项")
    
    def create_action_group(self):
        """创建操作按钮组"""
        action_layout = QHBoxLayout()
        action_layout.setSpacing(5)  # 减少按钮间距
        
        # 创建统一大小的按钮
        button_height = 25  # 统一按钮高度
        
        # 扫描按钮
        self.scan_button = QPushButton("开始扫描")
        self.scan_button.setFixedHeight(button_height)
        self.scan_button.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_button)
        
        # 停止按钮
        self.stop_button = QPushButton("停止")
        self.stop_button.setFixedHeight(button_height)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        action_layout.addWidget(self.stop_button)
        
        # 清空按钮
        self.clear_button = QPushButton("清空")
        self.clear_button.setFixedHeight(button_height)
        self.clear_button.clicked.connect(self.clear_results)
        action_layout.addWidget(self.clear_button)
        
        # 导出按钮
        self.export_button = QPushButton("导出报告")
        self.export_button.setFixedHeight(button_height)
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        action_layout.addWidget(self.export_button)
        
        # 添加弹性空间
        action_layout.addStretch(1)
        
        # 设置最小高度，使布局紧凑
        action_widget = QWidget()
        action_widget.setLayout(action_layout)
        action_widget.setMinimumHeight(button_height + 4)  # 仅留少量边距
        
        self.config_layout.addWidget(action_widget)
        
        # 添加进度条
        progress_layout = QVBoxLayout()
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.setSpacing(1)  # 减小进度条和标签间的间距
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(12)  # 设置进度条高度
        self.progress_bar.setMaximumHeight(12)  # 确保进度条不会过高
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("就绪")
        self.status_label.setMinimumHeight(12)  # 设置状态标签高度
        self.status_label.setMaximumHeight(12)  # 确保状态标签不会过高
        progress_layout.addWidget(self.status_label)
        
        self.config_layout.addLayout(progress_layout) 