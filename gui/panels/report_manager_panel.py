#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
报告管理界面模块
提供查看、管理和操作之前生成的所有扫描报告的功能
"""

import os
import logging
import datetime
import json
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QLineEdit, QTextEdit, QComboBox, QTableWidget, QTableWidgetItem, 
    QHeaderView, QFileDialog, QTabWidget, QGroupBox, QMessageBox, 
    QSplitter, QProgressBar, QDateEdit, QCheckBox, QMenu, QAction,
    QToolButton, QInputDialog, QApplication
)
from PyQt5.QtCore import Qt, QDateTime, QDate, QSize, QTimer
from PyQt5.QtGui import QIcon, QColor, QDesktopServices
from PyQt5.QtCore import QUrl, QSortFilterProxyModel

class ReportManagerPanel(QWidget):
    """报告管理面板"""
    
    MODULE_ID = "report_manager"
    MODULE_NAME = "报告管理"
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger("gui.panels.report_manager")
        
        # 报告列表
        self.reports = []
        
        # 初始化UI
        self.setup_ui()
        
        # 加载报告列表
        self.load_reports()
        
        # 设置计时器，定期刷新报告列表
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.load_reports)
        self.refresh_timer.start(60000)  # 每分钟刷新一次
    
    def setup_ui(self):
        """初始化UI组件"""
        # 创建主布局
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(2, 2, 2, 2)  # 减小边距
        main_layout.setSpacing(2)  # 减小间距
        
        # === 顶部筛选和操作区域 ===
        filter_action_layout = QHBoxLayout()
        filter_action_layout.setSpacing(5)
        
        # --- 左侧筛选部分 ---
        filter_group = QGroupBox("筛选条件")
        filter_group_layout = QVBoxLayout(filter_group)
        filter_group_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        filter_group_layout.setSpacing(3)  # 减小间距
        
        # 搜索框
        search_layout = QHBoxLayout()
        search_layout.setSpacing(3)
        
        search_label = QLabel("关键词:")
        search_label.setFixedWidth(45)  # 统一标签宽度
        search_layout.addWidget(search_label)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("输入关键词筛选报告")
        self.search_input.setMinimumHeight(22)  # 统一控件高度
        self.search_input.textChanged.connect(self.filter_reports)
        search_layout.addWidget(self.search_input)
        
        filter_group_layout.addLayout(search_layout)
        
        # 报告类型筛选
        type_layout = QHBoxLayout()
        type_layout.setSpacing(3)
        
        type_label = QLabel("类型:")
        type_label.setFixedWidth(45)  # 统一标签宽度
        type_layout.addWidget(type_label)
        
        self.type_combo = QComboBox()
        self.type_combo.setMinimumHeight(22)  # 统一控件高度
        self.type_combo.addItem("全部报告", "all")
        self.type_combo.addItem("Web风险扫描", "web_risk_scan")
        self.type_combo.addItem("POC漏洞扫描", "poc_scan")
        self.type_combo.addItem("爆破扫描", "bruteforce")
        self.type_combo.addItem("其他", "others")
        self.type_combo.currentIndexChanged.connect(self.filter_reports)
        type_layout.addWidget(self.type_combo)
        
        filter_group_layout.addLayout(type_layout)
        
        # 日期范围筛选
        date_layout = QHBoxLayout()
        date_layout.setSpacing(3)
        
        date_label = QLabel("日期:")
        date_label.setFixedWidth(45)  # 统一标签宽度
        date_layout.addWidget(date_label)
        
        self.date_from = QDateEdit()
        self.date_from.setMinimumHeight(22)  # 统一控件高度
        self.date_from.setCalendarPopup(True)
        self.date_from.setDateTime(QDateTime.currentDateTime().addDays(-30))  # 默认过去30天
        self.date_from.dateChanged.connect(self.filter_reports)
        date_layout.addWidget(self.date_from)
        
        date_layout.addWidget(QLabel("至"))
        
        self.date_to = QDateEdit()
        self.date_to.setMinimumHeight(22)  # 统一控件高度
        self.date_to.setCalendarPopup(True)
        self.date_to.setDateTime(QDateTime.currentDateTime())  # 默认今天
        self.date_to.dateChanged.connect(self.filter_reports)
        date_layout.addWidget(self.date_to)
        
        filter_group_layout.addLayout(date_layout)
        
        # 格式筛选
        format_layout = QHBoxLayout()
        format_layout.setSpacing(3)
        
        self.html_check = QCheckBox("HTML")
        self.html_check.setChecked(True)
        self.html_check.stateChanged.connect(self.filter_reports)
        format_layout.addWidget(self.html_check)
        
        self.pdf_check = QCheckBox("PDF")
        self.pdf_check.setChecked(True)
        self.pdf_check.stateChanged.connect(self.filter_reports)
        format_layout.addWidget(self.pdf_check)
        
        format_layout.addStretch(1)
        
        filter_group_layout.addLayout(format_layout)
        
        # --- 右侧操作按钮部分 ---
        action_group = QGroupBox("操作")
        action_group_layout = QVBoxLayout(action_group)
        action_group_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        action_group_layout.setSpacing(3)  # 减小间距
        
        button_height = 25  # 统一按钮高度
        
        # 刷新按钮
        self.refresh_btn = QPushButton("刷新列表")
        self.refresh_btn.setFixedHeight(button_height)
        self.refresh_btn.clicked.connect(self.load_reports)
        action_group_layout.addWidget(self.refresh_btn)
        
        # 打开按钮
        self.open_btn = QPushButton("打开报告")
        self.open_btn.setFixedHeight(button_height)
        self.open_btn.clicked.connect(self.open_selected_report)
        action_group_layout.addWidget(self.open_btn)
        
        # 导出按钮
        self.export_btn = QPushButton("导出报告")
        self.export_btn.setFixedHeight(button_height)
        self.export_btn.clicked.connect(self.export_selected_report)
        action_group_layout.addWidget(self.export_btn)
        
        # 删除按钮
        self.delete_btn = QPushButton("删除报告")
        self.delete_btn.setFixedHeight(button_height)
        self.delete_btn.clicked.connect(self.delete_selected_reports)
        action_group_layout.addWidget(self.delete_btn)
        
        # 添加到筛选操作布局
        filter_action_layout.addWidget(filter_group, 7)  # 筛选区域占更多空间
        filter_action_layout.addWidget(action_group, 3)
        
        main_layout.addLayout(filter_action_layout)
        
        # === 报告列表区域 ===
        list_group = QGroupBox("报告列表")
        list_layout = QVBoxLayout(list_group)
        list_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        list_layout.setSpacing(3)  # 减小间距
        
        # 创建报告列表表格
        self.report_table = QTableWidget()
        self.report_table.setColumnCount(7)
        self.report_table.setHorizontalHeaderLabels(["文件名", "报告类型", "格式", "生成时间", "大小", "目标数", "发现问题数"])
        
        # 设置表格属性
        self.report_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.report_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.report_table.setAlternatingRowColors(True)
        
        # 设置列宽
        header = self.report_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # 文件名列可伸缩
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        
        # 设置行高
        self.report_table.verticalHeader().setDefaultSectionSize(22)
        self.report_table.verticalHeader().setVisible(False)  # 隐藏行号
        
        # 连接双击事件
        self.report_table.doubleClicked.connect(self.on_report_double_clicked)
        
        # 添加右键菜单
        self.report_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.report_table.customContextMenuRequested.connect(self.show_context_menu)
        
        list_layout.addWidget(self.report_table)
        
        main_layout.addWidget(list_group)
        
        # === 报告摘要区域 ===
        preview_group = QGroupBox("报告摘要")
        preview_layout = QVBoxLayout(preview_group)
        preview_layout.setContentsMargins(5, 8, 5, 5)  # 减小边距
        preview_layout.setSpacing(3)  # 减小间距
        
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        preview_layout.addWidget(self.preview_text)
        
        main_layout.addWidget(preview_group)
        
        # 设置区域比例
        main_layout.setStretch(0, 1)  # 筛选操作区域
        main_layout.setStretch(1, 3)  # 报告列表区域
        main_layout.setStretch(2, 2)  # 报告摘要区域
        
        # 初始状态更新
        self.update_button_states()
    
    def show_context_menu(self, position):
        """显示右键菜单"""
        # 检查是否有选中的行
        if not self.report_table.selectedItems():
            return
        
        menu = QMenu(self)
        
        # 创建菜单项
        open_action = QAction("打开报告", self)
        open_action.triggered.connect(self.open_selected_report)
        menu.addAction(open_action)
        
        export_action = QAction("导出报告", self)
        export_action.triggered.connect(self.export_selected_report)
        menu.addAction(export_action)
        
        menu.addSeparator()
        
        delete_action = QAction("删除报告", self)
        delete_action.triggered.connect(self.delete_selected_reports)
        menu.addAction(delete_action)
        
        # 显示菜单
        menu.exec_(self.report_table.mapToGlobal(position))
    
    def update_button_states(self):
        """更新按钮状态"""
        has_selection = len(self.report_table.selectedItems()) > 0
        self.open_btn.setEnabled(has_selection)
        self.export_btn.setEnabled(has_selection)
        self.delete_btn.setEnabled(has_selection)
    
    def on_report_double_clicked(self, index):
        """处理报告双击事件"""
        self.open_selected_report()
    
    def load_reports(self):
        """加载报告列表"""
        try:
            self.reports = []
            reports_dir = os.path.join(os.getcwd(), "reports")
            
            # 确保报告目录存在
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
                return
            
            # 遍历报告目录
            for filename in os.listdir(reports_dir):
                file_path = os.path.join(reports_dir, filename)
                
                # 只处理html和pdf文件
                if os.path.isfile(file_path) and (filename.endswith('.html') or filename.endswith('.pdf')):
                    # 获取文件信息
                    stat_info = os.stat(file_path)
                    created_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
                    file_size = stat_info.st_size
                    
                    # 解析报告类型
                    report_type = self.parse_report_type(filename)
                    
                    # 获取报告格式
                    report_format = filename.split('.')[-1].upper()
                    
                    # 尝试解析元数据
                    target_count, issue_count = self.extract_report_metadata(file_path, report_format)
                    
                    # 添加到报告列表
                    self.reports.append({
                        'filename': filename,
                        'filepath': file_path,
                        'type': report_type,
                        'format': report_format,
                        'created_time': created_time,
                        'size': file_size,
                        'target_count': target_count,
                        'issue_count': issue_count
                    })
            
            # 按时间排序，最新的在前
            self.reports.sort(key=lambda x: x['created_time'], reverse=True)
            
            # 更新表格
            self.display_reports()
            
            self.logger.info(f"加载了 {len(self.reports)} 个报告")
            
        except Exception as e:
            self.logger.error(f"加载报告列表时出错: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
    
    def parse_report_type(self, filename):
        """解析报告类型"""
        filename = filename.lower()
        if 'web_risk' in filename:
            return "Web风险扫描"
        elif 'poc' in filename:
            return "POC漏洞扫描"
        elif 'bruteforce' in filename:
            return "爆破扫描"
        else:
            return "其他"
    
    def extract_report_metadata(self, file_path, format_type):
        """
        尝试从报告文件中提取元数据
        
        Args:
            file_path: 报告文件路径
            format_type: 报告格式类型
            
        Returns:
            (目标数, 问题数)的元组
        """
        target_count = 0
        issue_count = 0
        
        try:
            if format_type.upper() == 'HTML':
                # 从HTML文件中提取元数据
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 简单解析HTML内容，寻找目标数和问题数
                import re
                
                # 尝试查找目标数量文本
                target_match = re.search(r'目标URL数量[:：]\s*(\d+)', content)
                if target_match:
                    target_count = int(target_match.group(1))
                
                # 寻找存活URL数量
                alive_match = re.search(r'存活URL数量[:：]\s*(\d+)', content)
                if alive_match and not target_count:
                    target_count = int(alive_match.group(1))
                
                # 查找问题数量文本
                issue_match = re.search(r'(发现问题数量|发现漏洞数量)[:：]\s*(\d+)', content)
                if issue_match:
                    issue_count = int(issue_match.group(2))
                
        except Exception as e:
            self.logger.debug(f"提取报告元数据时出错: {str(e)}")
        
        return target_count, issue_count
    
    def display_reports(self):
        """显示报告列表"""
        # 清空表格
        self.report_table.setRowCount(0)
        
        # 填充表格
        for row, report in enumerate(self.reports):
            self.report_table.insertRow(row)
            
            # 文件名
            self.report_table.setItem(row, 0, QTableWidgetItem(report['filename']))
            
            # 报告类型
            self.report_table.setItem(row, 1, QTableWidgetItem(report['type']))
            
            # 格式
            format_item = QTableWidgetItem(report['format'])
            # 根据格式设置不同颜色
            if report['format'] == 'HTML':
                format_item.setForeground(QColor(0, 128, 255))  # 蓝色
            elif report['format'] == 'PDF':
                format_item.setForeground(QColor(255, 0, 0))  # 红色
            self.report_table.setItem(row, 2, format_item)
            
            # 生成时间
            time_str = report['created_time'].strftime("%Y-%m-%d %H:%M:%S")
            self.report_table.setItem(row, 3, QTableWidgetItem(time_str))
            
            # 文件大小
            size_str = self.format_file_size(report['size'])
            self.report_table.setItem(row, 4, QTableWidgetItem(size_str))
            
            # 目标数
            target_count = report['target_count']
            self.report_table.setItem(row, 5, QTableWidgetItem(str(target_count) if target_count else "未知"))
            
            # 问题数
            issue_count = report['issue_count']
            issue_item = QTableWidgetItem(str(issue_count) if issue_count else "未知")
            # 如果问题数大于0，设置为红色
            if issue_count > 0:
                issue_item.setForeground(QColor(255, 0, 0))  # 红色
            self.report_table.setItem(row, 6, issue_item)
        
        # 连接选择变更事件
        self.report_table.itemSelectionChanged.connect(self.on_selection_changed)
        
        # 更新按钮状态
        self.update_button_states()
    
    def format_file_size(self, size_in_bytes):
        """格式化文件大小显示"""
        if size_in_bytes < 1024:
            return f"{size_in_bytes} B"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.1f} KB"
        elif size_in_bytes < 1024 * 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_in_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def on_selection_changed(self):
        """处理选择变更事件"""
        self.update_button_states()
        
        # 更新摘要
        selected_rows = self.report_table.selectionModel().selectedRows()
        if not selected_rows:
            self.preview_text.setText("")
            return
        
        # 获取选中行的报告
        row = selected_rows[0].row()
        report = self.reports[row]
        
        # 显示报告摘要信息
        self.display_report_summary(report)
    
    def display_report_summary(self, report):
        """显示报告摘要信息"""
        try:
            # 基本摘要信息
            summary = f"<h3>报告摘要</h3>"
            summary += f"<p><b>文件名:</b> {report['filename']}</p>"
            summary += f"<p><b>报告类型:</b> {report['type']}</p>"
            summary += f"<p><b>格式:</b> {report['format']}</p>"
            summary += f"<p><b>生成时间:</b> {report['created_time'].strftime('%Y-%m-%d %H:%M:%S')}</p>"
            summary += f"<p><b>文件大小:</b> {self.format_file_size(report['size'])}</p>"
            
            # 如果是HTML文件，尝试提取更多信息
            if report['format'] == 'HTML':
                try:
                    with open(report['filepath'], 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(10000)  # 只读取前10000个字符
                    
                    # 提取标题
                    import re
                    title_match = re.search(r'<title>(.*?)</title>', content)
                    if title_match:
                        summary += f"<p><b>报告标题:</b> {title_match.group(1)}</p>"
                    
                    # 提取更多信息
                    if report['target_count']:
                        summary += f"<p><b>目标数量:</b> {report['target_count']}</p>"
                    
                    if report['issue_count']:
                        summary += f"<p><b>发现问题数:</b> <span style='color:red'>{report['issue_count']}</span></p>"
                    
                except Exception as e:
                    self.logger.debug(f"提取HTML摘要时出错: {str(e)}")
            
            # 设置摘要文本
            self.preview_text.setHtml(summary)
            
        except Exception as e:
            self.logger.error(f"显示报告摘要时出错: {str(e)}")
            self.preview_text.setPlainText(f"无法加载摘要: {str(e)}")
    
    def filter_reports(self):
        """根据筛选条件过滤报告"""
        # 获取筛选条件
        search_text = self.search_input.text().lower()
        report_type = self.type_combo.currentData()
        date_from = self.date_from.date().toPyDate()
        date_to = self.date_to.date().toPyDate()
        show_html = self.html_check.isChecked()
        show_pdf = self.pdf_check.isChecked()
        
        # 清空表格
        self.report_table.setRowCount(0)
        
        # 应用筛选
        row = 0
        for report in self.reports:
            # 检查关键词
            if search_text and search_text not in report['filename'].lower():
                continue
            
            # 检查报告类型
            if report_type != "all":
                type_map = {
                    "web_risk_scan": "Web风险扫描",
                    "poc_scan": "POC漏洞扫描",
                    "bruteforce": "爆破扫描",
                    "others": "其他"
                }
                if report['type'] != type_map.get(report_type, ""):
                    continue
            
            # 检查日期范围
            report_date = report['created_time'].date()
            if report_date < date_from or report_date > date_to:
                continue
            
            # 检查格式
            if (report['format'] == 'HTML' and not show_html) or (report['format'] == 'PDF' and not show_pdf):
                continue
            
            # 添加到表格
            self.report_table.insertRow(row)
            
            # 文件名
            self.report_table.setItem(row, 0, QTableWidgetItem(report['filename']))
            
            # 报告类型
            self.report_table.setItem(row, 1, QTableWidgetItem(report['type']))
            
            # 格式
            format_item = QTableWidgetItem(report['format'])
            # 根据格式设置不同颜色
            if report['format'] == 'HTML':
                format_item.setForeground(QColor(0, 128, 255))  # 蓝色
            elif report['format'] == 'PDF':
                format_item.setForeground(QColor(255, 0, 0))  # 红色
            self.report_table.setItem(row, 2, format_item)
            
            # 生成时间
            time_str = report['created_time'].strftime("%Y-%m-%d %H:%M:%S")
            self.report_table.setItem(row, 3, QTableWidgetItem(time_str))
            
            # 文件大小
            size_str = self.format_file_size(report['size'])
            self.report_table.setItem(row, 4, QTableWidgetItem(size_str))
            
            # 目标数
            target_count = report['target_count']
            self.report_table.setItem(row, 5, QTableWidgetItem(str(target_count) if target_count else "未知"))
            
            # 问题数
            issue_count = report['issue_count']
            issue_item = QTableWidgetItem(str(issue_count) if issue_count else "未知")
            # 如果问题数大于0，设置为红色
            if issue_count > 0:
                issue_item.setForeground(QColor(255, 0, 0))  # 红色
            self.report_table.setItem(row, 6, issue_item)
            
            row += 1
    
    def open_selected_report(self):
        """打开选中的报告"""
        selected_rows = self.report_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        filename = self.report_table.item(row, 0).text()
        
        # 找到对应的报告
        for report in self.reports:
            if report['filename'] == filename:
                try:
                    # 使用系统默认程序打开报告
                    import webbrowser
                    webbrowser.open('file://' + os.path.abspath(report['filepath']))
                    self.logger.info(f"已打开报告: {report['filepath']}")
                except Exception as e:
                    self.logger.error(f"打开报告时出错: {str(e)}")
                    QMessageBox.critical(self, "错误", f"打开报告时出错: {str(e)}")
                break
    
    def export_selected_report(self):
        """导出选中的报告"""
        selected_rows = self.report_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        filename = self.report_table.item(row, 0).text()
        
        # 找到对应的报告
        for report in self.reports:
            if report['filename'] == filename:
                try:
                    # 选择保存位置
                    file_path, _ = QFileDialog.getSaveFileName(
                        self, "保存报告", filename, 
                        f"{report['format']} 文件 (*.{report['format'].lower()});;所有文件 (*)"
                    )
                    
                    if not file_path:
                        return
                    
                    # 复制文件
                    import shutil
                    shutil.copy2(report['filepath'], file_path)
                    
                    self.logger.info(f"已导出报告到: {file_path}")
                    QMessageBox.information(self, "导出成功", f"报告已成功导出到:\n{file_path}")
                    
                except Exception as e:
                    self.logger.error(f"导出报告时出错: {str(e)}")
                    QMessageBox.critical(self, "错误", f"导出报告时出错: {str(e)}")
                break
    
    def delete_selected_reports(self):
        """删除选中的报告"""
        selected_rows = self.report_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        # 确认删除
        count = len(selected_rows)
        reply = QMessageBox.question(
            self, "确认删除", 
            f"确定要删除选中的 {count} 个报告吗？此操作不可恢复。",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # 收集要删除的文件
        to_delete = []
        for idx in selected_rows:
            row = idx.row()
            filename = self.report_table.item(row, 0).text()
            
            # 找到对应的报告
            for report in self.reports:
                if report['filename'] == filename:
                    to_delete.append(report)
                    break
        
        # 执行删除
        deleted_count = 0
        for report in to_delete:
            try:
                os.remove(report['filepath'])
                deleted_count += 1
                self.logger.info(f"已删除报告: {report['filepath']}")
            except Exception as e:
                self.logger.error(f"删除报告时出错: {str(e)}")
                QMessageBox.warning(self, "警告", f"删除报告 {report['filename']} 时出错: {str(e)}")
        
        # 重新加载报告列表
        self.load_reports()
        
        # 显示结果
        QMessageBox.information(self, "删除完成", f"成功删除 {deleted_count} 个报告") 