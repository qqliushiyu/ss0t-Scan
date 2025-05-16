#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
端口扫描面板
用于图形化操作端口扫描模块
"""

import logging
import math
import re
from typing import Dict, List, Any
import time
import random

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QPushButton, QLabel, QLineEdit, QCheckBox, QSpinBox, 
    QDoubleSpinBox, QComboBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QApplication, QGridLayout
)
from PyQt5.QtCore import Qt, QRectF
from PyQt5.QtGui import QColor, QPainter, QPen, QBrush, QFont

# 导入图形相关
from PyQt5.QtWidgets import QGraphicsScene, QGraphicsView, QGraphicsItem, QGraphicsEllipseItem, QGraphicsTextItem

from gui.panels.base_panel import BasePanel
from utils.network import is_valid_ip, parse_ip_range, parse_port_range

# 导入新的端口拓扑图实现
from gui.port_topology_networkx import PortTopologyNetworkX


class PortScanPanel(BasePanel):
    """端口扫描面板"""
    
    MODULE_ID = "portscanner"
    MODULE_NAME = "端口扫描"
    
    def __init__(self, parent=None):
        """初始化端口扫描面板"""
        super().__init__(parent)
        
        # 确保端口扫描器已正确注册
        from core.scanner_manager import scanner_manager
        from core.port_scan import PortScanner
        
        # 如果端口扫描器未注册，手动注册
        if not scanner_manager.get_scanner(self.MODULE_ID):
            self.logger.warning(f"端口扫描器({self.MODULE_ID})未注册，正在手动注册...")
            scanner_manager.register_scanner(PortScanner)
            self.logger.info(f"端口扫描器已手动注册")
        
        # 添加NetworkX可视化标签页
        self.networkx_tab = QWidget()
        self.networkx_layout = QVBoxLayout(self.networkx_tab)
        
        # 创建NetworkX拓扑图控件
        self.port_topology = PortTopologyNetworkX(self)
        self.networkx_layout.addWidget(self.port_topology)
        
        # 将可视化标签页添加到结果标签页组
        self.result_tabs.addTab(self.networkx_tab, "端口拓扑图")
        
        # 性能相关配置
        self.last_layout_update_time = 0
        self.layout_update_interval = 500  # 毫秒
    
    def create_param_group(self):
        """创建参数组"""
        self.param_group = QGroupBox("扫描参数")
        param_layout = QGridLayout()
        param_layout.setVerticalSpacing(8)  # 减小垂直间距
        param_layout.setHorizontalSpacing(15)  # 保持适当水平间距
        
        # 目标输入
        target_label = QLabel("目标:")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("单个IP、多个IP或IP范围，如: 192.168.1.1 或 192.168.1.0/24")
        param_layout.addWidget(target_label, 0, 0)
        param_layout.addWidget(self.target_input, 0, 1, 1, 3)  # 跨3列
        
        # 端口范围和端口预设放在同一行
        ports_label = QLabel("端口范围:")
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("如: 80,443,8000-8100,22")
        param_layout.addWidget(ports_label, 1, 0)
        param_layout.addWidget(self.ports_input, 1, 1)
        
        preset_label = QLabel("端口预设:")
        self.port_preset_combo = QComboBox()
        self.port_preset_combo.addItem("自定义", "custom")
        self.port_preset_combo.addItem("常用端口", "common")
        self.port_preset_combo.addItem("全部端口 (1-65535)", "all")
        self.port_preset_combo.addItem("已知危险端口", "dangerous")
        self.port_preset_combo.addItem("Web服务端口", "web")
        self.port_preset_combo.addItem("数据库端口", "database")
        self.port_preset_combo.currentIndexChanged.connect(self.on_port_preset_changed)
        param_layout.addWidget(preset_label, 1, 2)
        param_layout.addWidget(self.port_preset_combo, 1, 3)
        
        # 超时设置和线程数放在同一行
        timeout_label = QLabel("超时时间:")
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setSingleStep(0.1)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSuffix(" 秒")
        param_layout.addWidget(timeout_label, 2, 0)
        param_layout.addWidget(self.timeout_spin, 2, 1)
        
        threads_label = QLabel("最大线程数:")
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(100)
        param_layout.addWidget(threads_label, 2, 2)
        param_layout.addWidget(self.threads_spin, 2, 3)
        
        # 扫描延迟和服务识别放在同一行
        delay_label = QLabel("扫描延迟:")
        self.scan_delay_spin = QSpinBox()
        self.scan_delay_spin.setRange(0, 1000)
        self.scan_delay_spin.setValue(0)
        self.scan_delay_spin.setSuffix(" 毫秒")
        self.scan_delay_spin.setToolTip("设置为0表示无延迟，值越大扫描越慢但越稳定")
        param_layout.addWidget(delay_label, 3, 0)
        param_layout.addWidget(self.scan_delay_spin, 3, 1)
        
        # 获取服务信息
        self.get_service_check = QCheckBox("识别服务")
        self.get_service_check.setChecked(True)
        self.get_service_check.setToolTip("识别端口上运行的服务类型")
        param_layout.addWidget(self.get_service_check, 3, 2)
        
        # 获取Banner
        self.get_banner_check = QCheckBox("获取Banner信息")
        self.get_banner_check.setChecked(True)
        self.get_banner_check.setToolTip("获取服务返回的Banner信息，有助于识别服务版本")
        param_layout.addWidget(self.get_banner_check, 3, 3)
        
        # 高级选项一行布局
        advanced_box = QHBoxLayout()
        advanced_box.setSpacing(10)
        
        # 启用拓扑图复选框
        self.enable_topology_check = QCheckBox("启用端口拓扑图")
        self.enable_topology_check.setChecked(True)
        self.enable_topology_check.setToolTip("是否生成并显示端口拓扑图，关闭可节省系统资源")
        self.enable_topology_check.stateChanged.connect(self.on_enable_topology_changed)
        advanced_box.addWidget(self.enable_topology_check)
        
        # 性能优先模式复选框
        self.advanced_performance_mode_check = QCheckBox("性能优先模式")
        self.advanced_performance_mode_check.setChecked(False)
        self.advanced_performance_mode_check.setToolTip("启用后将降低绘制质量以提高性能，适合大量端口时使用")
        self.advanced_performance_mode_check.stateChanged.connect(self.on_performance_mode_changed)
        advanced_box.addWidget(self.advanced_performance_mode_check)
        
        # 实时更新复选框
        self.advanced_realtime_update_check = QCheckBox("实时更新视图")
        self.advanced_realtime_update_check.setChecked(True)
        self.advanced_realtime_update_check.setToolTip("扫描过程中实时将发现的开放端口添加到视图中")
        advanced_box.addWidget(self.advanced_realtime_update_check)
        
        # 添加高级选项到布局
        param_layout.addLayout(advanced_box, 4, 0, 1, 4)
        
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
    
    def on_port_preset_changed(self, index):
        """端口预设变更处理"""
        preset = self.port_preset_combo.currentData()
        
        if preset == "custom":
            # 自定义模式不改变当前输入
            return
        
        # 根据预设设置端口
        if preset == "common":
            ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"
        elif preset == "all":
            ports = "1-65535"
        elif preset == "dangerous":
            ports = "21,22,23,25,80,135,137,139,443,445,1433,3306,3389,5432,5900,6379"
        elif preset == "web":
            ports = "80,81,443,8000,8008,8080,8443,8888,9000,9090"
        elif preset == "database":
            ports = "1433,1521,3306,5432,6379,27017,6379,9200,9300"
        else:
            return
        
        self.ports_input.setText(ports)
    
    def get_scan_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        return {
            "target": self.target_input.text().strip(),
            "ports": self.ports_input.text().strip(),
            "timeout": self.timeout_spin.value(),
            "max_threads": self.threads_spin.value(),
            "get_service": self.get_service_check.isChecked(),
            "get_banner": self.get_banner_check.isChecked(),
            "scan_delay": self.scan_delay_spin.value(),
            "realtime_update": self.advanced_realtime_update_check.isChecked(),
            "enable_topology": self.enable_topology_check.isChecked(),
            "performance_mode": self.advanced_performance_mode_check.isChecked()
        }
    
    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """设置扫描配置到UI控件"""
        if "target" in config:
            self.target_input.setText(str(config["target"]))
        
        if "ports" in config:
            self.ports_input.setText(str(config["ports"]))
            # 设置为自定义模式
            for i in range(self.port_preset_combo.count()):
                if self.port_preset_combo.itemData(i) == "custom":
                    self.port_preset_combo.setCurrentIndex(i)
                    break
        
        if "timeout" in config:
            self.timeout_spin.setValue(float(config["timeout"]))
        
        if "max_threads" in config:
            self.threads_spin.setValue(int(config["max_threads"]))
        
        if "get_service" in config:
            self.get_service_check.setChecked(config["get_service"])
        
        if "get_banner" in config:
            self.get_banner_check.setChecked(config["get_banner"])
        
        if "scan_delay" in config:
            self.scan_delay_spin.setValue(int(config["scan_delay"]))
            
        if "realtime_update" in config:
            self.advanced_realtime_update_check.setChecked(config["realtime_update"])
            
        if "enable_topology" in config:
            self.enable_topology_check.setChecked(config["enable_topology"])
            
        if "performance_mode" in config:
            self.advanced_performance_mode_check.setChecked(config["performance_mode"])
    
    def validate_params(self, config: Dict[str, Any]) -> bool:
        """验证扫描参数"""
        # 检查目标
        target = config.get("target", "")
        if not target:
            QMessageBox.warning(self, "参数错误", "请输入目标IP或IP范围")
            return False
        
        # 尝试解析目标
        ips = parse_ip_range(target)
        if not ips:
            # 尝试当作单个IP解析
            if not is_valid_ip(target):
                QMessageBox.warning(self, "参数错误", "无效的目标IP或IP范围")
                return False
        
        # 检查IP范围大小
        ip_count = len(ips) if ips else 1
        
        # 检查端口
        ports_str = config.get("ports", "")
        if not ports_str:
            QMessageBox.warning(self, "参数错误", "请输入扫描端口范围")
            return False
        
        # 尝试解析端口
        ports = parse_port_range(ports_str)
        if not ports:
            QMessageBox.warning(self, "参数错误", "无效的端口范围格式")
            return False
        
        # 检查端口数量
        port_count = len(ports)
        
        # 计算总扫描数量
        total_scans = ip_count * port_count
        
        # 检查扫描规模并给出警告
        if total_scans > 5000:
            # 大规模扫描警告
            message = f"您将扫描 {ip_count} 个IP地址的 {port_count} 个端口，总计 {total_scans} 次扫描。\n\n"
            
            if total_scans > 50000:
                message += "警告：这是一个超大规模扫描，可能会消耗大量系统资源并导致界面卡顿。\n\n"
            elif total_scans > 10000:
                message += "警告：这是一个大规模扫描，可能会导致界面短暂卡顿。\n\n"
            
            # 性能优化建议
            message += "建议：\n"
            if self.enable_topology_check.isChecked():
                message += "1. 已自动启用拓扑图的性能模式\n"
                message += "2. 如果界面仍然卡顿，可尝试关闭拓扑图功能\n"
            else:
                message += "1. 您已关闭拓扑图功能，这有助于提高性能\n"
            message += "3. 如果界面卡顿，建议关闭实时更新选项\n"
            message += "4. 考虑减少扫描范围或增加扫描超时\n"
            
            result = QMessageBox.question(
                self, "大规模扫描确认", 
                message,
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if result != QMessageBox.Yes:
                return False
            
            # 如果用户确认，自动启用性能优化选项
            self.advanced_performance_mode_check.setChecked(True)
            
            # 如果是超大规模扫描，建议关闭实时更新
            if total_scans > 50000 and self.advanced_realtime_update_check.isChecked():
                realtime_result = QMessageBox.question(
                    self, "实时更新建议",
                    "对于如此大规模的扫描，建议关闭实时更新以提高性能。\n是否关闭实时更新？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                if realtime_result == QMessageBox.Yes:
                    self.advanced_realtime_update_check.setChecked(False)
        
        return True
    
    def start_scan(self):
        """开始扫描前准备"""
        # 清理表格和拓扑图
        self.clear_results()
        
        # 只有在启用拓扑图时，才设置性能模式
        if self.enable_topology_check.isChecked() and hasattr(self.port_topology, 'canvas'):
            self.port_topology.canvas.set_performance_mode(self.advanced_performance_mode_check.isChecked())
        
        # 添加大规模扫描提示
        config = self.get_scan_config()
        ips = parse_ip_range(config.get("target", ""))
        ports = parse_port_range(config.get("ports", ""))
        ip_count = len(ips) if ips else 1
        port_count = len(ports) if ports else 0
        
        if ip_count > 100 or port_count > 1000:
            self.status_label.setText(f"扫描准备中... (大规模扫描: {ip_count}个IP, {port_count}个端口)")
        else:
            self.status_label.setText("扫描准备中...")
        
        # 调用父类的扫描方法
        super().start_scan()
    
    def clear_table(self):
        """清空表格"""
        self.result_table.clearContents()
        self.result_table.setRowCount(0)
    
    def clear_results(self):
        """清除所有结果"""
        # 清除表格
        self.clear_table()
        
        # 清除NetworkX拓扑图
        self.port_topology.clear()
        
        # 清除状态
        self.status_label.setText("就绪")
        self.scan_running = False
    
    def on_scan_progress(self, percent: int, message: str) -> None:
        """
        扫描进度更新
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        # 调用父类的进度更新
        super().on_scan_progress(percent, message)
        
        # 检查是否有端口发现消息
        if "found open port" in message.lower():
            # 解析消息中的IP和端口
            ip_port_match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)', message)
            if ip_port_match:
                ip = ip_port_match.group(1)
                port = int(ip_port_match.group(2))
                
                # 提取服务信息（如果有）
                service = ""
                service_match = re.search(r'\(([^)]+)\)', message)
                if service_match:
                    service = service_match.group(1)
                
                # 创建端口信息对象
                port_data = {
                    "ip": ip,
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": ""
                }
                
                # 无论是否勾选实时更新，都添加到表格
                self.add_port_to_table(port_data)
                
                # 如果启用了实时更新视图，并且拓扑图也启用了，才添加到拓扑图
                if self.advanced_realtime_update_check.isChecked() and self.enable_topology_check.isChecked():
                    self.port_topology.add_port(port_data)
                
                # 更新状态栏
                total_ports = self.result_table.rowCount()
                unique_ips = len(set(self.result_table.item(r, 0).text() 
                             for r in range(self.result_table.rowCount())
                             if self.result_table.item(r, 0)))
                
                self.status_label.setText(f"扫描中: 已发现 {unique_ips} 台主机上的 {total_ports} 个开放端口")
    
    def add_port_to_table(self, port_data):
        """添加端口到表格"""
        if not port_data or 'ip' not in port_data or 'port' not in port_data:
            return
            
        # 获取当前列配置
        columns = []
        for col in range(self.result_table.columnCount()):
            columns.append(self.result_table.horizontalHeaderItem(col).text())
        
        # 如果表格未初始化，初始化表格列
        if not columns:
            columns = ["IP地址", "端口", "状态", "服务", "Banner"]
            self.result_table.setColumnCount(len(columns))
            self.result_table.setHorizontalHeaderLabels(columns)
            
        # 准备行数据：确保顺序与表格列对应
        row_data = []
        field_map = {
            "IP地址": "ip",
            "端口": "port",
            "状态": "status",
            "服务": "service",
            "Banner": "banner"
        }
        
        for col_name in columns:
            field = field_map.get(col_name, "")
            value = port_data.get(field, "")
            row_data.append(value)
            
        # 将数据添加到表格
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        
        for col, value in enumerate(row_data):
            # 获取对应的字段名
            field = field_map.get(columns[col], "")
            
            # 特殊处理端口列（整数）和状态列（颜色）
            if field == "port":
                item = QTableWidgetItem(str(value))
                # 右对齐
                item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.result_table.setItem(row, col, item)
                continue
            elif field == "status":
                item = QTableWidgetItem(str(value))
                # 根据状态设置颜色
                if value == "open":
                    item.setBackground(QColor(144, 238, 144))  # 浅绿色
                else:
                    item.setBackground(QColor(255, 200, 200))  # 浅红色
                
                self.result_table.setItem(row, col, item)
                continue
            elif field == "port":
                value = str(value)
            elif field == "service" and not value and "product" in port_data:
                # 尝试从product字段获取服务信息
                value = port_data.get("product", "")
            elif field == "banner" and not value and "version" in port_data:
                # 尝试从version字段获取Banner信息
                value = port_data.get("version", "")
            
            # 正常处理
            item = QTableWidgetItem(str(value) if value is not None else "")
            self.result_table.setItem(row, col, item)
        
        # 调整列宽
        self.result_table.resizeColumnsToContents()
        
        # 更新状态栏
        total_ports = self.result_table.rowCount()
        unique_ips = len(set(self.result_table.item(r, 0).text() 
                         for r in range(self.result_table.rowCount())
                         if self.result_table.item(r, 0)))
        
        self.status_label.setText(f"扫描中: 已发现 {unique_ips} 台主机上的 {total_ports} 个开放端口")
    
    def display_results(self, result):
        """显示扫描结果"""
        # 先清空现有结果
        self.clear_results()
        
        # 检查结果是否有效
        if not result:
            logging.warning("无扫描结果")
            QMessageBox.warning(self, "扫描结果", "无扫描结果")
            self.scan_running = False
            return
        
        # 处理不同格式的结果结构
        results_data = []
        
        # 处理ScanResult对象
        if hasattr(result, 'data') and hasattr(result, 'success'):
            # 如果是ScanResult对象
            if not result.success or not result.data:
                logging.warning(f"扫描未成功或无结果数据: {getattr(result, 'error_msg', '未知错误')}")
                self.scan_running = False
                return
            
            results_data = result.data
        elif isinstance(result, dict):
            # 处理字典格式
            if 'results' in result and isinstance(result['results'], list):
                results_data = result['results']
            elif 'data' in result and isinstance(result['data'], list):
                results_data = result['data']
            elif 'ip' in result and 'port' in result:
                results_data = [result]
        elif isinstance(result, list):
            # 直接是结果列表
            results_data = result
        
        # 如果没有有效的扫描结果
        if not results_data:
            logging.warning("未找到有效的扫描结果数据")
            QMessageBox.warning(self, "扫描结果", "未找到有效的扫描结果数据")
            self.scan_running = False
            return
        
        # 将结果按IP-端口组织
        ip_data = {}
        
        # 处理每个结果项
        for item in results_data:
            if isinstance(item, dict) and 'ip' in item and 'port' in item:
                ip = item['ip']
                if ip not in ip_data:
                    ip_data[ip] = []
                
                ip_data[ip].append(item)
                
                # 添加到表格
                self.add_port_to_table(item)
                
                # 只有在启用拓扑图时才添加到拓扑图
                if self.enable_topology_check.isChecked():
                    self.port_topology.add_port(item)
        
        # 计算统计信息
        total_ips = len(ip_data)
        total_ports = sum(len(ports) for ports in ip_data.values())
        open_ports = sum(1 for ports in ip_data.values() for port in ports if port.get('status') == 'open')
        
        # 更新统计信息标签
        stats_text = f"扫描完成: 发现 {total_ips} 个主机, {total_ports} 个端口 (其中 {open_ports} 个开放端口)"
        self.status_label.setText(stats_text)
        
        # 如果有扫描结果且启用了拓扑图，默认选择端口拓扑图标签页
        if ip_data and self.enable_topology_check.isChecked():
            self.result_tabs.setCurrentWidget(self.networkx_tab)
        
        # 更新扫描状态
        self.scan_running = False
    
    def on_performance_mode_changed(self, state):
        """处理性能模式变更"""
        if hasattr(self, 'port_topology') and hasattr(self.port_topology, 'canvas'):
            enabled = state == Qt.Checked
            self.port_topology.canvas.set_performance_mode(enabled)
            # 如果拓扑图已经有内容，重新绘制以应用性能模式
            if self.port_topology.canvas.graph.number_of_nodes() > 0:
                self.port_topology.update_display() 

    def on_enable_topology_changed(self, state):
        """处理启用拓扑图变更"""
        if hasattr(self, 'port_topology'):
            enabled = state == Qt.Checked
            
            # 如果存在NetworkX标签页，设置其可见性
            if hasattr(self, 'networkx_tab') and hasattr(self, 'result_tabs'):
                # 找到NetworkX标签页的索引
                for i in range(self.result_tabs.count()):
                    if self.result_tabs.widget(i) == self.networkx_tab:
                        # 如果启用拓扑图，显示标签页；否则隐藏标签页
                        if enabled:
                            self.result_tabs.setTabVisible(i, True)
                        else:
                            self.result_tabs.setTabVisible(i, False)
                        break
                
                # 如果当前选中的是即将隐藏的拓扑图标签，则切换到表格视图
                if not enabled and self.result_tabs.currentWidget() == self.networkx_tab:
                    # 切换到表格视图（通常是第一个标签页）
                    self.result_tabs.setCurrentIndex(0)