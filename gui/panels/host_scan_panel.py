#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
主机扫描面板
用于图形化操作主机扫描模块
"""

import logging
import ipaddress
from typing import Dict, List, Any
import math
import random

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QPushButton, QLabel, QLineEdit, QCheckBox, QSpinBox, 
    QDoubleSpinBox, QComboBox, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QGridLayout, QMenu, QAction
)
from PyQt5.QtCore import Qt, QRectF, pyqtSignal
from PyQt5.QtGui import QColor, QPainter, QPen, QBrush, QFont

# 导入NetworkX拓扑图组件
from gui.host_topology_networkx import HostTopologyNetworkX

from gui.panels.base_panel import BasePanel
from utils.network import is_valid_ip_network, parse_ip_range


class HostScanPanel(BasePanel):
    """主机扫描面板"""
    
    MODULE_ID = "hostscanner"
    MODULE_NAME = "主机扫描"
    
    def __init__(self, parent=None):
        """初始化主机扫描面板"""
        super().__init__(parent)
        
        # 确保主机扫描器已正确注册
        from core.scanner_manager import scanner_manager
        from core.host_scan import HostScanner
        
        # 如果主机扫描器未注册，手动注册
        if not scanner_manager.get_scanner(self.MODULE_ID):
            self.logger.warning(f"主机扫描器({self.MODULE_ID})未注册，正在手动注册...")
            scanner_manager.register_scanner(HostScanner)
            self.logger.info(f"主机扫描器已手动注册")
        
        # 初始化网络拓扑图
        self.init_network_topology()
        
        # 创建一个字典来跟踪已添加到拓扑图的主机
        self.topology_hosts = {}
        
        # 添加网络拓扑图标签页
        self.result_tabs.addTab(self.network_topology_widget, "网络拓扑图")
    
    def init_network_topology(self):
        """初始化网络拓扑图"""
        # 创建NetworkX拓扑图控件
        self.network_topology_widget = HostTopologyNetworkX(self)
        
        # 连接节点选择信号
        self.network_topology_widget.host_selected.connect(self.on_host_selected)
    
    def on_host_selected(self, node_id):
        """处理主机节点被选中事件"""
        # 如果是网关节点，无需特殊处理
        if node_id == "gateway":
            return
            
        # 查找表格中对应的行
        for row in range(self.result_table.rowCount()):
            ip_item = self.result_table.item(row, 0)
            if ip_item and ip_item.text() == node_id:
                # 选中该行，但不切换到表格视图
                self.result_table.selectRow(row)
                break
    
    def get_ip_subnet(self, ip):
        """获取IP地址的子网（C类网络）"""
        try:
            # 对于IPv4，提取前3个八位字节作为子网
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                return '.'.join(ip_parts[:3]) + '.0/24'
        except:
            pass
        return "未知子网"
    
    def get_ip_class(self, ip):
        """获取IP地址的类别（A/B/C类网络）"""
        try:
            # 对于IPv4，根据第一个八位字节确定网络类别
            first_octet = int(ip.split('.')[0])
            if first_octet < 128:
                return "A类网络"
            elif first_octet < 192:
                return "B类网络"
            elif first_octet < 224:
                return "C类网络"
            else:
                return "D/E类网络"
        except:
            pass
        return "未知网络"

    def add_host_to_topology(self, host_data):
        """将主机添加到网络拓扑图"""
        if not host_data or host_data.get("status") != "up":
            return
        
        ip = host_data.get("ip", "")
        if not ip:
            return
            
        # 添加到新的NetworkX拓扑图
        self.network_topology_widget.add_host(host_data)
            
        # 记录主机数据，用于重新布局
        self.topology_hosts[ip] = {
            "data": host_data,
            "display_name": host_data.get("hostname", ip) if host_data.get("hostname") else ip
        }

    def wheel_zoom_event(self, event):
        """处理鼠标滚轮事件，实现缩放功能"""
        # 此方法不再需要，由NetworkX拓扑图组件自行处理
        event.accept()
    
    def change_topology_mode(self, mode):
        """更改拓扑布局模式"""
        # 此方法交由NetworkX拓扑图组件处理
        # 可以通过设置HostTopologyNetworkX的布局类型来实现
        layout_map = {
            "standard": "spring",
            "subnet_grouped": "shell",
            "hierarchical": "kamada_kawai"
        }
        
        if mode in layout_map:
            # 查找对应的布局索引
            layout_data = layout_map[mode]
            for i in range(self.network_topology_widget.layout_combo.count()):
                if self.network_topology_widget.layout_combo.itemData(i) == layout_data:
                    self.network_topology_widget.layout_combo.setCurrentIndex(i)
                    break
        
        self.topology_mode = mode
    
    def relayout_topology(self):
        """重新布局拓扑图"""
        # 让NetworkX拓扑图组件处理布局
        self.network_topology_widget.refresh_topology()
    
    def create_param_group(self):
        """创建参数组"""
        self.param_group = QGroupBox("扫描参数")
        param_layout = QGridLayout()
        param_layout.setVerticalSpacing(8)  # 减小垂直间距
        param_layout.setHorizontalSpacing(15)  # 保持适当水平间距
        
        # IP范围输入
        ip_range_label = QLabel("目标IP范围:")
        self.ip_range_input = QLineEdit()
        self.ip_range_input.setPlaceholderText("192.168.1.0/24, 10.0.0.1-10.0.0.10, 172.16.1.*")
        param_layout.addWidget(ip_range_label, 0, 0)
        param_layout.addWidget(self.ip_range_input, 0, 1, 1, 3)  # 跨3列
        
        # 扫描方法选择
        scan_method_label = QLabel("扫描方法:")
        self.scan_method_combo = QComboBox()
        self.scan_method_combo.addItem("ICMP和TCP (推荐)", "all")
        self.scan_method_combo.addItem("仅ICMP", "icmp")
        self.scan_method_combo.addItem("仅TCP", "tcp")
        param_layout.addWidget(scan_method_label, 1, 0)
        param_layout.addWidget(self.scan_method_combo, 1, 1)
        
        # TCP端口输入
        tcp_ports_label = QLabel("TCP Ping端口:")
        self.tcp_ports_input = QLineEdit()
        self.tcp_ports_input.setPlaceholderText("80,443,22,445")
        param_layout.addWidget(tcp_ports_label, 1, 2)
        param_layout.addWidget(self.tcp_ports_input, 1, 3)
        
        # Ping次数和超时设置放在同一行
        ping_count_label = QLabel("Ping次数:")
        self.ping_count_spin = QSpinBox()
        self.ping_count_spin.setRange(1, 10)
        self.ping_count_spin.setValue(1)
        param_layout.addWidget(ping_count_label, 2, 0)
        param_layout.addWidget(self.ping_count_spin, 2, 1)
        
        timeout_label = QLabel("超时时间:")
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setSingleStep(0.1)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSuffix(" 秒")
        param_layout.addWidget(timeout_label, 2, 2)
        param_layout.addWidget(self.timeout_spin, 2, 3)
        
        # 线程数和主机名解析放在同一行
        threads_label = QLabel("最大线程数:")
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(50)
        param_layout.addWidget(threads_label, 3, 0)
        param_layout.addWidget(self.threads_spin, 3, 1)
        
        # 解析主机名复选框
        self.resolve_hostname_check = QCheckBox("解析主机名")
        self.resolve_hostname_check.setChecked(True)
        self.resolve_hostname_check.setToolTip("尝试解析目标IP的主机名(DNS反向查询)")
        param_layout.addWidget(self.resolve_hostname_check, 3, 2, 1, 2)
        
        # 高级选项一行布局
        advanced_box = QHBoxLayout()
        advanced_box.setSpacing(10)
        
        # 启用拓扑图复选框
        self.enable_topology_check = QCheckBox("启用拓扑图")
        self.enable_topology_check.setChecked(True)
        self.enable_topology_check.setToolTip("是否生成并显示网络拓扑图，关闭可节省系统资源")
        self.enable_topology_check.stateChanged.connect(self.on_enable_topology_changed)
        advanced_box.addWidget(self.enable_topology_check)
        
        # 获取MAC地址
        self.get_mac_check = QCheckBox("获取MAC地址")
        self.get_mac_check.setChecked(True)
        self.get_mac_check.setToolTip("通过ARP请求获取目标主机的MAC地址，可用于识别设备制造商")
        advanced_box.addWidget(self.get_mac_check)
        
        # 检测操作系统
        self.detect_os_check = QCheckBox("检测操作系统")
        self.detect_os_check.setChecked(False)
        self.detect_os_check.setToolTip("尝试通过TTL值和其他网络特征识别目标主机的操作系统类型")
        advanced_box.addWidget(self.detect_os_check)
        
        # 实时更新拓扑图
        self.realtime_topology_check = QCheckBox("实时更新视图")
        self.realtime_topology_check.setChecked(True)
        self.realtime_topology_check.setToolTip("扫描过程中实时将发现的主机添加到视图中")
        advanced_box.addWidget(self.realtime_topology_check)
        
        # 性能优先模式
        self.performance_mode_check = QCheckBox("性能优先")
        self.performance_mode_check.setChecked(False)
        self.performance_mode_check.setToolTip("启用后将降低绘制质量以提高性能，适合扫描大型网络")
        self.performance_mode_check.stateChanged.connect(self.on_performance_mode_changed)
        advanced_box.addWidget(self.performance_mode_check)
        
        # 自动重试
        self.auto_retry_check = QCheckBox("自动重试")
        self.auto_retry_check.setChecked(True)
        self.auto_retry_check.setToolTip("对未响应的主机进行额外的扫描尝试")
        advanced_box.addWidget(self.auto_retry_check)
        
        # 添加高级选项到布局
        param_layout.addLayout(advanced_box, 4, 0, 1, 4)
        
        self.param_group.setLayout(param_layout)
        self.config_layout.addWidget(self.param_group)
    
    def get_scan_config(self) -> Dict[str, Any]:
        """获取扫描配置"""
        # 处理TCP端口
        tcp_ports_str = self.tcp_ports_input.text().strip()
        tcp_ports = []
        if tcp_ports_str:
            try:
                tcp_ports = [int(p.strip()) for p in tcp_ports_str.split(",") if p.strip()]
            except ValueError:
                # 忽略无效的端口
                pass
        
        if not tcp_ports:
            tcp_ports = [80, 443, 22, 445]  # 默认端口
            
        return {
            "ip_range": self.ip_range_input.text().strip(),
            "scan_method": self.scan_method_combo.currentData(),
            "tcp_ports": tcp_ports,
            "ping_count": self.ping_count_spin.value(),
            "timeout": self.timeout_spin.value(),
            "max_threads": self.threads_spin.value(),
            "resolve_hostname": self.resolve_hostname_check.isChecked(),
            "get_mac": self.get_mac_check.isChecked(),
            "detect_os": self.detect_os_check.isChecked(),
            "realtime_update": self.realtime_topology_check.isChecked(),
            "performance_mode": self.performance_mode_check.isChecked(),
            "enable_topology": self.enable_topology_check.isChecked(),
            "auto_retry": self.auto_retry_check.isChecked()
        }
    
    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """设置扫描配置"""
        if "ip_range" in config:
            self.ip_range_input.setText(config["ip_range"])
        
        if "scan_method" in config:
            # 查找对应的扫描方法
            for i in range(self.scan_method_combo.count()):
                if self.scan_method_combo.itemData(i) == config["scan_method"]:
                    self.scan_method_combo.setCurrentIndex(i)
                    break
        
        if "tcp_ports" in config:
            ports = config["tcp_ports"]
            if isinstance(ports, list):
                self.tcp_ports_input.setText(",".join(map(str, ports)))
            elif isinstance(ports, str):
                self.tcp_ports_input.setText(ports)
        
        if "ping_count" in config:
            self.ping_count_spin.setValue(int(config["ping_count"]))
        
        if "timeout" in config:
            self.timeout_spin.setValue(float(config["timeout"]))
        
        if "max_threads" in config:
            self.threads_spin.setValue(int(config["max_threads"]))
        
        if "resolve_hostname" in config:
            self.resolve_hostname_check.setChecked(config["resolve_hostname"])
        
        if "get_mac" in config:
            self.get_mac_check.setChecked(config["get_mac"])
        
        if "detect_os" in config:
            self.detect_os_check.setChecked(config["detect_os"])
        
        if "realtime_update" in config:
            self.realtime_topology_check.setChecked(config["realtime_update"])
            
        if "performance_mode" in config:
            self.performance_mode_check.setChecked(config["performance_mode"])
            
        if "enable_topology" in config:
            self.enable_topology_check.setChecked(config["enable_topology"])
            
        if "auto_retry" in config:
            self.auto_retry_check.setChecked(config["auto_retry"])
    
    def validate_params(self, config: Dict[str, Any]) -> bool:
        """验证扫描参数"""
        # 检查IP范围
        ip_range = config.get("ip_range", "").strip()
        if not ip_range:
            QMessageBox.warning(self, "参数错误", "请输入目标IP范围")
            return False
        
        # 尝试解析IP范围
        ips = parse_ip_range(ip_range)
        if not ips:
            QMessageBox.warning(self, "参数错误", "无效的IP范围格式，请检查输入")
            return False
        
        # 检查IP范围大小，给出性能警告
        ip_count = len(ips)
        if ip_count > 254:  # 超过一个C类网段
            message = f"您将扫描 {ip_count} 个IP地址，这是一个较大规模的扫描。\n\n"
            
            if ip_count > 1000:
                message += "警告：这是一个大规模扫描，可能会消耗大量系统资源并导致界面卡顿。\n\n"
            
            # 性能建议
            message += "性能建议：\n"
            if self.enable_topology_check.isChecked():
                message += "1. 考虑关闭拓扑图功能以提高扫描速度和响应性\n"
                message += "2. 或启用性能优先模式减少图形渲染负担\n"
            else:
                message += "1. 您已关闭拓扑图功能，这有助于提高性能\n"
            
            message += "3. 考虑减少线程数，防止网络拥塞\n"
            message += "4. 对于超大规模扫描，建议分多次进行\n"
            
            # 如果是特别大的网段，自动启用性能优化
            if ip_count > 1000 and self.enable_topology_check.isChecked():
                message += "\n已自动启用性能优先模式，并建议关闭实时更新。"
                self.performance_mode_check.setChecked(True)
                # 询问是否关闭拓扑图
                result = QMessageBox.question(
                    self, "大规模扫描确认", 
                    message + "\n\n是否继续扫描？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                
                if result != QMessageBox.Yes:
                    return False
                
                # 询问是否关闭拓扑图
                disable_topology = QMessageBox.question(
                    self, "拓扑图设置",
                    f"对于{ip_count}个IP的扫描，建议关闭拓扑图以提高性能。\n是否关闭拓扑图？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                
                if disable_topology == QMessageBox.Yes:
                    self.enable_topology_check.setChecked(False)
            else:
                # 常规提示
                result = QMessageBox.question(
                    self, "扫描确认", 
                    message + "\n\n是否继续扫描？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                
                if result != QMessageBox.Yes:
                    return False
        
        return True
    
    def start_scan(self) -> None:
        """开始扫描前的准备"""
        # 清理拓扑图
        self.clear_topology()
        
        # 检查IP范围大小
        ip_range = self.ip_range_input.text().strip()
        ips = parse_ip_range(ip_range)
        ip_count = len(ips) if ips else 0
        
        # 大规模扫描提示
        if ip_count > 254:
            self.status_label.setText(f"扫描准备中... (大规模扫描: {ip_count}个IP)")
        else:
            self.status_label.setText("扫描准备中...")
        
        # 如果启用拓扑图且在性能优先模式，设置NetworkX组件为性能模式
        if self.enable_topology_check.isChecked() and self.performance_mode_check.isChecked():
            if hasattr(self.network_topology_widget, 'canvas') and hasattr(self.network_topology_widget.canvas, 'set_performance_mode'):
                self.network_topology_widget.canvas.set_performance_mode(True)
        
        # 调用父类的start_scan方法
        super().start_scan()
    
    def clear_topology(self):
        """清理拓扑图"""
        # 清空NetworkX拓扑图
        self.network_topology_widget.clear()
        
        # 清空记录的主机数据
        self.topology_hosts.clear()
    
    def clear_results(self) -> None:
        """清除结果"""
        # 清理拓扑图
        self.clear_topology()
        
        # 清空表格
        self.result_table.clearContents()
        self.result_table.setRowCount(0)
        
        # 更新状态栏
        self.status_label.setText("就绪")
    
    def on_scan_progress(self, percent: int, message: str) -> None:
        """
        扫描进度更新
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        # 调用父类的进度更新
        super().on_scan_progress(percent, message)
        
        # 检查消息中是否有主机信息，如果有，实时更新表格
        if "found host" in message.lower():
            # 从消息中提取IP
            import re
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)
            if ip_match:
                ip = ip_match.group(0)
                
                # 尝试提取主机名 (如果有的话)
                hostname = ""
                hostname_match = re.search(r'\(([^)]+)\)', message)
                if hostname_match:
                    hostname = hostname_match.group(1)
                
                # 创建一个临时主机数据对象
                host_data = {
                    "ip": ip, 
                    "status": "up",
                    "hostname": hostname
                }
                
                # 添加到表格（无论是否实时更新）
                self.add_host_to_table(host_data)
                
                # 如果启用了拓扑图和实时更新，则添加到拓扑图
                if self.enable_topology_check.isChecked() and self.realtime_topology_check.isChecked():
                    # 如果启用了性能优先模式，减少更新频率
                    should_update = True
                    if hasattr(self, 'performance_mode_check') and self.performance_mode_check.isChecked():
                        # 在性能模式下，每发现5个主机才更新一次拓扑图
                        current_hosts = len(self.topology_hosts)
                        should_update = (current_hosts % 5 == 0) or (current_hosts < 5)
                    
                    # 添加到拓扑图
                    if should_update:
                        self.add_host_to_topology(host_data)
    
    def add_host_to_table(self, host_data):
        """将主机添加到表格视图"""
        # 如果表格未初始化，则先设置列
        if self.result_table.columnCount() == 0:
            columns = ["ip", "hostname", "mac_address", "response_time", "os"]
            column_names = ["IP地址", "主机名", "MAC地址", "响应时间(ms)", "系统"]
            self.result_table.setColumnCount(len(columns))
            self.result_table.setHorizontalHeaderLabels(column_names)
        
        # 检查该IP是否已在表格中
        ip = host_data.get("ip", "")
        for row in range(self.result_table.rowCount()):
            if self.result_table.item(row, 0) and self.result_table.item(row, 0).text() == ip:
                return  # 该IP已存在，不重复添加
        
        # 添加新行
        row = self.result_table.rowCount()
        self.result_table.setRowCount(row + 1)
        
        # 设置数据
        columns = ["ip", "hostname", "mac_address", "response_time", "os"]
        bg_color = QColor(144, 238, 144)  # 浅绿色
        
        for col, key in enumerate(columns):
            value = host_data.get(key, "")
            item = QTableWidgetItem(str(value) if value is not None else "")
            item.setBackground(bg_color)
            self.result_table.setItem(row, col, item)
        
        # 调整列宽
        self.result_table.resizeColumnsToContents()
        
        # 更新状态栏，显示当前发现的主机数量
        scanned_ips = 0
        try:
            ip_range = self.ip_range_input.text().strip()
            scanned_ips = len(parse_ip_range(ip_range))
        except:
            scanned_ips = 0
        
        total_hosts = self.result_table.rowCount()
        self.status_label.setText(f"扫描中: 已发现 {total_hosts}/{scanned_ips} 个在线主机")
    
    def display_results(self, result):
        """显示扫描结果"""
        if not result.success or not result.data:
            return
        
        # 提取数据
        data = result.data
        
        # 确保表格已经初始化
        if self.result_table.columnCount() == 0:
            # 为主机扫描结果设置自定义列
            columns = ["ip", "hostname", "mac_address", "response_time", "os"]
            column_names = ["IP地址", "主机名", "MAC地址", "响应时间(ms)", "系统"]
            
            # 设置表格列
            self.result_table.setColumnCount(len(columns))
            self.result_table.setHorizontalHeaderLabels(column_names)
        
        # 将扫描结果中的每个主机与表格中已有的主机进行对比，更新或添加
        existing_ips = []
        for row in range(self.result_table.rowCount()):
            if self.result_table.item(row, 0):
                existing_ips.append(self.result_table.item(row, 0).text())
        
        # 更新或添加主机数据
        for host in data:
            ip = host.get("ip", "")
            
            # 如果IP已在表格中，更新数据
            if ip in existing_ips:
                row = existing_ips.index(ip)
                self.update_host_in_table(row, host)
            else:
                # 否则添加新行
                self.add_host_to_table(host)
            
            # 如果启用了拓扑图，但没有实时更新，则扫描完成后添加到拓扑图
            if self.enable_topology_check.isChecked() and not self.realtime_topology_check.isChecked() and ip not in self.topology_hosts:
                self.add_host_to_topology(host)
        
        # 调整列宽
        self.result_table.resizeColumnsToContents()
        
        # 统计结果
        total_hosts = len(data)
        scanned_ips = 0
        if hasattr(result, 'metadata') and result.metadata and 'total_scanned' in result.metadata:
            scanned_ips = result.metadata.get('total_scanned', 0)
        else:
            # 尝试从日志提取或通过IP范围计算
            try:
                ip_range = self.ip_range_input.text().strip()
                scanned_ips = len(parse_ip_range(ip_range))
            except:
                scanned_ips = 0
        
        # 更新状态栏
        self.status_label.setText(
            f"扫描完成: 发现 {total_hosts}/{scanned_ips} 个在线主机，"
            f"用时 {result.duration:.2f} 秒"
        )
        
        # 如果有扫描结果且启用了拓扑图，默认切换到拓扑图标签页
        if total_hosts > 0 and self.enable_topology_check.isChecked():
            for i in range(self.result_tabs.count()):
                if self.result_tabs.widget(i) == self.network_topology_widget:
                    self.result_tabs.setCurrentIndex(i)
                    break
    
    def update_host_in_table(self, row, host_data):
        """更新表格中已存在的主机数据"""
        columns = ["ip", "hostname", "mac_address", "response_time", "os"]
        bg_color = QColor(144, 238, 144)  # 浅绿色
        
        for col, key in enumerate(columns):
            value = host_data.get(key, "")
            
            # 创建或更新单元格
            if self.result_table.item(row, col) is None:
                item = QTableWidgetItem(str(value) if value is not None else "")
                item.setBackground(bg_color)
                self.result_table.setItem(row, col, item)
            else:
                self.result_table.item(row, col).setText(str(value) if value is not None else "")
    
    def on_performance_mode_changed(self, state):
        """处理性能优先模式变更"""
        if self.enable_topology_check.isChecked() and hasattr(self.network_topology_widget, 'canvas'):
            if hasattr(self.network_topology_widget.canvas, 'set_performance_mode'):
                enabled = state == Qt.Checked
                self.network_topology_widget.canvas.set_performance_mode(enabled)
                
                # 如果已有拓扑图数据，重新绘制
                if hasattr(self.network_topology_widget, 'refresh_topology'):
                    self.network_topology_widget.refresh_topology()

    def on_enable_topology_changed(self, state):
        """处理启用拓扑图复选框变更"""
        if hasattr(self, 'network_topology_widget'):
            enabled = state == Qt.Checked
            
            # 如果存在网络拓扑图标签页，设置其可见性
            if hasattr(self, 'result_tabs'):
                # 找到网络拓扑图标签页的索引
                for i in range(self.result_tabs.count()):
                    if self.result_tabs.widget(i) == self.network_topology_widget:
                        # 如果启用拓扑图，显示标签页；否则隐藏标签页
                        if enabled:
                            self.result_tabs.setTabVisible(i, True)
                        else:
                            self.result_tabs.setTabVisible(i, False)
                        break
                
                # 如果当前选中的是即将隐藏的拓扑图标签，则切换到表格视图
                if not enabled and self.result_tabs.currentWidget() == self.network_topology_widget:
                    # 切换到表格视图（通常是第一个标签页）
                    self.result_tabs.setCurrentIndex(0)