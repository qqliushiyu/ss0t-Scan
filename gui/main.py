#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络工具箱图形界面主程序
基于 PyQt5 实现，提供各扫描模块的图形化操作界面
"""

import logging
import os
import sys
import time
import inspect
import threading
from typing import Dict, List, Any

# 将父目录添加到模块搜索路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, 
    QHBoxLayout, QLabel, QPushButton, QToolBar, QAction, QMenu,
    QStatusBar, QMessageBox, QFileDialog, QDialog, QLineEdit,
    QInputDialog, QComboBox, QFormLayout, QGroupBox, QCheckBox, 
    QSpinBox, QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QProgressDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPoint, QSize, QEventLoop, QTimer
from PyQt5.QtGui import QIcon, QFont

from core.scanner_manager import scanner_manager
from utils.config import config_manager
from gui.config_editor import ConfigEditorDialog, show_config_editor
from gui.plugin_config_editor import show_plugin_config_editor

# 导入ScanThread和各模块面板
from gui.panels.base_panel import ScanThread
from gui.panels.host_scan_panel import HostScanPanel
from gui.panels.port_scan_panel import PortScanPanel
from gui.panels.dns_panel import DnsPanel
from gui.panels.traceroute_panel import TraceroutePanel
from gui.panels.ping_monitor_panel import PingMonitorPanel
from gui.panels.tcp_ping_panel import TcpPingPanel
from gui.panels.web_risk_scan_panel import WebRiskScanPanel
from gui.panels.web_dir_scan_panel import WebDirScanPanel
from gui.panels.poc_scan_panel import POCScanPanel
from gui.panels.bruteforce_panel import BruteforcePanel

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/gui.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("ss0t-scna.gui")

class PluginConfigLoaderThread(QThread):
    """插件配置加载线程"""
    finished = pyqtSignal()  # 发送加载完成信号
    error = pyqtSignal(str)  # 发送加载错误信息
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_widget = parent
    
    def run(self):
        """线程执行函数"""
        try:
            # 不在线程中创建UI对话框，只进行数据准备工作
            # 导入模块
            from plugins.config_manager import plugin_config_manager
            
            # 检查配置目录
            if not os.path.exists(plugin_config_manager.config_dir):
                raise FileNotFoundError(f"配置目录不存在: {plugin_config_manager.config_dir}")
            
            if not os.access(plugin_config_manager.config_dir, os.R_OK):
                raise PermissionError(f"无权限访问配置目录: {plugin_config_manager.config_dir}")
            
            # 完成后发送成功信号
            self.finished.emit()
        except Exception as e:
            # 发射错误信号
            self.error.emit(str(e))

class MainWindow(QMainWindow):
    """主窗口类"""
    
    def __init__(self):
        """初始化主窗口"""
        super().__init__()
        
        self.setWindowTitle("ss0t-Scan")
        self.setMinimumSize(1100, 920)
        
        # 初始化 UI
        self.init_ui()
        
        # 加载扫描模块
        self.load_modules()
    
    def init_ui(self):
        """初始化用户界面"""
        # 主布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # 创建标签页控件
        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget)
        
        # 创建状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("就绪")
        self.status_bar.addWidget(self.status_label)
        
        # 创建菜单栏
        self.create_menu_bar()
    
    def create_menu_bar(self):
        """创建菜单栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu('文件')
        
        # 导出配置
        export_config_action = QAction('导出配置', self)
        export_config_action.triggered.connect(self.export_config)
        file_menu.addAction(export_config_action)
        
        # 导入配置
        import_config_action = QAction('导入配置', self)
        import_config_action.triggered.connect(self.import_config)
        file_menu.addAction(import_config_action)
        
        # 编辑配置
        edit_config_action = QAction('编辑配置文件', self)
        edit_config_action.triggered.connect(self.edit_config)
        file_menu.addAction(edit_config_action)
        
        # 编辑插件配置
        edit_plugin_config_action = QAction('编辑插件配置', self)
        edit_plugin_config_action.triggered.connect(self.edit_plugin_config)
        file_menu.addAction(edit_plugin_config_action)
        
        file_menu.addSeparator()
        
        # 退出
        exit_action = QAction('退出', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 模块菜单
        module_menu = menubar.addMenu('模块')
        
        # 刷新模块
        refresh_modules_action = QAction('刷新模块', self)
        refresh_modules_action.triggered.connect(self.load_modules)
        module_menu.addAction(refresh_modules_action)
        
        # 帮助菜单
        help_menu = menubar.addMenu('帮助')
        
        # 关于
        about_action = QAction('关于', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def load_modules(self):
        """加载扫描模块"""
        # 先清空标签页
        self.tab_widget.clear()
        
        # 发现扫描模块
        scanner_manager.discover_scanners()
        
        try:
            # 添加各模块面板
            # 主机扫描
            host_panel = HostScanPanel()
            self.tab_widget.addTab(host_panel, "主机扫描")
            
            # 端口扫描
            port_panel = PortScanPanel()
            self.tab_widget.addTab(port_panel, "端口扫描")
            
            # DNS 检测
            dns_panel = DnsPanel()
            self.tab_widget.addTab(dns_panel, "DNS 检测")
            
            # 路由追踪
            traceroute_panel = TraceroutePanel()
            self.tab_widget.addTab(traceroute_panel, "路由追踪")
            
            # Ping 监控
            ping_panel = PingMonitorPanel()
            self.tab_widget.addTab(ping_panel, "Ping 监控")
            
            # TCP Ping
            tcp_ping_panel = TcpPingPanel()
            self.tab_widget.addTab(tcp_ping_panel, "TCP Ping")
            
            # Web风险扫描
            web_risk_panel = WebRiskScanPanel()
            self.tab_widget.addTab(web_risk_panel, "Web风险扫描")
            
            # Web目录扫描
            web_dir_panel = WebDirScanPanel()
            self.tab_widget.addTab(web_dir_panel, "Web目录扫描")
            
            # POC扫描
            poc_panel = POCScanPanel()
            self.tab_widget.addTab(poc_panel, "POC扫描")
            
            # 爆破扫描
            bruteforce_panel = BruteforcePanel()
            self.tab_widget.addTab(bruteforce_panel, "爆破扫描")
            
            # 其他模块可以在这里添加...
            
            self.status_label.setText(f"已加载 {self.tab_widget.count()} 个模块")
            logger.info(f"已加载 {self.tab_widget.count()} 个模块")
        
        except Exception as e:
            logger.error(f"加载模块失败: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "错误", f"加载模块失败: {str(e)}")
    
    def export_config(self):
        """导出配置"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出配置", "", "INI 文件 (*.ini)"
        )
        
        if file_path:
            try:
                # 保存当前配置
                config_manager.config_file = file_path
                if config_manager.save_config():
                    QMessageBox.information(self, "成功", f"配置已导出到 {file_path}")
                else:
                    QMessageBox.warning(self, "警告", "配置导出失败")
            except Exception as e:
                logger.error(f"导出配置失败: {str(e)}", exc_info=True)
                QMessageBox.critical(self, "错误", f"导出配置失败: {str(e)}")
    
    def import_config(self):
        """导入配置"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "导入配置", "", "INI 文件 (*.ini)"
        )
        
        if file_path:
            try:
                # 保存当前配置文件路径
                original_config_file = config_manager.config_file
                
                # 设置新配置文件路径
                config_manager.config_file = file_path
                
                # 加载配置
                if config_manager.load_config():
                    # 应用配置到各面板
                    for i in range(self.tab_widget.count()):
                        panel = self.tab_widget.widget(i)
                        if hasattr(panel, 'load_config'):
                            panel.load_config()
                    
                    QMessageBox.information(self, "成功", f"配置已从 {file_path} 导入")
                else:
                    # 恢复原配置文件
                    config_manager.config_file = original_config_file
                    QMessageBox.warning(self, "警告", "配置导入失败")
            except Exception as e:
                logger.error(f"导入配置失败: {str(e)}", exc_info=True)
                QMessageBox.critical(self, "错误", f"导入配置失败: {str(e)}")
    
    def edit_config(self):
        """编辑配置文件"""
        try:
            # 获取配置文件路径选项
            config_paths = [
                ("主配置文件", config_manager.config_file),
                ("指纹配置", "configs/fingerprints.txt"),
            ]
            
            # 创建配置文件选择菜单
            menu = QMenu(self)
            for name, path in config_paths:
                action = QAction(f"{name} ({path})", self)
                action.setData(path)
                menu.addAction(action)
            
            # 添加自定义配置选项
            menu.addSeparator()
            custom_action = QAction("选择其他配置文件...", self)
            menu.addAction(custom_action)
            
            # 显示菜单并获取选择的动作
            chosen_action = menu.exec_(self.mapToGlobal(self.menuBar().pos() + 
                                      QPoint(100, self.menuBar().height())))
            
            if not chosen_action:
                return
            
            if chosen_action == custom_action:
                # 选择自定义配置文件
                file_path, _ = QFileDialog.getOpenFileName(
                    self, "选择配置文件", "", "所有文件 (*)"
                )
                if not file_path:
                    return
                config_path = file_path
            else:
                config_path = chosen_action.data()
            
            # 使用高级配置编辑器对话框
            if show_config_editor(config_path, self):
                # 配置已保存，重新加载所有面板的配置
                for i in range(self.tab_widget.count()):
                    panel = self.tab_widget.widget(i)
                    if hasattr(panel, 'load_config'):
                        panel.load_config()
                
                self.status_label.setText("配置已更新")
        
        except Exception as e:
            logger.error(f"编辑配置文件失败: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "错误", f"编辑配置文件失败: {str(e)}")
    
    def edit_plugin_config(self):
        """编辑插件配置文件"""
        try:
            # 显示等待消息
            self.status_label.setText("正在加载插件配置编辑器...")
            
            # 创建一个进度对话框
            progress_dialog = QProgressDialog("正在加载插件配置编辑器...", "取消", 0, 100, self)
            progress_dialog.setWindowTitle("加载中")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)  # 立即显示
            progress_dialog.setValue(10)
            
            # 创建并启动加载线程
            self.plugin_config_loader_thread = PluginConfigLoaderThread(self)
            
            # 创建事件循环，用于等待加载完成
            loop = QEventLoop()
            
            # 加载成功的回调
            def on_load_success():
                # 更新进度
                progress_dialog.setValue(80)
                progress_dialog.setLabelText("加载完成，正在打开编辑器...")
                
                # 给UI时间更新
                QTimer.singleShot(200, lambda: self._open_plugin_config_editor(progress_dialog, loop))
            
            # 加载失败的回调
            def on_load_error(error_msg):
                progress_dialog.close()
                self.status_label.setText("就绪")
                logger.error(f"加载插件配置编辑器失败: {error_msg}")
                QMessageBox.critical(self, "错误", f"加载插件配置编辑器失败: {error_msg}")
                loop.quit()
            
            # 取消操作的回调
            def on_canceled():
                # 终止线程（如果可能）
                if self.plugin_config_loader_thread.isRunning():
                    self.plugin_config_loader_thread.terminate()
                    self.plugin_config_loader_thread.wait()
                
                self.status_label.setText("就绪")
                loop.quit()
            
            # 连接信号
            self.plugin_config_loader_thread.finished.connect(on_load_success)
            self.plugin_config_loader_thread.error.connect(on_load_error)
            progress_dialog.canceled.connect(on_canceled)
            
            # 启动线程
            self.plugin_config_loader_thread.start()
            
            # 开始更新进度条
            def update_progress():
                if progress_dialog and not progress_dialog.wasCanceled():
                    current = progress_dialog.value()
                    if current < 70:  # 最多更新到70%，剩下的在加载成功后更新
                        progress_dialog.setValue(current + 5)
                        QTimer.singleShot(150, update_progress)
            
            # 启动进度更新
            QTimer.singleShot(100, update_progress)
            
            # 等待加载完成或用户取消
            loop.exec_()
            
        except Exception as e:
            logger.error(f"编辑插件配置失败: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "错误", f"编辑插件配置失败: {str(e)}")
    
    def _open_plugin_config_editor(self, progress_dialog, loop):
        """在线程加载完成后打开插件配置编辑器
        
        Args:
            progress_dialog: 进度对话框
            loop: 事件循环
        """
        try:
            # 更新进度
            progress_dialog.setValue(100)
            
            # 打开编辑器
            from gui.plugin_config_editor import show_plugin_config_editor
            
            # 关闭进度对话框
            progress_dialog.close()
            
            # 打开编辑器
            result = show_plugin_config_editor(self)
            
            # 更新状态
            self.status_label.setText("就绪")
            
            # 结束事件循环
            loop.quit()
            
        except Exception as e:
            progress_dialog.close()
            logger.error(f"打开插件配置编辑器失败: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "错误", f"打开插件配置编辑器失败: {str(e)}")
            self.status_label.setText("就绪")
            loop.quit()
    
    def show_about(self):
        """显示关于信息"""
        about_text = """
        <h2>ss0t-Scan</h2>
        <p>版本: 1.0.0</p>
        <p>一个综合性的网络安全扫描工具集，提供多种扫描和监控功能。</p>
        <p>包括主机扫描、端口扫描、DNS检测、路由追踪、Ping监控等模块。</p>
        <p>© ss0t 网络安全团队</p>
        """
        QMessageBox.about(self, "关于", about_text)
    
    def closeEvent(self, event):
        """
        应用关闭时的处理，确保所有线程停止
        
        Args:
            event: 关闭事件
        """
        # 停止所有面板中的扫描线程
        for i in range(self.tab_widget.count()):
            panel = self.tab_widget.widget(i)
            
            # 检查是否有正在运行的扫描线程
            if hasattr(panel, 'scan_thread') and panel.scan_thread:
                logger.info(f"正在停止 {panel.__class__.__name__} 中的扫描")
                
                # 先判断线程类型
                if hasattr(panel.scan_thread, 'isRunning'):  # QThread
                    is_running = panel.scan_thread.isRunning()
                else:  # Python标准线程
                    is_running = panel.scan_thread.is_alive() if hasattr(panel.scan_thread, 'is_alive') else False
                
                if is_running:
                    # 停止扫描器
                    if hasattr(panel, 'scanner') and panel.scanner:
                        panel.scanner.stop()
                    elif hasattr(panel.scan_thread, 'scanner') and panel.scan_thread.scanner:
                        panel.scan_thread.scanner.stop()
                    
                    # 等待线程结束
                    if hasattr(panel.scan_thread, 'wait'):  # QThread
                        if not panel.scan_thread.wait(1000):  # 等待1秒
                            logger.warning(f"强制终止 {panel.__class__.__name__} 中的QThread")
                            panel.scan_thread.terminate()
                            panel.scan_thread.wait()
                    else:  # Python标准线程
                        # 标准线程只能等待不能强制终止
                        panel.scan_thread.join(1.0)  # 等待1秒
                        if panel.scan_thread.is_alive():
                            logger.warning(f"{panel.__class__.__name__} 中的线程未能立即停止，程序将继续关闭")
        
        # 调用父类的关闭事件处理
        super().closeEvent(event)

def main():
    """主函数"""
    # 确保日志目录存在
    os.makedirs('logs', exist_ok=True)
    
    # 创建应用
    app = QApplication(sys.argv)
    
    # 应用样式
    app.setStyle("Fusion")
    
    # 创建主窗口
    window = MainWindow()
    window.show()
    
    # 运行应用
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 