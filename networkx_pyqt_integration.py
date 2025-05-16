#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetworkX与PyQt5集成示例
实现交互式网络拓扑图显示
"""

import sys
import os
import random
import networkx as nx
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QPushButton, QLabel, QComboBox, QSlider,
                             QCheckBox, QGroupBox, QFrame, QSplitter, QSizePolicy)
from PyQt5.QtCore import Qt, pyqtSignal, QSize

# 确保matplotlib使用Qt5后端
matplotlib.use('Qt5Agg')

class NetworkCanvas(FigureCanvas):
    """集成NetworkX和Matplotlib的画布类"""
    
    node_clicked = pyqtSignal(str)  # 定义节点点击信号
    
    def __init__(self, parent=None, width=8, height=6, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        
        super(NetworkCanvas, self).__init__(self.fig)
        self.setParent(parent)
        
        # 设置画布大小策略
        FigureCanvas.setSizePolicy(self,
                                  QSizePolicy.Expanding,
                                  QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)
        
        # 初始化图形
        self.graph = None
        self.pos = None
        self.picked_node = None
        
        # 连接鼠标点击事件
        self.fig.canvas.mpl_connect('pick_event', self.on_pick)
    
    def draw_network(self, graph, layout_type='spring'):
        """绘制网络拓扑图"""
        self.graph = graph
        self.axes.clear()
        
        # 根据选择的布局算法计算节点位置
        if layout_type == 'spring':
            self.pos = nx.spring_layout(self.graph, seed=42)
        elif layout_type == 'circular':
            self.pos = nx.circular_layout(self.graph)
        elif layout_type == 'shell':
            self.pos = nx.shell_layout(self.graph)
        elif layout_type == 'spectral':
            self.pos = nx.spectral_layout(self.graph)
        else:
            self.pos = nx.kamada_kawai_layout(self.graph)
        
        # 准备节点颜色和大小
        node_colors = []
        node_sizes = []
        for node, attrs in self.graph.nodes(data=True):
            if attrs.get('type') == 'gateway':
                node_colors.append('red')
                node_sizes.append(800)
            elif attrs.get('status') == 'up':
                node_colors.append('green')
                node_sizes.append(400)
            else:
                node_colors.append('gray')
                node_sizes.append(400)
        
        # 准备边的宽度和颜色
        edge_widths = []
        edge_colors = []
        for u, v, attrs in self.graph.edges(data=True):
            latency = attrs.get('latency', 50)
            width = 5 * (1 - latency/100)
            edge_widths.append(max(0.5, width))
            
            if latency < 30:
                edge_colors.append('green')
            elif latency < 70:
                edge_colors.append('orange')
            else:
                edge_colors.append('red')
        
        # 绘制节点
        nx.draw_networkx_nodes(self.graph, self.pos,
                              ax=self.axes,
                              node_color=node_colors,
                              node_size=node_sizes,
                              picker=5)  # 启用节点选择
        
        # 绘制边
        nx.draw_networkx_edges(self.graph, self.pos,
                              ax=self.axes,
                              width=edge_widths,
                              edge_color=edge_colors,
                              alpha=0.7)
        
        # 绘制标签
        nx.draw_networkx_labels(self.graph, self.pos, ax=self.axes, font_size=10)
        
        self.axes.set_title("网络拓扑图")
        self.axes.axis('off')
        self.fig.tight_layout()
        self.draw()
    
    def highlight_node(self, node_id):
        """高亮显示选中的节点"""
        if self.graph is None or node_id not in self.graph:
            return
        
        self.axes.clear()
        
        # 绘制基本网络
        self.draw_network(self.graph)
        
        # 突出显示选中的节点
        nx.draw_networkx_nodes(self.graph, self.pos,
                              ax=self.axes,
                              nodelist=[node_id],
                              node_color='yellow',
                              node_size=600,
                              edgecolors='black',
                              linewidths=2)
        
        # 重绘
        self.draw()
    
    def on_pick(self, event):
        """处理节点点击事件"""
        if hasattr(event, 'ind') and len(event.ind) > 0:
            # 从event.ind获取点击的节点索引
            ind = event.ind[0]
            
            # 转换为实际的节点ID
            node_list = list(self.graph.nodes())
            if ind < len(node_list):
                self.picked_node = node_list[ind]
                self.node_clicked.emit(self.picked_node)
                
                # 高亮显示节点
                self.highlight_node(self.picked_node)

class NetworkTopologyApp(QMainWindow):
    """网络拓扑图应用主窗口"""
    
    def __init__(self):
        super().__init__()
        
        # 创建测试网络
        self.network = self.create_test_network()
        
        # 设置UI
        self.init_ui()
    
    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle('网络拓扑图可视化工具')
        self.setGeometry(100, 100, 1200, 800)
        
        # 创建主窗口部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QHBoxLayout(central_widget)
        
        # 创建网络画布
        self.canvas = NetworkCanvas(width=8, height=6, dpi=100)
        self.canvas.node_clicked.connect(self.on_node_clicked)
        
        # 创建控制面板
        control_panel = self.create_control_panel()
        
        # 创建信息面板
        info_panel = self.create_info_panel()
        
        # 设置分割器
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(control_panel)
        
        graph_widget = QWidget()
        graph_layout = QVBoxLayout(graph_widget)
        graph_layout.addWidget(self.canvas)
        graph_layout.addWidget(info_panel)
        
        graph_container = QWidget()
        graph_container.setLayout(graph_layout)
        splitter.addWidget(graph_container)
        
        # 设置分割器初始大小
        splitter.setSizes([200, 1000])
        
        main_layout.addWidget(splitter)
        
        # 绘制初始网络
        self.canvas.draw_network(self.network)
    
    def create_control_panel(self):
        """创建控制面板"""
        control_widget = QWidget()
        control_layout = QVBoxLayout(control_widget)
        
        # 布局选择
        layout_group = QGroupBox("布局算法")
        layout_layout = QVBoxLayout(layout_group)
        
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Spring", "Circular", "Shell", "Spectral", "Kamada-Kawai"])
        self.layout_combo.currentTextChanged.connect(self.change_layout)
        layout_layout.addWidget(self.layout_combo)
        
        control_layout.addWidget(layout_group)
        
        # 其他控制选项
        display_group = QGroupBox("显示选项")
        display_layout = QVBoxLayout(display_group)
        
        self.show_labels = QCheckBox("显示标签")
        self.show_labels.setChecked(True)
        self.show_labels.stateChanged.connect(self.update_display)
        display_layout.addWidget(self.show_labels)
        
        self.show_weights = QCheckBox("显示延迟")
        self.show_weights.setChecked(False)
        self.show_weights.stateChanged.connect(self.update_display)
        display_layout.addWidget(self.show_weights)
        
        control_layout.addWidget(display_group)
        
        # 添加刷新按钮
        refresh_btn = QPushButton("刷新网络")
        refresh_btn.clicked.connect(self.refresh_network)
        control_layout.addWidget(refresh_btn)
        
        # 添加伸缩空间
        control_layout.addStretch()
        
        return control_widget
    
    def create_info_panel(self):
        """创建信息面板"""
        info_panel = QFrame()
        info_panel.setFrameShape(QFrame.StyledPanel)
        info_panel.setMinimumHeight(150)
        info_panel.setMaximumHeight(150)
        
        info_layout = QVBoxLayout(info_panel)
        
        self.info_title = QLabel("节点详情")
        self.info_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        info_layout.addWidget(self.info_title)
        
        self.info_content = QLabel("点击节点查看详情")
        info_layout.addWidget(self.info_content)
        
        info_layout.addStretch()
        
        return info_panel
    
    def change_layout(self, layout_name):
        """改变网络布局"""
        layout_type = layout_name.lower()
        self.canvas.draw_network(self.network, layout_type)
    
    def update_display(self):
        """更新显示选项"""
        # 在实际应用中这应该重新绘制图形
        self.canvas.draw_network(self.network, self.layout_combo.currentText().lower())
        
        # 如果有选中的节点，重新高亮它
        if hasattr(self.canvas, 'picked_node') and self.canvas.picked_node:
            self.canvas.highlight_node(self.canvas.picked_node)
    
    def refresh_network(self):
        """刷新网络"""
        self.network = self.create_test_network()
        self.canvas.draw_network(self.network, self.layout_combo.currentText().lower())
        self.info_content.setText("点击节点查看详情")
    
    def on_node_clicked(self, node_id):
        """处理节点点击事件"""
        # 显示节点信息
        node_attrs = self.network.nodes[node_id]
        
        info_text = f"节点: {node_id}\n"
        info_text += f"类型: {node_attrs.get('type', 'unknown')}\n"
        info_text += f"状态: {node_attrs.get('status', 'unknown')}\n"
        
        # 显示连接信息
        neighbors = list(self.network.neighbors(node_id))
        info_text += f"\n连接节点数: {len(neighbors)}\n"
        
        if neighbors:
            info_text += "连接节点: " + ", ".join(neighbors[:5])
            if len(neighbors) > 5:
                info_text += f" ... (共{len(neighbors)}个)"
        
        self.info_title.setText(f"节点详情 - {node_id}")
        self.info_content.setText(info_text)
    
    def create_test_network(self):
        """创建测试网络图"""
        # 创建空图
        G = nx.Graph()
        
        # 添加节点
        for i in range(10):
            ip = f"192.168.1.{i+1}"
            # 添加节点及其属性
            G.add_node(ip, type="host", status="up" if random.random() > 0.2 else "down")
        
        # 添加网关
        G.add_node("192.168.1.254", type="gateway", status="up")
        
        # 随机添加边（代表网络连接）
        for i in range(10):
            ip = f"192.168.1.{i+1}"
            # 所有主机连接到网关
            G.add_edge(ip, "192.168.1.254", latency=round(random.random()*100, 2))
            
            # 添加一些随机的主机间连接
            if random.random() > 0.7:
                target = f"192.168.1.{random.randint(1, 10)}"
                if target != ip:
                    G.add_edge(ip, target, latency=round(random.random()*50, 2))
        
        return G

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkTopologyApp()
    window.show()
    sys.exit(app.exec_()) 