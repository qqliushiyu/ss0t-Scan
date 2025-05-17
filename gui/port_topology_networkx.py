#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
端口扫描网络拓扑图实现
使用NetworkX库生成端口网络拓扑图，并集成到PyQt5界面中
"""

import math
import networkx as nx
import matplotlib
matplotlib.use('Qt5Agg')
# 配置matplotlib中文字体支持
import platform
if platform.system() == 'Windows':
    # Windows系统尝试使用微软雅黑
    matplotlib.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'Arial Unicode MS', 'sans-serif']
else:
    # Linux/Mac系统尝试使用其他中文字体
    matplotlib.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'WenQuanYi Micro Hei', 'Heiti SC', 'sans-serif']
matplotlib.rcParams['axes.unicode_minus'] = False  # 正确显示负号

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import random

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QLabel, 
    QPushButton, QCheckBox, QFrame, QGraphicsView, QGraphicsScene,
    QMenu, QAction, QSplitter, QSizePolicy
)
from PyQt5.QtCore import Qt, pyqtSignal, QPointF, QRectF
from PyQt5.QtGui import QColor, QPen, QBrush, QPainter

class PortNetworkCanvas(FigureCanvas):
    """集成NetworkX和Matplotlib的端口可视化画布类"""
    
    port_clicked = pyqtSignal(str, int)  # IP和端口点击信号
    
    def __init__(self, parent=None, width=8, height=6, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        
        super(PortNetworkCanvas, self).__init__(self.fig)
        self.setParent(parent)
        
        # 设置画布大小策略
        FigureCanvas.setSizePolicy(self,
                                  QSizePolicy.Expanding,
                                  QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)
        
        # 初始化图形
        self.graph = nx.Graph()
        self.pos = None
        self.picked_node = None
        
        # 连接鼠标点击事件，使用button_press_event而不是picker
        self.fig.canvas.mpl_connect('button_press_event', self.on_click_event)
        
        # 颜色映射，用于按服务类型标记端口节点
        self.port_color_map = {
            'web': '#1E88E5',       # 蓝色 - Web服务 (80,443,8080,8443)
            'file': '#43A047',      # 绿色 - 文件共享 (21,22,445,139)
            'database': '#FBC02D',  # 黄色 - 数据库 (1433,3306,5432,6379)
            'remote': '#E53935',    # 红色 - 远程访问 (3389,5900,22)
            'mail': '#8E24AA',      # 紫色 - 邮件服务 (25,110,143,993)
            'mixed': '#FF9800',     # 橙色 - 混合服务
            'other': '#757575'      # 灰色 - 其他服务
        }
        
        # 性能模式设置
        self.performance_mode = False
        
        # 节点大小调整阈值
        self.node_size_thresholds = {
            50: [900, 450],    # 节点数<50: IP节点大小900, 端口节点大小450
            100: [700, 350],   # 节点数<100: IP节点大小700, 端口节点大小350
            200: [500, 250],   # 节点数<200: IP节点大小500, 端口节点大小250
            500: [300, 150],   # 节点数<500: IP节点大小300, 端口节点大小150
            # 其他情况使用最小值
            float('inf'): [200, 100]
        }
    
    def get_port_category(self, port, service=""):
        """根据端口和服务获取服务类别"""
        port = int(port)
        
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        file_ports = [21, 22, 445, 139, 2049, 20]
        remote_ports = [3389, 5900, 22, 23]
        database_ports = [1433, 3306, 5432, 6379, 27017, 1521]
        mail_ports = [25, 110, 143, 993, 995, 587]
        
        # 先根据服务名称判断类型
        service_lower = service.lower() if service else ""
        
        if "http" in service_lower or "web" in service_lower:
            return 'web'
        elif "ftp" in service_lower or "smb" in service_lower or "netbios" in service_lower:
            return 'file'
        elif "ssh" in service_lower or "rdp" in service_lower or "vnc" in service_lower:
            return 'remote'
        elif "sql" in service_lower or "db" in service_lower or "redis" in service_lower:
            return 'database'
        elif "smtp" in service_lower or "pop" in service_lower or "imap" in service_lower:
            return 'mail'
        
        # 根据端口号判断类型
        if port in web_ports:
            return 'web'
        elif port in file_ports:
            return 'file'
        elif port in remote_ports:
            return 'remote'
        elif port in database_ports:
            return 'database'
        elif port in mail_ports:
            return 'mail'
        else:
            return 'other'
    
    def highlight_port(self, node_id):
        """高亮显示选中的端口节点"""
        if node_id not in self.graph:
            return
            
        # 保存选中的节点ID
        self.picked_node = node_id
        
        # 重新绘制网络
        self.draw_network()
        
        # 高亮节点本身
        highlight_pos = {node_id: self.pos[node_id]}
        nx.draw_networkx_nodes(self.graph, highlight_pos,
                              nodelist=[node_id],
                              node_color='yellow',
                              node_size=600,
                              edgecolors='black',
                              linewidths=3,
                              ax=self.axes)
        
        # 高亮与节点相连的边和邻居节点
        neighbors = list(self.graph.neighbors(node_id))
        if neighbors:
            # 高亮相连的边
            edge_list = [(node_id, n) for n in neighbors]
            
            # 绘制高亮边
            nx.draw_networkx_edges(self.graph, self.pos,
                                  edgelist=edge_list,
                                  width=3.0,
                                  edge_color='cyan',
                                  ax=self.axes)
            
            # 高亮邻居节点
            neighbor_pos = {n: self.pos[n] for n in neighbors}
            nx.draw_networkx_nodes(self.graph, neighbor_pos,
                                  nodelist=neighbors,
                                  node_color='lightgreen',
                                  node_size=500,
                                  edgecolors='darkblue',
                                  linewidths=2,
                                  ax=self.axes)
            
            # 高亮标签
            all_highlighted = [node_id] + neighbors
            highlight_labels = {n: self.graph.nodes[n].get('label', n) 
                              for n in all_highlighted}
            
            nx.draw_networkx_labels(self.graph, self.pos,
                                   labels=highlight_labels,
                                   font_size=9,
                                   font_weight='bold',
                                   ax=self.axes)
        
        self.draw()
    
    def set_performance_mode(self, enabled=True):
        """设置性能优先模式"""
        self.performance_mode = enabled
        
        # 设置matplotlib渲染选项以提高性能
        if enabled:
            # 减少绘图精度，提高性能
            matplotlib.rcParams['path.simplify'] = True
            matplotlib.rcParams['path.simplify_threshold'] = 0.5
            matplotlib.rcParams['agg.path.chunksize'] = 10000
            # 禁用抗锯齿
            matplotlib.rcParams['text.antialiased'] = False
            matplotlib.rcParams['lines.antialiased'] = False
            matplotlib.rcParams['patch.antialiased'] = False
            # 降低DPI以加快渲染
            if hasattr(self.fig, 'dpi'):
                self._original_dpi = self.fig.dpi
                self.fig.dpi = 72
        else:
            # 恢复默认绘图精度
            matplotlib.rcParams['path.simplify'] = True
            matplotlib.rcParams['path.simplify_threshold'] = 0.1
            matplotlib.rcParams['agg.path.chunksize'] = 0
            # 启用抗锯齿
            matplotlib.rcParams['text.antialiased'] = True
            matplotlib.rcParams['lines.antialiased'] = True
            matplotlib.rcParams['patch.antialiased'] = True
            # 恢复原始DPI
            if hasattr(self, '_original_dpi') and hasattr(self.fig, 'dpi'):
                self.fig.dpi = self._original_dpi
    
    def get_node_sizes(self):
        """根据节点数量动态计算节点大小"""
        node_count = self.graph.number_of_nodes()
        
        # 根据节点数量选择合适的节点大小
        for threshold, sizes in sorted(self.node_size_thresholds.items()):
            if node_count <= threshold:
                return sizes
        
        # 默认返回最小尺寸
        return self.node_size_thresholds[float('inf')]
    
    def draw_network(self, layout_type='spring'):
        """绘制端口网络拓扑图"""
        self.axes.clear()
        
        # 获取节点数量
        node_count = self.graph.number_of_nodes()
        
        # 如果节点数量大于100，自动启用性能模式
        if node_count > 100:
            self.set_performance_mode(True)
        else:
            self.set_performance_mode(False)
        
        # 如果图为空，添加一个临时节点以避免布局错误
        if node_count == 0:
            self.graph.add_node("temp", type="unknown")
            
        # 根据选择的布局算法计算节点位置
        if layout_type == 'spring':
            # 增加k值(弹簧系数)以增大节点间距离，防止重叠
            # 对于大规模图，减少迭代次数以提高性能
            iterations = 50 if node_count < 100 else 20
            k_value = 1.8 / math.sqrt(max(1, node_count))
            
            # 对于大型图形，使用较小的k值和较少的迭代次数
            if node_count > 500:
                k_value = 0.8 / math.sqrt(max(1, node_count))
                iterations = 10
                
            self.pos = nx.spring_layout(self.graph, k=k_value, 
                                      iterations=iterations, seed=42)
        elif layout_type == 'circular':
            self.pos = nx.circular_layout(self.graph, scale=2.0)
        elif layout_type == 'shell':
            # 按IP分组进行布局
            try:
                # 获取节点IP信息并分组
                ip_groups = {}
                for node, attrs in self.graph.nodes(data=True):
                    ip = attrs.get('ip', 'unknown')
                    if ip not in ip_groups:
                        ip_groups[ip] = []
                    ip_groups[ip].append(node)
                
                # 按IP地址排序，并创建组列表
                shell_groups = [ip_groups[ip] for ip in sorted(ip_groups.keys())]
                
                # 应用shell布局
                self.pos = nx.shell_layout(self.graph, nlist=shell_groups, scale=2.0)
            except:
                # 如果分组失败，回退到普通shell布局
                self.pos = nx.shell_layout(self.graph, scale=2.0)
        elif layout_type == 'spectral':
            # 对于大型图，spectral布局可能会很慢，回退到spring布局
            if node_count > 300:
                iterations = 10 if node_count > 500 else 20
                k_value = 0.8 / math.sqrt(max(1, node_count))
                self.pos = nx.spring_layout(self.graph, k=k_value, 
                                          iterations=iterations, seed=42)
            else:
                self.pos = nx.spectral_layout(self.graph, scale=2.0)
        elif layout_type == 'kamada_kawai':
            # Kamada-Kawai布局对于大型图非常慢，超过一定规模自动回退
            if node_count > 200:
                iterations = 10 if node_count > 500 else 20
                k_value = 0.8 / math.sqrt(max(1, node_count))
                self.pos = nx.spring_layout(self.graph, k=k_value, 
                                          iterations=iterations, seed=42)
            else:
                self.pos = nx.kamada_kawai_layout(self.graph, scale=2.0)
        else:
            self.pos = nx.spring_layout(self.graph, scale=2.0)
        
        # 如果添加了临时节点，移除它
        if "temp" in self.graph.nodes():
            self.graph.remove_node("temp")
            # 如果pos字典中存在temp节点，也移除它
            if "temp" in self.pos:
                del self.pos["temp"]
        
        # 获取动态节点大小
        ip_node_size, port_node_size = self.get_node_sizes()
            
        # 根据节点类型准备颜色和大小
        node_colors = []
        node_sizes = []
        node_borders = []
        for node, attrs in self.graph.nodes(data=True):
            node_type = attrs.get('type', 'unknown')
            
            if node_type == 'ip':
                # IP节点使用灰色
                node_colors.append('#607D8B')  # 灰蓝色
                node_sizes.append(ip_node_size)
                node_borders.append('black')
            elif node_type == 'port':
                # 端口节点根据服务类型设置颜色
                category = attrs.get('category', 'other')
                node_colors.append(self.port_color_map.get(category, self.port_color_map['other']))
                node_sizes.append(port_node_size)
                node_borders.append('darkgray')
            else:
                # 未知类型，使用默认灰色
                node_colors.append('gray')
                node_sizes.append(port_node_size * 0.7)
                node_borders.append('darkgray')
        
        # 绘制节点
        nx.draw_networkx_nodes(self.graph, self.pos,
                              ax=self.axes,
                              node_color=node_colors,
                              node_size=node_sizes,
                              edgecolors=node_borders,
                              linewidths=1.5,
                              alpha=0.9)
        
        # 绘制边
        edge_width = 1.5 if node_count < 100 else 0.8
        nx.draw_networkx_edges(self.graph, self.pos,
                              ax=self.axes,
                              width=edge_width,
                              alpha=0.6,
                              edge_color='#CCCCCC')
        
        # 绘制标签 - 大图形时减少或禁用标签以提高性能
        if node_count <= 100:
            # 对于小图显示所有标签
            labels = {node: self.graph.nodes[node].get('label', node) 
                     for node in self.graph.nodes()}
            font_size = 8 if node_count < 50 else 6
            nx.draw_networkx_labels(self.graph, self.pos, 
                                  labels=labels, 
                                  ax=self.axes,
                                  font_size=font_size)
        elif node_count <= 300:
            # 对于中型图只显示IP节点标签
            labels = {node: self.graph.nodes[node].get('label', node) 
                     for node in self.graph.nodes() 
                     if self.graph.nodes[node].get('type') == 'ip'}
            nx.draw_networkx_labels(self.graph, self.pos, 
                                  labels=labels, 
                                  ax=self.axes,
                                  font_size=6)
        # 大型图不显示标签
        
        # 设置标题 - 在性能模式下不显示标题以提高性能
        if not self.performance_mode:
            self.axes.set_title("端口扫描网络拓扑图")
        
        self.axes.axis('off')
        
        # 在性能模式下关闭自动调整，提高绘制速度
        if not self.performance_mode:
            self.fig.tight_layout()
            
        self.draw()
    
    def on_click_event(self, event):
        """处理鼠标点击事件"""
        if event.inaxes != self.axes or self.pos is None:
            return
            
        # 获取点击位置
        click_x, click_y = event.xdata, event.ydata
        
        # 查找最近的节点
        min_dist = float('inf')
        closest_node = None
        
        for node, (x, y) in self.pos.items():
            # 确保节点仍然存在于图中（可能已被移除，如临时节点）
            if node not in self.graph:
                continue
                
            # 计算点击位置与节点位置的距离
            dist = ((x - click_x) ** 2 + (y - click_y) ** 2) ** 0.5
            
            # 根据节点大小和类型调整选中半径
            node_type = self.graph.nodes[node].get('type', 'unknown')
            
            # 增大选中半径以便更容易点击
            if node_type == 'ip':
                node_size = 0.2  # IP节点选中半径更大
            elif node_type == 'port':
                node_size = 0.1  # 端口节点选中半径
            else:
                node_size = 0.08  # 默认选中半径
            
            # 如果点击位置在节点选中半径内，且是最近的节点
            if dist < node_size and dist < min_dist:
                min_dist = dist
                closest_node = node
        
        # 如果找到了节点，发送信号并高亮显示
        if closest_node is not None and closest_node in self.graph:
            self.picked_node = closest_node
            node_attrs = self.graph.nodes[closest_node]
            
            if node_attrs.get('type') == 'port':
                ip = node_attrs.get('ip', '')
                port = node_attrs.get('port', 0)
                if ip and port:
                    self.port_clicked.emit(ip, port)
            
            self.highlight_port(closest_node)
    
    def on_pick(self, event):
        """
        此方法已弃用，改为使用on_click_event
        保留此方法是为了兼容性
        """
        pass
    
    def add_ip(self, ip, pos=None):
        """添加IP节点到图中"""
        # 创建唯一节点ID
        node_id = f"ip:{ip}"
        
        # 如果节点已存在，返回现有节点ID
        if node_id in self.graph:
            return node_id
            
        # 创建IP节点
        self.graph.add_node(
            node_id,
            type='ip',
            ip=ip,
            label=ip
        )
        
        return node_id
    
    def add_port(self, ip, port, service=""):
        """添加端口节点到图中"""
        # 确保IP节点存在
        ip_node_id = self.add_ip(ip)
        
        # 创建唯一的端口节点ID
        port_node_id = f"port:{ip}:{port}"
        
        # 获取服务类别
        category = self.get_port_category(port, service)
        
        # 准备端口标签
        if service:
            # 限制服务名长度
            short_service = service[:10] + ('...' if len(service) > 10 else '')
            label = f"{port}\n{short_service}"
        else:
            label = f"{port}"
            
        # 添加端口节点
        if port_node_id not in self.graph:
            self.graph.add_node(
                port_node_id,
                type='port',
                ip=ip,
                port=port,
                service=service,
                category=category,
                label=label
            )
            
            # 连接IP和端口节点
            self.graph.add_edge(ip_node_id, port_node_id)
        
        return port_node_id
    
    def clear_graph(self):
        """清除图中所有节点"""
        self.graph.clear()
        self.draw_network()

class PortTopologyNetworkX(QWidget):
    """端口扫描网络拓扑图控件"""
    
    port_selected = pyqtSignal(str, int)  # IP和端口选择信号
    
    # 设置节点数量限制
    MAX_NODES = 200  # 最大节点数（IP节点 + 端口节点）
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        """初始化用户界面"""
        # 主布局
        main_layout = QVBoxLayout(self)
        
        # 控制区域
        control_layout = QHBoxLayout()
        
        # 布局选择
        layout_label = QLabel("布局方式:")
        self.layout_combo = QComboBox()
        self.layout_combo.addItem("弹簧布局", "spring")
        self.layout_combo.addItem("圆形布局", "circular")
        self.layout_combo.addItem("同心圆布局", "shell")
        self.layout_combo.addItem("谱布局", "spectral")
        self.layout_combo.addItem("Kamada-Kawai布局", "kamada_kawai")
        self.layout_combo.currentIndexChanged.connect(self.on_layout_changed)
        
        control_layout.addWidget(layout_label)
        control_layout.addWidget(self.layout_combo)
        
        # 分组选项
        group_label = QLabel("分组方式:")
        self.group_combo = QComboBox()
        self.group_combo.addItem("按IP分组", "ip")
        self.group_combo.addItem("按服务类型分组", "service")
        self.group_combo.addItem("按端口范围分组", "port_range")
        self.group_combo.currentIndexChanged.connect(self.update_display)
        
        control_layout.addWidget(group_label)
        control_layout.addWidget(self.group_combo)
        
        # 添加过滤控件
        filter_label = QLabel("过滤:")
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("全部", "all")
        self.filter_combo.addItem("常见端口", "common")
        self.filter_combo.addItem("Web服务", "web")
        self.filter_combo.addItem("数据库", "database")
        self.filter_combo.addItem("仅HTTP(S)", "http")
        self.filter_combo.currentIndexChanged.connect(self.apply_filter)
        
        control_layout.addWidget(filter_label)
        control_layout.addWidget(self.filter_combo)
        
        # 刷新按钮
        refresh_btn = QPushButton("刷新拓扑图")
        refresh_btn.clicked.connect(self.refresh_topology)
        control_layout.addWidget(refresh_btn)
        
        # 添加控制区域到主布局
        main_layout.addLayout(control_layout)
        
        # 添加状态标签
        self.status_label = QLabel("当前显示: 0 个节点")
        main_layout.addWidget(self.status_label)
        
        # 添加网络拓扑图
        self.canvas = PortNetworkCanvas(self)
        self.canvas.port_clicked.connect(self.on_port_clicked)
        main_layout.addWidget(self.canvas)
        
        # 添加底部信息区域
        self.info_frame = QFrame()
        self.info_frame.setFrameShape(QFrame.StyledPanel)
        self.info_frame.setMaximumHeight(100)
        
        info_layout = QVBoxLayout(self.info_frame)
        self.info_title = QLabel("端口详情")
        self.info_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        
        self.info_content = QLabel("点击端口查看详情")
        
        info_layout.addWidget(self.info_title)
        info_layout.addWidget(self.info_content)
        
        main_layout.addWidget(self.info_frame)
        
        # 初始化拓扑图
        self.canvas.draw_network()
        
        # 存储端口数据
        self.ports_data = {}
        
        # 当前过滤器
        self.current_filter = "all"
        
        # 过滤器定义 - 不同过滤器包含的端口列表
        self.filter_ports = {
            "common": [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080],
            "web": [80, 443, 8080, 8443, 8000, 8888, 9000, 9090],
            "database": [1433, 1521, 3306, 5432, 6379, 27017],
            "http": [80, 443]
        }
    
    def on_layout_changed(self, index):
        """处理布局类型变更"""
        layout_type = self.layout_combo.currentData()
        self.canvas.draw_network(layout_type)
    
    def update_display(self):
        """更新显示选项"""
        self.canvas.draw_network(self.layout_combo.currentData())
        
        # 如果有选中的节点，重新高亮它
        if hasattr(self.canvas, 'picked_node') and self.canvas.picked_node:
            self.canvas.highlight_port(self.canvas.picked_node)
        
        # 更新状态标签
        nodes_count = self.canvas.graph.number_of_nodes()
        total_ports = len(self.ports_data)
        self.status_label.setText(f"当前显示: {nodes_count} 个节点 (总计: {total_ports} 个端口)")
    
    def refresh_topology(self):
        """刷新拓扑图"""
        # 重新创建图
        self.canvas.clear_graph()
        
        # 应用当前过滤器并重新添加端口
        self.apply_filter(self.filter_combo.currentIndex())
    
    def apply_filter(self, index):
        """应用过滤器筛选显示内容"""
        # 获取过滤器类型
        filter_type = self.filter_combo.itemData(index)
        self.current_filter = filter_type
        
        # 清除图
        self.canvas.clear_graph()
        
        # 根据过滤器类型筛选端口
        filtered_ports = {}
        total_nodes_estimate = 0  # 估计节点数量（IP节点 + 端口节点）
        
        # 如果是"all"过滤器，先计算总节点数，以便应用节点限制
        if filter_type == "all":
            # 估算总节点数：每个不同IP一个节点，加上所有端口节点
            unique_ips = set()
            for key, port_data in self.ports_data.items():
                ip = port_data.get("ip", "")
                if ip:
                    unique_ips.add(ip)
            
            total_nodes_estimate = len(unique_ips) + len(self.ports_data)
            
            # 如果节点太多，自动切换到"common"过滤器
            if total_nodes_estimate > self.MAX_NODES:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.warning(self, "性能警告", 
                    f"检测到 {total_nodes_estimate} 个节点，超过了 {self.MAX_NODES} 的限制。\n"
                    f"已自动切换到'常见端口'过滤器以提高性能。")
                
                # 设置过滤器为"common"
                for i in range(self.filter_combo.count()):
                    if self.filter_combo.itemData(i) == "common":
                        self.filter_combo.setCurrentIndex(i)
                        return
        
        # 应用过滤器
        for key, port_data in self.ports_data.items():
            ip = port_data.get("ip", "")
            port = port_data.get("port", 0)
            
            # 根据过滤器类型决定是否包含此端口
            include = False
            
            if filter_type == "all":
                include = True
            elif filter_type in self.filter_ports:
                # 检查端口是否在过滤器定义的列表中
                try:
                    port_num = int(port)
                    include = port_num in self.filter_ports[filter_type]
                except (ValueError, TypeError):
                    pass
            
            if include:
                filtered_ports[key] = port_data
        
        # 检查节点数量限制
        if len(filtered_ports) > self.MAX_NODES:
            # 对端口按重要性排序并取前N个
            sorted_ports = sorted(
                filtered_ports.items(), 
                key=lambda x: self._get_port_importance(x[1]),
                reverse=True
            )
            
            # 只保留最重要的MAX_NODES个端口
            filtered_ports = {k: v for k, v in sorted_ports[:self.MAX_NODES]}
            
            # 显示警告信息
            self.status_label.setText(
                f"警告: 显示了 {len(filtered_ports)}/{len(self.ports_data)} 个重要端口 (已达到节点数量限制)"
            )
            self.status_label.setStyleSheet("color: red;")
        else:
            self.status_label.setStyleSheet("")
        
        # 添加过滤后的端口
        for port_data in filtered_ports.values():
            ip = port_data.get("ip", "")
            port = port_data.get("port", "")
            service = port_data.get("service", "")
            
            # 添加到图
            self.canvas.add_port(ip, port, service)
        
        # 更新图显示
        self.canvas.draw_network(self.layout_combo.currentData())
        
        # 更新状态标签
        nodes_count = self.canvas.graph.number_of_nodes()
        self.status_label.setText(f"当前显示: {nodes_count} 个节点 (总计: {len(self.ports_data)} 个端口)")
    
    def _get_port_importance(self, port_data):
        """计算端口的重要性分数，用于排序"""
        # 根据端口号和服务类型计算重要性分数
        try:
            port = int(port_data.get("port", 0))
            service = port_data.get("service", "").lower()
            
            # 重要端口列表
            important_ports = {
                80: 100,    # HTTP
                443: 100,   # HTTPS
                22: 90,     # SSH
                21: 85,     # FTP
                3389: 85,   # RDP
                3306: 80,   # MySQL
                1433: 80,   # MSSQL
                8080: 75,   # HTTP代理
                445: 70,    # SMB
                25: 65,     # SMTP
                # 其他端口默认为50
            }
            
            # 重要服务关键词
            important_services = {
                "http": 30,
                "https": 30,
                "ssh": 25,
                "ftp": 20,
                "rdp": 20,
                "sql": 20,
                "mysql": 20,
                "smb": 15,
                "smtp": 15,
                "pop3": 15,
                "imap": 15
            }
            
            # 基础分数为端口号的分数
            score = important_ports.get(port, 50)
            
            # 加上服务相关分数
            for keyword, value in important_services.items():
                if keyword in service:
                    score += value
                    break
            
            return score
        except:
            return 0
    
    def on_port_clicked(self, ip, port):
        """处理端口点击事件"""
        # 构建端口数据键
        port_key = f"{ip}:{port}"
        
        if port_key not in self.ports_data:
            return
            
        # 获取端口数据
        port_data = self.ports_data[port_key]
        
        # 构建信息文本
        ip = port_data.get('ip', '')
        port = port_data.get('port', '')
        service = port_data.get('service', '')
        protocol = port_data.get('protocol', 'tcp').upper()
        
        # 主要信息
        info_text = f"IP: {ip}  端口: {port}/{protocol}"
        
        if service:
            info_text += f"  服务: {service}"
            
        # 添加状态信息
        status = port_data.get('status', '')
        if status:
            info_text += f"  状态: {status}"
            
        # 添加版本信息
        version = port_data.get('version', '')
        if version:
            info_text += f"\n版本: {version}"
            
        # 更新信息面板
        self.info_title.setText(f"端口: {ip}:{port}")
        self.info_content.setText(info_text)
        
        # 发射端口选择信号
        self.port_selected.emit(ip, port)
    
    def add_port(self, port_data):
        """添加端口到拓扑图
        
        Args:
            port_data: 包含端口信息的字典，至少包含ip和port
        """
        ip = port_data.get("ip", "")
        port = port_data.get("port", "")
        if not ip or not port:
            return
            
        # 创建端口数据键
        port_key = f"{ip}:{port}"
        
        # 保存端口数据
        self.ports_data[port_key] = port_data
        
        # 检查是否需要应用过滤器
        # 如果已存在过多节点，不立即添加到图中，而是在apply_filter中处理
        if self.current_filter == "all" and len(self.ports_data) > self.MAX_NODES:
            # 切换到更严格的过滤器
            for i in range(self.filter_combo.count()):
                if self.filter_combo.itemData(i) == "common":
                    self.filter_combo.setCurrentIndex(i)
                    return
        
        # 检查是否符合当前过滤条件
        should_add = True
        if self.current_filter != "all":
            try:
                port_num = int(port)
                should_add = port_num in self.filter_ports.get(self.current_filter, [])
            except (ValueError, TypeError):
                should_add = False
        
        # 如果符合过滤条件且没有超过节点限制，则添加到图中
        if should_add and self.canvas.graph.number_of_nodes() < self.MAX_NODES * 2:  # 一些缓冲空间
            # 提取服务信息
            service = port_data.get("service", "")
            
            # 添加到图
            self.canvas.add_port(ip, port, service)
            
            # 更新图形显示
            self.update_display()
    
    def clear(self):
        """清除拓扑图和数据"""
        self.ports_data.clear()
        self.canvas.clear_graph()
        self.info_content.setText("点击端口查看详情")
        self.info_title.setText("端口详情")
        self.status_label.setText("当前显示: 0 个节点")
        self.status_label.setStyleSheet("")

# 测试代码
if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    window = PortTopologyNetworkX()
    
    # 添加一些测试数据
    for i in range(1, 3):
        ip = f"192.168.1.{i}"
        
        # 为每个IP添加几个常见端口
        ports = [80, 443, 22, 3389] if i == 1 else [21, 25, 3306, 1433]
        services = ["HTTP", "HTTPS", "SSH", "RDP"] if i == 1 else ["FTP", "SMTP", "MySQL", "MSSQL"]
        
        for j, port in enumerate(ports):
            port_data = {
                "ip": ip,
                "port": port,
                "protocol": "tcp",
                "status": "open",
                "service": services[j] if j < len(services) else "",
                "version": f"版本 {random.randint(1, 10)}.{random.randint(0, 9)}"
            }
            window.add_port(port_data)
    
    window.show()
    sys.exit(app.exec_()) 