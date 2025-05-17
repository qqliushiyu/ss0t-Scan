#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
主机扫描网络拓扑图实现
使用NetworkX库生成网络拓扑图，并集成到PyQt5界面中
"""

import math
import networkx as nx
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import random
import ipaddress

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QLabel, 
    QPushButton, QCheckBox, QFrame, QGraphicsView, QGraphicsScene,
    QMenu, QAction, QSplitter, QSizePolicy
)
from PyQt5.QtCore import Qt, pyqtSignal, QPointF, QRectF
from PyQt5.QtGui import QColor, QPen, QBrush, QPainter

class NetworkCanvas(FigureCanvas):
    """集成NetworkX和Matplotlib的画布类"""
    
    node_clicked = pyqtSignal(str)  # 节点点击信号
    
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
        self.graph = nx.Graph()
        self.pos = None
        self.picked_node = None
        
        # 添加网关节点
        self.graph.add_node("gateway", type="gateway", status="up", name="网关", 
                          ip="", hostname="")
        
        # 连接鼠标点击事件
        self.fig.canvas.mpl_connect('button_press_event', self.on_click_event)
        
        # 颜色映射，用于按端口类型标记节点
        self.port_color_map = {
            'web': '#1E88E5',       # 蓝色 - Web服务 (80,443,8080,8443)
            'file': '#43A047',      # 绿色 - 文件共享 (21,22,445,139)
            'database': '#FBC02D',  # 黄色 - 数据库 (1433,3306,5432,6379)
            'remote': '#E53935',    # 红色 - 远程访问 (3389,5900,22)
            'mail': '#8E24AA',      # 紫色 - 邮件服务 (25,110,143,993)
            'mixed': '#FF9800',     # 橙色 - 混合服务
            'other': '#757575'      # 灰色 - 其他服务
        }
    
    def highlight_node_with_connections(self, node_id):
        """高亮显示选中的节点及其连接"""
        if node_id not in self.graph:
            return
        
        # 保存选中的节点ID
        self.picked_node = node_id
        
        # 重新绘制网络
        self.draw_network()
        
        # 获取节点的邻居
        neighbors = list(self.graph.neighbors(node_id))
        
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
        if neighbors:
            # 高亮相连的边
            edge_list = [(node_id, n) for n in neighbors]
            edge_colors = []
            edge_widths = []
            
            for u, v in edge_list:
                edge_data = self.graph.get_edge_data(u, v)
                latency = edge_data.get('latency', 50)
                
                # 根据延迟设定边的颜色
                if latency < 30:
                    edge_colors.append('green')
                elif latency < 100:
                    edge_colors.append('yellow')
                elif latency < 300:
                    edge_colors.append('orange')
                else:
                    edge_colors.append('red')
                
                # 计算边的宽度
                width = 6 * (1 - latency/1000)
                edge_widths.append(max(2.0, width))
            
            # 绘制高亮边
            nx.draw_networkx_edges(self.graph, self.pos,
                                  edgelist=edge_list,
                                  width=edge_widths,
                                  edge_color=edge_colors,
                                  ax=self.axes)
            
            # 高亮邻居节点
            neighbor_pos = {n: self.pos[n] for n in neighbors}
            neighbor_colors = []
            for n in neighbors:
                if n == "gateway":
                    neighbor_colors.append('orange')
                else:
                    neighbor_colors.append('cyan')
            
            nx.draw_networkx_nodes(self.graph, neighbor_pos,
                                  nodelist=neighbors,
                                  node_color=neighbor_colors,
                                  node_size=500,
                                  edgecolors='darkblue',
                                  linewidths=2,
                                  ax=self.axes)
            
            # 高亮标签
            all_highlighted = [node_id] + neighbors
            highlight_labels = {n: self.graph.nodes[n].get('name', n) 
                              for n in all_highlighted}
            
            nx.draw_networkx_labels(self.graph, self.pos,
                                   labels=highlight_labels,
                                   font_weight='bold',
                                   ax=self.axes)
            
            # 高亮边标签
            edge_labels = {}
            for u, v in edge_list:
                edge_data = self.graph.get_edge_data(u, v)
                label = ""
                
                # 添加端口信息
                if 'ports' in edge_data and edge_data['ports']:
                    ports = edge_data['ports']
                    if len(ports) > 3:
                        port_str = ",".join(str(p) for p in ports[:3]) + "..."
                    else:
                        port_str = ",".join(str(p) for p in ports)
                    label += f"{port_str} "
                
                # 添加延迟信息
                if 'latency' in edge_data:
                    label += f"{edge_data['latency']}ms"
                    
                if label:
                    edge_labels[(u, v)] = label
            
            if edge_labels:
                nx.draw_networkx_edge_labels(self.graph, self.pos,
                                            edge_labels=edge_labels,
                                            font_size=9,
                                            font_weight='bold',
                                            ax=self.axes)
        
        self.draw()
    
    def highlight_node(self, node_id):
        """
        基础节点高亮，使用更先进的highlight_node_with_connections方法代替
        保留此方法是为了兼容性
        """
        self.highlight_node_with_connections(node_id)
    
    def get_port_category(self, ports):
        """根据开放端口获取主机的服务类别"""
        if not ports:
            return 'other'
            
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        file_ports = [21, 22, 445, 139, 2049, 20]
        remote_ports = [3389, 5900, 22, 23]
        database_ports = [1433, 3306, 5432, 6379, 27017, 1521]
        mail_ports = [25, 110, 143, 993, 995, 587]
        
        categories = {
            'web': 0,
            'file': 0,
            'remote': 0,
            'database': 0,
            'mail': 0,
            'other': 0
        }
        
        for port in ports:
            if port in web_ports:
                categories['web'] += 1
            elif port in file_ports:
                categories['file'] += 1
            elif port in remote_ports:
                categories['remote'] += 1
            elif port in database_ports:
                categories['database'] += 1
            elif port in mail_ports:
                categories['mail'] += 1
            else:
                categories['other'] += 1
        
        # 如果多个类别都有端口，则返回"混合"
        active_categories = [c for c, count in categories.items() if count > 0 and c != 'other']
        
        if len(active_categories) > 1:
            return 'mixed'
        elif len(active_categories) == 1:
            return active_categories[0]
        else:
            return 'other'
    
    def draw_network(self, layout_type='spring'):
        """绘制网络拓扑图"""
        self.axes.clear()
        
        # 如果图为空只有网关节点，添加一个临时节点以避免布局错误
        if self.graph.number_of_nodes() == 1:
            self.graph.add_node("temp", type="host", status="down", 
                               ip="", hostname="")
            
        # 根据选择的布局算法计算节点位置
        if layout_type == 'spring':
            # 增加k值(弹簧系数)以增大节点间距离，防止重叠
            self.pos = nx.spring_layout(self.graph, k=1.5/math.sqrt(self.graph.number_of_nodes()), 
                                      iterations=50, seed=42)
        elif layout_type == 'circular':
            self.pos = nx.circular_layout(self.graph, scale=2.0)
        elif layout_type == 'shell':
            # 按子网分组进行布局
            try:
                # 按子网收集节点
                subnets = {}
                for node in self.graph.nodes():
                    if node == "temp":
                        continue
                        
                    if node == "gateway":
                        # 网关节点放在中心
                        if "center" not in subnets:
                            subnets["center"] = []
                        subnets["center"].append(node)
                    else:
                        ip = self.graph.nodes[node].get('ip', '')
                        if not ip:
                            continue
                            
                        subnet = self.get_ip_subnet(ip)
                        if subnet not in subnets:
                            subnets[subnet] = []
                        subnets[subnet].append(node)
                
                # 确保中心组存在且网关在最内层
                if "center" not in subnets:
                    subnets["center"] = []
                    if "gateway" in self.graph.nodes():
                        subnets["center"].append("gateway")
                
                # 构建shell序列
                shells = [subnets["center"]]
                for subnet, nodes in subnets.items():
                    if subnet != "center" and nodes:
                        shells.append(nodes)
                
                # 如果只有一个shell，添加一个虚拟shell防止错误
                if len(shells) == 1:
                    if "temp" not in self.graph.nodes():
                        self.graph.add_node("temp", type="host", status="down", 
                                           ip="", hostname="")
                    shells.append(["temp"])
                
                # 使用shell布局
                self.pos = nx.shell_layout(self.graph, shells)
            except Exception as e:
                # 失败时回退到圆形布局
                self.pos = nx.circular_layout(self.graph, scale=2.0)
        elif layout_type == 'kamada_kawai':
            try:
                self.pos = nx.kamada_kawai_layout(self.graph)
            except:
                # 有时Kamada-Kawai会失败，回退到弹簧布局
                self.pos = nx.spring_layout(self.graph, k=1.5/math.sqrt(self.graph.number_of_nodes()), 
                                      iterations=50, seed=42)
        elif layout_type == 'spectral':
            try:
                self.pos = nx.spectral_layout(self.graph)
            except:
                # 有时谱布局会失败，回退到弹簧布局
                self.pos = nx.spring_layout(self.graph, k=1.5/math.sqrt(self.graph.number_of_nodes()), 
                                      iterations=50, seed=42)
        else:
            # 默认使用弹簧布局
            self.pos = nx.spring_layout(self.graph, k=1.0/math.sqrt(self.graph.number_of_nodes()), 
                                      iterations=50, seed=42)
        
        # 优化节点位置，防止重叠
        self.optimize_node_positions()
        
        # 如果有临时节点，移除它
        if "temp" in self.graph.nodes():
            self.graph.remove_node("temp")
        
        # 准备节点颜色和大小
        node_colors = []
        node_sizes = []
        node_borders = []
        node_border_widths = []
        
        for node in self.graph.nodes():
            if node == "gateway":
                # 网关节点使用橙色，大尺寸
                node_colors.append('#FF9800')  # 橙色
                node_sizes.append(700)  # 更大的节点
                node_borders.append('black')
                node_border_widths.append(2.0)
            else:
                # 其他主机节点
                node_type = self.graph.nodes[node].get('type', 'host')
                
                if node_type == 'host':
                    # 根据端口分类设置颜色
                    ports = self.graph.nodes[node].get('open_ports', [])
                    category = self.get_port_category(ports)
                    node_colors.append(self.port_color_map.get(category, self.port_color_map['other']))
                    
                    # 设置大小
                    response_time = self.graph.nodes[node].get('response_time', 0)
                    size = 500
                    if response_time > 0:
                        # 响应时间越快，节点越大 (0-100ms:500-300, >100ms:300)
                        size = max(300, 500 - response_time * 2)
                    node_sizes.append(size)
                    
                    # 边框
                    node_borders.append('black')
                    node_border_widths.append(1.0)
                else:
                    # 其他类型节点使用默认样式
                    node_colors.append('#757575')  # 灰色
                    node_sizes.append(300)
                    node_borders.append('black')
                    node_border_widths.append(1.0)
        
        # 绘制边
        edge_colors = []
        edge_widths = []
        
        for u, v in self.graph.edges():
            # 获取边属性
            edge_data = self.graph.get_edge_data(u, v)
            latency = edge_data.get('latency', 50) if edge_data else 50
            
            # 根据延迟设定边的颜色
            if latency < 30:
                edge_colors.append('green')
            elif latency < 100:
                edge_colors.append('yellow')
            elif latency < 300:
                edge_colors.append('orange')
            else:
                edge_colors.append('red')
            
            # 计算边的宽度
            width = 3 * (1 - latency/1000)
            edge_widths.append(max(1.0, width))
        
        # 绘制节点
        nx.draw_networkx_nodes(self.graph, self.pos,
                              node_color=node_colors,
                              node_size=node_sizes,
                              edgecolors=node_borders,
                              linewidths=node_border_widths,
                              alpha=0.9,
                              ax=self.axes)
        
        # 绘制边
        nx.draw_networkx_edges(self.graph, self.pos,
                              edge_color=edge_colors,
                              width=edge_widths,
                              alpha=0.7,
                              ax=self.axes)
        
        # 准备节点标签
        labels = {}
        for node in self.graph.nodes():
            # 获取节点的名称属性
            name = self.graph.nodes[node].get('name', node)
            labels[node] = name
        
        # 绘制节点标签
        nx.draw_networkx_labels(self.graph, self.pos,
                               labels=labels,
                               font_size=9,
                               font_weight='bold',
                               ax=self.axes)
        
        # 禁用坐标轴
        self.axes.set_axis_off()
        
        # 添加节点点击事件处理
        self.fig.canvas.mpl_connect('button_press_event', self.on_click_event)
        
        # 调整图像边界
        self.fig.tight_layout()
        
        # 更新画布
        self.draw()
    
    def optimize_node_positions(self):
        """优化节点位置，避免节点重叠"""
        if not self.pos or len(self.pos) <= 1:
            return
            
        # 最小节点间距
        min_distance = 0.15
        
        # 最大迭代次数
        max_iterations = 50
        
        # 迭代优化
        for _ in range(max_iterations):
            # 计算是否需要继续优化
            need_more_iterations = False
            
            # 遍历所有节点对
            nodes = list(self.pos.keys())
            for i in range(len(nodes)):
                for j in range(i+1, len(nodes)):
                    node1, node2 = nodes[i], nodes[j]
                    
                    # 计算节点间距离
                    pos1, pos2 = self.pos[node1], self.pos[node2]
                    dx = pos2[0] - pos1[0]
                    dy = pos2[1] - pos1[1]
                    distance = math.sqrt(dx*dx + dy*dy)
                    
                    # 如果距离小于最小间距
                    if distance < min_distance:
                        # 计算调整量
                        if distance > 0:
                            # 按比例调整
                            factor = 0.1 * (min_distance - distance) / distance
                            adjust_x = dx * factor
                            adjust_y = dy * factor
                        else:
                            # 随机调整防止重合
                            angle = random.uniform(0, 2 * math.pi)
                            adjust_x = min_distance * 0.5 * math.cos(angle)
                            adjust_y = min_distance * 0.5 * math.sin(angle)
                        
                        # 应用调整
                        self.pos[node1] = (pos1[0] - adjust_x, pos1[1] - adjust_y)
                        self.pos[node2] = (pos2[0] + adjust_x, pos2[1] + adjust_y)
                        need_more_iterations = True
            
            # 如果没有重叠，结束优化
            if not need_more_iterations:
                break
    
    def on_click_event(self, event):
        """处理图表点击事件"""
        if event.inaxes != self.axes or self.pos is None:
            return
            
        # 获取点击位置
        click_x, click_y = event.xdata, event.ydata
        
        # 查找最近的节点
        min_dist = float('inf')
        closest_node = None
        
        for node, (x, y) in self.pos.items():
            # 计算点击位置与节点位置的距离
            dist = ((x - click_x) ** 2 + (y - click_y) ** 2) ** 0.5
            
            # 根据节点大小调整选中半径
            node_size = 0.15  # 增大默认选中半径
            if node in self.graph.nodes and 'type' in self.graph.nodes[node]:
                if self.graph.nodes[node]['type'] == 'gateway':
                    node_size = 0.2  # 网关节点选中半径更大
            
            # 如果点击位置在节点选中半径内，且是最近的节点
            if dist < node_size and dist < min_dist:
                min_dist = dist
                closest_node = node
        
        # 如果找到了节点，发送信号并高亮显示
        if closest_node is not None:
            self.picked_node = closest_node
            self.node_clicked.emit(closest_node)
            self.highlight_node(closest_node)
    
    def get_ip_subnet(self, ip):
        """提取IP地址的子网前缀"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                # 对于IPv4，提取C类子网（前24位）
                parts = ip.split('.')
                if len(parts) == 4:
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            pass
        return "未知子网"

    def clear_graph(self):
        """清除图形，但保留网关节点"""
        # 创建一个新图，仅包含网关节点
        new_graph = nx.Graph()
        
        # 如果有网关节点，保留它
        if "gateway" in self.graph.nodes():
            attrs = self.graph.nodes["gateway"]
            new_graph.add_node("gateway", **attrs)
        
        self.graph = new_graph
        self.draw_network()

    def add_host(self, host_data):
        """向图中添加主机节点
        
        Args:
            host_data: 包含主机信息的字典，至少包含ip和status
        """
        ip = host_data.get("ip", "")
        if not ip or host_data.get("status") != "up":
            return
            
        # 创建节点ID
        node_id = ip
        
        # 创建显示名称
        hostname = host_data.get("hostname", "")
        if hostname and hostname != ip:
            display_name = f"{ip}\n({hostname})"
        else:
            display_name = ip
        
        # 获取主机信息
        response_time = host_data.get("response_time", 0)
        
        # 提取服务和开放端口信息
        open_ports = []
        if "services" in host_data:
            # 如果有服务信息数据
            services = host_data.get("services", [])
            if isinstance(services, list):
                for service in services:
                    if "port" in service:
                        open_ports.append(service["port"])
            elif isinstance(services, dict):
                for port, info in services.items():
                    open_ports.append(int(port))
        
        # 从TCP端口扫描结果提取端口信息
        if "tcp_ports" in host_data:
            tcp_ports = host_data.get("tcp_ports", {})
            if isinstance(tcp_ports, dict):
                for port, state in tcp_ports.items():
                    if state == "open":
                        try:
                            open_ports.append(int(port))
                        except ValueError:
                            pass
            elif isinstance(tcp_ports, list):
                open_ports.extend(tcp_ports)
        
        # 如果是字符串形式的端口列表，进行解析
        if "open_ports" in host_data:
            port_data = host_data.get("open_ports", "")
            if isinstance(port_data, str):
                try:
                    # 尝试解析如 "80,443,22" 这样的格式
                    for p in port_data.split(","):
                        if p.strip():
                            open_ports.append(int(p.strip()))
                except ValueError:
                    pass
            elif isinstance(port_data, list):
                open_ports.extend(port_data)
        
        # 去重
        open_ports = list(set(open_ports))
        
        # 如果节点已存在，更新属性
        if node_id in self.graph.nodes():
            self.graph.nodes[node_id].update({
                'type': 'host',
                'status': 'up',
                'name': display_name,
                'ip': ip,
                'hostname': hostname,
                'response_time': response_time,
                'mac_address': host_data.get("mac_address", ""),
                'os': host_data.get("os", ""),
                'open_ports': open_ports
            })
        else:
            # 添加新节点
            self.graph.add_node(
                node_id,
                type='host',
                status='up',
                name=display_name,
                ip=ip,
                hostname=hostname,
                response_time=response_time,
                mac_address=host_data.get("mac_address", ""),
                os=host_data.get("os", ""),
                open_ports=open_ports
            )
            
            # 连接到网关节点（如果存在）
            if "gateway" in self.graph.nodes():
                self.graph.add_edge(
                    "gateway", node_id,
                    latency=response_time,
                    ports=open_ports
                )
            
            # 提取子网信息
            subnet = self.get_ip_subnet(ip)
            
            # 获取同子网的其他主机
            same_subnet_hosts = []
            other_subnet_hosts = []
            
            for other_node in self.graph.nodes():
                if other_node == node_id or other_node == "gateway":
                    continue
                
                other_ip = self.graph.nodes[other_node].get('ip', '')
                if not other_ip:
                    continue
                
                if self.get_ip_subnet(other_ip) == subnet:
                    same_subnet_hosts.append(other_node)
                else:
                    other_subnet_hosts.append(other_node)
            
            # 智能连接到同子网的其他主机
            # 规则：开放相似端口的主机更可能相连
            candidate_connections = []
            
            # 同子网内优先连接开放相似端口的主机
            for other_node in same_subnet_hosts:
                other_ports = self.graph.nodes[other_node].get('open_ports', [])
                
                # 计算端口相似度（共同开放的端口数量）
                common_ports = [p for p in open_ports if p in other_ports]
                similarity = len(common_ports) if common_ports else 0
                
                # 相似性大于0或随机概率
                if similarity > 0 or (len(same_subnet_hosts) < 10 and random.random() < 0.3):
                    # 端口相似度越高，连接机会越大
                    latency = random.randint(5, 30)  # 同子网延迟较低
                    candidate_connections.append((other_node, similarity, latency, common_ports))
            
            # 按相似度排序
            candidate_connections.sort(key=lambda x: x[1], reverse=True)
            
            # 从相似度最高的开始，最多连接3个节点
            max_connections = min(3, len(candidate_connections))
            for i in range(max_connections):
                if i < len(candidate_connections):
                    other_node, similarity, latency, common_ports = candidate_connections[i]
                    
                    # 添加边，包含端口信息
                    self.graph.add_edge(
                        node_id, other_node,
                        latency=latency,
                        ports=common_ports if common_ports else open_ports[:3]  # 限制显示的端口数量
                    )
            
            # 25%的概率连接到其他子网的主机（模拟跨网段通信）
            if other_subnet_hosts and random.random() < 0.25:
                # 随机选择一个其他子网的主机
                other_node = random.choice(other_subnet_hosts)
                other_ports = self.graph.nodes[other_node].get('open_ports', [])
                
                # 计算有用的端口（例如常见服务端口）
                useful_ports = [p for p in open_ports if p in [80, 443, 22, 3389, 445, 139]]
                if not useful_ports and open_ports:
                    useful_ports = [open_ports[0]]  # 至少使用一个端口
                
                # 跨子网延迟较高
                latency = random.randint(50, 200)
                
                self.graph.add_edge(
                    node_id, other_node,
                    latency=latency,
                    ports=useful_ports
                )
                

class HostTopologyNetworkX(QWidget):
    """主机扫描网络拓扑图控件"""
    
    host_selected = pyqtSignal(str)  # 主机选择信号
    
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
        self.layout_combo.addItem("Kamada-Kawai布局", "kamada_kawai")
        self.layout_combo.addItem("谱布局", "spectral")
        self.layout_combo.currentIndexChanged.connect(self.on_layout_changed)
        
        control_layout.addWidget(layout_label)
        control_layout.addWidget(self.layout_combo)
        
        # 显示选项
        self.show_edge_labels = QCheckBox("显示延迟")
        self.show_edge_labels.setChecked(True)
        self.show_edge_labels.stateChanged.connect(self.update_display)
        control_layout.addWidget(self.show_edge_labels)
        
        # 分组选项
        group_label = QLabel("分组方式:")
        self.group_combo = QComboBox()
        self.group_combo.addItem("不分组", "none")
        self.group_combo.addItem("按子网分组", "subnet")
        self.group_combo.addItem("按响应时间分组", "response_time")
        self.group_combo.currentIndexChanged.connect(self.update_display)
        
        control_layout.addWidget(group_label)
        control_layout.addWidget(self.group_combo)
        
        # 刷新按钮
        refresh_btn = QPushButton("刷新拓扑图")
        refresh_btn.clicked.connect(self.refresh_topology)
        control_layout.addWidget(refresh_btn)
        
        # 添加控制区域到主布局
        main_layout.addLayout(control_layout)
        
        # 添加网络拓扑图
        self.canvas = NetworkCanvas(self)
        self.canvas.node_clicked.connect(self.on_node_clicked)
        main_layout.addWidget(self.canvas)
        
        # 添加底部信息区域
        self.info_frame = QFrame()
        self.info_frame.setFrameShape(QFrame.StyledPanel)
        self.info_frame.setMaximumHeight(100)
        
        info_layout = QVBoxLayout(self.info_frame)
        self.info_title = QLabel("节点详情")
        self.info_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        
        self.info_content = QLabel("点击节点查看详情")
        
        info_layout.addWidget(self.info_title)
        info_layout.addWidget(self.info_content)
        
        main_layout.addWidget(self.info_frame)
        
        # 初始化拓扑图
        self.canvas.draw_network()
        
        # 存储主机数据
        self.hosts_data = {}
    
    def on_layout_changed(self, index):
        """处理布局类型变更"""
        layout_type = self.layout_combo.currentData()
        self.canvas.draw_network(layout_type)
    
    def update_display(self):
        """更新显示选项"""
        self.canvas.draw_network(self.layout_combo.currentData())
        
        # 如果有选中的节点，重新高亮它
        if hasattr(self.canvas, 'picked_node') and self.canvas.picked_node:
            self.canvas.highlight_node(self.canvas.picked_node)
    
    def refresh_topology(self):
        """刷新拓扑图"""
        # 重新创建图
        self.canvas.clear_graph()
        
        # 重新添加所有已知主机
        for ip, host_data in self.hosts_data.items():
            self.add_host(host_data)
        
        # 应用当前布局
        self.canvas.draw_network(self.layout_combo.currentData())
    
    def on_node_clicked(self, node_id):
        """处理节点点击事件"""
        if node_id not in self.canvas.graph.nodes():
            return
            
        # 获取节点属性
        node_attrs = self.canvas.graph.nodes[node_id]
        
        # 构建信息文本
        if node_attrs.get('type') == 'gateway':
            info_text = "网关节点"
            self.info_title.setText("网关节点")
        else:
            ip = node_attrs.get('ip', '')
            hostname = node_attrs.get('hostname', '')
            mac = node_attrs.get('mac_address', '')
            response_time = node_attrs.get('response_time', 0)
            os = node_attrs.get('os', '')
            open_ports = node_attrs.get('open_ports', [])
            
            # 主要信息
            info_text = f"IP: {ip}"
            if hostname and hostname != ip:
                info_text += f"  主机名: {hostname}"
            if mac:
                info_text += f"  MAC: {mac}"
            if response_time > 0:
                info_text += f"  响应时间: {response_time}ms"
            if os:
                info_text += f"  系统: {os}"
            
            # 添加端口信息
            if open_ports:
                # 排序端口列表
                open_ports.sort()
                
                # 将端口分类成已知服务和未知服务
                known_ports = []
                other_ports = []
                
                common_ports = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                    53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3",
                    111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
                    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
                    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
                    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
                    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
                }
                
                for port in open_ports:
                    if port in common_ports:
                        known_ports.append(f"{port}/{common_ports[port]}")
                    else:
                        other_ports.append(str(port))
                
                # 构建端口信息字符串
                port_info = ""
                if known_ports:
                    port_info += "\n已知服务端口: " + ", ".join(known_ports)
                if other_ports:
                    port_info += "\n其他开放端口: " + ", ".join(other_ports)
                
                info_text += port_info
            
            # 获取连接信息
            neighbors = list(self.canvas.graph.neighbors(node_id))
            if neighbors:
                info_text += f"\n连接节点数: {len(neighbors)}  "
                if "gateway" in neighbors:
                    neighbors.remove("gateway")
                    info_text += "连接到网关 "
                
                if neighbors:
                    # 提取连接主机的最常用端口
                    connection_info = []
                    for neighbor in neighbors[:5]:  # 最多显示5个连接
                        edge_data = self.canvas.graph.get_edge_data(node_id, neighbor) or {}
                        ports = edge_data.get('ports', [])
                        
                        if ports:
                            # 格式化端口信息
                            if len(ports) > 2:
                                port_str = f"{ports[0]},{ports[1]}..."
                            else:
                                port_str = ",".join(str(p) for p in ports)
                            connection_info.append(f"{neighbor}({port_str})")
                        else:
                            connection_info.append(neighbor)
                    
                    info_text += "连接主机: " + ", ".join(connection_info)
                    if len(neighbors) > 5:
                        info_text += f" ...(共{len(neighbors)}个)"
            
            self.info_title.setText(f"主机: {ip}")
        
        self.info_content.setText(info_text)
        
        # 高亮显示节点及其连接
        self.canvas.highlight_node_with_connections(node_id)
        
        # 发射主机选择信号
        self.host_selected.emit(node_id)
    
    def add_host(self, host_data):
        """添加主机到拓扑图
        
        Args:
            host_data: 包含主机信息的字典
        """
        ip = host_data.get("ip", "")
        if not ip:
            return
            
        # 保存主机数据
        self.hosts_data[ip] = host_data
        
        # 添加到图
        self.canvas.add_host(host_data)
        
        # 如果图中节点数量变化很多，重新绘制
        node_count = self.canvas.graph.number_of_nodes()
        if node_count <= 5 or node_count % 10 == 0:
            self.canvas.draw_network(self.layout_combo.currentData())
    
    def clear(self):
        """清除拓扑图和数据"""
        self.hosts_data.clear()
        self.canvas.clear_graph()
        self.info_content.setText("点击节点查看详情")
        self.info_title.setText("节点详情")

if __name__ == "__main__":
    # 简单测试代码
    import sys
    from PyQt5.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    window = HostTopologyNetworkX()
    
    # 添加一些测试数据
    for i in range(1, 10):
        host_data = {
            "ip": f"192.168.1.{i}",
            "hostname": f"host-{i}",
            "mac_address": f"00:1A:2B:3C:4D:{i:02x}",
            "status": "up",
            "response_time": random.randint(5, 500),
            "os": random.choice(["Windows", "Linux", "MacOS"])
        }
        window.add_host(host_data)
    
    window.show()
    sys.exit(app.exec_()) 