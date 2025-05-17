#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetworkX到PyQt5的转换器工具
用于将NetworkX图形转换为可在PyQt5中显示的交互式图形
"""

import sys
import os
import math
import random
import networkx as nx
from PyQt5.QtWidgets import (QApplication, QGraphicsScene, QGraphicsView, 
                            QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
                            QMainWindow, QWidget, QVBoxLayout)
from PyQt5.QtCore import Qt, QRectF, QPointF, QLineF, pyqtSignal, QObject
from PyQt5.QtGui import QPen, QBrush, QColor, QFont, QPainter

class DraggableNode(QGraphicsEllipseItem):
    """可拖拽的节点类"""
    
    def __init__(self, x, y, radius, node_id, parent=None):
        super().__init__(-radius, -radius, radius*2, radius*2, parent)
        self.node_id = node_id
        self.setPos(x, y)
        self.setFlag(QGraphicsEllipseItem.ItemIsMovable, True)
        self.setFlag(QGraphicsEllipseItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsEllipseItem.ItemSendsGeometryChanges, True)
        
        # 节点的辅助信息
        self.edges = []  # 连接到此节点的边列表
        self.label = None  # 节点标签
        
    def add_edge(self, edge):
        """添加连接到此节点的边"""
        self.edges.append(edge)
    
    def set_label(self, label):
        """设置节点标签"""
        self.label = label
    
    def itemChange(self, change, value):
        """处理项目改变事件，用于在节点移动时更新边"""
        if change == QGraphicsEllipseItem.ItemPositionChange and self.scene():
            # 更新连接到此节点的所有边
            for edge in self.edges:
                edge.update_position()
            
            # 如果有标签，更新标签位置
            if self.label:
                self.update_label_position()
        
        return super().itemChange(change, value)
    
    def update_label_position(self):
        """更新标签位置"""
        if self.label:
            # 标签放在节点下方
            label_width = self.label.boundingRect().width()
            self.label.setPos(self.pos().x() - label_width/2, 
                             self.pos().y() + self.rect().height()/2 + 5)
    
    def mouseDoubleClickEvent(self, event):
        """处理鼠标双击事件"""
        # 发送节点被选中的信号
        # 在实际应用中，这可以通过图形场景的信号系统来实现
        scene = self.scene()
        if hasattr(scene, 'node_selected') and callable(scene.node_selected):
            scene.node_selected(self.node_id)
        
        super().mouseDoubleClickEvent(event)

class NetworkEdge(QGraphicsLineItem):
    """网络边类"""
    
    def __init__(self, source_node, target_node, weight=1.0, parent=None):
        super().__init__(parent)
        self.source_node = source_node
        self.target_node = target_node
        self.weight = weight
        
        # 设置边线的属性
        self.set_appearance()
        
        # 连接到源节点和目标节点
        source_node.add_edge(self)
        target_node.add_edge(self)
        
        # 初始化边的位置
        self.update_position()
        
        # 边的标签
        self.label = None
    
    def set_appearance(self):
        """设置边的外观"""
        # 根据权重设置线的粗细，权重越大线越粗
        pen_width = 1 + self.weight * 3
        pen = QPen(QColor(100, 100, 100))
        pen.setWidth(pen_width)
        self.setPen(pen)
    
    def update_position(self):
        """更新边的位置以跟随节点移动"""
        # 获取源节点和目标节点的中心点
        source_pos = self.source_node.pos()
        target_pos = self.target_node.pos()
        
        # 设置线的新位置
        self.setLine(QLineF(source_pos, target_pos))
        
        # 更新标签位置（如果有）
        self.update_label_position()
    
    def set_label(self, label):
        """设置边标签"""
        self.label = label
        self.update_label_position()
    
    def update_label_position(self):
        """更新标签位置"""
        if self.label:
            # 计算边的中点
            center_x = (self.line().x1() + self.line().x2()) / 2
            center_y = (self.line().y1() + self.line().y2()) / 2
            
            # 将标签放在边的中点，稍微偏移以避免与边重叠
            label_width = self.label.boundingRect().width()
            label_height = self.label.boundingRect().height()
            self.label.setPos(center_x - label_width/2, center_y - label_height/2)

class NetworkXConverter:
    """NetworkX到PyQt5的转换器类"""
    
    def __init__(self, scene=None):
        """初始化转换器
        
        Args:
            scene: QGraphicsScene对象，如果为None则创建新场景
        """
        self.scene = scene if scene else QGraphicsScene()
        self.nodes = {}  # 节点字典 {node_id: DraggableNode}
        self.edges = {}  # 边字典 {(source_id, target_id): NetworkEdge}
        
        # 注册节点选择回调
        self.scene.node_selected = self._on_node_selected
        
        # 设置场景
        self.scene.setBackgroundBrush(QBrush(QColor(240, 240, 250)))
    
    def convert_graph(self, graph, show_labels=True, show_weights=False, node_color_attr=None, edge_width_attr=None):
        """将NetworkX图转换为PyQt图形元素
        
        Args:
            graph: NetworkX图对象
            show_labels: 是否显示节点和边标签
            show_weights: 是否在边标签上显示权重
            node_color_attr: 用于确定节点颜色的节点属性
            edge_width_attr: 用于确定边宽度的边属性
            
        Returns:
            场景对象(QGraphicsScene)
        """
        # 清除旧的图形
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        
        # 计算节点位置
        # 这里使用spring_layout，也可以根据需要使用其他布局算法
        pos = nx.spring_layout(graph, seed=42)
        
        # 缩放因子，使节点适合场景
        scale = 200  # 可根据需要调整
        
        # 添加节点
        for node in graph.nodes():
            # 从NetworkX布局中获取位置
            if node in pos:
                x, y = pos[node]
                # 将位置缩放到场景坐标
                x *= scale
                y *= scale
            else:
                # 如果没有位置信息，随机放置节点
                x = random.uniform(-100, 100)
                y = random.uniform(-100, 100)
            
            # 确定节点大小（可以根据度或其他属性调整）
            node_size = 20
            if hasattr(graph, 'nodes') and node in graph.nodes and 'size' in graph.nodes[node]:
                node_size = graph.nodes[node]['size']
            
            # 创建节点
            node_item = DraggableNode(x, y, node_size, node)
            
            # 设置节点颜色
            node_color = QColor('dodgerblue')
            if node_color_attr and hasattr(graph, 'nodes') and node in graph.nodes and node_color_attr in graph.nodes[node]:
                color_value = graph.nodes[node][node_color_attr]
                # 根据属性值选择颜色（这里简单地根据字符串解析）
                if isinstance(color_value, str):
                    node_color = QColor(color_value)
                elif isinstance(color_value, (int, float)):
                    # 根据数值生成颜色（例如，热力图）
                    intensity = max(0, min(255, int(color_value * 255)))
                    node_color = QColor(intensity, 50, 255 - intensity)
            
            node_item.setBrush(QBrush(node_color))
            node_item.setPen(QPen(node_color.darker()))
            
            # 添加到场景
            self.scene.addItem(node_item)
            self.nodes[node] = node_item
            
            # 添加标签
            if show_labels:
                label_text = str(node)
                label = QGraphicsTextItem(label_text)
                label.setFont(QFont("Arial", 8))
                self.scene.addItem(label)
                node_item.set_label(label)
                node_item.update_label_position()
        
        # 添加边
        for u, v, data in graph.edges(data=True):
            if u in self.nodes and v in self.nodes:
                # 确定边的宽度/权重
                weight = 1.0
                if edge_width_attr and edge_width_attr in data:
                    weight = data[edge_width_attr]
                elif 'weight' in data:
                    weight = data['weight']
                
                # 创建边
                edge = NetworkEdge(self.nodes[u], self.nodes[v], weight)
                self.scene.addItem(edge)
                self.edges[(u, v)] = edge
                
                # 添加边标签
                if show_labels and show_weights:
                    label_text = str(round(weight, 2))
                    label = QGraphicsTextItem(label_text)
                    label.setFont(QFont("Arial", 7))
                    self.scene.addItem(label)
                    edge.set_label(label)
        
        # 调整场景区域
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))
        
        return self.scene
    
    def _on_node_selected(self, node_id):
        """处理节点选择事件"""
        # 这个方法可以被子类覆盖以实现自定义的节点选择处理
        print(f"节点 {node_id} 被选择")
    
    def highlight_node(self, node_id, color=QColor('yellow'), border_color=QColor('red')):
        """高亮显示节点
        
        Args:
            node_id: 要高亮的节点ID
            color: 高亮颜色
            border_color: 边框颜色
        """
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.setBrush(QBrush(color))
            node.setPen(QPen(border_color, 2))
    
    def highlight_path(self, path, line_color=QColor('red'), line_width=3):
        """高亮显示路径（节点序列）
        
        Args:
            path: 节点ID列表，表示路径
            line_color: 路径边的颜色
            line_width: 路径边的宽度
        """
        if not path or len(path) < 2:
            return
        
        # 遍历路径中的每一对相邻节点
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            # 检查是否存在从u到v的边
            if (u, v) in self.edges:
                edge = self.edges[(u, v)]
            elif (v, u) in self.edges:  # 如果是无向图
                edge = self.edges[(v, u)]
            else:
                continue
            
            # 高亮边
            pen = QPen(line_color)
            pen.setWidth(line_width)
            edge.setPen(pen)

class NetworkViewWidget(QWidget):
    """包含网络视图的小部件"""
    
    node_selected = pyqtSignal(str)  # 节点被选择的信号
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # 创建布局
        layout = QVBoxLayout(self)
        
        # 创建场景
        self.scene = QGraphicsScene()
        self.scene.node_selected = self._on_node_selected
        
        # 创建视图
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.view.setDragMode(QGraphicsView.ScrollHandDrag)  # 允许通过拖拽滚动视图
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        
        # 添加视图到布局
        layout.addWidget(self.view)
        
        # 创建转换器
        self.converter = NetworkXConverter(self.scene)
    
    def set_graph(self, graph, show_labels=True, show_weights=False, node_color_attr=None, edge_width_attr=None):
        """设置并显示图形
        
        Args:
            graph: NetworkX图对象
            show_labels: 是否显示标签
            show_weights: 是否显示权重
            node_color_attr: 用于节点颜色的属性名
            edge_width_attr: 用于边宽度的属性名
        """
        self.converter.convert_graph(graph, show_labels, show_weights, node_color_attr, edge_width_attr)
        
        # 适应视图内容
        self.view.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio)
    
    def highlight_node(self, node_id, color=QColor('yellow'), border_color=QColor('red')):
        """高亮节点"""
        self.converter.highlight_node(node_id, color, border_color)
    
    def highlight_path(self, path, line_color=QColor('red'), line_width=3):
        """高亮路径"""
        self.converter.highlight_path(path, line_color, line_width)
    
    def _on_node_selected(self, node_id):
        """处理节点选择，发射信号"""
        self.node_selected.emit(node_id)
    
    def wheelEvent(self, event):
        """处理鼠标滚轮事件 - 用于缩放"""
        # 根据滚轮方向缩放视图
        factor = 1.2
        if event.angleDelta().y() < 0:
            factor = 1.0 / factor
        
        self.view.scale(factor, factor)

# 简单的测试代码
if __name__ == "__main__":
    # 创建测试图
    G = nx.Graph()
    
    # 添加节点
    for i in range(10):
        G.add_node(i, color='skyblue', size=20)
    
    # 添加边
    for i in range(9):
        G.add_edge(i, i+1, weight=random.random())
    
    # 添加一些额外的边
    G.add_edge(0, 5, weight=0.8)
    G.add_edge(2, 7, weight=0.5)
    G.add_edge(3, 8, weight=0.7)
    
    # 创建应用
    app = QApplication(sys.argv)
    
    # 创建主窗口
    window = QMainWindow()
    window.setWindowTitle("NetworkX to PyQt5 转换器示例")
    window.setGeometry(100, 100, 800, 600)
    
    # 创建网络视图小部件
    network_widget = NetworkViewWidget()
    network_widget.node_selected.connect(lambda node_id: print(f"节点 {node_id} 被选择"))
    
    # 设置图形
    network_widget.set_graph(G, show_labels=True, show_weights=True)
    
    # 高亮示例
    network_widget.highlight_node(3)
    network_widget.highlight_path([0, 1, 2, 3])
    
    # 设置中央小部件
    window.setCentralWidget(network_widget)
    
    # 显示窗口
    window.show()
    
    # 运行应用
    sys.exit(app.exec_()) 