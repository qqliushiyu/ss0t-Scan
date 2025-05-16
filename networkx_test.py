#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetworkX测试脚本
演示使用NetworkX实现网络拓扑图可视化
"""

import networkx as nx
import matplotlib.pyplot as plt
import random

def create_test_network():
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

def visualize_network(G):
    """使用NetworkX可视化网络拓扑图"""
    plt.figure(figsize=(12, 8))
    
    # 设置节点颜色
    node_colors = []
    for node, attrs in G.nodes(data=True):
        if attrs.get('type') == 'gateway':
            node_colors.append('red')
        elif attrs.get('status') == 'up':
            node_colors.append('green')
        else:
            node_colors.append('gray')
    
    # 设置节点大小
    node_sizes = []
    for node, attrs in G.nodes(data=True):
        if attrs.get('type') == 'gateway':
            node_sizes.append(800)
        else:
            node_sizes.append(400)
    
    # 设置边的宽度和颜色
    edge_widths = []
    edge_colors = []
    for u, v, attrs in G.edges(data=True):
        latency = attrs.get('latency', 50)
        # 延迟越低，线越粗
        width = 5 * (1 - latency/100)
        edge_widths.append(max(0.5, width))
        
        # 延迟越低，颜色越绿；越高，颜色越红
        if latency < 30:
            edge_colors.append('green')
        elif latency < 70:
            edge_colors.append('orange')
        else:
            edge_colors.append('red')
    
    # 使用spring layout算法布局
    pos = nx.spring_layout(G, seed=42)
    
    # 绘制节点
    nx.draw_networkx_nodes(G, pos, 
                          node_color=node_colors, 
                          node_size=node_sizes)
    
    # 绘制边
    nx.draw_networkx_edges(G, pos, 
                          width=edge_widths, 
                          edge_color=edge_colors,
                          alpha=0.7)
    
    # 绘制标签
    nx.draw_networkx_labels(G, pos, font_size=10)
    
    # 绘制边标签（显示延迟）
    edge_labels = {(u, v): f"{attrs['latency']}ms" 
                  for u, v, attrs in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    
    plt.title("网络拓扑图 (NetworkX)")
    plt.axis('off')
    plt.tight_layout()
    plt.savefig("networkx_topology.png", dpi=300)
    plt.show()

if __name__ == "__main__":
    # 创建测试网络
    G = create_test_network()
    
    # 可视化网络
    visualize_network(G)
    
    print("节点数:", G.number_of_nodes())
    print("连接数:", G.number_of_edges()) 