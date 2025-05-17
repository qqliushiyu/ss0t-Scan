#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络扫描工具箱安装脚本
创建必要的目录结构并安装依赖
"""

import os
import sys
import subprocess
import platform
from setuptools import setup, find_packages

# 确保必要的目录结构存在
REQUIRED_DIRS = [
    'logs',
    'results',
    'config',
    'plugins'
]

for directory in REQUIRED_DIRS:
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"创建目录: {directory}")

# 确保配置文件存在
CONFIG_FILE = 'config/settings.ini'
if not os.path.exists(CONFIG_FILE):
    # 自动创建空配置文件
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        f.write("; 网络扫描工具箱配置文件\n")
        f.write("; 此文件由工具自动管理，也可手动编辑\n\n")
    print(f"创建配置文件: {CONFIG_FILE}")

# 检测是否在虚拟环境中运行
IN_VENV = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

# 自动检测并安装依赖
def install_dependencies():
    """安装依赖包"""
    try:
        # 基础依赖
        dependencies = [
            'PyQt5',           # GUI界面
            'dnspython',       # DNS功能
            'pandas',          # 数据处理
            'openpyxl',        # Excel导出
        ]
        
        # 平台特定依赖
        system = platform.system().lower()
        if system == 'windows':
            dependencies.append('pywin32')  # Windows平台特定功能
        
        # 检查是否允许安装依赖
        if not IN_VENV and sys.prefix == sys.base_prefix:
            print("\n警告：未在虚拟环境中运行。")
            answer = input("是否继续安装依赖包到系统Python环境？ (y/n): ")
            if answer.lower() != 'y':
                print("跳过依赖安装。请手动安装以下包:")
                for dep in dependencies:
                    print(f"  - {dep}")
                return
        
        # 安装依赖
        print("\n安装依赖包...")
        for dep in dependencies:
            print(f"安装 {dep}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
        
        print("依赖安装完成！")
    
    except Exception as e:
        print(f"安装依赖时出错: {str(e)}")
        print("请手动安装必要的依赖包")

# 如果直接执行此脚本，则安装依赖
if __name__ == "__main__":
    install_dependencies()

# 包信息
setup(
    name="nettools",
    version="1.0.0",
    description="多模块网络扫描工具箱",
    author="NetTools Team",
    author_email="admin@example.com",
    packages=find_packages(),
    install_requires=[
        'PyQt5',
        'dnspython',
        'pandas',
        'openpyxl'
    ],
    entry_points={
        'console_scripts': [
            'nettools-cli=cli.main:main',
            'nettools-gui=gui.main:main',
        ],
    },
    python_requires='>=3.8',
) 