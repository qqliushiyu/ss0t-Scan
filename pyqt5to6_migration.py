#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PyQt5到PyQt6迁移工具
自动将项目中的PyQt5代码转换为PyQt6兼容的代码
"""

import os
import re
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Set

def find_py_files(directory: str) -> List[str]:
    """查找目录中的所有Python文件
    
    Args:
        directory: 要搜索的目录
        
    Returns:
        Python文件路径列表
    """
    py_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                py_files.append(os.path.join(root, file))
    return py_files

def contains_pyqt5(file_path: str) -> bool:
    """检查文件是否包含PyQt5导入
    
    Args:
        file_path: 文件路径
        
    Returns:
        是否包含PyQt5导入
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        return 'PyQt5' in content

def update_imports(content: str) -> str:
    """更新PyQt5导入为PyQt6
    
    Args:
        content: 文件内容
        
    Returns:
        更新后的内容
    """
    # 替换导入语句
    content = re.sub(r'from PyQt5\.', r'from PyQt5.', content)
    content = re.sub(r'import PyQt5\.', r'import PyQt5.', content)
    
    # 处理QAction移动到QtGui的情况
    qaction_pattern = re.compile(r'from PyQt6\.QtWidgets import \(([^)]*)\)')
    for match in qaction_pattern.finditer(content):
        imports = match.group(1)
        if 'QAction' in imports:
            # 从QtWidgets中移除QAction
            new_imports = re.sub(r'(?:,\s*)?QAction(?:,\s*)?', ', ', imports)
            new_imports = re.sub(r',\s*,', ',', new_imports)  # 修复连续逗号
            new_imports = re.sub(r',\s*\)', ')', new_imports)  # 修复末尾逗号
            
            # 替换导入语句
            content = content.replace(match.group(0), f'from PyQt5.QtWidgets import ({new_imports})'), QAction
            
            # 如果内容中不包含QAction的QtGui导入，添加它
            if 'from PyQt5.QtGui import' in content:
                if 'QAction' not in content.split('from PyQt5.QtGui import')[1].split('\n')[0]:
                    # 在现有QtGui导入中添加QAction
                    content = re.sub(
                        r'from PyQt6\.QtGui import (.*)',
                        r'from PyQt5.QtGui import \1',
                        content
                    )
            else:
                # 添加新的QtGui导入
                content = re.sub(
                    r'from PyQt6\.QtWidgets import \(([^)]*)\)',
                    r'from PyQt5.QtWidgets import (\1)\nfrom PyQt5.QtGui import QAction',
                    content
                )
    
    # 处理QRegularExpression移动到QtCore的情况
    qregexp_pattern = re.compile(r'from PyQt6\.QtGui import (.*?)QRegularExpression(.*?)')
    if qregexp_pattern.search(content):
        # 从QtGui中移除QRegularExpression
        content = re.sub(
            r'from PyQt6\.QtGui import (.*?)QRegularExpression(.*?)',
            r'from PyQt5.QtGui import \1\2',
            content
        )
        
        # 修复连续逗号
        content = re.sub(r',\s*,', ',', content)
        
        # 如果内容中不包含QRegularExpression的QtCore导入，添加它
        if 'from PyQt5.QtCore import' in content:
            if 'QRegularExpression' not in content.split('from PyQt5.QtCore import')[1].split('\n')[0]:
                # 在现有QtCore导入中添加QRegularExpression
                content = re.sub(
                    r'from PyQt6\.QtCore import (.*)',
                    r'from PyQt5.QtCore import \1, QRegularExpression',
                    content
                )
        else:
            # 添加新的QtCore导入
            content = re.sub(
                r'from PyQt6\.QtGui import (.*)',
                r'from PyQt5.QtGui import \1\nfrom PyQt5.QtCore import QRegularExpression',
                content
            )
    
    return content

def update_enums(content: str) -> str:
    """更新枚举值使用
    
    Args:
        content: 文件内容
        
    Returns:
        更新后的内容
    """
    # 替换Qt枚举
    qt_enums = {
        'Qt.Horizontal': 'Qt.Orientation.Horizontal',
        'Qt.Vertical': 'Qt.Orientation.Vertical',
        'Qt.CustomContextMenu': 'Qt.ContextMenuPolicy.CustomContextMenu',
        'Qt.WindowModal': 'Qt.WindowModality.WindowModal',
        'Qt.ApplicationModal': 'Qt.WindowModality.ApplicationModal',
        'Qt.UserRole': 'Qt.ItemDataRole.UserRole',
        'Qt.DisplayRole': 'Qt.ItemDataRole.DisplayRole',
        'Qt.WindowStaysOnTopHint': 'Qt.WindowType.WindowStaysOnTopHint',
        'Qt.AlignCenter': 'Qt.AlignmentFlag.AlignCenter',
        'Qt.AlignLeft': 'Qt.AlignmentFlag.AlignLeft',
        'Qt.AlignRight': 'Qt.AlignmentFlag.AlignRight',
        'Qt.AlignTop': 'Qt.AlignmentFlag.AlignTop',
        'Qt.AlignBottom': 'Qt.AlignmentFlag.AlignBottom',
        'Qt.AlignHCenter': 'Qt.AlignmentFlag.AlignHCenter',
        'Qt.AlignVCenter': 'Qt.AlignmentFlag.AlignVCenter',
    }
    
    for old, new in qt_enums.items():
        content = re.sub(r'\b' + old + r'\b', new, content)
    
    # 替换QFont枚举
    font_enums = {
        'QFont.Bold': 'QFont.Weight.Bold',
        'QFont.Normal': 'QFont.Weight.Normal',
        'QFont.Light': 'QFont.Weight.Light',
    }
    
    for old, new in font_enums.items():
        content = re.sub(r'\b' + old + r'\b', new, content)
    
    # 替换QFrame枚举
    frame_enums = {
        'QFrame.StyledPanel': 'QFrame.Shape.StyledPanel',
        'QFrame.Panel': 'QFrame.Shape.Panel',
        'QFrame.Box': 'QFrame.Shape.Box',
    }
    
    for old, new in frame_enums.items():
        content = re.sub(r'\b' + old + r'\b', new, content)
    
    # 替换QMessageBox枚举
    msgbox_enums = {
        'QMessageBox.Yes': 'QMessageBox.StandardButton.Yes',
        'QMessageBox.No': 'QMessageBox.StandardButton.No',
        'QMessageBox.Ok': 'QMessageBox.StandardButton.Ok',
        'QMessageBox.Cancel': 'QMessageBox.StandardButton.Cancel',
        'QMessageBox.Information': 'QMessageBox.Icon.Information',
        'QMessageBox.Warning': 'QMessageBox.Icon.Warning',
        'QMessageBox.Critical': 'QMessageBox.Icon.Critical',
        'QMessageBox.Question': 'QMessageBox.Icon.Question',
    }
    
    for old, new in msgbox_enums.items():
        content = re.sub(r'\b' + old + r'\b', new, content)
    
    # 替换QSizePolicy枚举
    sizepolicy_enums = {
        'QSizePolicy.Expanding': 'QSizePolicy.Policy.Expanding',
        'QSizePolicy.Fixed': 'QSizePolicy.Policy.Fixed',
        'QSizePolicy.Minimum': 'QSizePolicy.Policy.Minimum',
        'QSizePolicy.Maximum': 'QSizePolicy.Policy.Maximum',
        'QSizePolicy.Preferred': 'QSizePolicy.Policy.Preferred',
    }
    
    for old, new in sizepolicy_enums.items():
        content = re.sub(r'\b' + old + r'\b', new, content)
    
    # 替换QLineEdit枚举
    lineedit_enums = {
        'QLineEdit.Normal': 'QLineEdit.InputMode.Normal',
        'QLineEdit.Password': 'QLineEdit.InputMode.Password',
    }
    
    for old, new in lineedit_enums.items():
        content = re.sub(r'\b' + old + r'\b', new, content)
    
    return content

def update_methods(content: str) -> str:
    """更新方法名称
    
    Args:
        content: 文件内容
        
    Returns:
        更新后的内容
    """
    # 替换exec_()为exec()
    content = re.sub(r'\.exec_\(\)', '.exec()', content)
    
    # 更新showFullScreen()等方法
    # 这些方法在PyQt6中保持不变，但提供以备将来需要
    
    return content

def update_file(file_path: str, backup: bool = True) -> bool:
    """更新文件内容
    
    Args:
        file_path: 文件路径
        backup: 是否创建备份
        
    Returns:
        是否成功更新
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 检查是否包含PyQt5
        if 'PyQt5' not in content:
            return False
        
        # 创建备份
        if backup:
            backup_path = file_path + '.bak'
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        # 更新内容
        new_content = update_imports(content)
        new_content = update_enums(new_content)
        new_content = update_methods(new_content)
        
        # 写入更新后的内容
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        return True
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {str(e)}")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='PyQt5到PyQt6迁移工具')
    parser.add_argument('directory', help='要处理的目录路径')
    parser.add_argument('--no-backup', action='store_true', help='不创建备份文件')
    args = parser.parse_args()
    
    directory = args.directory
    if not os.path.isdir(directory):
        print(f"错误: {directory} 不是有效的目录")
        return 1
    
    # 查找所有Python文件
    py_files = find_py_files(directory)
    print(f"找到 {len(py_files)} 个Python文件")
    
    # 筛选包含PyQt5的文件
    pyqt_files = [f for f in py_files if contains_pyqt5(f)]
    print(f"其中 {len(pyqt_files)} 个文件包含PyQt5")
    
    # 更新文件
    updated = 0
    for file_path in pyqt_files:
        print(f"正在处理 {file_path}...")
        if update_file(file_path, not args.no_backup):
            updated += 1
    
    print(f"已成功更新 {updated}/{len(pyqt_files)} 个文件")
    return 0

if __name__ == '__main__':
    sys.exit(main()) 