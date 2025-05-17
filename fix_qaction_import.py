#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
修复PyQt5中QAction的导入位置
在PyQt5中，QAction位于QtWidgets模块，而在PyQt6中，它位于QtGui模块
"""

import os
import re
import sys

def fix_qaction_import(file_path):
    """修复QAction导入位置"""
    print(f"处理文件: {file_path}")
    
    # 读取文件内容
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 检查是否从QtGui导入了QAction
    qaction_in_gui = re.search(r'from PyQt5\.QtGui import (.*?)QAction(.*?)', content)
    if qaction_in_gui:
        # 从QtGui导入中移除QAction
        gui_match = qaction_in_gui.group(0)
        imports_before = qaction_in_gui.group(1)
        imports_after = qaction_in_gui.group(2)
        
        # 如果前后都有其他导入，则保留导入语句
        if imports_before.strip() or imports_after.strip():
            # 移除QAction并清理逗号
            new_gui_import = gui_match.replace('QAction', '').replace(', ,', ',')
            # 清理开头和结尾的逗号
            new_gui_import = re.sub(r'import\s+,', 'import ', new_gui_import)
            new_gui_import = re.sub(r',\s*$', '', new_gui_import)
            
            # 替换原导入语句
            content = content.replace(gui_match, new_gui_import)
        else:
            # 如果没有其他导入，则删除整个导入语句
            content = content.replace(gui_match, '')
        
        # 检查是否已经从QtWidgets导入了QAction
        if 'from PyQt5.QtWidgets import' in content:
            # 如果导入语句是单行形式
            widgets_match = re.search(r'from PyQt5\.QtWidgets import ([^\n]*?)(?:\n|$)', content)
            if widgets_match and 'QAction' not in widgets_match.group(1):
                # 在现有导入语句末尾添加QAction
                new_widgets_import = widgets_match.group(0).rstrip() + ', QAction\n'
                content = content.replace(widgets_match.group(0), new_widgets_import)
            # 如果导入语句是多行形式
            elif re.search(r'from PyQt5\.QtWidgets import \(', content):
                # 检查是否已存在QAction
                if 'QAction' not in content.split('from PyQt5.QtWidgets import (')[1].split(')')[0]:
                    # 在括号内末尾添加QAction
                    bracket_end = re.search(r'\s+\)', content)
                    if bracket_end:
                        pos = bracket_end.start()
                        content = content[:pos] + ', QAction' + content[pos:]
        else:
            # 如果没有从QtWidgets导入，则添加新的导入语句
            content = re.sub(
                r'(from PyQt5\.QtGui import .*?\n)',
                r'\1from PyQt5.QtWidgets import QAction\n',
                content
            )
    
    # 保存修改后的内容
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"已处理文件: {file_path}")

def find_python_files(root_dir):
    """查找所有Python文件"""
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith('.py'):
                yield os.path.join(dirpath, filename)

def main():
    """主函数"""
    # 获取项目根目录
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        root_dir = os.getcwd()
    
    # 查找并处理所有Python文件
    count = 0
    for file_path in find_python_files(root_dir):
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 如果文件中包含从QtGui导入QAction，则进行修复
        if re.search(r'from PyQt5\.QtGui import (.*?)QAction(.*?)', content):
            fix_qaction_import(file_path)
            count += 1
    
    print(f"处理完成，共修改了 {count} 个文件。")

if __name__ == '__main__':
    main() 