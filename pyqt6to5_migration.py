#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
将PyQt6的导入语句替换为PyQt5
"""

import os
import re
import sys

def convert_file(file_path):
    """将单个文件中的PyQt6引用转换为PyQt5"""
    print(f"处理文件: {file_path}")
    
    # 读取文件内容
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 备份原文件
    backup_path = file_path + '.bak'
    if not os.path.exists(backup_path):
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    # 替换PyQt6为PyQt5
    content = re.sub(r'from PyQt6\.', r'from PyQt5.', content)
    content = re.sub(r'import PyQt6\.', r'import PyQt5.', content)
    
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
        
        # 如果文件中包含PyQt6，则进行转换
        if 'PyQt6' in content:
            convert_file(file_path)
            count += 1
    
    print(f"处理完成，共修改了 {count} 个文件。")

if __name__ == '__main__':
    main() 