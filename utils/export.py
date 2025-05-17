#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据导出模块
将扫描结果导出为各种格式
"""

import csv
import json
import os
from datetime import datetime
from typing import List, Dict, Any

def ensure_dir(directory: str) -> None:
    """
    确保目录存在，不存在则创建
    
    Args:
        directory: 目录路径
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_output_filename(module_name: str, file_format: str) -> str:
    """
    生成输出文件名
    
    Args:
        module_name: 模块名称
        file_format: 文件格式（csv, json, xlsx）
    
    Returns:
        完整的文件名
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{module_name}_{timestamp}.{file_format}"

def export_to_csv(data: List[Dict[str, Any]], output_file: str, fields: List[str] = None) -> str:
    """
    将数据导出为 CSV 文件
    
    Args:
        data: 要导出的数据列表
        output_file: 输出文件路径
        fields: 要包含的字段列表，如果为 None 则使用数据中的所有字段
    
    Returns:
        完整的文件路径
    """
    if not data:
        return ""
    
    # 确保目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir:
        ensure_dir(output_dir)
    
    # 如果未指定字段，则使用第一条数据的所有键
    if fields is None:
        fields = list(data[0].keys())
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    
    return os.path.abspath(output_file)

def export_to_json(data: List[Dict[str, Any]], output_file: str) -> str:
    """
    将数据导出为 JSON 文件
    
    Args:
        data: 要导出的数据
        output_file: 输出文件路径
    
    Returns:
        完整的文件路径
    """
    # 确保目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir:
        ensure_dir(output_dir)
    
    with open(output_file, 'w', encoding='utf-8') as jsonfile:
        json.dump(data, jsonfile, ensure_ascii=False, indent=2)
    
    return os.path.abspath(output_file)

def export_to_excel(data: List[Dict[str, Any]], output_file: str, fields: List[str] = None) -> str:
    """
    将数据导出为 Excel 文件
    
    Args:
        data: 要导出的数据列表
        output_file: 输出文件路径
        fields: 要包含的字段列表，如果为 None 则使用数据中的所有字段
    
    Returns:
        完整的文件路径
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("导出 Excel 格式需要安装 pandas 和 openpyxl 库。请运行: pip install pandas openpyxl")
    
    if not data:
        return ""
    
    # 确保目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir:
        ensure_dir(output_dir)
    
    # 如果未指定字段，则使用所有字段
    if fields is None:
        df = pd.DataFrame(data)
    else:
        # 选择指定的字段
        df = pd.DataFrame(data)[fields]
    
    # 导出到 Excel
    df.to_excel(output_file, index=False)
    
    return os.path.abspath(output_file)

def export_result(data: List[Dict[str, Any]], module_name: str, format_type: str = 'csv', 
                 output_dir: str = 'results', fields: List[str] = None) -> str:
    """
    将扫描结果导出为指定格式
    
    Args:
        data: 要导出的数据列表
        module_name: 模块名称
        format_type: 导出格式（csv, json, xlsx）
        output_dir: 输出目录
        fields: 要包含的字段列表，如果为 None 则使用所有字段
    
    Returns:
        完整的文件路径或空字符串（导出失败）
    """
    if not data:
        return ""
    
    # 确保输出目录存在
    ensure_dir(output_dir)
    
    # 生成输出文件名
    filename = get_output_filename(module_name, format_type)
    output_path = os.path.join(output_dir, filename)
    
    # 根据格式类型导出
    if format_type.lower() == 'csv':
        return export_to_csv(data, output_path, fields)
    elif format_type.lower() == 'json':
        return export_to_json(data, output_path)
    elif format_type.lower() in ('xlsx', 'excel'):
        return export_to_excel(data, output_path, fields)
    else:
        raise ValueError(f"不支持的导出格式: {format_type}") 