#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件配置编辑器线程模块
提供用于异步加载和处理配置文件的线程类
"""

import os
import json
import yaml
import re
import logging
import time
from typing import Dict, List, Any, Optional, Tuple

from PyQt5.QtCore import QThread, pyqtSignal

# 配置日志
logger = logging.getLogger("ss0t-scna.plugin_config_editor.threads")

class LoadConfigListThread(QThread):
    """加载配置文件列表线程"""
    load_complete = pyqtSignal(list, str)
    progress_update = pyqtSignal(int)
    
    def __init__(self, config_manager):
        """
        初始化线程
        
        Args:
            config_manager: 配置管理器实例
        """
        super().__init__()
        self.config_manager = config_manager
        self.configs = []
        
    def run(self):
        """执行线程任务"""
        try:
            # 获取配置目录
            config_dir = self.config_manager.config_dir
            
            # 确保配置目录存在且有权限访问
            if not os.path.exists(config_dir):
                self.load_complete.emit([], f"配置目录不存在: {config_dir}")
                return
            
            if not os.access(config_dir, os.R_OK):
                self.load_complete.emit([], f"无权限访问配置目录: {config_dir}")
                return
            
            # 获取所有配置文件路径
            config_files = self.config_manager.get_plugin_config_files()
            
            # 按字母排序
            config_files.sort()
            
            configs = []
            total_files = len(config_files)
            
            # 分批处理文件，批量报告进度
            for i, config_file in enumerate(config_files):
                # 每处理10%的文件更新一次进度
                if i % max(1, total_files // 10) == 0:
                    progress = int((i / total_files) * 100) if total_files > 0 else 0
                    self.progress_update.emit(progress)
                
                file_name = os.path.basename(config_file)
                plugin_id = os.path.splitext(file_name)[0]
                
                # 检查是否有读取权限
                has_read_access = os.access(config_file, os.R_OK)
                if not has_read_access:
                    configs.append({
                        'file': config_file,
                        'name': f"{file_name} (无读取权限)",
                        'access': False
                    })
                    continue
                
                # 检查是否有写入权限
                has_write_access = os.access(config_file, os.W_OK)
                
                # 尝试加载配置获取插件名称
                try:
                    # 对于大文件，只读取开头部分来获取名称
                    config = None
                    file_size = os.path.getsize(config_file)
                    
                    if file_size > 1024 * 1024:  # 大于1MB的文件
                        # 大文件只读取前50KB来提取名称
                        with open(config_file, 'r', encoding='utf-8') as f:
                            content = f.read(51200)  # 读取前50KB
                        
                        # 尝试解析JSON
                        if config_file.lower().endswith('.json'):
                            # 对于不完整的JSON，尝试在有效的地方截断并添加结束括号
                            try:
                                # 找到最后一个完整的对象或数组结束
                                last_valid = max(content.rfind('}'), content.rfind(']'))
                                if last_valid > 0:
                                    # 构造一个可能有效的JSON片段
                                    valid_part = content[:last_valid+1]
                                    # 计算缺少的括号
                                    open_braces = valid_part.count('{')
                                    close_braces = valid_part.count('}')
                                    open_brackets = valid_part.count('[')
                                    close_brackets = valid_part.count(']')
                                    
                                    # 添加缺少的结束括号
                                    for _ in range(open_braces - close_braces):
                                        valid_part += '}'
                                    for _ in range(open_brackets - close_brackets):
                                        valid_part += ']'
                                        
                                    # 尝试解析修复后的JSON
                                    try:
                                        config = json.loads(valid_part)
                                    except:
                                        # 如果还是失败，尝试解析完整文件
                                        pass
                            except:
                                pass
                        elif config_file.lower().endswith(('.yaml', '.yml')):
                            # YAML可以是部分有效的
                            try:
                                config = yaml.safe_load(content)
                            except:
                                pass
                    
                    # 如果部分解析失败或者是小文件，尝试加载完整配置
                    if config is None:
                        config = self.config_manager.load_config(plugin_id)
                        
                    name = config.get("name", plugin_id) if config else plugin_id
                    
                    display_name = name
                    if not has_write_access:
                        display_name = f"{name} ({file_name}) [只读]"
                    else:
                        display_name = f"{name} ({file_name})"
                        
                    configs.append({
                        'file': config_file, 
                        'name': display_name,
                        'access': has_write_access
                    })
                except Exception as e:
                    logger.warning(f"加载插件配置 {file_name} 失败: {str(e)}")
                    if not has_write_access:
                        configs.append({
                            'file': config_file,
                            'name': f"{file_name} [只读]",
                            'access': False
                        })
                    else:
                        configs.append({
                            'file': config_file,
                            'name': file_name,
                            'access': True
                        })
            
            self.load_complete.emit(configs, "")
        
        except Exception as e:
            logger.error(f"加载插件配置列表失败: {str(e)}")
            self.load_complete.emit([], str(e))


class LoadFileThread(QThread):
    """加载文件内容线程"""
    load_complete = pyqtSignal(str, bool, str)
    progress_update = pyqtSignal(int)
    
    def __init__(self, file_path):
        """
        初始化线程
        
        Args:
            file_path: 文件路径
        """
        super().__init__()
        self.file_path = file_path
        
    def run(self):
        """执行线程任务"""
        try:
            # 检查文件大小
            file_size = os.path.getsize(self.file_path)
            is_large = file_size > 1024 * 1024  # 大于1MB的文件
            
            # 读取文件内容
            content = ""
            with open(self.file_path, 'r', encoding='utf-8') as f:
                if is_large:
                    # 对于大文件，分块读取
                    chunk_size = 102400  # 100KB 每块
                    total_size = file_size
                    read_size = 0
                    
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        
                        content += chunk
                        read_size += len(chunk.encode('utf-8'))
                        progress = int((read_size / total_size) * 100)
                        self.progress_update.emit(progress)
                        
                        # 给UI线程一些处理时间
                        self.msleep(1)
                else:
                    # 对于小文件，直接读取
                    content = f.read()
                    self.progress_update.emit(100)
            
            self.load_complete.emit(content, False, "")
        except Exception as e:
            self.load_complete.emit("", True, str(e))


class ParseConfigThread(QThread):
    """解析配置内容线程"""
    parse_complete = pyqtSignal(object, bool, str)
    progress_update = pyqtSignal(int, str)
    
    def __init__(self, content, is_json, max_nodes=1500):
        """
        初始化线程
        
        Args:
            content: 文件内容
            is_json: 是否为JSON格式
            max_nodes: 最大节点数
        """
        super().__init__()
        self.content = content
        self.is_json = is_json
        self.is_yaml = not is_json
        self.result = None
        self.max_nodes = max_nodes
        self.canceled = False
        
    def cancel(self):
        """取消解析操作"""
        if self.canceled:
            logger.info("解析线程已经在取消状态，不再重复发送取消信号")
            return
        
        logger.info("解析线程接收到取消请求")
        self.canceled = True
        
        # 强制发送取消信号，取消解析
        self.progress_update.emit(0, "解析已取消")
        self.parse_complete.emit({"status": "canceled"}, False, "用户取消")
        
    def run(self):
        """执行线程任务"""
        if self.canceled:
            logger.info("解析线程在开始时已经处于取消状态，直接返回")
            self.progress_update.emit(0, "解析已取消")
            self.parse_complete.emit({"status": "canceled"}, False, "用户取消")
            return
        
        try:
            # 更新解析开始状态
            self.progress_update.emit(5, "开始解析...")
            
            # 对于大文件，先检查大小
            content_size = len(self.content)
            is_large = content_size > 1024 * 1024  # 1MB
            
            # 为大文件设置较短的超时时间
            timeout_seconds = 10 if is_large else 30
            start_time = time.time()
            
            # 如果文件太大，尝试采样解析
            if is_large and self.is_json:
                self.progress_update.emit(10, "大文件，进行采样解析...")
                
                # 尝试找到有效的JSON根元素
                try:
                    # 先尝试只解析大型文件的开头和结尾部分
                    sample_size = min(200 * 1024, content_size // 4)  # 最多200KB或1/4文件
                    
                    # 解析开头
                    self.progress_update.emit(20, "解析文件开头...")
                    start_content = self.content[:sample_size]
                    
                    # 解析有效的JSON结构
                    self.progress_update.emit(25, "检索JSON结构...")
                    depth = 0
                    in_string = False
                    escape = False
                    start_obj_pos = -1
                    
                    # 定期更新进度和检查取消状态
                    progress_step = max(1, len(start_content) // 5)
                    
                    # 寻找第一个有效的对象或数组开始位置
                    for i, c in enumerate(start_content):
                        # 检查是否被取消
                        if self.canceled:
                            self.progress_update.emit(0, "解析已取消")
                            return
                            
                        # 每处理一部分数据更新一次进度
                        if i % progress_step == 0:
                            progress = 25 + (i / len(start_content)) * 5
                            self.progress_update.emit(int(progress), "检索JSON结构中...")
                            
                            # 检查是否超时
                            if time.time() - start_time > timeout_seconds:
                                self.progress_update.emit(30, "采样解析超时，尝试简化解析...")
                                break
                                
                        if c == '"' and not escape:
                            in_string = not in_string
                        elif not in_string:
                            if c == '{' or c == '[':
                                if depth == 0:
                                    start_obj_pos = i
                                depth += 1
                            elif c == '}' or c == ']':
                                depth -= 1
                        
                        escape = c == '\\' and not escape
                    
                    # 检查是否被取消
                    if self.canceled:
                        self.progress_update.emit(0, "解析已取消")
                        return
                    
                    if start_obj_pos >= 0:
                        # 找到第一个有效的对象/数组，从这里开始解析
                        self.progress_update.emit(30, "尝试采样解析JSON对象...")
                        chunk = self.content[start_obj_pos:start_obj_pos + sample_size]
                        
                        # 确保我们有完整的JSON结构
                        self.progress_update.emit(35, "检查JSON完整性...")
                        brackets_stack = []
                        
                        # 定期更新进度
                        progress_step = max(1, len(chunk) // 5)
                        
                        for i, c in enumerate(chunk):
                            # 检查是否被取消
                            if self.canceled:
                                self.progress_update.emit(0, "解析已取消")
                                return
                                
                            # 每处理一部分数据更新一次进度
                            if i % progress_step == 0:
                                progress = 35 + (i / len(chunk)) * 5
                                self.progress_update.emit(int(progress), "检查JSON完整性...")
                                
                                # 检查是否超时
                                if time.time() - start_time > timeout_seconds:
                                    self.progress_update.emit(40, "完整性检查超时，使用截断数据...")
                                    break
                                    
                            if c == '{':
                                brackets_stack.append('}')
                            elif c == '[':
                                brackets_stack.append(']')
                            elif c in ('}', ']'):
                                if brackets_stack and brackets_stack[-1] == c:
                                    brackets_stack.pop()
                                # 如果是根节点的结束括号，截断这里
                                if not brackets_stack:
                                    chunk = chunk[:i+1]
                                    break
                        
                        # 检查是否被取消
                        if self.canceled:
                            self.progress_update.emit(0, "解析已取消")
                            return
                            
                        # 尝试解析这个截断的JSON
                        try:
                            self.progress_update.emit(45, "解析采样JSON...")
                            partial_result = json.loads(chunk)
                            self.progress_update.emit(60, "成功解析采样内容...")
                            self.result = partial_result
                            self.parse_complete.emit(self.result, False, "采样解析")
                            return
                        except Exception as e:
                            # 采样解析失败，尝试完整解析
                            self.progress_update.emit(40, f"采样解析失败: {str(e)}, 尝试完整解析...")
                except Exception as e:
                    self.progress_update.emit(30, f"采样解析异常: {str(e)}")
            
            # 检查是否被取消
            if self.canceled:
                self.progress_update.emit(0, "解析已取消")
                return
                
            # 如果采样解析失败或不是大文件，尝试完整解析
            self.progress_update.emit(50, "进行完整解析...")
            
            # 检查是否已经超时
            if time.time() - start_time > timeout_seconds:
                if is_large:
                    # 大文件超时，使用简单解析
                    self.progress_update.emit(55, "解析耗时较长，尝试简化处理...")
                    self.parse_complete.emit({"message": "文件过大，无法完整解析"}, False, "简化解析")
                    return
            
            # 根据文件类型使用不同的解析方法
            if self.is_json:
                # 使用标准JSON解析，增加超时保护
                try:
                    # 执行带超时的JSON解析
                    self.progress_update.emit(60, "使用标准JSON解析器...")
                    
                    # 直接解析小文件
                    if not is_large:
                        # 定期检查取消状态
                        max_check_interval = 0.5  # 最多0.5秒检查一次取消状态
                        last_check_time = time.time()
                        
                        try:
                            self.result = json.loads(self.content)
                            
                            # 检查是否被取消
                            if self.canceled:
                                self.progress_update.emit(0, "解析已取消")
                                return
                        except Exception as json_error:
                            if self.canceled:
                                self.progress_update.emit(0, "解析已取消")
                                return
                            raise json_error
                    else:
                        # 对大文件的解析进行超时处理和取消检查
                        try:
                            # 这里只能在主线程中检查超时和取消
                            timer_start = time.time()
                            self.result = json.loads(self.content)
                            parse_time = time.time() - timer_start
                            
                            # 检查是否被取消
                            if self.canceled:
                                self.progress_update.emit(0, "解析已取消")
                                return
                                
                            # 记录解析时间
                            self.progress_update.emit(70, f"JSON解析完成，耗时: {parse_time:.2f}秒")
                        except Exception as json_error:
                            if self.canceled:
                                self.progress_update.emit(0, "解析已取消")
                                return
                            raise json_error
                except Exception as e:
                    self.parse_complete.emit(str(e), True, f"JSON解析错误: {str(e)}")
                    return
            else:
                # 使用YAML解析
                try:
                    self.progress_update.emit(60, "使用YAML解析器...")
                    try:
                        self.result = yaml.safe_load(self.content)
                        
                        # 检查是否被取消
                        if self.canceled:
                            self.progress_update.emit(0, "解析已取消")
                            return
                    except Exception as yaml_error:
                        if self.canceled:
                            self.progress_update.emit(0, "解析已取消")
                            return
                        raise yaml_error
                except Exception as e:
                    self.parse_complete.emit(str(e), True, f"YAML解析错误: {str(e)}")
                    return
            
            # 检查是否被取消
            if self.canceled:
                self.progress_update.emit(0, "解析已取消")
                return
                
            self.progress_update.emit(80, "解析完成，准备构建树...")
            logger.info(f"发送解析完成信号: is_error={False}, error_info=''")
            self.parse_complete.emit(self.result, False, "")
        except Exception as e:
            error_msg = str(e)
            self.progress_update.emit(0, f"解析失败: {error_msg}")
            self.parse_complete.emit(error_msg, True, error_msg)


class SaveConfigThread(QThread):
    """保存配置文件线程"""
    save_complete = pyqtSignal(bool, str)
    progress_update = pyqtSignal(int)
    
    def __init__(self, file_path, content):
        """
        初始化线程
        
        Args:
            file_path: 文件路径
            content: 文件内容
        """
        super().__init__()
        self.file_path = file_path
        self.content = content
        
    def run(self):
        """执行线程任务"""
        try:
            # 对于大文件，分批写入
            file_size = len(self.content.encode('utf-8'))
            is_large = file_size > 1024 * 1024  # 1MB
            
            if is_large:
                # 分批写入大文件
                chunk_size = 102400  # 100KB
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    total_size = file_size
                    written_size = 0
                    
                    # 分批写入内容
                    for i in range(0, len(self.content), chunk_size):
                        chunk = self.content[i:i+chunk_size]
                        f.write(chunk)
                        written_size += len(chunk.encode('utf-8'))
                        progress = int((written_size / total_size) * 80) + 10  # 10-90%
                        self.progress_update.emit(progress)
            else:
                # 直接写入小文件
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    f.write(self.content)
                self.progress_update.emit(90)  # 完成写入
                
            self.save_complete.emit(True, "")
        except Exception as e:
            self.save_complete.emit(False, str(e)) 