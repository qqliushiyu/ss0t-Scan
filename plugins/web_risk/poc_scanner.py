#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC扫描框架插件
支持POC的加载、批量扫描和结果输出
"""

import os
import re
import json
import importlib.util
import requests
import logging
import threading
import concurrent.futures
from typing import Dict, List, Any, Optional, Callable, Union, Tuple

from plugins.base_plugin import WebRiskPlugin

class POCScanner(WebRiskPlugin):
    """POC扫描框架插件"""
    
    NAME = "POC漏洞扫描"
    DESCRIPTION = "基于POC的漏洞验证框架，支持加载自定义POC进行批量扫描"
    VERSION = "1.0.0"
    AUTHOR = "NetTools"
    CATEGORY = "漏洞检测"
    
    # POC文件默认目录
    DEFAULT_POC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pocs")
    
    def __init__(self, config: Dict[str, Any] = None):
        """初始化POC扫描框架插件"""
        super().__init__(config)
        
        # 从配置中加载POC目录
        self.poc_dir = self.config.get("poc_dir", self.DEFAULT_POC_DIR)
        
        # 确保POC目录存在
        if not os.path.exists(self.poc_dir):
            os.makedirs(self.poc_dir, exist_ok=True)
        
        # 加载的POC列表
        self.pocs = {}
        
        # 设置最大线程数
        self.max_threads = self.config.get("max_threads", 10)
        
        # 扫描超时时间
        self.timeout = self.config.get("timeout", 10)
        
        # 扫描控制
        self.running = False
        self.stop_event = threading.Event()
        
        # 进度回调函数
        self.progress_callback = None
        
        # 加载所有POC
        self.load_all_pocs()
    
    def set_progress_callback(self, callback: Callable[[int, str], None]) -> None:
        """
        设置进度回调函数
        
        Args:
            callback: 回调函数，接收(进度百分比, 状态消息)两个参数
        """
        self.progress_callback = callback
    
    def update_progress(self, percent: int, message: str) -> None:
        """
        更新进度信息
        
        Args:
            percent: 进度百分比 (0-100)
            message: 状态消息
        """
        if self.progress_callback:
            self.progress_callback(percent, message)
        self.logger.debug(f"Progress: {percent}%, {message}")
    
    def load_all_pocs(self) -> int:
        """
        加载所有POC
        
        Returns:
            加载的POC数量
        """
        self.pocs = {}
        count = 0
        
        # 检查POC目录
        if not os.path.exists(self.poc_dir):
            self.logger.warning(f"POC目录不存在: {self.poc_dir}")
            return 0
        
        # 遍历POC目录，加载所有.py和.json格式的POC
        for root, _, files in os.walk(self.poc_dir):
            for file in files:
                if file.endswith('.py') and not file.startswith('_'):
                    # 加载Python格式POC
                    try:
                        poc_path = os.path.join(root, file)
                        poc_id = os.path.splitext(file)[0]
                        poc = self.load_python_poc(poc_path, poc_id)
                        if poc:
                            self.pocs[poc_id] = poc
                            count += 1
                    except Exception as e:
                        self.logger.error(f"加载Python POC {file} 失败: {str(e)}")
                
                elif file.endswith('.json'):
                    # 加载JSON格式POC
                    try:
                        poc_path = os.path.join(root, file)
                        poc_id = os.path.splitext(file)[0]
                        poc = self.load_json_poc(poc_path, poc_id)
                        if poc:
                            self.pocs[poc_id] = poc
                            count += 1
                    except Exception as e:
                        self.logger.error(f"加载JSON POC {file} 失败: {str(e)}")
        
        self.logger.info(f"共加载 {count} 个POC")
        return count
    
    def load_python_poc(self, poc_path: str, poc_id: str) -> Optional[Dict[str, Any]]:
        """
        加载Python格式的POC
        
        Args:
            poc_path: POC文件路径
            poc_id: POC ID
            
        Returns:
            POC信息字典
        """
        try:
            # 动态加载Python模块
            spec = importlib.util.spec_from_file_location(poc_id, poc_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # 检查必要属性
            if not hasattr(module, 'verify') or not callable(module.verify):
                self.logger.warning(f"POC {poc_id} 缺少verify函数")
                return None
            
            # 提取POC信息
            poc_info = {
                'id': poc_id,
                'name': getattr(module, 'name', poc_id),
                'description': getattr(module, 'description', '无描述'),
                'author': getattr(module, 'author', '未知'),
                'type': getattr(module, 'type', '未分类'),
                'severity': getattr(module, 'severity', 'medium'),
                'verify': module.verify,
                'format': 'python'
            }
            
            # 检查是否有额外的exploit函数
            if hasattr(module, 'exploit') and callable(module.exploit):
                poc_info['exploit'] = module.exploit
            
            self.logger.debug(f"成功加载Python POC: {poc_id}")
            return poc_info
            
        except Exception as e:
            self.logger.error(f"加载Python POC {poc_id} 时出错: {str(e)}")
            return None
    
    def load_json_poc(self, poc_path: str, poc_id: str) -> Optional[Dict[str, Any]]:
        """
        加载JSON格式的POC
        
        Args:
            poc_path: POC文件路径
            poc_id: POC ID
            
        Returns:
            POC信息字典
        """
        try:
            with open(poc_path, 'r', encoding='utf-8') as f:
                poc_data = json.load(f)
            
            # 检查必要字段
            required_fields = ['name', 'matchers']
            for field in required_fields:
                if field not in poc_data:
                    self.logger.warning(f"JSON POC {poc_id} 缺少必要字段: {field}")
                    return None
            
            # 提取POC信息
            poc_info = {
                'id': poc_id,
                'name': poc_data.get('name', poc_id),
                'description': poc_data.get('description', '无描述'),
                'author': poc_data.get('author', '未知'),
                'type': poc_data.get('type', '未分类'),
                'severity': poc_data.get('severity', 'medium'),
                'request': poc_data.get('request', {}),
                'matchers': poc_data.get('matchers', []),
                'format': 'json'
            }
            
            self.logger.debug(f"成功加载JSON POC: {poc_id}")
            return poc_info
            
        except Exception as e:
            self.logger.error(f"加载JSON POC {poc_id} 时出错: {str(e)}")
            return None
    
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行POC扫描
        
        Args:
            target: 目标URL
            session: 请求会话对象
            **kwargs: 其他参数
            
        Returns:
            检测结果列表
        """
        results = []
        
        # 确保target以/结尾
        if not target.endswith('/'):
            target = target + '/'
        
        # 使用提供的会话或创建新会话
        if session is None:
            session = requests.Session()
            # 设置请求头
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
            })
        
        # 获取额外配置
        timeout = kwargs.get('timeout', self.timeout)
        verify_ssl = kwargs.get('verify_ssl', False)
        scan_depth = kwargs.get('scan_depth', 1)
        use_concurrent = kwargs.get('concurrent', True)
        
        # 根据扫描深度调整测试数量
        if scan_depth == 0:
            # 最小扫描模式，跳过POC检测
            return [{
                "check_type": "vulnerability",
                "vulnerability": "POC漏洞",
                "url": target,
                "status": "skipped",
                "details": "根据扫描深度设置跳过POC漏洞检测"
            }]
        
        # 限制要运行的POC数量
        poc_limit = len(self.pocs)  # 默认运行所有POC
        if scan_depth == 1:
            # 标准扫描模式，只运行高危POC
            poc_ids = [
                poc_id for poc_id, poc in self.pocs.items() 
                if poc.get('severity') in ['critical', 'high']
            ]
        else:
            # 深度扫描模式，运行所有POC
            poc_ids = list(self.pocs.keys())
        
        if not poc_ids:
            self.logger.info(f"没有适合当前扫描深度的POC: {scan_depth}")
            return [{
                "check_type": "vulnerability",
                "vulnerability": "POC漏洞",
                "url": target,
                "status": "info",
                "details": "没有适合当前扫描深度的POC"
            }]
        
        self.logger.info(f"开始对 {target} 运行 {len(poc_ids)} 个POC")
        self.running = True
        self.stop_event.clear()
        
        try:
            # 并发执行POC
            if use_concurrent and len(poc_ids) > 1:
                self.update_progress(10, f"正在并发执行 {len(poc_ids)} 个POC...")
                future_to_poc = {}
                
                # 创建线程池
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_threads, len(poc_ids))) as executor:
                    # 提交所有任务
                    for poc_id in poc_ids:
                        if self.stop_event.is_set():
                            break
                        future = executor.submit(
                            self.run_single_poc, 
                            poc_id, 
                            target, 
                            session, 
                            timeout, 
                            verify_ssl
                        )
                        future_to_poc[future] = poc_id
                    
                    # 收集结果
                    completed = 0
                    for future in concurrent.futures.as_completed(future_to_poc):
                        if self.stop_event.is_set():
                            break
                        
                        completed += 1
                        progress = int(10 + (90 * completed / len(future_to_poc)))
                        poc_id = future_to_poc[future]
                        self.update_progress(progress, f"已完成 {completed}/{len(future_to_poc)} 个POC, 当前: {poc_id}")
                        
                        try:
                            poc_result = future.result()
                            if poc_result:
                                results.append(poc_result)
                        except Exception as e:
                            self.logger.error(f"执行POC {poc_id} 时发生异常: {str(e)}")
                            # 添加一个错误结果
                            results.append({
                                "check_type": "vulnerability",
                                "vulnerability": f"POC执行错误: {poc_id}",
                                "url": target,
                                "poc_id": poc_id,
                                "status": "error",
                                "details": f"执行POC时发生异常: {str(e)}"
                            })
            else:
                # 顺序执行POC
                for i, poc_id in enumerate(poc_ids):
                    if self.stop_event.is_set():
                        break
                    
                    progress = int(10 + (90 * i / len(poc_ids)))
                    self.update_progress(progress, f"正在执行POC {i+1}/{len(poc_ids)}: {poc_id}")
                    
                    poc_result = self.run_single_poc(poc_id, target, session, timeout, verify_ssl)
                    if poc_result:
                        results.append(poc_result)
            
            self.update_progress(100, f"POC扫描完成，发现 {len(results)} 个漏洞")
            
        except Exception as e:
            self.logger.error(f"执行POC扫描时出错: {str(e)}")
            results.append({
                "check_type": "vulnerability",
                "vulnerability": "POC扫描",
                "url": target,
                "status": "error",
                "details": f"执行POC扫描时出错: {str(e)}"
            })
        finally:
            self.running = False
        
        # 如果没有发现漏洞，添加一个安全的结果
        if not results:
            results.append({
                "check_type": "vulnerability",
                "vulnerability": "POC扫描",
                "url": target,
                "status": "safe",
                "details": "未发现POC能检出的漏洞",
                "recommendation": "继续保持良好的安全实践，定期进行安全测试。"
            })
        
        return results
    
    def run_single_poc(self, poc_id: str, target: str, session, timeout: int, verify_ssl: bool) -> Optional[Dict[str, Any]]:
        """
        运行单个POC
        
        Args:
            poc_id: POC ID
            target: 目标URL
            session: 请求会话
            timeout: 超时时间
            verify_ssl: 是否验证SSL证书
            
        Returns:
            POC检测结果
        """
        poc = self.pocs.get(poc_id)
        if not poc:
            self.logger.warning(f"未找到POC: {poc_id}")
            return None
        
        try:
            if poc['format'] == 'python':
                # 执行Python格式POC
                verify_func = poc['verify']
                is_vulnerable, details = verify_func(target, session, timeout=timeout, verify=verify_ssl)
                
                if is_vulnerable:
                    return {
                        "check_type": "vulnerability",
                        "vulnerability": poc['name'],
                        "url": target,
                        "poc_id": poc_id,
                        "status": "vulnerable",
                        "severity": poc['severity'],
                        "details": details,
                        "recommendation": "及时修复相关漏洞，参考POC描述进行安全加固"
                    }
            
            elif poc['format'] == 'json':
                # 执行JSON格式POC
                is_vulnerable, details = self.execute_json_poc(poc, target, session, timeout, verify_ssl)
                
                if is_vulnerable:
                    return {
                        "check_type": "vulnerability",
                        "vulnerability": poc['name'],
                        "url": target,
                        "poc_id": poc_id,
                        "status": "vulnerable",
                        "severity": poc['severity'],
                        "details": details,
                        "recommendation": "及时修复相关漏洞，参考POC描述进行安全加固"
                    }
                
        except Exception as e:
            self.logger.error(f"执行POC {poc_id} 时出错: {str(e)}")
        
        return None
    
    def execute_json_poc(self, poc: Dict[str, Any], target: str, session, timeout: int, verify_ssl: bool) -> Tuple[bool, str]:
        """
        执行JSON格式的POC
        
        Args:
            poc: POC信息
            target: 目标URL
            session: 请求会话
            timeout: 超时时间
            verify_ssl: 是否验证SSL证书
            
        Returns:
            (是否存在漏洞, 详细信息)
        """
        request_config = poc.get('request', {})
        matchers = poc.get('matchers', [])
        
        if not request_config or not matchers:
            return False, "POC配置不完整"
        
        # 构建请求
        method = request_config.get('method', 'GET')
        path = request_config.get('path', '/')
        headers = request_config.get('headers', {})
        body = request_config.get('body', '')
        params = request_config.get('params', {})
        
        # 构建完整URL
        if path.startswith('/'):
            path = path[1:]
        url = target + path
        
        try:
            # 发送请求
            response = session.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                params=params,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True
            )
            
            # 应用匹配器
            for matcher in matchers:
                matcher_type = matcher.get('type', 'status')
                
                if matcher_type == 'status':
                    # 状态码匹配
                    status = matcher.get('status', [200])
                    if response.status_code in status:
                        return True, f"状态码匹配: {response.status_code}"
                
                elif matcher_type == 'body':
                    # 响应体匹配
                    pattern = matcher.get('pattern', '')
                    if pattern and re.search(pattern, response.text, re.IGNORECASE):
                        return True, f"响应体匹配: {pattern}"
                
                elif matcher_type == 'header':
                    # 响应头匹配
                    header = matcher.get('header', '')
                    pattern = matcher.get('pattern', '')
                    if header and pattern:
                        header_value = response.headers.get(header, '')
                        if re.search(pattern, header_value, re.IGNORECASE):
                            return True, f"响应头匹配: {header}={pattern}"
                
                elif matcher_type == 'regex':
                    # 正则表达式匹配
                    regex = matcher.get('regex', '')
                    if regex and re.search(regex, response.text):
                        return True, f"正则表达式匹配: {regex}"
            
            return False, "未匹配任何条件"
            
        except requests.RequestException as e:
            return False, f"请求异常: {str(e)}"
        except Exception as e:
            return False, f"执行异常: {str(e)}"
    
    def stop_scan(self) -> None:
        """停止正在执行的扫描"""
        if self.running:
            self.logger.info("正在停止POC扫描...")
            self.stop_event.set()
    
    def add_poc(self, poc_content: str, poc_name: str, poc_format: str = 'python') -> bool:
        """
        添加新的POC
        
        Args:
            poc_content: POC内容
            poc_name: POC名称
            poc_format: POC格式 (python或json)
            
        Returns:
            是否添加成功
        """
        try:
            # 确保POC目录存在
            if not os.path.exists(self.poc_dir):
                os.makedirs(self.poc_dir, exist_ok=True)
            
            # 生成文件名
            if not poc_name.lower().endswith(f'.{poc_format}'):
                filename = f"{poc_name}.{poc_format}"
            else:
                filename = poc_name
            
            # 写入POC文件
            poc_path = os.path.join(self.poc_dir, filename)
            with open(poc_path, 'w', encoding='utf-8') as f:
                f.write(poc_content)
            
            self.logger.info(f"成功添加POC: {filename}")
            
            # 重新加载POC
            self.load_all_pocs()
            return True
            
        except Exception as e:
            self.logger.error(f"添加POC失败: {str(e)}")
            return False
    
    def remove_poc(self, poc_id: str) -> bool:
        """
        删除POC
        
        Args:
            poc_id: POC ID
            
        Returns:
            是否删除成功
        """
        try:
            # 查找POC文件
            poc_path = None
            for ext in ['py', 'json']:
                path = os.path.join(self.poc_dir, f"{poc_id}.{ext}")
                if os.path.exists(path):
                    poc_path = path
                    break
            
            if not poc_path:
                self.logger.warning(f"未找到POC文件: {poc_id}")
                return False
            
            # 删除POC文件
            os.remove(poc_path)
            self.logger.info(f"成功删除POC: {poc_id}")
            
            # 从内存中移除
            if poc_id in self.pocs:
                del self.pocs[poc_id]
            
            return True
            
        except Exception as e:
            self.logger.error(f"删除POC失败: {str(e)}")
            return False
    
    def get_poc_list(self) -> List[Dict[str, Any]]:
        """
        获取POC列表
        
        Returns:
            POC信息列表
        """
        result = []
        for poc_id, poc in self.pocs.items():
            poc_info = {
                'id': poc_id,
                'name': poc.get('name', poc_id),
                'description': poc.get('description', '无描述'),
                'author': poc.get('author', '未知'),
                'type': poc.get('type', '未分类'),
                'severity': poc.get('severity', 'medium'),
                'format': poc.get('format', 'unknown')
            }
            result.append(poc_info)
        
        return result
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """验证配置"""
        # 检查POC目录是否有效
        poc_dir = self.config.get("poc_dir", self.DEFAULT_POC_DIR)
        if poc_dir and not os.path.exists(poc_dir):
            try:
                os.makedirs(poc_dir, exist_ok=True)
            except Exception as e:
                return False, f"无法创建POC目录: {str(e)}"
        
        # 检查线程数是否合理
        max_threads = self.config.get("max_threads", 10)
        if not isinstance(max_threads, int) or max_threads <= 0:
            return False, "线程数必须是正整数"
        
        return True, None 