#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
POC扫描核心模块
提供基于POC的批量漏洞验证功能
"""

import os
import time
import logging
import requests
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor

from core.base_scanner import BaseScanner, ScanResult
from plugins.plugin_manager import PluginManager

# 初始化插件管理器
plugin_manager = PluginManager()

class POCScanner(BaseScanner):
    """POC扫描器，用于批量执行POC验证"""
    
    VERSION = "1.0.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化POC扫描器
        
        Args:
            config: 扫描器配置
        """
        super().__init__(config)
        self.logger = logging.getLogger("scanner.poc_scan")
        
        # 初始化插件管理器
        plugin_manager.discover_plugins()
        
        # POC扫描配置
        self.targets = self.config.get('targets', [])
        self.threads = min(int(self.config.get('threads', 10)), 50)  # 限制最大线程数
        self.timeout = int(self.config.get('timeout', 10))
        self.verify_ssl = bool(self.config.get('verify_ssl', False))
        self.scan_depth = int(self.config.get('scan_depth', 1))
        self.selected_pocs = self.config.get('selected_pocs', [])
        
        # HTTP会话
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.110'
        })
        
        # 扫描控制
        self.scan_started = False
        self.scan_stopped = False
        
        # 扫描结果
        self.results = []
        
        # 获取POC插件
        self.poc_plugin = plugin_manager.get_plugin('pocscanner')
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """验证扫描配置是否有效"""
        # 检查目标
        if not self.targets:
            return False, "请指定扫描目标"
        
        # 检查线程数
        if self.threads <= 0:
            return False, "线程数必须大于0"
        
        # 检查扫描深度
        if self.scan_depth not in [0, 1, 2]:
            return False, "扫描深度必须是0-2之间的整数"
        
        # 检查POC插件是否可用
        if not self.poc_plugin:
            # 尝试初始化插件
            plugin_manager.init_plugins()
            self.poc_plugin = plugin_manager.get_plugin('pocscanner')
            if not self.poc_plugin:
                return False, "POC扫描插件不可用"
        
        return True, None
    
    def run_scan(self) -> ScanResult:
        """
        执行POC扫描
        
        Returns:
            扫描结果对象
        """
        self.scan_started = True
        self.scan_stopped = False
        self.results = []
        
        # 初始化进度
        self.update_progress(5, "正在准备POC扫描...")
        
        try:
            # 解析目标列表
            if isinstance(self.targets, str):
                targets = [t.strip() for t in self.targets.split(',') if t.strip()]
            elif isinstance(self.targets, list):
                targets = self.targets
            else:
                targets = []
            
            # 确保所有目标都以http://或https://开头
            processed_targets = []
            for target in targets:
                if not target.startswith(('http://', 'https://')):
                    target = 'http://' + target
                processed_targets.append(target)
            
            if not processed_targets:
                return ScanResult(
                    success=False,
                    data=[],
                    error_msg="没有有效的扫描目标"
                )
            
            target_count = len(processed_targets)
            self.logger.info(f"开始POC扫描，共 {target_count} 个目标")
            self.update_progress(10, f"开始扫描 {target_count} 个目标...")
            
            # 获取或初始化POC插件
            if not self.poc_plugin:
                self.poc_plugin = plugin_manager.get_plugin('pocscanner')
                if not self.poc_plugin:
                    return ScanResult(
                        success=False,
                        data=[],
                        error_msg="无法初始化POC扫描插件"
                    )
            
            # 设置POC插件的进度回调
            self.poc_plugin.set_progress_callback(self._handle_poc_progress)
            
            # 根据扫描深度过滤POC
            poc_list = self.poc_plugin.get_poc_list()
            if self.scan_depth == 0:
                # 最小扫描，跳过POC
                filtered_pocs = []
            elif self.scan_depth == 1:
                # 标准扫描，只使用critical和high级别的POC
                filtered_pocs = [p for p in poc_list if p.get('severity') in ['critical', 'high']]
            else:
                # 深度扫描，使用所有POC
                filtered_pocs = poc_list
            
            # 如果指定了特定POC，则过滤
            if self.selected_pocs:
                filtered_pocs = [p for p in filtered_pocs if p.get('id') in self.selected_pocs]
            
            # 检查是否有可用POC
            if not filtered_pocs:
                self.logger.warning("没有可用的POC或适合当前扫描深度的POC")
                return ScanResult(
                    success=True,
                    data=[{
                        "check_type": "poc_scan",
                        "status": "info",
                        "details": "没有可用的POC或适合当前扫描深度的POC"
                    }]
                )
            
            poc_count = len(filtered_pocs)
            self.logger.info(f"加载了 {poc_count} 个POC，开始扫描...")
            
            # 使用线程池并发扫描
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # 提交所有扫描任务
                futures = []
                for target in processed_targets:
                    if self.scan_stopped:
                        break
                    futures.append(
                        executor.submit(
                            self.scan_target, 
                            target
                        )
                    )
                
                # 处理扫描结果
                completed = 0
                for future in futures:
                    if self.scan_stopped:
                        break
                    
                    completed += 1
                    progress = int(10 + (85 * completed / len(futures)))
                    self.update_progress(
                        progress, 
                        f"已完成 {completed}/{len(futures)} 个目标"
                    )
                    
                    try:
                        target_results = future.result()
                        if target_results:
                            self.results.extend(target_results)
                    except Exception as e:
                        self.logger.error(f"获取扫描结果时出错: {str(e)}")
            
            # 扫描完成
            self.logger.info(f"POC扫描完成，发现 {len(self.results)} 个漏洞")
            
            # 对扫描结果做一些统计
            vuln_targets = set()
            vuln_types = {}
            
            for result in self.results:
                if result.get("status") == "vulnerable":
                    vuln_targets.add(result.get("url", "").split('/')[2])
                    
                    vuln_type = result.get("vulnerability", "未知漏洞")
                    if vuln_type in vuln_types:
                        vuln_types[vuln_type] += 1
                    else:
                        vuln_types[vuln_type] = 1
            
            # 添加扫描统计摘要
            summary = {
                "check_type": "poc_scan_summary",
                "total_targets": target_count,
                "vulnerable_targets": len(vuln_targets),
                "total_vulnerabilities": len([r for r in self.results if r.get("status") == "vulnerable"]),
                "vulnerability_types": vuln_types,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            }
            self.results.append(summary)
            
            return ScanResult(
                success=True,
                data=self.results,
                metadata={
                    "scan_type": "poc_scan",
                    "targets": targets,
                    "poc_count": poc_count,
                    "vulnerable_targets": len(vuln_targets)
                }
            )
            
        except Exception as e:
            self.logger.error(f"执行POC扫描时出错: {str(e)}", exc_info=True)
            return ScanResult(
                success=False,
                data=self.results,
                error_msg=f"扫描错误: {str(e)}"
            )
        finally:
            self.scan_started = False
    
    def scan_target(self, target: str) -> List[Dict[str, Any]]:
        """
        扫描单个目标
        
        Args:
            target: 目标URL
            
        Returns:
            扫描结果列表
        """
        try:
            # 执行POC检查
            results = self.poc_plugin.check(
                target=target,
                session=self.session,
                timeout=self.timeout,
                verify_ssl=self.verify_ssl,
                scan_depth=self.scan_depth
            )
            
            return results
            
        except Exception as e:
            self.logger.error(f"扫描目标 {target} 时出错: {str(e)}")
            return [{
                "check_type": "vulnerability",
                "vulnerability": "扫描错误",
                "url": target,
                "status": "error",
                "details": f"扫描过程中出错: {str(e)}"
            }]
    
    def _handle_poc_progress(self, percent: int, message: str) -> None:
        """
        处理POC插件的进度更新
        
        Args:
            percent: 进度百分比
            message: 进度消息
        """
        # 将POC插件的进度映射到整体进度的10-95%范围内
        overall_percent = 10 + (percent * 0.85)
        self.update_progress(int(overall_percent), message)
    
    def stop(self) -> None:
        """停止扫描"""
        if self.scan_started and not self.scan_stopped:
            self.logger.info("正在停止POC扫描...")
            self.scan_stopped = True
            
            # 停止POC插件的扫描
            if self.poc_plugin:
                self.poc_plugin.stop_scan()
            
            super().stop()
    
    def get_available_pocs(self) -> List[Dict[str, Any]]:
        """
        获取可用的POC列表
        
        Returns:
            POC信息列表
        """
        if not self.poc_plugin:
            self.poc_plugin = plugin_manager.get_plugin('pocscanner')
            if not self.poc_plugin:
                return []
        
        return self.poc_plugin.get_poc_list()
    
    def add_poc(self, poc_content: str, poc_name: str, poc_format: str = 'python') -> bool:
        """
        添加POC
        
        Args:
            poc_content: POC内容
            poc_name: POC名称
            poc_format: POC格式
            
        Returns:
            是否添加成功
        """
        if not self.poc_plugin:
            self.poc_plugin = plugin_manager.get_plugin('pocscanner')
            if not self.poc_plugin:
                return False
        
        return self.poc_plugin.add_poc(poc_content, poc_name, poc_format)
    
    def remove_poc(self, poc_id: str) -> bool:
        """
        删除POC
        
        Args:
            poc_id: POC ID
            
        Returns:
            是否删除成功
        """
        if not self.poc_plugin:
            self.poc_plugin = plugin_manager.get_plugin('pocscanner')
            if not self.poc_plugin:
                return False
        
        return self.poc_plugin.remove_poc(poc_id) 