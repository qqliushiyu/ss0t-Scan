#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基础扫描器模块
为所有网络工具模块提供统一的接口和基础功能
"""

import abc
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple, Callable

# 配置日志格式
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scanner.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class ScanResult:
    """扫描结果数据类"""
    success: bool
    data: List[Dict[str, Any]]
    error_msg: Optional[str] = None
    start_time: float = 0.0
    end_time: float = 0.0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        """初始化后处理"""
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def duration(self) -> float:
        """返回扫描持续时间（秒）"""
        return self.end_time - self.start_time
    
    @property
    def record_count(self) -> int:
        """返回结果记录数量"""
        return len(self.data)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "success": self.success,
            "data": self.data,
            "error_msg": self.error_msg,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(self.end_time).isoformat(),
            "duration": self.duration,
            "record_count": self.record_count,
            "metadata": self.metadata
        }


class BaseScanner(abc.ABC):
    """
    扫描器基类
    所有网络工具模块都应继承此类并实现其抽象方法
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化扫描器
        
        Args:
            config: 扫描器配置字典
        """
        self.module_name = self.__class__.__name__
        self.config = config or {}
        self.logger = logging.getLogger(f"scanner.{self.module_name}")
        self.task_id = str(uuid.uuid4())
        self.result = None
        self.running = False
        # 进度回调函数
        self.progress_callback = None
    
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
    
    @abc.abstractmethod
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证配置参数是否有效
        
        Returns:
            (成功标志, 错误信息)
        """
        pass
    
    @abc.abstractmethod
    def run_scan(self) -> ScanResult:
        """
        执行扫描操作
        
        Returns:
            ScanResult: 扫描结果对象
        """
        pass
    
    def execute(self) -> ScanResult:
        """
        执行扫描并返回结果
        
        Returns:
            ScanResult: 扫描结果对象
        """
        if self.running:
            self.logger.warning(f"Scanner {self.module_name} is already running")
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"Scanner {self.module_name} is already running"
            )
        
        self.running = True
        self.logger.info(f"Starting {self.module_name} scan with task_id: {self.task_id}")
        
        # 更新初始进度
        self.update_progress(0, f"正在启动 {self.module_name} 扫描...")
        
        # 验证配置
        is_valid, error_msg = self.validate_config()
        if not is_valid:
            self.logger.error(f"Configuration validation failed: {error_msg}")
            self.running = False
            return ScanResult(success=False, data=[], error_msg=error_msg)
        
        try:
            self.update_progress(5, "验证配置成功，开始扫描...")
            start_time = time.time()
            result = self.run_scan()
            end_time = time.time()
            
            # 更新时间信息
            result.start_time = start_time
            result.end_time = end_time
            
            # 记录结果
            self.result = result
            self.logger.info(
                f"Scan completed: {self.module_name}, records: {result.record_count}, "
                f"duration: {result.duration:.2f}s"
            )
            
            # 最终进度更新
            if result.success:
                self.update_progress(100, f"扫描完成，获取到 {result.record_count} 条记录")
            else:
                self.update_progress(100, f"扫描失败: {result.error_msg}")
            
            return result
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}", exc_info=True)
            self.update_progress(100, f"扫描异常: {str(e)}")
            return ScanResult(
                success=False,
                data=[],
                error_msg=f"Scan error: {str(e)}",
                start_time=time.time(),
                end_time=time.time()
            )
        finally:
            self.running = False
    
    def stop(self) -> None:
        """停止扫描"""
        if self.running:
            self.logger.info(f"Stopping scan: {self.module_name}")
            self.update_progress(100, "扫描已停止")
            self.running = False
    
    @classmethod
    def get_scanner_info(cls) -> Dict[str, Any]:
        """
        获取扫描器基本信息
        
        Returns:
            Dict: 包含名称、描述等信息的字典
        """
        return {
            "name": cls.__name__,
            "description": cls.__doc__.strip() if cls.__doc__ else "No description",
            "version": getattr(cls, "VERSION", "1.0.0")
        } 