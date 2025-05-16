#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web风险扫描插件基类
定义所有Web风险扫描插件必须实现的接口
"""

import abc
import logging
from typing import Dict, List, Any, Optional, Tuple

class WebRiskPlugin(abc.ABC):
    """
    Web风险扫描插件基类
    所有Web风险扫描插件必须继承这个类并实现其抽象方法
    """
    
    # 插件元数据
    NAME = "基础插件"
    DESCRIPTION = "Web风险扫描插件基类"
    VERSION = "1.0.0"
    AUTHOR = "ss0t-scna"
    CATEGORY = "安全"  # 可以是"漏洞检测", "信息收集", "安全配置", "指纹识别"等
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化插件
        
        Args:
            config: 插件配置
        """
        self.config = config or {}
        self.logger = logging.getLogger(f"plugins.web_risk.{self.__class__.__name__}")
        self._enabled = True
    
    @property
    def enabled(self) -> bool:
        """获取插件启用状态"""
        return self._enabled
    
    @enabled.setter
    def enabled(self, value: bool) -> None:
        """设置插件启用状态"""
        self._enabled = value
    
    @abc.abstractmethod
    def check(self, target: str, session=None, **kwargs) -> List[Dict[str, Any]]:
        """
        执行检查
        
        Args:
            target: 目标URL
            session: 可选的HTTP会话对象
            **kwargs: 其他参数
            
        Returns:
            检查结果列表
        """
        pass
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """
        验证插件配置
        
        Returns:
            (是否有效, 错误消息)
        """
        return True, None
    
    def get_info(self) -> Dict[str, Any]:
        """
        获取插件信息
        
        Returns:
            插件信息字典
        """
        return {
            "name": self.NAME,
            "description": self.DESCRIPTION,
            "version": self.VERSION,
            "author": self.AUTHOR,
            "category": self.CATEGORY,
            "class_name": self.__class__.__name__
        }
    
    def __repr__(self) -> str:
        """字符串表示"""
        return f"<{self.__class__.__name__} {self.NAME} v{self.VERSION}>" 