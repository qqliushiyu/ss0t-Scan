#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
扫描模块管理器
负责注册、获取和管理所有扫描模块
"""

import importlib
import inspect
import logging
import os
import pkgutil
import sys
from typing import Dict, List, Type, Any, Optional

from core.base_scanner import BaseScanner

# 配置日志
logger = logging.getLogger("scanner.manager")

class ScannerManager:
    """
    扫描模块管理器类
    负责发现、注册和管理所有扫描模块
    """

    def __init__(self):
        """初始化扫描模块管理器"""
        self._scanners: Dict[str, Type[BaseScanner]] = {}
        self._initialized = False
    
    def discover_scanners(self) -> None:
        """
        发现并注册所有可用的扫描模块
        自动搜索 core 和 plugins 目录中的扫描模块并注册
        """
        # 确保只初始化一次
        if self._initialized:
            return
        
        self._initialized = True
        
        # 扫描目录列表
        scan_dirs = ['core', 'plugins']
        
        for scan_dir in scan_dirs:
            if not os.path.exists(scan_dir):
                logger.warning(f"Directory {scan_dir} does not exist, skipping")
                continue
            
            logger.info(f"Discovering scanners in {scan_dir}")
            
            # 添加到 Python 路径
            if scan_dir not in sys.path:
                sys.path.insert(0, scan_dir)
            
            # 遍历目录中的所有模块
            for _, name, is_pkg in pkgutil.iter_modules([scan_dir]):
                if is_pkg:
                    continue  # 跳过包，只处理模块
                
                if name == 'base_scanner' or name == 'scanner_manager':
                    continue  # 跳过基础模块
                
                try:
                    # 导入模块
                    module_path = f"{scan_dir}.{name}" if scan_dir != '.' else name
                    module = importlib.import_module(module_path)
                    
                    # 查找模块中的扫描器类 (继承自 BaseScanner)
                    for item_name, item in inspect.getmembers(module, inspect.isclass):
                        if (issubclass(item, BaseScanner) and 
                            item != BaseScanner and
                            not item.__name__.startswith('_')):
                            
                            module_id = item.__name__.lower()
                            self._scanners[module_id] = item
                            logger.info(f"Registered scanner: {item.__name__}")
                
                except (ImportError, AttributeError) as e:
                    logger.error(f"Error importing module {name}: {str(e)}")
        
        logger.info(f"Total {len(self._scanners)} scanners registered")
    
    def register_scanner(self, scanner_class: Type[BaseScanner]) -> None:
        """
        手动注册扫描模块
        
        Args:
            scanner_class: 扫描器类，必须继承自 BaseScanner
        """
        if not issubclass(scanner_class, BaseScanner):
            raise TypeError("Scanner class must inherit from BaseScanner")
        
        module_id = scanner_class.__name__.lower()
        self._scanners[module_id] = scanner_class
        logger.info(f"Manually registered scanner: {scanner_class.__name__}")
    
    def get_scanner(self, module_id: str) -> Optional[Type[BaseScanner]]:
        """
        获取扫描器类
        
        Args:
            module_id: 模块ID（类名的小写形式）
        
        Returns:
            Scanner class or None if not found
        """
        return self._scanners.get(module_id.lower())
    
    def create_scanner(self, module_id: str, config: Dict[str, Any] = None) -> Optional[BaseScanner]:
        """
        创建扫描器实例
        
        Args:
            module_id: 模块ID（类名的小写形式）
            config: 扫描器配置
        
        Returns:
            Scanner instance or None if not found
        """
        scanner_class = self.get_scanner(module_id)
        if scanner_class:
            return scanner_class(config or {})
        return None
    
    def get_all_scanners(self) -> Dict[str, Type[BaseScanner]]:
        """
        获取所有注册的扫描器
        
        Returns:
            所有扫描器类的字典 {module_id: scanner_class}
        """
        return self._scanners.copy()
    
    def get_scanner_info_list(self) -> List[Dict[str, Any]]:
        """
        获取所有扫描器的基本信息列表
        
        Returns:
            扫描器信息列表
        """
        result = []
        for module_id, scanner_class in self._scanners.items():
            info = scanner_class.get_scanner_info()
            info['module_id'] = module_id
            result.append(info)
        return result


# 单例模式，全局扫描模块管理器实例
scanner_manager = ScannerManager() 