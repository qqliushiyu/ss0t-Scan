#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web风险扫描插件包
包含各种Web安全风险检测插件
"""

import logging
from typing import List

logger = logging.getLogger(__name__)

# 尝试导入可能存在的插件模块
try:
    from .secure_headers import SecurityHeadersCheck
except ImportError:
    SecurityHeadersCheck = None

try:
    from .xss_scanner import XSSScanner
except ImportError:
    XSSScanner = None

try:
    from .sql_injection import SQLInjectionScanner
except ImportError:
    SQLInjectionScanner = None

try:
    from .vuln_scanner import VulnScanner
except ImportError:
    VulnScanner = None

try:
    from .waf_detector import WAFDetector
except ImportError:
    WAFDetector = None

try:
    from .fingerprint_scanner import FingerprintScanner
except ImportError:
    FingerprintScanner = None


# 在插件管理器中注册所有Web风险扫描插件
def register_plugins(plugin_manager):
    """向插件管理器注册Web风险扫描插件"""
    # 注册已导入的插件类
    plugins = [
        SecurityHeadersCheck,
        XSSScanner,
        SQLInjectionScanner,
        VulnScanner, 
        WAFDetector,
        FingerprintScanner
    ]
    
    registered_count = 0
    for plugin_class in plugins:
        if plugin_class is not None:
            try:
                plugin_manager.register_plugin(plugin_class)
                registered_count += 1
            except Exception as e:
                logger.error(f"注册插件 {plugin_class.__name__} 失败: {e}")
    
    logger.info(f"已注册 {registered_count} 个Web风险扫描插件")
    
    return registered_count 