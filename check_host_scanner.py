#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.scanner_manager import scanner_manager

# 发现扫描器
scanner_manager.discover_scanners()

# 尝试获取HostScanner
host_scanner = scanner_manager.get_scanner("hostscanner")
print(f"HostScanner class: {host_scanner}")

# 打印所有已注册的扫描器
print("\n所有已注册的扫描器:")
for scanner_id, scanner_class in scanner_manager.get_all_scanners().items():
    print(f"{scanner_id} -> {scanner_class.__name__}") 