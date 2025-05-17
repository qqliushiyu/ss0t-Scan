#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.scanner_manager import scanner_manager

# 发现扫描器
scanner_manager.discover_scanners()

# 获取并打印所有扫描器
print("已注册的所有扫描器:")
for scanner_id, scanner_class in scanner_manager.get_all_scanners().items():
    print(f"{scanner_id} -> {scanner_class.__name__}")

# 特别检查HostScanner
host_scanner = scanner_manager.get_scanner("hostscanner")
if host_scanner:
    print(f"\nHostScanner类已成功注册: {host_scanner.__name__}")
else:
    print("\n错误: HostScanner类未成功注册!")

# 尝试使用不同的ID获取HostScanner
alternate_ids = ["host_scanner", "host-scanner", "hostscan", "hostscanner"]
for alt_id in alternate_ids:
    scanner = scanner_manager.get_scanner(alt_id)
    if scanner and "Host" in scanner.__name__:
        print(f"使用ID '{alt_id}'找到了HostScanner: {scanner.__name__}") 