#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件系统包
用于支持Web风险扫描插件管理
"""

from plugins.plugin_manager import plugin_manager
from plugins.base_plugin import WebRiskPlugin

__all__ = ['plugin_manager', 'WebRiskPlugin'] 