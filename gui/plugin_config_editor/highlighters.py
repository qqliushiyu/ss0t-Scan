#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置文件语法高亮器模块
提供JSON和YAML文件的语法高亮功能
"""

import re
from PyQt5.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont

class JsonSyntaxHighlighter(QSyntaxHighlighter):
    """JSON语法高亮器"""
    
    def __init__(self, parent=None):
        """初始化语法高亮器"""
        super().__init__(parent)
        
        # 语法高亮规则
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor(0, 0, 255))  # 蓝色
        self.keyword_format.setFontWeight(QFont.Bold)
        
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor(0, 128, 0))  # 绿色
        
        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor(128, 0, 128))  # 紫色
        
        self.boolean_format = QTextCharFormat()
        self.boolean_format.setForeground(QColor(255, 0, 0))  # 红色
        self.boolean_format.setFontWeight(QFont.Bold)
        
        self.bracket_format = QTextCharFormat()
        self.bracket_format.setForeground(QColor(128, 128, 128))  # 灰色
        self.bracket_format.setFontWeight(QFont.Bold)
        
        # 简单的JSON语法高亮规则
        # 完整的JSON解析需要更复杂的状态机，这里只做简单处理
        self.string_regex = r'"[^"\\]*(\\.[^"\\]*)*"'
        self.number_regex = r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b'
        self.keyword_regex = r'\b(true|false|null)\b'
        self.bracket_regex = r'[\{\}\[\],:]'
    
    def highlightBlock(self, text: str):
        """
        对文本块进行高亮处理
        
        Args:
            text: 文本块内容
        """
        # 字符串
        for match in re.finditer(self.string_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.string_format)
        
        # 数字
        for match in re.finditer(self.number_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.number_format)
        
        # 关键字
        for match in re.finditer(self.keyword_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.boolean_format)
        
        # 括号和冒号
        for match in re.finditer(self.bracket_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.bracket_format)


class YamlSyntaxHighlighter(QSyntaxHighlighter):
    """YAML语法高亮器"""
    
    def __init__(self, parent=None):
        """初始化语法高亮器"""
        super().__init__(parent)
        
        # 语法高亮规则
        self.key_format = QTextCharFormat()
        self.key_format.setForeground(QColor(0, 0, 255))  # 蓝色
        self.key_format.setFontWeight(QFont.Bold)
        
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor(0, 128, 0))  # 绿色
        
        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor(128, 0, 128))  # 紫色
        
        self.boolean_format = QTextCharFormat()
        self.boolean_format.setForeground(QColor(255, 0, 0))  # 红色
        self.boolean_format.setFontWeight(QFont.Bold)
        
        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor(128, 128, 128))  # 灰色
        self.comment_format.setFontItalic(True)
        
        # YAML语法高亮规则
        self.key_regex = r'^(\s*)([^:]+):'
        self.string_regex = r'"[^"\\]*(\\.[^"\\]*)*"|\'[^\'\\]*(\\.[^\'\\]*)*\''
        self.number_regex = r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b'
        self.boolean_regex = r'\b(true|false|yes|no|on|off)\b'
        self.comment_regex = r'#.*$'
    
    def highlightBlock(self, text: str):
        """
        对文本块进行高亮处理
        
        Args:
            text: 文本块内容
        """
        # 注释
        for match in re.finditer(self.comment_regex, text, re.MULTILINE):
            start, end = match.span()
            self.setFormat(start, end - start, self.comment_format)
        
        # 键
        for match in re.finditer(self.key_regex, text, re.MULTILINE):
            indent, key = match.groups()
            start = len(indent)
            self.setFormat(start, len(key), self.key_format)
        
        # 字符串
        for match in re.finditer(self.string_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.string_format)
        
        # 数字
        for match in re.finditer(self.number_regex, text):
            start, end = match.span()
            self.setFormat(start, end - start, self.number_format)
        
        # 布尔值
        for match in re.finditer(self.boolean_regex, text, re.IGNORECASE):
            start, end = match.span()
            self.setFormat(start, end - start, self.boolean_format) 