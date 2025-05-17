#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
报告生成模块
为扫描结果生成HTML和PDF格式的报告
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# 创建日志记录器
logger = logging.getLogger(__name__)

def ensure_dir(directory: str) -> None:
    """确保目录存在，不存在则创建"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_report_filename(module_name: str, report_type: str) -> str:
    """
    生成报告文件名
    
    Args:
        module_name: 模块名称
        report_type: 报告类型（html, pdf）
    
    Returns:
        完整的文件名
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{module_name}_report_{timestamp}.{report_type}"

def generate_html_report(data: List[Dict[str, Any]], metadata: Dict[str, Any], output_file: str) -> str:
    """
    生成HTML格式的报告
    
    Args:
        data: 扫描结果数据
        metadata: 元数据信息
        output_file: 输出文件路径
    
    Returns:
        生成的HTML报告的完整路径
    """
    # 确保目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir:
        ensure_dir(output_dir)
    
    # 确保metadata不为None
    metadata = metadata or {}
    
    # 提取metadata中的信息
    target_urls = metadata.get("target_urls", []) or []
    alive_urls = metadata.get("alive_urls", []) or []  # 获取存活的URL列表
    scan_config = metadata.get("scan_config", {}) or {}
    plugin_info = metadata.get("plugin_info", []) or []
    module_name = metadata.get("module", "Web风险扫描")
    
    # 检查是否是POC扫描
    is_poc_scan = module_name.lower() in ["poc漏洞扫描", "poc_vulnerability_scan"]
    
    # 针对POC扫描的特殊处理
    if is_poc_scan:
        # 对于POC扫描，所有结果都是相关的
        alive_data = data
        
        # 统计信息
        total_urls = len(set([r.get("url", "") for r in alive_data if "url" in r]))
        total_vulns = len([r for r in alive_data if r.get("status") == "vulnerable"])
        total_headers = 0  # POC扫描不关注headers
        total_issues = total_vulns
        
        # 按URL分组
        url_results = {}
        for item in alive_data:
            url = item.get("url", "")
            if not url:
                continue
            if url not in url_results:
                url_results[url] = {
                    "vulnerabilities": [],
                    "headers": [],
                    "server_info": None,
                    "waf_info": None,
                    "ssl_info": None
                }
            
            # 只处理漏洞结果
            if item.get("status") == "vulnerable":
                url_results[url]["vulnerabilities"].append(item)
    else:
        # 原有的Web风险扫描逻辑
        # 统计信息 - 只统计存活URL的问题
        alive_data = [r for r in data if r.get("url", "") in alive_urls]
        
        total_urls = len(set([r.get("url", "") for r in alive_data if "url" in r]))
        total_vulns = len([r for r in alive_data if r.get("check_type") == "vulnerability" and r.get("status") == "vulnerable"])
        total_headers = len([r for r in alive_data if r.get("check_type") == "security_header" and r.get("status") == "missing"])
        total_issues = total_vulns + total_headers
        
        # 按URL分组 - 只处理存活的URL
        url_results = {}
        for item in alive_data:
            url = item.get("url", "")
            if not url:
                continue
            if url not in url_results:
                url_results[url] = {
                    "vulnerabilities": [],
                    "headers": [],
                    "server_info": None,
                    "waf_info": None,
                    "ssl_info": None
                }
            
            check_type = item.get("check_type", "")
            if check_type == "vulnerability" and item.get("status") == "vulnerable":
                url_results[url]["vulnerabilities"].append(item)
            elif check_type == "security_header":
                url_results[url]["headers"].append(item)
            elif check_type == "server_info":
                url_results[url]["server_info"] = item
            elif check_type == "waf":
                url_results[url]["waf_info"] = item
            elif check_type == "ssl":
                url_results[url]["ssl_info"] = item
    
    # 生成HTML内容
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{module_name}报告</title>
    <style>
        body {{
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .section {{
            margin-bottom: 25px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section-title {{
            border-bottom: 1px solid #ddd;
            padding-bottom: 8px;
            margin-top: 0;
            color: #2c3e50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .summary-box {{
            display: inline-block;
            padding: 10px 15px;
            margin: 10px;
            border-radius: 5px;
            text-align: center;
            min-width: 100px;
        }}
        .vulnerable {{
            color: white;
            background-color: #e74c3c;
        }}
        .warning {{
            color: white;
            background-color: #f39c12;
        }}
        .safe {{
            color: white;
            background-color: #2ecc71;
        }}
        .severity-high {{
            background-color: #e74c3c;
            color: white;
            padding: 3px 6px;
            border-radius: 3px;
        }}
        .severity-medium {{
            background-color: #f39c12;
            color: white;
            padding: 3px 6px;
            border-radius: 3px;
        }}
        .severity-low {{
            background-color: #3498db;
            color: white;
            padding: 3px 6px;
            border-radius: 3px;
        }}
        .status-missing {{
            color: #e74c3c;
        }}
        .status-present {{
            color: #2ecc71;
        }}
        .url-card {{
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }}
        .url-header {{
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
        }}
        .url-content {{
            padding: 15px;
        }}
        .subsection {{
            margin-bottom: 15px;
        }}
        .subsection-title {{
            font-weight: bold;
            border-bottom: 1px dashed #ccc;
            padding-bottom: 5px;
            margin-bottom: 10px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{module_name}报告</h1>
        <p>生成时间: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="section">
        <h2 class="section-title">扫描概要</h2>
        <div style="text-align: center;">
            <div class="summary-box {('vulnerable' if total_issues > 0 else 'safe')}">
                <h3>安全评分</h3>
                <p style="font-size: 24px; font-weight: bold;">{max(0, 100 - min(80, total_issues * 5))}分</p>
            </div>
            <div class="summary-box {('vulnerable' if total_vulns > 0 else 'safe')}">
                <h3>漏洞</h3>
                <p style="font-size: 24px; font-weight: bold;">{total_vulns}</p>
            </div>
            {'' if is_poc_scan else f'''
            <div class="summary-box {('warning' if total_headers > 0 else 'safe')}">
                <h3>配置问题</h3>
                <p style="font-size: 24px; font-weight: bold;">{total_headers}</p>
            </div>
            '''}
            <div class="summary-box">
                <h3>URL数量</h3>
                <p style="font-size: 24px; font-weight: bold;">{total_urls}</p>
            </div>
        </div>
        
        <h3>目标URL</h3>
        <ul>
            {''.join([f'<li>{url}</li>' for url in alive_urls])}
        </ul>
    </div>
    
    <div class="section">
        <h2 class="section-title">详细结果</h2>
"""
    
    # 按URL添加详细结果
    for url, url_data in url_results.items():
        # 计算风险评分
        vuln_count = len(url_data["vulnerabilities"])
        header_issues = len([h for h in url_data["headers"] if h.get("status") == "missing"])
        risk_score = max(0, 100 - min(80, vuln_count * 15 + header_issues * 5))
        
        server_info = url_data.get("server_info", {}) or {}
        server = server_info.get("server", "未知")
        technologies = ", ".join(server_info.get("technologies", []) or []) if server_info else "未知"
        
        waf_info = url_data.get("waf_info", {}) or {}
        waf_name = waf_info.get("waf_name", "未检测到") if waf_info else "未检测"
        
        ssl_info = url_data.get("ssl_info", {}) or {}
        tls_version = ssl_info.get("tls_version", "未知") if ssl_info else "未知"
        
        html_content += f"""
        <div class="url-card">
            <div class="url-header">
                <h3>{url}</h3>
                <p>风险评分: <span class="{('vulnerable' if risk_score < 60 else 'warning' if risk_score < 80 else 'safe')}">{risk_score}分</span> | 服务器: {server} | WAF: {waf_name}</p>
            </div>
            <div class="url-content">
"""
        
        # 漏洞信息
        if url_data["vulnerabilities"]:
            html_content += """
                <div class="subsection">
                    <h4 class="subsection-title">漏洞信息</h4>
                    <table>
                        <tr>
                            <th>漏洞类型</th>
                            <th>严重程度</th>
                            <th>详情</th>
                            <th>建议</th>
                        </tr>
"""
            for vuln in url_data["vulnerabilities"]:
                vuln_type = vuln.get("vulnerability", "未知")
                details = vuln.get("details", "")
                recommendation = vuln.get("recommendation", "")
                
                # 根据漏洞类型确定严重程度
                severity = "high"
                if vuln_type in ["敏感文件"]:
                    severity = "medium"
                elif vuln_type in ["信息泄露"]:
                    severity = "low"
                
                html_content += f"""
                        <tr>
                            <td>{vuln_type}</td>
                            <td><span class="severity-{severity}">{{"high": "高", "medium": "中", "low": "低"}}[severity]</span></td>
                            <td>{details}</td>
                            <td>{recommendation}</td>
                        </tr>
"""
            html_content += """
                    </table>
                </div>
"""
        
        # 安全响应头
        if url_data["headers"]:
            html_content += """
                <div class="subsection">
                    <h4 class="subsection-title">安全响应头</h4>
                    <table>
                        <tr>
                            <th>响应头</th>
                            <th>状态</th>
                            <th>说明</th>
                            <th>建议</th>
                        </tr>
"""
            for header in url_data["headers"]:
                header_name = header.get("header", "")
                status = header.get("status", "")
                description = header.get("description", "")
                recommendation = header.get("recommendation", "")
                
                html_content += f"""
                        <tr>
                            <td>{header_name}</td>
                            <td class="status-{status}">{{"missing": "缺失", "present": "存在"}}[status]</td>
                            <td>{description}</td>
                            <td>{recommendation}</td>
                        </tr>
"""
            html_content += """
                    </table>
                </div>
"""
        
        # 服务器和技术信息
        html_content += f"""
                <div class="subsection">
                    <h4 class="subsection-title">服务器信息</h4>
                    <p><strong>服务器:</strong> {server}</p>
                    <p><strong>技术栈:</strong> {technologies}</p>
                    <p><strong>WAF保护:</strong> {waf_name}</p>
"""
        
        # SSL/TLS信息（如果有）
        if ssl_info:
            cert_issuer = ssl_info.get("issuer", {}).get("commonName", "未知")
            cert_subject = ssl_info.get("subject", {}).get("commonName", "未知")
            cert_expiry = ssl_info.get("not_after", "未知")
            
            html_content += f"""
                    <p><strong>TLS版本:</strong> {tls_version}</p>
                    <p><strong>证书发行方:</strong> {cert_issuer}</p>
                    <p><strong>证书主题:</strong> {cert_subject}</p>
                    <p><strong>过期时间:</strong> {cert_expiry}</p>
"""
        
        html_content += """
                </div>
            </div>
        </div>
"""
    
    # 添加扫描配置和插件信息部分
    html_content += """
    </div>
    
    <div class="section">
        <h2 class="section-title">扫描配置</h2>
        <table>
            <tr>
                <th>配置项</th>
                <th>值</th>
            </tr>
"""
    
    # 过滤和显示重要配置项
    important_configs = [
        "threads", "timeout", "verify_ssl", "follow_redirects", 
        "scan_headers", "scan_ssl", "user_agent"
    ]
    
    for key in important_configs:
        if key in scan_config:
            html_content += f"""
            <tr>
                <td>{key}</td>
                <td>{scan_config[key]}</td>
            </tr>
"""
    
    html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2 class="section-title">使用的插件</h2>
        <table>
            <tr>
                <th>插件名称</th>
                <th>版本</th>
                <th>描述</th>
            </tr>
"""
    
    for plugin in plugin_info:
        plugin_name = plugin.get("name", "")
        plugin_version = plugin.get("version", "")
        plugin_description = plugin.get("description", "")
        
        html_content += f"""
            <tr>
                <td>{plugin_name}</td>
                <td>{plugin_version}</td>
                <td>{plugin_description}</td>
            </tr>
"""
    
    html_content += """
        </table>
    </div>
    
    <div class="footer">
        <p>此报告由ss0t-Scan Web风险扫描模块生成</p>
        <p>© {0} 版权所有</p>
    </div>
</body>
</html>
""".format(datetime.datetime.now().year)
    
    # 写入HTML文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"已生成HTML报告: {output_file}")
    return os.path.abspath(output_file)

def generate_simple_pdf_with_reportlab(html_report_path: str) -> Optional[str]:
    """
    使用reportlab库生成一个简单的PDF报告
    不依赖于外部工具，但生成的PDF报告内容比较简单
    
    Args:
        html_report_path: HTML报告路径
    
    Returns:
        生成的PDF报告路径，如果生成失败则返回None
    """
    if not os.path.exists(html_report_path):
        logger.error(f"HTML报告文件不存在: {html_report_path}")
        return None
    
    pdf_path = html_report_path.replace('.html', '.pdf')
    
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        
        # 提取HTML报告的基本内容
        with open(html_report_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # 创建PDF文档
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        
        # 添加自定义样式
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            alignment=1,  # 居中
        ))
        
        # 提取报告标题和日期信息
        import re
        title = "Web风险扫描报告"
        date_match = re.search(r"生成时间: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", html_content)
        date = date_match.group(1) if date_match else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 提取目标URL信息
        urls = []
        url_match = re.findall(r"<li>(https?://[^<]+)</li>", html_content)
        if url_match:
            urls = url_match
        
        # 创建报告内容
        story = []
        
        # 添加标题
        story.append(Paragraph(title, styles['CustomTitle']))
        story.append(Spacer(1, 12))
        
        # 添加生成日期
        story.append(Paragraph(f"生成时间: {date}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # 添加目标URL
        if urls:
            story.append(Paragraph("扫描目标:", styles['Heading2']))
            story.append(Spacer(1, 6))
            for url in urls:
                story.append(Paragraph(f"• {url}", styles['Normal']))
                story.append(Spacer(1, 4))
        
        # 提取漏洞信息
        vuln_data = []
        vuln_match = re.findall(r'<td>(.+?)</td>\s*<td>.+?</td>\s*<td>(.+?)</td>\s*<td>(.+?)</td>', html_content)
        if vuln_match:
            story.append(Spacer(1, 12))
            story.append(Paragraph("漏洞信息", styles['Heading2']))
            story.append(Spacer(1, 6))
            
            vuln_table_data = [["漏洞类型", "详情", "建议"]]
            for vuln in vuln_match:
                vuln_table_data.append([vuln[0], vuln[1], vuln[2]])
            
            if len(vuln_table_data) > 1:
                vuln_table = Table(vuln_table_data, repeatRows=1)
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                story.append(vuln_table)
            else:
                story.append(Paragraph("未发现漏洞", styles['Normal']))
        
        # 添加注释
        story.append(Spacer(1, 30))
        story.append(Paragraph("注意: 此报告为简化版PDF，完整报告内容请参考HTML报告。", styles['Italic']))
        story.append(Paragraph(f"HTML报告路径: {os.path.basename(html_report_path)}", styles['Italic']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"此报告由Web风险扫描模块生成 © {datetime.datetime.now().year}", styles['Normal']))
        
        # 生成PDF
        doc.build(story)
        logger.info(f"已使用reportlab生成简化版PDF报告: {pdf_path}")
        return os.path.abspath(pdf_path)
        
    except Exception as e:
        logger.error(f"使用reportlab生成PDF报告时出错: {str(e)}")
        return None

def generate_pdf_report(html_report_path: str) -> Optional[str]:
    """
    将HTML报告转换为PDF格式
    
    Args:
        html_report_path: HTML报告路径
    
    Returns:
        生成的PDF报告路径，如果生成失败则返回None
    """
    if not os.path.exists(html_report_path):
        logger.error(f"HTML报告文件不存在: {html_report_path}")
        return None
    
    pdf_path = html_report_path.replace('.html', '.pdf')
    
    # 首先尝试使用优化后的外部工具
    external_success = False
    
    # 1. 尝试使用纯Python的reportlab库生成PDF (最可靠)
    logger.info("尝试使用reportlab生成PDF报告...")
    reportlab_pdf = generate_simple_pdf_with_reportlab(html_report_path)
    if reportlab_pdf and os.path.exists(reportlab_pdf):
        logger.info(f"已使用reportlab生成简化版PDF报告: {reportlab_pdf}")
        return reportlab_pdf
    
    # 2. 如果简化版不满足需求，尝试使用外部工具生成完整版PDF
    # 优先使用更可靠的pdfkit (wkhtmltopdf)
    if not external_success:
        try:
            # 重定向标准错误输出以捕获Qt警告
            import sys
            import os
            from contextlib import contextmanager
            
            @contextmanager
            def suppress_stderr():
                """临时重定向标准错误输出"""
                # 保存当前的stderr
                original_stderr = sys.stderr
                # 重定向到/dev/null或NUL
                if os.name == 'nt':  # Windows
                    with open('NUL', 'w') as devnull:
                        sys.stderr = devnull
                        try:
                            yield
                        finally:
                            sys.stderr = original_stderr
                else:  # Unix/Linux
                    with open('/dev/null', 'w') as devnull:
                        sys.stderr = devnull
                        try:
                            yield
                        finally:
                            sys.stderr = original_stderr
            
            # 导入pdfkit库
            import pdfkit
            
            # 配置wkhtmltopdf路径
            config = None
            wkhtmltopdf_paths = [
                r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',  # 标准安装路径
                r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',  # 32位程序路径
                os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'bin', 'wkhtmltopdf.exe')  # 项目内置路径
            ]
            
            # 在Windows系统上查找wkhtmltopdf
            if os.name == 'nt':
                for path in wkhtmltopdf_paths:
                    if os.path.exists(path):
                        config = pdfkit.configuration(wkhtmltopdf=path)
                        break
                
                # 如果没有找到预定义路径中的可执行文件，则尝试使用PATH中的
                if config is None:
                    try:
                        # 尝试使用未指定路径的配置（依赖PATH环境变量）
                        config = pdfkit.configuration()
                    except Exception:
                        pass
            
            # 设置选项以处理中文和其他特殊字符
            options = {
                'encoding': 'UTF-8',
                'quiet': '',
                'no-outline': None  # 避免生成目录，可能会导致一些Qt问题
            }
            
            # 转换为PDF，使用上下文管理器抑制stderr输出
            with suppress_stderr():
                pdfkit.from_file(html_report_path, pdf_path, configuration=config, options=options)
            
            # 检查文件是否真的生成了
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                logger.info(f"已使用pdfkit生成PDF报告: {pdf_path}")
                external_success = True
                return os.path.abspath(pdf_path)
            else:
                logger.warning("pdfkit似乎生成了文件，但文件可能损坏或为空")
                    
        except ImportError:
            logger.info("pdfkit未安装，跳过此方法")
        except Exception as e:
            logger.warning(f"使用pdfkit生成PDF报告失败: {str(e)}")
    
    # 如果pdfkit失败，尝试使用weasyprint
    if not external_success:
        try:
            from weasyprint import HTML
            
            # 将HTML转换为PDF
            HTML(html_report_path).write_pdf(pdf_path)
            
            # 检查文件是否真的生成了
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                logger.info(f"已使用weasyprint生成PDF报告: {pdf_path}")
                external_success = True
                return os.path.abspath(pdf_path)
            else:
                logger.warning("weasyprint似乎生成了文件，但文件可能损坏或为空")
                
        except ImportError:
            logger.warning("未安装weasyprint库")
        except Exception as e:
            logger.error(f"使用weasyprint生成PDF报告时出错: {str(e)}")
    
    # 如果外部工具都失败了但我们已经有了reportlab生成的PDF
    if reportlab_pdf and os.path.exists(reportlab_pdf):
        return reportlab_pdf
    
    return None

def generate_report(data: List[Dict[str, Any]], metadata: Dict[str, Any], 
                   output_dir: str = 'reports', format_type: str = 'html') -> Optional[str]:
    """
    生成Web风险扫描报告
    
    Args:
        data: 扫描结果数据
        metadata: 元数据
        output_dir: 输出目录
        format_type: 报告格式（html 或 pdf）
    
    Returns:
        生成的报告文件路径，失败返回None
    """
    # 确保数据不为None
    data = data or []
    metadata = metadata or {}
    
    # 如果没有数据，记录警告并返回None
    if not data:
        logger.warning("没有扫描结果数据，无法生成报告")
        return None
    
    # 获取模块名称，默认为web_risk_scan
    module_name = metadata.get("module", "web_risk_scan").lower().replace(" ", "_")
    
    # 获取存活URL列表
    alive_urls = metadata.get("alive_urls", [])
    
    # 如果是POC扫描模块并且没有存活URLs，则从数据中提取URLs
    if module_name == "poc漏洞扫描" or module_name == "poc_vulnerability_scan":
        # 将模块名称标准化为英文
        module_name = "poc_vulnerability_scan"
        
        # 如果没有存活URLs，从结果中提取
        if not alive_urls:
            alive_urls = []
            target_urls = metadata.get("targets", [])
            # 从数据中提取URL
            for item in data:
                if isinstance(item, dict) and "url" in item:
                    url = item.get("url")
                    if url and url not in alive_urls:
                        alive_urls.append(url)
            
            # 如果还是没有URL，使用targets作为URL
            if not alive_urls and target_urls:
                # 确保targets中的每个URL都有http前缀
                alive_urls = []
                for target in target_urls:
                    if target:
                        if not target.startswith(('http://', 'https://')):
                            target = 'http://' + target
                        alive_urls.append(target)
                        
            # 更新元数据
            metadata["alive_urls"] = alive_urls
    
    # 如果仍然没有存活URL，记录警告（但仍会生成报告）
    if not alive_urls:
        logger.warning("没有存活的URL，但仍将生成报告")
    else:
        logger.info(f"将生成包含 {len(alive_urls)} 个存活URL的报告")
    
    # 确保输出目录存在
    ensure_dir(output_dir)
    
    # 生成文件名
    html_filename = get_report_filename(module_name, "html")
    html_path = os.path.join(output_dir, html_filename)
    
    # 生成HTML报告
    html_report = generate_html_report(data, metadata, html_path)
    
    # 如果需要PDF格式，转换HTML为PDF
    if format_type.lower() == 'pdf':
        try:
            logger.info("尝试生成PDF报告...")
            pdf_report = generate_pdf_report(html_report)
            if pdf_report and os.path.exists(pdf_report):
                # 检查PDF文件大小，如果小于阈值，可能是简化版PDF
                pdf_size = os.path.getsize(pdf_report)
                html_size = os.path.getsize(html_report)
                
                # 如果PDF比HTML小很多，说明可能是简化版PDF
                if pdf_size < html_size * 0.5:
                    logger.info("注意: 生成的是简化版PDF报告，如需完整版PDF，请安装wkhtmltopdf或weasyprint")
                    logger.info("wkhtmltopdf安装指南: https://wkhtmltopdf.org/downloads.html")
                    logger.info(f"完整HTML报告可在此查看: {html_report}")
                
                logger.info(f"PDF报告生成成功: {pdf_report}")
                return pdf_report
            else:
                logger.warning("PDF生成失败，返回HTML报告")
                # 显示更明确的错误信息
                logger.info(f"HTML报告可以在这里找到: {html_report}")
                return html_report
        except Exception as e:
            logger.error(f"生成PDF报告时发生异常: {str(e)}")
            logger.info(f"HTML报告可以在这里找到: {html_report}")
            return html_report
    
    return html_report 