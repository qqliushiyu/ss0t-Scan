#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络工具箱命令行入口
支持调用各种扫描模块，配置参数，并导出结果
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, Any, Optional

# 将父目录添加到模块搜索路径
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.insert(0, root_dir)

# 修改当前工作目录为项目根目录
os.chdir(root_dir)

from core.scanner_manager import scanner_manager
from utils.config import config_manager
from utils.export import export_result

# 配置日志目录
logs_dir = os.path.join(root_dir, 'logs')
os.makedirs(logs_dir, exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(logs_dir, 'cli.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("ss0t-scna.cli")

def create_parser() -> argparse.ArgumentParser:
    """
    创建命令行参数解析器
    
    Returns:
        参数解析器
    """
    parser = argparse.ArgumentParser(
        description="ss0t-Scan - 命令行版",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # 全局参数
    parser.add_argument('-v', '--verbose', action='store_true', help='启用详细输出')
    parser.add_argument('--config', type=str, help='配置文件路径')
    
    # 创建子命令
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # list 命令 - 列出所有可用模块
    list_parser = subparsers.add_parser('list', help='列出所有可用模块')
    list_parser.add_argument('-v', '--verbose', action='store_true', help='启用详细输出')
    
    # scan 命令 - 执行扫描
    scan_parser = subparsers.add_parser('scan', help='执行扫描')
    scan_parser.add_argument('-v', '--verbose', action='store_true', help='启用详细输出')
    scan_parser.add_argument('-m', '--module', type=str, required=True, 
                           help='扫描模块名称')
    scan_parser.add_argument('-p', '--params', type=str, help='扫描参数 (JSON 格式)')
    scan_parser.add_argument('-f', '--params-file', type=str, help='扫描参数文件 (JSON)')
    scan_parser.add_argument('-o', '--output', type=str, help='输出文件路径')
    scan_parser.add_argument('-t', '--output-type', type=str, default='csv', 
                           choices=['csv', 'json', 'xlsx'], help='输出文件类型')
    
    # config 命令 - 配置管理
    config_parser = subparsers.add_parser('config', help='配置管理')
    config_parser.add_argument('-V', '--verbose', action='store_true', help='启用详细输出')
    config_parser.add_argument('action', choices=['show', 'get', 'set'], 
                             help='配置操作')
    config_parser.add_argument('-s', '--section', type=str, help='配置节')
    config_parser.add_argument('-k', '--key', type=str, help='配置键')
    config_parser.add_argument('-v', '--value', type=str, help='配置值')
    
    return parser

def list_modules() -> None:
    """列出所有可用的扫描模块"""
    # 确保扫描模块已发现
    scanner_manager.discover_scanners()
    
    # 获取模块信息
    modules = scanner_manager.get_scanner_info_list()
    
    if not modules:
        print("未找到任何扫描模块")
        return
    
    print(f"可用扫描模块 ({len(modules)}):")
    print("=" * 80)
    
    for module in modules:
        name = module['name']
        module_id = module['module_id']
        version = module.get('version', '1.0.0')
        description = module.get('description', 'No description')
        
        print(f"- {name} (ID: {module_id}, 版本: {version})")
        print(f"  {description}")
        print()
    
    print("=" * 80)
    print("使用示例: python cli/main.py scan --module=hostscanner --params='{\"ip_range\":\"192.168.1.1/24\"}'")

def load_params(args) -> Dict[str, Any]:
    """
    从命令行参数加载扫描参数
    
    Args:
        args: 命令行参数
    
    Returns:
        参数字典
    """
    params = {}
    
    # 从 JSON 字符串加载
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            logger.error(f"参数 JSON 格式错误: {str(e)}")
            sys.exit(1)
    
    # 从文件加载
    elif args.params_file:
        try:
            with open(args.params_file, 'r', encoding='utf-8') as f:
                params = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"从文件加载参数失败: {str(e)}")
            sys.exit(1)
    
    return params

def run_scan(args) -> None:
    """
    执行扫描
    
    Args:
        args: 命令行参数
    """
    # 确保扫描模块已发现
    scanner_manager.discover_scanners()
    
    module_id = args.module.lower()
    scanner_class = scanner_manager.get_scanner(module_id)
    
    if not scanner_class:
        logger.error(f"未找到模块: {args.module}")
        print(f"错误: 未找到模块 '{args.module}'，请使用 'list' 命令查看可用模块")
        sys.exit(1)
    
    # 加载参数
    params = load_params(args)
    
    # 合并模块配置
    module_config = config_manager.load_module_config(module_id)
    module_config.update(params)
    
    logger.info(f"创建扫描器: {module_id}")
    scanner = scanner_class(module_config)
    
    try:
        logger.info(f"开始扫描: {module_id}")
        result = scanner.execute()
        
        if result.success:
            logger.info(f"扫描成功: {module_id}，记录数: {result.record_count}")
            print(f"扫描成功，获取到 {result.record_count} 条记录")
            
            # 导出结果
            if result.data:
                output_file = args.output
                output_type = args.output_type.lower()
                
                # 如果未指定输出文件，则使用默认路径
                if not output_file:
                    output_dir = config_manager.get("general", "output_dir", fallback="results")
                    # 确保结果目录为绝对路径
                    if not os.path.isabs(output_dir):
                        output_dir = os.path.join(root_dir, output_dir)
                    # 确保目录存在
                    os.makedirs(output_dir, exist_ok=True)
                    output_file = export_result(
                        result.data, module_id, output_type, output_dir
                    )
                else:
                    # 确保目录存在
                    output_dir = os.path.dirname(output_file)
                    if output_dir and not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    
                    # 导出到指定文件
                    if output_type == 'csv':
                        from utils.export import export_to_csv
                        output_file = export_to_csv(result.data, output_file)
                    elif output_type == 'json':
                        from utils.export import export_to_json
                        output_file = export_to_json(result.data, output_file)
                    elif output_type == 'xlsx':
                        from utils.export import export_to_excel
                        output_file = export_to_excel(result.data, output_file)
                
                if output_file:
                    print(f"结果已导出到: {output_file}")
                else:
                    print("结果导出失败")
            
            # 详细输出所有结果
            if args.verbose:
                print("\n结果详情:")
                print(json.dumps(result.data, indent=2, ensure_ascii=False))
        
        else:
            logger.error(f"扫描失败: {result.error_msg}")
            print(f"扫描失败: {result.error_msg}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.warning("扫描被用户中断")
        print("\n扫描已中断")
        scanner.stop()
        sys.exit(1)
    
    except Exception as e:
        logger.error(f"扫描时发生错误: {str(e)}", exc_info=True)
        print(f"错误: {str(e)}")
        sys.exit(1)

def handle_config(args) -> None:
    """
    处理配置命令
    
    Args:
        args: 命令行参数
    """
    action = args.action
    
    if action == 'show':
        # 显示配置
        if args.section:
            # 显示指定节
            section_config = config_manager.get_section(args.section)
            if section_config:
                print(f"[{args.section}]")
                for key, value in section_config.items():
                    print(f"{key} = {value}")
            else:
                print(f"未找到配置节: {args.section}")
        else:
            # 显示所有配置
            for section in config_manager.config.sections():
                print(f"\n[{section}]")
                for key, value in config_manager.config[section].items():
                    print(f"{key} = {value}")
    
    elif action == 'get':
        # 获取配置值
        if not args.section or not args.key:
            print("错误: 获取配置需要指定节和键")
            sys.exit(1)
        
        value = config_manager.get(args.section, args.key)
        if value is None:
            print(f"未找到配置: [{args.section}] {args.key}")
        else:
            print(f"{value}")
    
    elif action == 'set':
        # 设置配置值
        if not args.section or not args.key or args.value is None:
            print("错误: 设置配置需要指定节、键和值")
            sys.exit(1)
        
        config_manager.set(args.section, args.key, args.value)
        config_manager.save_config()
        print(f"配置已更新: [{args.section}] {args.key} = {args.value}")

def main() -> None:
    """主函数"""
    parser = create_parser()
    args = parser.parse_args()
    
    # 设置日志级别
    if hasattr(args, 'verbose') and args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("详细输出模式已启用")
    
    # 加载配置
    if args.config:
        config_manager.config_file = args.config
        config_manager.load_config()
    
    # 处理命令
    if args.command == 'list':
        list_modules()
    elif args.command == 'scan':
        run_scan(args)
    elif args.command == 'config':
        handle_config(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序已中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"未处理的异常: {str(e)}", exc_info=True)
        print(f"错误: {str(e)}")
        sys.exit(1) 