#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试插件配置加载
"""

from plugins.config_manager import plugin_config_manager

def main():
    """测试加载插件配置"""
    try:
        # 测试加载单个插件配置
        config = plugin_config_manager.load_config('myplugin')
        print('myplugin配置加载成功:')
        print(config)
        
        # 获取所有插件配置
        print('\n所有插件配置文件:')
        config_files = plugin_config_manager.get_plugin_config_files()
        for config_file in config_files:
            print(f' - {config_file}')
            
        # 加载所有插件配置
        print('\n所有插件配置:')
        all_configs = plugin_config_manager.get_all_plugin_configs()
        for plugin_id, config in all_configs.items():
            print(f' - {plugin_id}: {"启用" if config.get("enabled", True) else "禁用"}')
    except Exception as e:
        print(f'加载配置出错: {str(e)}')

if __name__ == '__main__':
    main() 