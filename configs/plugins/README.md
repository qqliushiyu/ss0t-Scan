# 插件配置文件使用说明

## 概述

插件配置文件系统允许您通过编辑JSON或YAML文件来自定义Web风险扫描插件的行为，而无需在GUI界面中进行繁琐的配置。

## 配置文件位置

配置文件默认位于`configs/plugins/`目录下，每个插件对应一个配置文件，命名规则为插件ID加上`.json`或`.yaml`扩展名。例如：

- `fingerprintscanner.json` - Web指纹识别插件的配置
- `wafdetector.json` - WAF检测插件的配置
- `vulnscanner.json` - 漏洞扫描插件的配置

## 配置文件格式

配置文件支持JSON和YAML两种格式，具有相同的结构。下面是一个JSON格式的示例：

```json
{
    "enabled": true,                  // 是否启用插件
    "name": "插件名称",               // 插件显示名称
    "description": "插件描述",        // 插件描述
    "version": "1.0.0",              // 插件版本
    "timeout": 10,                   // 超时时间（秒）
    "user_agent": "...",             // User-Agent字符串
    "verify_ssl": false,             // 是否验证SSL证书
    // 以下是插件特定配置...
    "plugin_specific_option1": "value1",
    "plugin_specific_option2": "value2"
}
```

## 通用配置选项

所有插件共享以下配置选项：

| 选项 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| enabled | 布尔值 | 是否启用插件 | true |
| name | 字符串 | 插件显示名称 | (插件默认名称) |
| description | 字符串 | 插件描述 | (插件默认描述) |
| version | 字符串 | 插件版本 | (插件默认版本) |
| timeout | 整数 | 请求超时时间（秒） | 10 |
| user_agent | 字符串 | HTTP请求的User-Agent | Mozilla/5.0 ... |
| verify_ssl | 布尔值 | 是否验证SSL证书 | false |

## 特定插件配置

### Web指纹识别插件 (fingerprintscanner.json)

```json
{
    // 通用配置...
    "custom_fingerprints": {
        "技术名称1": [
            {"path": "/路径1", "pattern": "匹配模式1"},
            {"path": "/路径2", "pattern": "匹配模式2", "header": "头名称", "regex": "正则表达式"}
        ],
        "技术名称2": [
            {"path": "/路径", "content": "内容正则表达式"}
        ]
    },
    "fingerprint_file": "配置文件路径.txt"
}
```

指纹文件格式 (每行一个指纹)：
```
技术名:路径:匹配模式[:header[:regex]]
```

### WAF检测插件 (wafdetector.json)

```json
{
    // 通用配置...
    "custom_waf_signatures": {
        "WAF名称1": [
            "特征1",
            "特征2"
        ],
        "WAF名称2": [
            "特征3",
            "特征4"
        ]
    },
    "test_payloads": [
        "/?id=1' OR 1=1 --",
        "/?id=<script>alert(1)</script>"
    ],
    "max_retries": 3,
    "retry_interval": 1.5
}
```

### 漏洞扫描插件 (vulnscanner.json)

```json
{
    // 通用配置...
    "scan_depth": 2,
    "max_urls_per_domain": 100,
    "custom_paths": {
        "SQL注入": [
            "/path1.php",
            "/path2.php"
        ],
        "XSS": [
            "/path3.php",
            "/path4.php"
        ],
        "目录遍历": [
            "/path5/",
            "/path6/"
        ],
        "文件包含": [
            "/path7.php",
            "/path8.php"
        ],
        "敏感文件": [
            "/path9",
            "/path10"
        ]
    },
    "detection_threads": 10,
    "follow_redirects": true
}
```

## 修改配置文件

1. 使用文本编辑器打开相应的配置文件
2. 根据需要修改配置选项
3. 保存文件
4. 下次启动扫描时，插件将自动加载最新的配置

## 重置为默认配置

如果您希望重置为默认配置，只需删除相应的配置文件，系统将在下次启动时自动创建默认配置文件。

## 配置文件优先级

1. 配置文件中的设置具有最高优先级
2. GUI界面中的设置（如果配置文件不存在或不包含某项设置）
3. 插件的默认设置（如果前两项均未指定） 