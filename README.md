# NetTools 网络工具箱

## 📋 项目简介

NetTools 是一个功能丰富的网络扫描与安全评估工具箱，基于Python实现，提供了图形界面(GUI)和命令行界面(CLI)两种使用方式。本工具箱集成了多种网络扫描、检测和分析功能，帮助网络管理员和安全专业人员快速了解网络状态和安全风险。

## ✨ 核心功能

- **主机扫描**：使用ICMP/ARP发现网络中的活跃主机
- **端口扫描**：检测目标主机开放的TCP/UDP端口
- **DNS检测**：DNS记录查询和解析测试
- **路由追踪**：分析网络路径和跳数
- **Ping监控**：长期监控网络连通性变化
- **TCP Ping**：基于TCP的连通性测试
- **Web风险扫描**：Web应用安全漏洞检测
- **Web目录扫描**：Web应用目录结构探测
- **POC扫描**：已知漏洞验证测试
- **爆破扫描**：对常见服务进行密码暴力破解

## 🌟 特色亮点

- **模块化设计**：所有功能模块独立，易于扩展和定制
- **可视化展示**：支持网络拓扑图自动生成和交互式探索
- **报告生成**：自动生成专业扫描报告（HTML、PDF、Excel格式）
- **插件系统**：支持通过插件扩展功能，尤其是Web风险检测
- **安全可控**：所有扫描操作可精细控制，避免对目标系统造成负面影响

## 📦 技术栈

- **编程语言**：Python 3.8+
- **GUI框架**：PyQt5
- **网络分析**：dnspython, scapy, requests
- **数据处理**：pandas, numpy
- **结果导出**：openpyxl, weasyprint
- **可视化**：networkx, matplotlib

## 🚀 安装说明

### 系统要求

- Python 3.8 或更高版本
- 支持的操作系统：Windows、Linux、macOS

### 安装步骤

1. 克隆或下载项目代码

```bash
git clone https://github.com/yourusername/nettools.git
cd nettools
```

2. 创建并激活虚拟环境（推荐）

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

3. 安装依赖包

```bash
pip install -r requirements.txt
```

4. 安装项目

```bash
pip install -e .
```

## 💻 使用方法

### 启动图形界面

```bash
# 从安装后的包启动
nettools-gui

# 或直接运行脚本
python gui/main.py
```

### 使用命令行工具

```bash
# 从安装后的包启动
nettools-cli --help

# 或直接运行脚本
python cli/main.py --help

# 示例：执行主机扫描
nettools-cli host-scan --target 192.168.1.0/24
```

### 基本界面操作

1. 启动GUI后，选择所需的功能模块标签页
2. 输入扫描参数，如目标地址、端口范围等
3. 点击"开始扫描"按钮执行扫描
4. 查看结果并可选择导出报告

## 📚 项目结构

```
nettools/
├── cli/                 # 命令行接口
├── config/              # 配置文件目录
├── configs/             # 其他配置目录
├── core/                # 核心扫描模块
│   ├── base_scanner.py  # 基础扫描器类
│   ├── dns_check.py     # DNS检测模块
│   ├── host_scan.py     # 主机扫描模块
│   └── ...              # 其他扫描模块
├── gui/                 # 图形用户界面
│   ├── main.py          # GUI主程序
│   ├── panels/          # 各功能面板
│   └── ...              # 其他GUI组件
├── logs/                # 日志目录
├── plugins/             # 插件系统
├── reports/             # 报告模板和生成目录
├── results/             # 扫描结果存储目录
├── tests/               # 单元测试
├── utils/               # 工具类库
└── setup.py             # 安装脚本
```

## 🛠️ 配置说明

NetTools 使用 INI 格式的配置文件，主要配置文件位于 `config/settings.ini`。你可以通过以下方式修改配置：

1. 直接编辑配置文件
2. 通过GUI界面的"文件 > 编辑配置文件"菜单
3. 使用命令行参数覆盖默认配置

主要配置项包括：

- 日志级别和输出格式
- 扫描超时和重试参数
- 并行任务数量
- 各模块的默认设置

## 🔌 插件系统

NetTools 支持通过插件扩展功能，特别是用于Web风险扫描。插件位于 `plugins/` 目录。

你可以：
- 使用已有插件进行扫描
- 开发新插件扩展功能
- 通过"文件 > 编辑插件配置"管理插件

## 📊 报告生成

扫描完成后，可以生成多种格式的报告：

- HTML报告：包含交互式图表和详细结果
- PDF报告：适合打印和分享的专业格式
- Excel报告：便于进一步数据分析和处理

## ⚠️ 使用须知

1. 本工具仅供网络管理、安全测试和教育目的使用
2. 在使用前，请确保获得目标系统所有者的明确授权
3. 请合理设置扫描参数，避免对目标系统造成过大负载
4. 对于可能产生安全风险的功能（如爆破模块），请谨慎使用

## 🔄 常见问题

### 安装依赖失败
- 确保已安装正确版本的pip和setuptools
- 考虑使用虚拟环境隔离依赖
- 检查requirements.txt中的版本限制

### GUI无法启动
- 确认已安装PyQt5及其依赖
- 检查系统图形环境是否正常
- 查看logs/gui.log日志文件查明具体错误

### 扫描功能失效
- 检查目标是否可访问
- 检查网络连接和防火墙设置
- 调整超时和重试参数
- 启用debug级别日志查看详细错误

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出新功能建议！贡献流程：

1. Fork仓库并创建特性分支
2. 编写代码和单元测试
3. 确保所有测试通过
4. 提交Pull Request

贡献代码需遵循项目的编码规范和最佳实践。

## 📄 许可证

本项目采用 [MIT许可证](LICENSE) 开源。

## 📞 联系方式

- 项目主页：[GitHub仓库地址]
- 问题反馈：通过GitHub Issues提交
- 邮件联系：example@example.com 