# Qinglong RCE Scanner

一个针对青龙面板的自动化漏洞扫描和RCE利用工具

## 功能

- 自动检测青龙面板及版本
- 漏洞扫描 (鉴权绕过/密码重置/配置泄露)
- 配置文件交互式查看
- 交互式RCE执行
- Bash/PowerShell反弹Shell
- 批量扫描和报告生成

## 安装

```bash
git clone https://github.com/Ropemakers5302/Qinglong-RCE-Scanner.git
```

## 使用

### 单个目标扫描
```bash
python scanner.py -u https://target:5700
```

### 直接执行命令
```bash
python scanner.py -u https://target:5700 -c "id"
```

### 批量扫描
```bash
python scanner.py -f targets.txt
```

### 使用代理
```bash
python scanner.py -u https://target:5700 -p socks5://127.0.0.1:1080
```

## 命令行参数

| 参数 | 说明 | 示例 |
|-----|------|------|
| -u, --url | 目标URL | `-u https://target:5700` |
| -f, --file | 批量扫描文件 | `-f targets.txt` |
| -c, --cmd | 执行命令 | `-c "id"` |
| -t, --timeout | 超时时间(秒) | `-t 15` |
| -p, --proxy | 代理地址 | `-p socks5://127.0.0.1:1080` |
| -v, --verbose | 详细输出 | `-v` |
| -h, --help | 帮助信息 | `-h` |

## 检测的漏洞

1. **鉴权绕过 (RCE)** - 大小写变形绕过认证 (`/API/`, `/aPi/` 等)
2. **密码重置** - `/open/user/init` 白名单路径重置密码
3. **配置泄露** - `/api/configs/detail` 配置文件读取

## 漏洞原理

Express框架默认路由大小写不敏感，但认证中间件严格匹配小写 `/api/` 和 `/open/`，因此 `/API/`、`/aPi/` 等变体可绕过认证但匹配路由。

## RCE利用方式

检测到RCE漏洞后，可选择：

1. **交互式RCE执行** - 实时执行命令
2. **Bash反弹Shell** - 获取bash反向连接
3. **PowerShell反弹Shell** - 获取powershell反向连接
4. **自定义命令执行** - 执行单条自定义命令

## 配置泄露利用

检测到配置泄露后，可查看：

1. **单文件模式** - 如果只找到一个配置文件，直接打印内容
2. **多文件模式** - 如果找到多个配置文件，提供交互式菜单

## 工作流程

```
1. 检查目标存活 (GET /api/health)
2. 获取版本信息 (GET /api/system)
3. 顺序测试漏洞 (鉴权绕过/密码重置/配置泄露)
4. 导出扫描报告
5. 若发现漏洞，提示用户是否进行利用
```

## 扫描报告

批量扫描时自动生成 `scan_report_YYYYMMDD_HHMMSS.txt` 报告，包含：

- 扫描统计 (总数/漏洞数/安全数)
- 详细扫描结果

## 免责声明

本工具仅供授权的渗透测试使用，未经授权使用本工具进行任何非法活动均属违法行为。使用者需自行承担所有法律和技术后果。

## License

MIT
