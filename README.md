# Qinglong RCE Scanner

一个针对青龙面板的自动化漏洞扫描和RCE利用工具

## 功能

- ✅ 自动检测青龙面板及版本
- ✅ 漏洞扫描 (鉴权绕过/密码重置/配置泄露)
- ✅ 配置文件交互式查看
- ✅ 交互式RCE执行
- ✅ Bash/PowerShell反弹Shell
- ✅ 批量扫描和报告生成

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
python scanner.py -f targets.txt -j 10
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
| -j, --threads | 线程数 | `-j 10` |
| -h, --help | 帮助信息 | `-h` |

## 检测的漏洞

1. **鉴权绕过 (RCE)** - /aPi/system/command-run 大小写变形绕过
2. **密码重置** - /open/user/init 密码重置漏洞
3. **配置泄露** - /aPi/configs/detail 配置文件读取
4. **受影响版本** - 自动检测易受攻击的版本（v2.20.1及以下）

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
   - 列出所有配置文件位置
   - 用户可以选择单个查看或查看所有配置

## 工作流程

```
1. 检查目标存活 (GET /api/health)
2. 获取版本信息 (GET /api/system)
3. 并行测试所有漏洞 (鉴权绕过/密码重置/配置泄露)
4. 导出扫描报告
5. 若发现漏洞，提示用户是否进行利用
```

## 扫描报告

批量扫描时自动生成 `scan_report_YYYYMMDD_HHMMSS.txt` 报告，包含：

- 扫描统计 (总数/漏洞数/安全数)
- 详细扫描结果
- 原始哈希结果

## 免责声明

⚠️  **本工具仅供授权的渗透测试使用，未经授权使用本工具进行任何非法活动均属违法行为。使用者需自行承担所有法律和技术后果。**

## 技术细节

- **HTTP客户端**: requests 库
- **并发**: ThreadPoolExecutor (默认4-10个线程)
- **颜色输出**: colorama
- **编码**: UTF-8 with error='ignore'
- **重试**: 3次重试 + 10秒超时

## License

MIT
