import subprocess
import sys
import argparse
import os
import socket
import ipaddress
import re
import time
import asyncio
import concurrent.futures
import shlex
import base64
from typing import List, Optional, Tuple, Dict, Any, Callable
from dataclasses import dataclass
from abc import ABC, abstractmethod
import importlib.util

_nmap_str = base64.b64decode(b'bm1hcA==').decode()
_subprocess_str = base64.b64decode(b'c3VicHJvY2Vzcw==').decode()

class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    BRIGHT_RED = '\033[31;1m'
    BRIGHT_GREEN = '\033[32;1m'
    BRIGHT_YELLOW = '\033[33;1m'
    BRIGHT_BLUE = '\033[34;1m'
    
    @staticmethod
    def init_windows():
        """Initialize colors for Windows"""
        if sys.platform == 'win32':
            try:
                import colorama
                colorama.init()
            except ImportError:
                os.system('')

Colors.init_windows()


@dataclass
class CommandOption:
    """Data structure for command option mapping"""
    attr_name: str
    flag: str
    has_value: bool = False
    value_formatter: Optional[Callable[[Any], str]] = None
    multi_value: bool = False


class NmapPlugin(ABC):
    """Base class for Nmap plugins"""
    
    @abstractmethod
    def get_name(self) -> str:
        """Return plugin name"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Return plugin description"""
        pass
    
    @abstractmethod
    def modify_command(self, command: List[str], args: Any) -> List[str]:
        """
        Modify nmap command before execution
        Returns modified command list
        """
        pass
    
    @abstractmethod
    def process_output(self, output: str, returncode: int) -> Optional[str]:
        """
        Process nmap output after execution
        Returns processed output or None
        """
        pass


class PluginManager:
    """Manages Nmap plugins"""
    
    def __init__(self):
        self.plugins: List[NmapPlugin] = []
        self.plugin_dir = os.path.join(os.path.dirname(__file__), 'plugins')
    
    def load_plugin(self, plugin_path: str) -> bool:
        """Load a plugin from file with security checks"""
        try:
            if not os.path.exists(plugin_path) or not os.path.isfile(plugin_path):
                print(f"{Colors.RED}[ERROR] Plugin file not found: {plugin_path}{Colors.RESET}")
                return False
            
            if not plugin_path.endswith('.py'):
                print(f"{Colors.RED}[ERROR] Only .py files are allowed as plugins{Colors.RESET}")
                return False
            
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            if spec is None or spec.loader is None:
                return False
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, NmapPlugin) and 
                    attr != NmapPlugin):
                    plugin = attr()
                    
                    base_methods = set(dir(NmapPlugin))
                    plugin_methods = set(dir(plugin))
                    extra_methods = plugin_methods - base_methods - {'__class__', '__dict__', '__doc__', '__module__', '__weakref__'}
                    
                    suspicious = {'eval', 'exec', '__import__', 'compile', 'open', 'file', 'input', 'raw_input'}
                    if any(sus in str(extra_methods).lower() for sus in suspicious):
                        print(f"{Colors.RED}[ERROR] Plugin contains suspicious methods: {extra_methods}{Colors.RESET}")
                        return False
                    
                    self.plugins.append(plugin)
                    print(f"{Colors.GREEN}[+] Loaded plugin: {plugin.get_name()}{Colors.RESET}")
                    return True
            
            return False
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to load plugin {plugin_path}: {e}{Colors.RESET}")
            return False
    
    def load_plugins_from_dir(self, directory: Optional[str] = None) -> int:
        """Load all plugins from directory"""
        if directory is None:
            directory = self.plugin_dir
        
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            return 0
        
        loaded = 0
        for filename in os.listdir(directory):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_path = os.path.join(directory, filename)
                if self.load_plugin(plugin_path):
                    loaded += 1
        
        return loaded
    
    def apply_plugins(self, command: List[str], args: Any) -> List[str]:
        """Apply all plugins to modify command"""
        result = command
        for plugin in self.plugins:
            try:
                result = plugin.modify_command(result, args)
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Plugin {plugin.get_name()} error: {e}{Colors.RESET}")
        return result
    
    def process_output(self, output: str, returncode: int) -> Optional[str]:
        """Process output through all plugins"""
        result = output
        for plugin in self.plugins:
            try:
                processed = plugin.process_output(result, returncode)
                if processed is not None:
                    result = processed
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Plugin {plugin.get_name()} error: {e}{Colors.RESET}")
        return result
    
    def list_plugins(self):
        """List all loaded plugins"""
        if not self.plugins:
            print(f"{Colors.YELLOW}No plugins loaded{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}Loaded Plugins:{Colors.RESET}\n")
        for plugin in self.plugins:
            print(f"  {Colors.GREEN}{plugin.get_name():30s}{Colors.RESET} : {plugin.get_description()}")


_plugin_manager = PluginManager()


class ScanProfile:
    """Predefined scan profiles"""
    PROFILES = {
        'full-scan': ['-sS', '-sV', '-sC', '-O', '-A', '-T4'],
        'stealth': ['-sS', '-T1', '-f', '--mtu', '16'],
        'vuln-scan': ['-sV', '--script', 'vuln'],
        'firewall-evasion': ['-f', '-D', 'RND:10', '--mtu', '16', '-T2'],
        'udp-heavy': ['-sU', '-sV', '-T4'],
        'reconnaissance': ['-sn', '--traceroute', '-T4'],
        'ultimate-stealth': ['-sS', '-T1', '-f', '--mtu', '8', '-D', 'RND:15', '-g', '53', 
                            '--data-length', '16', '--randomize-hosts', '--spoof-mac', '0', 
                            '--ttl', '64', '--badsum', '--scan-delay', '5s', '--max-retries', '1',
                            '--defeat-rst-ratelimit', '--defeat-icmp-ratelimit'],
    }
    
    HALL_OF_FAME = {
        'mr-robot-s1': {
            'name': 'Mr. Robot Season 1 Scan',
            'description': 'The classic stealth scan used by Elliot Alderson',
            'options': ['-sS', '-T2', '-f', '--mtu', '16', '-D', 'RND:5', '--randomize-hosts']
        },
        'anonymous-typical': {
            'name': 'Anonymous Typical Scan',
            'description': 'Common scan pattern used by Anonymous operations',
            'options': ['-sS', '-sV', '-sC', '-T4', '-f', '-D', 'RND:10']
        },
        'l33t-h4x0r': {
            'name': 'L33T H4X0R Scan',
            'description': 'Xmas + Null + FIN + badsum + decoys (script kiddie style)',
            'options': ['-sX', '-sN', '-sF', '--badsum', '-D', 'RND:20', '-T1', '-f']
        },
        'red-team-recon': {
            'name': 'Red Team Initial Recon',
            'description': 'Professional red team initial reconnaissance scan',
            'options': ['-sS', '-sV', '-sC', '-O', '-A', '-T4', '--top-ports', '1000', '--reason']
        },
        'bug-bounty-quick': {
            'name': 'Bug Bounty Quick Scan',
            'description': 'Fast comprehensive scan for bug bounty programs',
            'options': ['-sS', '-sV', '-sC', '--script', 'vuln,exploit', '-T4', '--top-ports', '100']
        },
    }
    
    @classmethod
    def get_profile(cls, name: str) -> List[str]:
        """Get profile options by name"""
        return cls.PROFILES.get(name, [])


class NmapWrapper:
    """Complete Nmap wrapper with all options - Stateless version"""
    
    COMMAND_OPTIONS: Dict[str, CommandOption] = {
        'target': CommandOption('target', '', multi_value=True),
        'input_list': CommandOption('input_list', '-iL', has_value=True),
        'random_targets': CommandOption('random_targets', '-iR', has_value=True, value_formatter=str),
        'exclude': CommandOption('exclude', '--exclude', has_value=True),
        'excludefile': CommandOption('excludefile', '--excludefile', has_value=True),
        
        'list_scan': CommandOption('list_scan', '-sL'),
        'ping_scan': CommandOption('ping_scan', '-sn'),
        'skip_discovery': CommandOption('skip_discovery', '-Pn'),
        'tcp_syn_discovery': CommandOption('tcp_syn_discovery', '-PS', has_value=True, value_formatter=lambda x: f'-PS{x}' if x else '-PS'),
        'tcp_ack_discovery': CommandOption('tcp_ack_discovery', '-PA', has_value=True, value_formatter=lambda x: f'-PA{x}' if x else '-PA'),
        'udp_discovery': CommandOption('udp_discovery', '-PU', has_value=True, value_formatter=lambda x: f'-PU{x}' if x else '-PU'),
        'sctp_discovery': CommandOption('sctp_discovery', '-PY', has_value=True, value_formatter=lambda x: f'-PY{x}' if x else '-PY'),
        'icmp_echo': CommandOption('icmp_echo', '-PE'),
        'icmp_timestamp': CommandOption('icmp_timestamp', '-PP'),
        'icmp_netmask': CommandOption('icmp_netmask', '-PM'),
        'ip_protocol_ping': CommandOption('ip_protocol_ping', '-PO', has_value=True, value_formatter=lambda x: f'-PO{x}' if x else '-PO'),
        'no_dns': CommandOption('no_dns', '-n'),
        'always_resolve': CommandOption('always_resolve', '-R'),
        'dns_servers': CommandOption('dns_servers', '--dns-servers', has_value=True),
        'system_dns': CommandOption('system_dns', '--system-dns'),
        'traceroute': CommandOption('traceroute', '--traceroute'),
        
        'syn_scan': CommandOption('syn_scan', '-sS'),
        'connect_scan': CommandOption('connect_scan', '-sT'),
        'ack_scan': CommandOption('ack_scan', '-sA'),
        'window_scan': CommandOption('window_scan', '-sW'),
        'maimon_scan': CommandOption('maimon_scan', '-sM'),
        'udp_scan': CommandOption('udp_scan', '-sU'),
        'null_scan': CommandOption('null_scan', '-sN'),
        'fin_scan': CommandOption('fin_scan', '-sF'),
        'xmas_scan': CommandOption('xmas_scan', '-sX'),
        'scanflags': CommandOption('scanflags', '--scanflags', has_value=True),
        'idle_scan': CommandOption('idle_scan', '-sI', has_value=True),
        'sctp_init_scan': CommandOption('sctp_init_scan', '-sY'),
        'sctp_cookie_scan': CommandOption('sctp_cookie_scan', '-sZ'),
        'ip_protocol_scan': CommandOption('ip_protocol_scan', '-sO'),
        'ftp_bounce': CommandOption('ftp_bounce', '-b', has_value=True),
        
        'ports': CommandOption('ports', '-p', has_value=True),
        'exclude_ports': CommandOption('exclude_ports', '--exclude-ports', has_value=True),
        'fast_scan': CommandOption('fast_scan', '-F'),
        'sequential': CommandOption('sequential', '-r'),
        'randomize_hosts': CommandOption('randomize_hosts', '--randomize-hosts'),
        'top_ports': CommandOption('top_ports', '--top-ports', has_value=True, value_formatter=str),
        'port_ratio': CommandOption('port_ratio', '--port-ratio', has_value=True, value_formatter=str),
        
        'version_detect': CommandOption('version_detect', '-sV'),
        'version_intensity': CommandOption('version_intensity', '--version-intensity', has_value=True, value_formatter=str),
        'version_light': CommandOption('version_light', '--version-light'),
        'version_all': CommandOption('version_all', '--version-all'),
        'version_trace': CommandOption('version_trace', '--version-trace'),
        
        'default_scripts': CommandOption('default_scripts', '-sC'),
        'script': CommandOption('script', '--script', has_value=True),
        'script_args': CommandOption('script_args', '--script-args', has_value=True),
        'script_args_file': CommandOption('script_args_file', '--script-args-file', has_value=True),
        'script_trace': CommandOption('script_trace', '--script-trace'),
        'script_updatedb': CommandOption('script_updatedb', '--script-updatedb'),
        'script_help': CommandOption('script_help', '--script-help', has_value=True),
        'script_timeout': CommandOption('script_timeout', '--script-timeout', has_value=True),
        'lua_exec': CommandOption('lua_exec', '--lua-exec', has_value=True),
        
        'os_detect': CommandOption('os_detect', '-O'),
        'osscan_limit': CommandOption('osscan_limit', '--osscan-limit'),
        'osscan_guess': CommandOption('osscan_guess', '--osscan-guess'),
        'max_os_tries': CommandOption('max_os_tries', '--max-os-tries', has_value=True, value_formatter=str),
        
        'timing': CommandOption('timing', '-T', has_value=True, value_formatter=lambda x: f'-T{x}'),
        'min_hostgroup': CommandOption('min_hostgroup', '--min-hostgroup', has_value=True, value_formatter=str),
        'max_hostgroup': CommandOption('max_hostgroup', '--max-hostgroup', has_value=True, value_formatter=str),
        'min_parallelism': CommandOption('min_parallelism', '--min-parallelism', has_value=True, value_formatter=str),
        'max_parallelism': CommandOption('max_parallelism', '--max-parallelism', has_value=True, value_formatter=str),
        'min_rtt_timeout': CommandOption('min_rtt_timeout', '--min-rtt-timeout', has_value=True),
        'max_rtt_timeout': CommandOption('max_rtt_timeout', '--max-rtt-timeout', has_value=True),
        'initial_rtt_timeout': CommandOption('initial_rtt_timeout', '--initial-rtt-timeout', has_value=True),
        'max_retries': CommandOption('max_retries', '--max-retries', has_value=True, value_formatter=str),
        'host_timeout': CommandOption('host_timeout', '--host-timeout', has_value=True),
        'scan_delay': CommandOption('scan_delay', '--scan-delay', has_value=True),
        'max_scan_delay': CommandOption('max_scan_delay', '--max-scan-delay', has_value=True),
        'scan_delay_type': CommandOption('scan_delay_type', '--scan-delay-type', has_value=True),
        'min_rate': CommandOption('min_rate', '--min-rate', has_value=True, value_formatter=str),
        'max_rate': CommandOption('max_rate', '--max-rate', has_value=True, value_formatter=str),
        'defeat_rst_ratelimit': CommandOption('defeat_rst_ratelimit', '--defeat-rst-ratelimit'),
        'defeat_icmp_ratelimit': CommandOption('defeat_icmp_ratelimit', '--defeat-icmp-ratelimit'),
        
        'fragment': CommandOption('fragment', '-f'),
        'mtu': CommandOption('mtu', '--mtu', has_value=True, value_formatter=str),
        'decoys': CommandOption('decoys', '-D', has_value=True),
        'spoof_source': CommandOption('spoof_source', '-S', has_value=True),
        'interface': CommandOption('interface', '-e', has_value=True),
        'source_port': CommandOption('source_port', '-g', has_value=True, value_formatter=str),
        'proxies': CommandOption('proxies', '--proxies', has_value=True),
        'proxy': CommandOption('proxy', '--proxy', has_value=True),
        'tor': CommandOption('tor', '--tor'),
        'data': CommandOption('data', '--data', has_value=True),
        'data_string': CommandOption('data_string', '--data-string', has_value=True),
        'data_length': CommandOption('data_length', '--data-length', has_value=True, value_formatter=str),
        'ip_options': CommandOption('ip_options', '--ip-options', has_value=True),
        'ttl': CommandOption('ttl', '--ttl', has_value=True, value_formatter=str),
        'spoof_mac': CommandOption('spoof_mac', '--spoof-mac', has_value=True),
        'badsum': CommandOption('badsum', '--badsum'),
        
        'output_normal': CommandOption('output_normal', '-oN', has_value=True),
        'output_xml': CommandOption('output_xml', '-oX', has_value=True),
        'output_script': CommandOption('output_script', '-oS', has_value=True),
        'output_grepable': CommandOption('output_grepable', '-oG', has_value=True),
        'output_all': CommandOption('output_all', '-oA', has_value=True),
        'verbose': CommandOption('verbose', '-v', has_value=True, value_formatter=lambda x: ['-v'] * x),
        'debug': CommandOption('debug', '-d', has_value=True, value_formatter=lambda x: ['-d'] * x),
        'reason': CommandOption('reason', '--reason'),
        'open_only': CommandOption('open_only', '--open'),
        'packet_trace': CommandOption('packet_trace', '--packet-trace'),
        'iflist': CommandOption('iflist', '--iflist'),
        'append_output': CommandOption('append_output', '--append-output'),
        'resume': CommandOption('resume', '--resume', has_value=True),
        'resume_control': CommandOption('resume_control', '--resume-control', has_value=True),
        'noninteractive': CommandOption('noninteractive', '--noninteractive'),
        'stylesheet': CommandOption('stylesheet', '--stylesheet', has_value=True),
        'webxml': CommandOption('webxml', '--webxml'),
        'no_stylesheet': CommandOption('no_stylesheet', '--no-stylesheet'),
        'http_useragent': CommandOption('http_useragent', '--http-useragent', has_value=True),
        
        'ipv6': CommandOption('ipv6', '-6'),
        'aggressive': CommandOption('aggressive', '-A'),
        'datadir': CommandOption('datadir', '--datadir', has_value=True),
        'send_eth': CommandOption('send_eth', '--send-eth'),
        'send_ip': CommandOption('send_ip', '--send-ip'),
        'privileged': CommandOption('privileged', '--privileged'),
        'unprivileged': CommandOption('unprivileged', '--unprivileged'),
        'version': CommandOption('version', '-V'),
    }
    
    def __init__(self):
        pass
    
    @staticmethod
    def build_command(parsed_args, profile: Optional[str] = None) -> List[str]:
        """
        Build nmap command from parsed arguments - STATELESS VERSION
        Returns a fresh command list every time
        """
        args_list: List[str] = [_nmap_str]
        
        if getattr(parsed_args, 'tor', False):
            args_list.extend(['--proxies', 'socks5://127.0.0.1:9050'])
        elif getattr(parsed_args, 'proxy', None):
            proxy_url = parsed_args.proxy
            if not proxy_url.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                proxy_url = f'socks5://{proxy_url}'
            args_list.extend(['--proxies', proxy_url])
        
        silent_mode = getattr(parsed_args, 'silent_mode', True)
        if silent_mode and not getattr(parsed_args, 'always_resolve', False) and not getattr(parsed_args, 'no_dns', False):
            args_list.extend(['-n', '--noninteractive'])
        
        profile_applied = False
        if profile:
            if profile in ScanProfile.HALL_OF_FAME:
                profile_data = ScanProfile.HALL_OF_FAME[profile]
                profile_opts = profile_data['options']
                print(f"{Colors.CYAN}[*]{Colors.RESET} Using Hall of Fame profile: {Colors.GREEN}{profile_data['name']}{Colors.RESET}")
                print(f"{Colors.CYAN}    Description: {profile_data['description']}{Colors.RESET}")
            else:
                profile_opts = ScanProfile.get_profile(profile)
            
            if profile_opts:
                for opt in profile_opts:
                    args_list.append(opt)
                profile_applied = True
        
        for attr_name, option in NmapWrapper.COMMAND_OPTIONS.items():
            value = getattr(parsed_args, attr_name, None)
            
            if value is None or value is False:
                continue

            if option.value_formatter:
                if attr_name in ('verbose', 'debug'):
                    args_list.extend(option.value_formatter(value))
                elif attr_name in ('tcp_syn_discovery', 'tcp_ack_discovery', 'udp_discovery', 'sctp_discovery', 'ip_protocol_ping'):
                    args_list.append(option.value_formatter(value))
                elif attr_name == 'timing':
                    args_list.append(option.value_formatter(value))
                else:
                    formatted = option.value_formatter(value)
                    if isinstance(formatted, str):
                        args_list.extend([option.flag, shlex.quote(formatted)])
                    else:
                        args_list.extend([option.flag, formatted])
            elif option.has_value:
                if option.multi_value:
                    args_list.extend(value)
                else:
                    sanitized_value = shlex.quote(str(value))
                    args_list.extend([option.flag, sanitized_value])
            else:
                args_list.append(option.flag)
        
        return args_list
    
    @staticmethod
    def execute(command: List[str], dry_run: bool = False, save_log: Optional[str] = None, args: Any = None):
        """
        Execute the nmap command with live output
        Returns: (returncode, execution_time)
        """
        if args is not None:
            command = _plugin_manager.apply_plugins(command, args)
        
        if dry_run:
            print(f"{Colors.CYAN}{Colors.BOLD}[DRY RUN]{Colors.RESET} Command that would be executed:")
            print(f"{Colors.GREEN}{' '.join(command)}{Colors.RESET}")
            return 0, 0.0
        
        raw_socket_options = ['-sS', '-sU', '-O', '-sY', '-sZ', '-sO', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX']
        requires_root = any(opt in command for opt in raw_socket_options)
        
        if requires_root:
            try:
                if sys.platform == 'win32':
                    import ctypes
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                    has_privilege = is_admin
                else:
                    has_privilege = os.geteuid() == 0
                
                if not has_privilege:
                    print(f"{Colors.YELLOW}{Colors.BOLD}[!] Warning:{Colors.RESET} Raw socket operations require elevated privileges.")
                    print(f"{Colors.YELLOW}    Options like -sS, -sU, -O require root/admin privileges.{Colors.RESET}")
                    if not getattr(args, 'unprivileged', False):
                        print(f"{Colors.CYAN}    Consider using --unprivileged flag or run with sudo/admin.{Colors.RESET}")
                        try:
                            continue_anyway = input(f"{Colors.YELLOW}Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                            if continue_anyway != 'y':
                                return 1, 0.0
                        except (EOFError, KeyboardInterrupt):
                            return 1, 0.0
            except Exception:
                pass
        
        start_time = time.time()
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}[*]{Colors.RESET} {Colors.BLUE}Executing Nmap Scan{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}Command:{Colors.RESET} {Colors.WHITE}{' '.join(command)}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}\n")
        
        log_file = None
        if save_log:
            try:
                log_file = open(save_log, 'w', encoding='utf-8')
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Warning: Could not open log file: {e}{Colors.RESET}")
        
        try:
            popen_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.STDOUT,
                'universal_newlines': True,
                'bufsize': 1
            }
            
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                popen_kwargs['startupinfo'] = startupinfo
                popen_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            
            process = subprocess.Popen(command, **popen_kwargs)
            
            output_lines: List[str] = []
            max_output_lines = 100000
            try:
                for line in process.stdout:
                    line = line.rstrip()
                    if line:
                        print(line)
                        if len(output_lines) < max_output_lines:
                            output_lines.append(line)
                        elif len(output_lines) == max_output_lines:
                            output_lines.append("... (output truncated to prevent memory issues)")
                        if log_file:
                            log_file.write(line + '\n')
                            log_file.flush()
            except KeyboardInterrupt:
                print(f"\n{Colors.RED}{Colors.BOLD}[!]{Colors.RESET} {Colors.YELLOW}Interrupting scan...{Colors.RESET}")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                raise
            
            returncode = process.wait()
            execution_time = time.time() - start_time
            
            output_text = '\n'.join(output_lines)
            if args is not None:
                processed_output = _plugin_manager.process_output(output_text, returncode)
                if processed_output and processed_output != output_text:
                    print(f"\n{Colors.CYAN}{Colors.BOLD}Plugin Processed Output:{Colors.RESET}")
                    print(processed_output)
            
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
            if returncode == 0:
                print(f"{Colors.GREEN}{Colors.BOLD}[+] Scan completed successfully{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}{Colors.BOLD}[!] Scan completed with exit code: {returncode}{Colors.RESET}")
            print(f"{Colors.CYAN}Execution time: {execution_time:.2f} seconds{Colors.RESET}")
            print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
            
            if log_file:
                log_file.close()
                print(f"{Colors.GREEN}Log saved to: {save_log}{Colors.RESET}")
            
            return returncode, execution_time
            
        except FileNotFoundError:
            print(f"{Colors.RED}{Colors.BOLD}[ERROR]{Colors.RESET} {Colors.RED}nmap not found. Please install nmap first.{Colors.RESET}")
            print(f"{Colors.YELLOW}Visit: https://nmap.org/download.html{Colors.RESET}")
            if log_file:
                log_file.close()
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}[ERROR]{Colors.RESET} {Colors.RED}{str(e)}{Colors.RESET}")
            if log_file:
                log_file.close()
            raise


def create_parser():
    """Create argument parser with all Nmap options"""
    parser = argparse.ArgumentParser(
        description='Complete Nmap Wrapper Script - All Options Supported',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python nmap_wrapper.py 192.168.1.1
  
  Comprehensive scan:
    python nmap_wrapper.py -sS -sV -sC -O -A -T4 192.168.1.1
  
  Stealth scan:
    python nmap_wrapper.py -sS -T1 -f 192.168.1.1
  
  Network scan:
    python nmap_wrapper.py -sn 192.168.1.0/24
  
  UDP scan:
    python nmap_wrapper.py -sU -p 1-1000 192.168.1.1

For more information, visit: https://nmap.org/book/man.html
        """
    )
    
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('target', nargs='*', help='Target hosts/networks (IP, hostname, CIDR)')
    target_group.add_argument('-iL', '--input-list', metavar='FILE', help='Input from list of hosts/networks')
    target_group.add_argument('-iR', '--random-targets', type=int, metavar='NUM', help='Choose random targets')
    target_group.add_argument('--exclude', metavar='HOSTS', help='Exclude hosts/networks (comma-separated)')
    target_group.add_argument('--excludefile', metavar='FILE', help='Exclude list from file')
    
    discovery_group = parser.add_argument_group('Host Discovery')
    discovery_group.add_argument('-sL', '--list-scan', action='store_true', help='List scan - list targets only')
    discovery_group.add_argument('-sn', '--ping-scan', action='store_true', help='Ping scan - disable port scan')
    discovery_group.add_argument('-Pn', '--skip-discovery', action='store_true', help='Skip host discovery - treat all hosts as online')
    discovery_group.add_argument('-PS', '--tcp-syn-discovery', nargs='?', const='', metavar='PORTLIST', help='TCP SYN discovery to ports')
    discovery_group.add_argument('-PA', '--tcp-ack-discovery', nargs='?', const='', metavar='PORTLIST', help='TCP ACK discovery to ports')
    discovery_group.add_argument('-PU', '--udp-discovery', nargs='?', const='', metavar='PORTLIST', help='UDP discovery to ports')
    discovery_group.add_argument('-PY', '--sctp-discovery', nargs='?', const='', metavar='PORTLIST', help='SCTP discovery to ports')
    discovery_group.add_argument('-PE', '--icmp-echo', action='store_true', help='ICMP echo discovery probe')
    discovery_group.add_argument('-PP', '--icmp-timestamp', action='store_true', help='ICMP timestamp discovery probe')
    discovery_group.add_argument('-PM', '--icmp-netmask', action='store_true', help='ICMP netmask request discovery probe')
    discovery_group.add_argument('-PO', '--ip-protocol-ping', nargs='?', const='', metavar='PROTOCOLS', help='IP Protocol Ping')
    discovery_group.add_argument('-n', '--no-dns', action='store_true', help='Never do DNS resolution')
    discovery_group.add_argument('-R', '--always-resolve', action='store_true', help='Always resolve DNS')
    discovery_group.add_argument('--dns-servers', metavar='SERVERS', help='Specify custom DNS servers (comma-separated)')
    discovery_group.add_argument('--system-dns', action='store_true', help='Use OS DNS resolver')
    discovery_group.add_argument('--traceroute', action='store_true', help='Trace hop path to each host')
    
    scan_group = parser.add_argument_group('Scan Techniques')
    scan_group.add_argument('-sS', '--syn-scan', action='store_true', help='TCP SYN scan (stealth scan)')
    scan_group.add_argument('-sT', '--connect-scan', action='store_true', help='TCP Connect() scan')
    scan_group.add_argument('-sA', '--ack-scan', action='store_true', help='TCP ACK scan')
    scan_group.add_argument('-sW', '--window-scan', action='store_true', help='TCP Window scan')
    scan_group.add_argument('-sM', '--maimon-scan', action='store_true', help='TCP Maimon scan')
    scan_group.add_argument('-sU', '--udp-scan', action='store_true', help='UDP scan')
    scan_group.add_argument('-sN', '--null-scan', action='store_true', help='TCP Null scan')
    scan_group.add_argument('-sF', '--fin-scan', action='store_true', help='TCP FIN scan')
    scan_group.add_argument('-sX', '--xmas-scan', action='store_true', help='TCP Xmas scan')
    scan_group.add_argument('--scanflags', metavar='FLAGS', help='Customize TCP scan flags')
    scan_group.add_argument('-sI', '--idle-scan', metavar='ZOMBIE[:PORT]', help='Idle scan using zombie host')
    scan_group.add_argument('-sY', '--sctp-init-scan', action='store_true', help='SCTP INIT scan')
    scan_group.add_argument('-sZ', '--sctp-cookie-scan', action='store_true', help='SCTP COOKIE-ECHO scan')
    scan_group.add_argument('-sO', '--ip-protocol-scan', action='store_true', help='IP protocol scan')
    scan_group.add_argument('-b', '--ftp-bounce', metavar='RELAY', help='FTP bounce scan')
    
    port_group = parser.add_argument_group('Port Specification and Scan Order')
    port_group.add_argument('-p', '--ports', metavar='RANGES', help='Only scan specified ports (e.g., 22,80,443 or 1-1000)')
    port_group.add_argument('--exclude-ports', metavar='RANGES', help='Exclude specified ports from scanning')
    port_group.add_argument('-F', '--fast-scan', action='store_true', help='Fast mode - scan fewer ports (top 100)')
    port_group.add_argument('-r', '--sequential', action='store_true', help='Scan ports sequentially - don\'t randomize')
    port_group.add_argument('--randomize-hosts', action='store_true', help='Randomize target host order')
    port_group.add_argument('--top-ports', type=int, metavar='NUM', help='Scan N most common ports')
    port_group.add_argument('--port-ratio', type=float, metavar='RATIO', help='Scan ports more common than ratio')
    
    version_group = parser.add_argument_group('Service/Version Detection')
    version_group.add_argument('-sV', '--version-detect', action='store_true', help='Probe open ports to determine service/version')
    version_group.add_argument('--version-intensity', type=int, choices=range(0, 10), metavar='0-9', help='Set version detection intensity (0-9)')
    version_group.add_argument('--version-light', action='store_true', help='Limit to most likely probes (intensity 2)')
    version_group.add_argument('--version-all', action='store_true', help='Try every single probe (intensity 9)')
    version_group.add_argument('--version-trace', action='store_true', help='Show detailed version scan activity')
    
    script_group = parser.add_argument_group('Script Scan (NSE - Nmap Scripting Engine)')
    script_group.add_argument('-sC', '--default-scripts', action='store_true', help='Equivalent to --script=default')
    script_group.add_argument('--script', metavar='SCRIPTS', help='Run specific scripts/categories (comma-separated)')
    script_group.add_argument('--script-args', metavar='ARGS', help='Provide arguments to scripts (key=value pairs)')
    script_group.add_argument('--script-args-file', metavar='FILE', help='Provide NSE script args in a file')
    script_group.add_argument('--script-trace', action='store_true', help='Show all data sent and received')
    script_group.add_argument('--script-updatedb', action='store_true', help='Update the script database')
    script_group.add_argument('--script-help', metavar='SCRIPTS', help='Show help about scripts')
    script_group.add_argument('--script-timeout', metavar='TIME', help='Set script timeout (e.g., 30s, 5m)')
    script_group.add_argument('--lua-exec', metavar='SCRIPT', help='Execute Lua script')
    
    os_group = parser.add_argument_group('OS Detection')
    os_group.add_argument('-O', '--os-detect', action='store_true', help='Enable OS detection')
    os_group.add_argument('--osscan-limit', action='store_true', help='Limit OS detection to promising targets')
    os_group.add_argument('--osscan-guess', action='store_true', help='Guess OS more aggressively')
    os_group.add_argument('--max-os-tries', type=int, metavar='NUM', help='Maximum OS detection attempts')
    
    timing_group = parser.add_argument_group('Timing and Performance')
    timing_group.add_argument('-T', '--timing', type=int, choices=[0, 1, 2, 3, 4, 5], metavar='0-5', 
                            help='Set timing template (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)')
    timing_group.add_argument('--min-hostgroup', type=int, metavar='SIZE', help='Parallel host scan group sizes (minimum)')
    timing_group.add_argument('--max-hostgroup', type=int, metavar='SIZE', help='Parallel host scan group sizes (maximum)')
    timing_group.add_argument('--min-parallelism', type=int, metavar='NUM', help='Probe parallelization (minimum)')
    timing_group.add_argument('--max-parallelism', type=int, metavar='NUM', help='Probe parallelization (maximum)')
    timing_group.add_argument('--min-rtt-timeout', metavar='TIME', help='Minimum probe round trip time (e.g., 100ms, 1s, 5m)')
    timing_group.add_argument('--max-rtt-timeout', metavar='TIME', help='Maximum probe round trip time')
    timing_group.add_argument('--initial-rtt-timeout', metavar='TIME', help='Initial probe round trip time')
    timing_group.add_argument('--max-retries', type=int, metavar='NUM', help='Caps port scan probe retransmissions')
    timing_group.add_argument('--host-timeout', metavar='TIME', help='Give up on target after this long')
    timing_group.add_argument('--scan-delay', metavar='TIME', help='Adjust delay between probes')
    timing_group.add_argument('--max-scan-delay', metavar='TIME', help='Maximum delay between probes')
    timing_group.add_argument('--scan-delay-type', metavar='TYPE', choices=['fixed', 'random'], help='Scan delay type (fixed or random)')
    timing_group.add_argument('--min-rate', type=int, metavar='NUM', help='Send packets no slower than N per second')
    timing_group.add_argument('--max-rate', type=int, metavar='NUM', help='Send packets no faster than N per second')
    timing_group.add_argument('--defeat-rst-ratelimit', action='store_true', help='Defeat RST rate limiting')
    timing_group.add_argument('--defeat-icmp-ratelimit', action='store_true', help='Defeat ICMP rate limiting')
    
    evasion_group = parser.add_argument_group('Firewall/IDS Evasion and Spoofing')
    evasion_group.add_argument('-f', '--fragment', action='store_true', help='Fragment packets')
    evasion_group.add_argument('--mtu', type=int, metavar='VAL', help='Fragment packets with given MTU')
    evasion_group.add_argument('-D', '--decoys', metavar='DECOYS', help='Cloak scan with decoys (comma-separated or RND:N)')
    evasion_group.add_argument('-S', '--spoof-source', metavar='IP', help='Spoof source address')
    evasion_group.add_argument('-e', '--interface', metavar='IFACE', help='Use specified interface')
    evasion_group.add_argument('-g', '--source-port', type=int, metavar='PORT', help='Use given source port')
    evasion_group.add_argument('--proxies', metavar='URLS', help='Relay through HTTP/SOCKS4 proxies (comma-separated)')
    evasion_group.add_argument('--proxy', metavar='URL', help='SOCKS5 proxy for evasion (e.g., socks5://127.0.0.1:9050 for Tor)')
    evasion_group.add_argument('--tor', action='store_true', help='Use Tor proxy (socks5://127.0.0.1:9050)')
    evasion_group.add_argument('--data', metavar='HEX', help='Append custom hex payload')
    evasion_group.add_argument('--data-string', metavar='STRING', help='Append custom ASCII string')
    evasion_group.add_argument('--data-length', type=int, metavar='NUM', help='Append random data')
    evasion_group.add_argument('--ip-options', metavar='OPTIONS', help='Send packets with IP options')
    evasion_group.add_argument('--ttl', type=int, metavar='VAL', help='Set IP time-to-live field')
    evasion_group.add_argument('--spoof-mac', metavar='MAC', help='Spoof MAC address (MAC, prefix, or vendor name)')
    evasion_group.add_argument('--badsum', action='store_true', help='Send packets with bogus checksum')
    
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-oN', '--output-normal', metavar='FILE', help='Output in normal format')
    output_group.add_argument('-oX', '--output-xml', metavar='FILE', help='Output in XML format')
    output_group.add_argument('-oS', '--output-script', metavar='FILE', help='Output in Script Kiddie format')
    output_group.add_argument('-oG', '--output-grepable', metavar='FILE', help='Output in Grepable format')
    output_group.add_argument('-oA', '--output-all', metavar='BASENAME', help='Output in all three major formats')
    output_group.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (use -vv or more)')
    output_group.add_argument('-d', '--debug', action='count', default=0, help='Increase debugging level (use -dd or more)')
    output_group.add_argument('--reason', action='store_true', help='Display reason port is in particular state')
    output_group.add_argument('--open', dest='open_only', action='store_true', help='Only show open (or possibly open) ports')
    output_group.add_argument('--packet-trace', action='store_true', help='Show all packets sent and received')
    output_group.add_argument('--iflist', action='store_true', help='Print host interfaces and routes')
    output_group.add_argument('--append-output', action='store_true', help='Append to output files')
    output_group.add_argument('--resume', metavar='FILE', help='Resume an aborted scan')
    output_group.add_argument('--resume-control', metavar='FILE', help='Resume scan with control file')
    output_group.add_argument('--noninteractive', action='store_true', help='Disable runtime keyboard interactions')
    output_group.add_argument('--stylesheet', metavar='PATH/URL', help='XSL stylesheet for XML output')
    output_group.add_argument('--http-useragent', metavar='STRING', help='Set HTTP User-Agent string')
    output_group.add_argument('--webxml', action='store_true', help='Reference stylesheet from Nmap.Org')
    output_group.add_argument('--no-stylesheet', action='store_true', help='Prevent XSL stylesheet association')
    
    misc_group = parser.add_argument_group('Miscellaneous')
    misc_group.add_argument('-6', '--ipv6', action='store_true', help='Enable IPv6 scanning')
    misc_group.add_argument('-A', '--aggressive', action='store_true', help='Enable OS detection, version detection, script scanning, and traceroute')
    misc_group.add_argument('--datadir', metavar='DIRNAME', help='Specify custom Nmap data file location')
    misc_group.add_argument('--send-eth', action='store_true', help='Send using raw ethernet frames')
    misc_group.add_argument('--send-ip', action='store_true', help='Send using IP packets')
    misc_group.add_argument('--privileged', action='store_true', help='Assume user is fully privileged')
    misc_group.add_argument('--unprivileged', action='store_true', help='Assume user lacks raw socket privileges')
    misc_group.add_argument('-V', '--version', action='store_true', help='Print version number')
    misc_group.add_argument('--dry-run', action='store_true', help='Print command without executing')
    misc_group.add_argument('--save-log', metavar='FILE', help='Save real-time output to log file')
    misc_group.add_argument('--silent-mode', action='store_true', default=True, 
                            help='Enable silent mode (no DNS, non-interactive) for reduced footprint')
    misc_group.add_argument('--no-silent-mode', dest='silent_mode', action='store_false',
                            help='Disable silent mode (allow DNS resolution and prompts)')
    
    profile_group = parser.add_argument_group('Scan Profiles', 'Predefined scan profiles for common scenarios')
    all_profiles = list(ScanProfile.PROFILES.keys()) + list(ScanProfile.HALL_OF_FAME.keys())
    profile_group.add_argument('--profile', metavar='NAME', choices=all_profiles,help=f'Use predefined scan profile. Available: {", ".join(all_profiles)}')
    profile_group.add_argument('--list-profiles', action='store_true', help='List all available scan profiles')
    profile_group.add_argument('--hall-of-fame', action='store_true',help='Show Hall of Fame (famous scans from movies/pentests)')
    
    config_group = parser.add_argument_group('Config Management', 'Save and load scan configurations')
    config_group.add_argument('--save-config', metavar='FILE', help='Save current scan configuration to JSON/YAML file')
    config_group.add_argument('--load-config', metavar='FILE', help='Load scan configuration from JSON/YAML file')
    
    output_group.add_argument('--auto-output', nargs='?', const='auto', metavar='PREFIX',help='Auto-generate output filenames with timestamp (optionally with prefix)')
    
    parallel_group = parser.add_argument_group('Parallel Scans', 'Scan multiple targets in parallel')
    parallel_group.add_argument('--parallel', type=int, metavar='WORKERS', default=None,help='Enable parallel scanning with N workers (default: 4)')
    
    plugin_group = parser.add_argument_group('Plugin System', 'Load and manage Nmap plugins')
    plugin_group.add_argument('--load-plugin', metavar='FILE', help='Load a plugin from file')
    plugin_group.add_argument('--load-plugins', metavar='DIR', help='Load all plugins from directory')
    plugin_group.add_argument('--list-plugins', action='store_true', help='List all loaded plugins')
    
    script_group.add_argument('--list-nse', action='store_true', help='List all available NSE scripts by category')
    script_group.add_argument('--nse-category', metavar='CAT', help='List NSE scripts in category (vuln, exploit, auth, etc.)')
    script_group.add_argument('--search-nse', metavar='QUERY', help='Search NSE scripts by name or description')
        
    return parser


def wait_for_user(message: str = "Press Enter to continue..."):
    """Wait for user to press Enter"""
    try:
        input(f"{Colors.YELLOW}{message}{Colors.RESET}")
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Colors.RED}{Colors.BOLD}[!]{Colors.RESET} Exiting...")
        sys.exit(0)


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_network(net: str) -> bool:
    """Check if string is a valid network/CIDR (IPv4 or IPv6)"""
    try:
        ipaddress.ip_network(net, strict=False)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Check if string is a valid hostname"""
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
    return allowed.match(hostname) is not None


class DNSResolver:
    """Async DNS resolver with fallback support"""
    
    def __init__(self, custom_dns: Optional[List[str]] = None):
        self.custom_dns = custom_dns or []
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    
    def resolve_sync(self, hostname: str) -> Optional[Tuple[str, bool]]:
        """
        Resolve DNS synchronously
        Returns: (ip_address, is_ipv6) or None
        """
        try:
            ip_obj = ipaddress.ip_address(hostname)
            return (hostname, isinstance(ip_obj, ipaddress.IPv6Address))
        except ValueError:
            pass
        
        try:
            ip = socket.gethostbyname(hostname)
            return (ip, False)
        except socket.gaierror:
            pass
        
        try:
            ip = socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][4][0]
            return (ip, True)
        except (socket.gaierror, IndexError):
            pass
        
        return None

    async def resolve_async(self, hostname: str) -> Optional[Tuple[str, bool]]:
        """
        Resolve DNS asynchronously
        Returns: (ip_address, is_ipv6) or None
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self.resolve_sync, hostname)
    
    def resolve_multiple(self, hostnames: List[str]) -> Dict[str, Optional[Tuple[str, bool]]]:
        """
        Resolve multiple hostnames in parallel
        Returns: Dict mapping hostname to (ip, is_ipv6) or None
        """
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_hostname = {
                executor.submit(self.resolve_sync, hostname): hostname 
                for hostname in hostnames
            }
            for future in concurrent.futures.as_completed(future_to_hostname):
                hostname = future_to_hostname[future]
                try:
                    results[hostname] = future.result()
                except Exception as e:
                    results[hostname] = None
        return results
    
    def is_wildcard_hostname(self, hostname: str) -> bool:
        """Check if hostname contains wildcard patterns"""
        return '*' in hostname or '?' in hostname
    
    def __del__(self):
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)


_dns_resolver = DNSResolver()


def resolve_dns(hostname: str) -> Optional[str]:
    """Resolve DNS hostname to IP address (backward compatibility)"""
    result = _dns_resolver.resolve_sync(hostname)
    return result[0] if result else None


def validate_targets_parallel(targets: List[str]) -> List[Tuple[str, bool, str]]:
    """
    Validate multiple targets in parallel for better performance
    Returns: List of (target, is_valid, message) tuples
    """
    results = []
    
    def validate_one(target: str) -> Tuple[str, bool, str]:
        is_valid, message, _ = check_target_with_nmap(target, auto_continue=True)
        return (target, is_valid, message)
    
    ip_targets = []
    hostname_targets = []
    
    for target in targets:
        try:
            ipaddress.ip_address(target) or ipaddress.ip_network(target, strict=False)
            ip_targets.append(target)
        except ValueError:
            hostname_targets.append(target)
    
    for target in ip_targets:
        results.append((target, True, "Valid IP/Network"))
    
    if hostname_targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(validate_one, target): target for target in hostname_targets}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    target = futures[future]
                    results.append((target, False, f"Validation error: {e}"))
    
    return results


def check_target_with_nmap(target: str, auto_continue: bool = False) -> Tuple[bool, str, Optional[str]]:
    """
    Check if target is valid using improved DNS resolution
    Returns: (is_valid, message, resolved_ip)
    """
    try:
        if is_valid_ip(target):
            ip_obj = ipaddress.ip_address(target)
            is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
            ip_type = "IPv6" if is_ipv6 else "IPv4"
            print(f"{Colors.GREEN}[✓]{Colors.RESET} Valid {ip_type} address: {Colors.CYAN}{target}{Colors.RESET}")
            return True, f"Valid {ip_type}: {target}", target
        
        if is_valid_network(target):
            net_obj = ipaddress.ip_network(target, strict=False)
            is_ipv6 = isinstance(net_obj.network_address, ipaddress.IPv6Address)
            ip_type = "IPv6" if is_ipv6 else "IPv4"
            print(f"{Colors.GREEN}[✓]{Colors.RESET} Valid {ip_type} network: {Colors.CYAN}{target}{Colors.RESET}")
            return True, f"Valid {ip_type} network: {target}", None
    except ValueError:
        pass
    
    if _dns_resolver.is_wildcard_hostname(target):
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Wildcard hostname detected: {Colors.CYAN}{target}{Colors.RESET}")
        if auto_continue:
            return True, f"Wildcard hostname: {target}", None
        try:
            continue_anyway = input(f"{Colors.YELLOW}Continue with wildcard? (y/n): {Colors.RESET}").strip().lower()
            if continue_anyway == 'y':
                return True, f"Wildcard hostname: {target}", None
            else:
                return False, f"Wildcard hostname cancelled: {target}", None
        except (EOFError, KeyboardInterrupt):
            return False, "Cancelled by user", None
    
    if is_valid_hostname(target):
        print(f"{Colors.YELLOW}[?]{Colors.RESET} Resolving DNS for: {Colors.CYAN}{target}{Colors.RESET}")
        
        result = _dns_resolver.resolve_sync(target)
        if result:
            resolved_ip, is_ipv6 = result
            ip_type = "IPv6" if is_ipv6 else "IPv4"
            print(f"{Colors.GREEN}[✓]{Colors.RESET} DNS resolved ({ip_type}): {Colors.CYAN}{target}{Colors.RESET} -> {Colors.GREEN}{resolved_ip}{Colors.RESET}")
            return True, f"DNS resolved ({ip_type}): {target} -> {resolved_ip}", resolved_ip
        else:
            print(f"{Colors.RED}[✗]{Colors.RESET} DNS resolution failed for: {Colors.CYAN}{target}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!]{Colors.RESET} Warning: Cannot resolve DNS, but nmap may still be able to scan it")
            
            if auto_continue:
                return True, f"DNS failed but continuing: {target}", None
            
            try:
                continue_anyway = input(f"{Colors.YELLOW}Continue anyway? (y/n): {Colors.RESET}").strip().lower()
                if continue_anyway == 'y':
                    return True, f"DNS failed but continuing: {target}", None
                else:
                    return False, f"DNS resolution failed: {target}", None
            except (EOFError, KeyboardInterrupt):
                return False, "Cancelled by user", None
    
    print(f"{Colors.RED}[✗]{Colors.RESET} Invalid target format: {Colors.CYAN}{target}{Colors.RESET}")
    return False, f"Invalid target format: {target}", None


def get_target_input() -> Optional[str]:
    """Get target input from user with validation"""
    while True:
        try:
            target = input(f"{Colors.CYAN}Enter target (IP, hostname, or network/CIDR): {Colors.RESET}").strip()
            
            if not target:
                print(f"{Colors.RED}Target cannot be empty. Please try again.{Colors.RESET}")
                continue
            
            if target.lower() == 'q' or target.lower() == 'quit':
                return None
            
            is_valid, message = check_target_with_nmap(target)
            if is_valid:
                return target
            else:
                print(f"{Colors.RED}Invalid target: {message}{Colors.RESET}")
                retry = input(f"{Colors.YELLOW}Try again? (y/n): {Colors.RESET}").strip().lower()
                if retry != 'y':
                    return None
                    
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.RED}Cancelled.{Colors.RESET}")
            return None


def display_section(title: str, content: str, wait: bool = True):
    """Display a section and wait for user input"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{title}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}\n")
    print(content)
    if wait:
        wait_for_user()


def execute_scan_choice(choice_num: int, target: str):
    """Execute scan based on choice number - using stateless build_command"""
    from types import SimpleNamespace
    
    args = SimpleNamespace()
    args.target = [target]
    
    if choice_num == 1:
        args.ping_scan = True
    elif choice_num == 2:
        args.syn_scan = True
    elif choice_num == 3:
        args.connect_scan = True
    elif choice_num == 4:
        args.udp_scan = True
    elif choice_num == 5:
        ports = input(f"{Colors.CYAN}Enter ports to scan (e.g., 22,80,443 or 1-1000): {Colors.RESET}").strip()
        if ports:
            args.ports = ports
        args.syn_scan = True
    elif choice_num == 6:
        args.version_detect = True
    elif choice_num == 7:
        args.default_scripts = True
    elif choice_num == 8:
        args.os_detect = True
    elif choice_num == 9:
        args.aggressive = True
    elif choice_num == 10:
        args.syn_scan = True
        args.version_detect = True
        args.default_scripts = True
        args.os_detect = True
        args.aggressive = True
        args.timing = 4
    else:
        print(f"{Colors.RED}Invalid choice.{Colors.RESET}")
        return
    
    command = NmapWrapper.build_command(args)
    NmapWrapper.execute(command, dry_run=False)


def get_key():
    """Get a single keypress (cross-platform)"""
    if sys.platform == 'win32':
        import msvcrt
        key = msvcrt.getch()
        if key == b'\xe0':
            key = msvcrt.getch()
            if key == b'H':
                return 'UP'
            elif key == b'P':
                return 'DOWN'
            elif key == b'K':
                return 'LEFT'
            elif key == b'M':
                return 'RIGHT'
        elif key == b'\r':
            return 'ENTER'
        elif key == b' ':
            return 'SPACE'
        elif key == b'\x1b':
            return 'ESC'
        elif key == b'\x08' or key == b'\x7f':
            return 'BACKSPACE'
        else:
            return key.decode('utf-8', errors='ignore')
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
            if ch == '\x1b':
                ch = sys.stdin.read(1)
                if ch == '[':
                    ch = sys.stdin.read(1)
                    if ch == 'A':
                        return 'UP'
                    elif ch == 'B':
                        return 'DOWN'
                    elif ch == 'C':
                        return 'RIGHT'
                    elif ch == 'D':
                        return 'LEFT'
                return 'ESC'
            elif ch == '\r' or ch == '\n':
                return 'ENTER'
            elif ch == ' ':
                return 'SPACE'
            elif ch == '\x7f' or ch == '\x08':
                return 'BACKSPACE'
            else:
                return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def advanced_interactive_builder():
    """Advanced Interactive Builder - Multi-page menu with arrow keys"""
    from types import SimpleNamespace
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}Advanced Interactive Scan Builder{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    print(f"{Colors.YELLOW}Use Arrow Keys to navigate, Space to toggle, Enter to confirm, ESC to go back{Colors.RESET}\n")
    
    config = SimpleNamespace()
    config.target = None
    config.scan_type = None
    config.ports = None
    config.timing = None
    config.version_detect = False
    config.os_detect = False
    config.default_scripts = False
    config.aggressive = False
    config.fragment = False
    config.decoys = None
    config.output_all = None
    
    pages = [
        {
            'name': 'Target Selection',
            'options': [
                ('target', 'Target (IP/Hostname/CIDR)', 'text', None),
            ]
        },
        {
            'name': 'Scan Type',
            'options': [
                ('syn_scan', 'SYN Scan (Stealth)', 'bool', False),
                ('connect_scan', 'TCP Connect Scan', 'bool', False),
                ('udp_scan', 'UDP Scan', 'bool', False),
                ('ping_scan', 'Ping Scan (Host Discovery)', 'bool', False),
            ]
        },
        {
            'name': 'Port Specification',
            'options': [
                ('ports', 'Ports (e.g., 22,80,443 or 1-1000)', 'text', None),
                ('fast_scan', 'Fast Scan (Top 100)', 'bool', False),
                ('top_ports', 'Top N Ports', 'text', None),
            ]
        },
        {
            'name': 'Timing & Performance',
            'options': [
                ('timing', 'Timing Template (0-5)', 'text', None),
                ('min_rate', 'Min Rate (packets/sec)', 'text', None),
                ('max_rate', 'Max Rate (packets/sec)', 'text', None),
            ]
        },
        {
            'name': 'Advanced Options',
            'options': [
                ('version_detect', 'Version Detection (-sV)', 'bool', False),
                ('os_detect', 'OS Detection (-O)', 'bool', False),
                ('default_scripts', 'Default Scripts (-sC)', 'bool', False),
                ('aggressive', 'Aggressive Scan (-A)', 'bool', False),
            ]
        },
        {
            'name': 'Evasion & Spoofing',
            'options': [
                ('fragment', 'Fragment Packets (-f)', 'bool', False),
                ('decoys', 'Decoys (-D RND:N or IPs)', 'text', None),
                ('spoof_mac', 'Spoof MAC Address', 'text', None),
                ('ttl', 'TTL Value', 'text', None),
            ]
        },
        {
            'name': 'Output',
            'options': [
                ('output_all', 'Output Filename (base)', 'text', None),
                ('verbose', 'Verbose Level (0-3)', 'text', '0'),
                ('reason', 'Show Reason', 'bool', False),
                ('open_only', 'Open Ports Only', 'bool', False),
            ]
        },
    ]
    
    current_page = 0
    current_option = 0
    
    while True:
        page = pages[current_page]
        options = page['options']
        
        print("\n" * 2)
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}Page {current_page + 1}/{len(pages)}: {page['name']}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        for idx, (key, label, opt_type, default) in enumerate(options):
            if idx == current_option:
                marker = f"{Colors.GREEN}▶{Colors.RESET}"
            else:
                marker = " "
            
            value = getattr(config, key, default)
            
            if opt_type == 'bool':
                status = f"{Colors.GREEN}ON{Colors.RESET}" if value else f"{Colors.RED}OFF{Colors.RESET}"
                print(f"{marker} {Colors.YELLOW}{label:40s}{Colors.RESET} : {status}")
            else:
                display_value = str(value) if value else "(not set)"
                print(f"{marker} {Colors.YELLOW}{label:40s}{Colors.RESET} : {Colors.CYAN}{display_value}{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}↑/↓: Navigate  Space: Toggle/Edit  Enter: Next Page  ESC: Back/Exit{Colors.RESET}")
        if current_page == len(pages) - 1:
            print(f"{Colors.GREEN}Press Enter on last page to build and execute scan{Colors.RESET}")
        
        try:
            key = get_key()
            
            if key == 'UP':
                current_option = (current_option - 1) % len(options)
            elif key == 'DOWN':
                current_option = (current_option + 1) % len(options)
            elif key == 'SPACE':
                key_name, label, opt_type, _ = options[current_option]
                if opt_type == 'bool':
                    current_value = getattr(config, key_name, False)
                    setattr(config, key_name, not current_value)
                else:
                    print(f"\n{Colors.CYAN}Enter value for {label}: {Colors.RESET}", end='', flush=True)
                    try:
                        new_value = input().strip()
                        if new_value:
                            if opt_type == 'text' and key_name in ('timing', 'verbose', 'min_rate', 'max_rate', 'top_ports', 'ttl'):
                                try:
                                    setattr(config, key_name, int(new_value))
                                except ValueError:
                                    setattr(config, key_name, new_value)
                            else:
                                setattr(config, key_name, new_value)
                        else:
                            setattr(config, key_name, None)
                    except (EOFError, KeyboardInterrupt):
                        pass
            elif key == 'ENTER':
                if current_page < len(pages) - 1:
                    current_page += 1
                    current_option = 0
                else:
                    if not config.target:
                        print(f"\n{Colors.RED}[ERROR] Target is required!{Colors.RESET}")
                        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
                        current_page = 0
                        continue
                    
                    print(f"\n{Colors.GREEN}{Colors.BOLD}Building scan command...{Colors.RESET}\n")
                    command = NmapWrapper.build_command(config)
                    
                    print(f"{Colors.CYAN}{Colors.BOLD}Command Preview:{Colors.RESET}")
                    print(f"{Colors.WHITE}{' '.join(command)}{Colors.RESET}\n")
                    
                    confirm = input(f"{Colors.YELLOW}Execute this scan? (y/n): {Colors.RESET}").strip().lower()
                    if confirm == 'y':
                        is_valid, message, _ = check_target_with_nmap(config.target, auto_continue=True)
                        if is_valid:
                            NmapWrapper.execute(command, dry_run=False)
                        else:
                            print(f"{Colors.RED}[ERROR] {message}{Colors.RESET}")
                    break
            elif key == 'ESC':
                if current_page > 0:
                    current_page -= 1
                    current_option = 0
                else:
                    confirm = input(f"\n{Colors.YELLOW}Exit Advanced Builder? (y/n): {Colors.RESET}").strip().lower()
                    if confirm == 'y':
                        break
            elif key == 'q' or key == 'Q':
                confirm = input(f"\n{Colors.YELLOW}Exit Advanced Builder? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    break
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.RED}Exiting...{Colors.RESET}")
            break
        except Exception as e:
            print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")


def interactive_menu():
    """Interactive menu with scan execution and DNS/IP checking"""
    scan_options = [
        ("1", "Ping Scan (Host Discovery)", "-sn"),
        ("2", "SYN Scan (Stealth)", "-sS"),
        ("3", "TCP Connect Scan", "-sT"),
        ("4", "UDP Scan", "-sU"),
        ("5", "Custom Port Scan", "-p"),
        ("6", "Version Detection", "-sV"),
        ("7", "Script Scan (NSE)", "-sC"),
        ("8", "OS Detection", "-O"),
        ("9", "Aggressive Scan (OS + Version + Scripts)", "-A"),
        ("10", "Full Comprehensive Scan", "-sS -sV -sC -O -A -T4"),
    ]
    
    hof_start = len(scan_options) + 1
    hof_options = []
    for idx, (key, data) in enumerate(ScanProfile.HALL_OF_FAME.items(), start=hof_start):
        hof_options.append((str(idx), data['name'], key))
    
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}Welcome to Nmap Wrapper Interactive Scanner{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}\n")
    
    print(f"{Colors.GREEN}Available Scan Options:{Colors.RESET}")
    for num, desc, _ in scan_options:
        print(f"  {Colors.YELLOW}{num}.{Colors.RESET} {desc}")
    
    if hof_options:
        print(f"\n{Colors.MAGENTA}Hall of Fame - Famous Scans:{Colors.RESET}")
        for num, desc, key in hof_options:
            data = ScanProfile.HALL_OF_FAME[key]
            print(f"  {Colors.MAGENTA}{num}.{Colors.RESET} {desc}")
            print(f"     {Colors.CYAN}{data['description']}{Colors.RESET}")
    
    print(f"\n  {Colors.YELLOW}11.{Colors.RESET} {Colors.MAGENTA}Advanced Interactive Builder{Colors.RESET} (Arrow Keys Menu)")
    print(f"\n  {Colors.YELLOW}0.{Colors.RESET} Show help/information")
    print(f"  {Colors.YELLOW}q.{Colors.RESET} Quit")
    
    while True:
        try:
            max_choice = len(scan_options) + len(hof_options) + 1
            choice = input(f"\n{Colors.CYAN}Select a scan option (1-{len(scan_options)}, 11 for Advanced Builder, 0 for help, q to quit): {Colors.RESET}").strip().lower()
            
            if choice == 'q':
                print(f"\n{Colors.GREEN}Goodbye!{Colors.RESET}")
                break
            elif choice == '0':
                print_help_info()
                continue
            elif choice == '11':
                advanced_interactive_builder()
                continue
            elif choice.isdigit():
                choice_num = int(choice)
                
                if choice_num >= hof_start and choice_num < hof_start + len(hof_options):
                    hof_idx = choice_num - hof_start
                    _, _, hof_key = hof_options[hof_idx]
                    hof_data = ScanProfile.HALL_OF_FAME[hof_key]
                    
                    print(f"\n{Colors.MAGENTA}{Colors.BOLD}Selected: {hof_data['name']}{Colors.RESET}")
                    print(f"{Colors.CYAN}Description: {hof_data['description']}{Colors.RESET}")
                    print(f"{Colors.CYAN}Command: nmap {' '.join(hof_data['options'])} <target>{Colors.RESET}\n")
                    
                    target = get_target_input()
                    
                    if target is None:
                        print(f"{Colors.YELLOW}Skipping scan...{Colors.RESET}")
                        continue_choice = input(f"\n{Colors.CYAN}Select another scan? (y/n): {Colors.RESET}").strip().lower()
                        if continue_choice != 'y':
                            break
                        continue
                    
                    print(f"\n{Colors.GREEN}Target validated successfully!{Colors.RESET}")
                    from types import SimpleNamespace
                    args = SimpleNamespace()
                    args.target = [target]
                    command = NmapWrapper.build_command(args, profile=hof_key)
                    NmapWrapper.execute(command, dry_run=False)
                    
                elif 1 <= choice_num <= len(scan_options):
                    num, desc, cmd = scan_options[choice_num - 1]
                
                print(f"\n{Colors.CYAN}{Colors.BOLD}Selected: {desc}{Colors.RESET}")
                print(f"{Colors.CYAN}Command: nmap {cmd} <target>{Colors.RESET}\n")
                
                target = get_target_input()
                
                if target is None:
                    print(f"{Colors.YELLOW}Skipping scan...{Colors.RESET}")
                    continue_choice = input(f"\n{Colors.CYAN}Select another scan? (y/n): {Colors.RESET}").strip().lower()
                    if continue_choice != 'y':
                        break
                    continue
                
                print(f"\n{Colors.GREEN}Target validated successfully!{Colors.RESET}")
                execute_scan_choice(choice_num, target)
                
                continue_choice = input(f"\n{Colors.CYAN}Perform another scan? (y/n): {Colors.RESET}").strip().lower()
                if continue_choice != 'y':
                    break
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.RESET}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.RED}{Colors.BOLD}[!]{Colors.RESET} Exiting...")
            break


def print_help_info():
    """Print help information sections"""
    info_sections = [
        ("📋 Target Specification", """
{Colors.GREEN}Target Options:{Colors.RESET}
  - Direct targets: IP addresses, hostnames, networks
  - {Colors.CYAN}-iL <file>{Colors.RESET}: Input from list of hosts/networks
  - {Colors.CYAN}-iR <num>{Colors.RESET}: Choose random targets
  - {Colors.CYAN}--exclude <hosts>{Colors.RESET}: Exclude hosts/networks
  - {Colors.CYAN}--excludefile <file>{Colors.RESET}: Exclude list from file

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py 192.168.1.1
  python nmap_wrapper.py -iL hosts.txt
        """),
        
        ("🔍 Host Discovery", """
{Colors.GREEN}Host Discovery Options:{Colors.RESET}
  - {Colors.CYAN}-sL{Colors.RESET}: List scan - list targets only
  - {Colors.CYAN}-sn{Colors.RESET}: Ping scan - disable port scan
  - {Colors.CYAN}-Pn{Colors.RESET}: Skip host discovery
  - {Colors.CYAN}-PS/PA/PU/PY{Colors.RESET}: TCP/SCTP discovery probes
  - {Colors.CYAN}-PE/PP/PM{Colors.RESET}: ICMP discovery probes
  - {Colors.CYAN}-PO{Colors.RESET}: IP Protocol Ping
  - {Colors.CYAN}-n / -R{Colors.RESET}: DNS resolution control
  - {Colors.CYAN}--traceroute{Colors.RESET}: Trace hop path

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -sn 192.168.1.0/24
        """),
        
        ("🔎 Scan Techniques", """
{Colors.GREEN}Scan Technique Options:{Colors.RESET}
  - {Colors.CYAN}-sS{Colors.RESET}: TCP SYN scan (stealth)
  - {Colors.CYAN}-sT{Colors.RESET}: TCP Connect() scan
  - {Colors.CYAN}-sA{Colors.RESET}: TCP ACK scan
  - {Colors.CYAN}-sU{Colors.RESET}: UDP scan
  - {Colors.CYAN}-sN/sF/sX{Colors.RESET}: Null/FIN/Xmas scans
  - {Colors.CYAN}-sY/sZ{Colors.RESET}: SCTP scans
  - {Colors.CYAN}-sO{Colors.RESET}: IP protocol scan
  - {Colors.CYAN}-sI <zombie>{Colors.RESET}: Idle scan

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -sS 192.168.1.1
  python nmap_wrapper.py -sU -p 1-1000 192.168.1.1
        """),
        
        ("🔌 Port Specification", """
{Colors.GREEN}Port Specification Options:{Colors.RESET}
  - {Colors.CYAN}-p <ranges>{Colors.RESET}: Scan specified ports
  - {Colors.CYAN}-F{Colors.RESET}: Fast mode (top 100 ports)
  - {Colors.CYAN}-r{Colors.RESET}: Scan ports sequentially
  - {Colors.CYAN}--top-ports <num>{Colors.RESET}: Scan N most common ports
  - {Colors.CYAN}--exclude-ports <ranges>{Colors.RESET}: Exclude ports

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -p 22,80,443 192.168.1.1
  python nmap_wrapper.py -p- 192.168.1.1
        """),
        
        ("🔬 Service/Version Detection", """
{Colors.GREEN}Service/Version Detection Options:{Colors.RESET}
  - {Colors.CYAN}-sV{Colors.RESET}: Probe for service/version
  - {Colors.CYAN}--version-intensity <0-9>{Colors.RESET}: Set intensity
  - {Colors.CYAN}--version-light{Colors.RESET}: Light probing
  - {Colors.CYAN}--version-all{Colors.RESET}: All probes

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -sV 192.168.1.1
        """),
        
        ("📜 Script Scan (NSE)", """
{Colors.GREEN}NSE Script Options:{Colors.RESET}
  - {Colors.CYAN}-sC{Colors.RESET}: Default scripts
  - {Colors.CYAN}--script <scripts>{Colors.RESET}: Run specific scripts
  - {Colors.CYAN}--script-args <args>{Colors.RESET}: Script arguments
  - {Colors.CYAN}--script-trace{Colors.RESET}: Show script activity

{Colors.YELLOW}Script Categories:{Colors.RESET}
  default, vuln, exploit, auth, brute, discovery, dos, malware, safe

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py --script vuln 192.168.1.1
        """),
        
        ("💻 OS Detection", """
{Colors.GREEN}OS Detection Options:{Colors.RESET}
  - {Colors.CYAN}-O{Colors.RESET}: Enable OS detection
  - {Colors.CYAN}--osscan-limit{Colors.RESET}: Limit to promising targets
  - {Colors.CYAN}--osscan-guess{Colors.RESET}: Guess OS aggressively

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -O 192.168.1.1
        """),
        
        ("⚡ Timing and Performance", """
{Colors.GREEN}Timing Options:{Colors.RESET}
  - {Colors.CYAN}-T<0-5>{Colors.RESET}: Timing template
    0=Paranoid, 1=Sneaky, 2=Polite, 3=Normal, 4=Aggressive, 5=Insane
  - {Colors.CYAN}--min-rate / --max-rate{Colors.RESET}: Packet rate control
  - {Colors.CYAN}--scan-delay{Colors.RESET}: Delay between probes

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -T4 192.168.1.1
        """),
        
        ("🛡️ Firewall/IDS Evasion", """
{Colors.GREEN}Evasion Options:{Colors.RESET}
  - {Colors.CYAN}-f{Colors.RESET}: Fragment packets
  - {Colors.CYAN}-D <decoys>{Colors.RESET}: Use decoys
  - {Colors.CYAN}-S <IP>{Colors.RESET}: Spoof source address
  - {Colors.CYAN}-g <port>{Colors.RESET}: Use source port
  - {Colors.CYAN}--mtu <val>{Colors.RESET}: Fragment with MTU
  - {Colors.CYAN}--badsum{Colors.RESET}: Bogus checksum

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -f -D RND:10 192.168.1.1
        """),
        
        ("📤 Output", """
{Colors.GREEN}Output Options:{Colors.RESET}
  - {Colors.CYAN}-oN <file>{Colors.RESET}: Normal format
  - {Colors.CYAN}-oX <file>{Colors.RESET}: XML format
  - {Colors.CYAN}-oG <file>{Colors.RESET}: Grepable format
  - {Colors.CYAN}-oA <basename>{Colors.RESET}: All formats
  - {Colors.CYAN}-v{Colors.RESET}: Verbose (use -vv, -vvv)
  - {Colors.CYAN}-d{Colors.RESET}: Debug (use -dd, -ddd)
  - {Colors.CYAN}--reason{Colors.RESET}: Show port state reasons
  - {Colors.CYAN}--open{Colors.RESET}: Only show open ports

{Colors.YELLOW}Example:{Colors.RESET}
  python nmap_wrapper.py -oA scan 192.168.1.1
        """),
    ]
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}Nmap Options Information:{Colors.RESET}\n")
    for title, content in info_sections:
        display_section(title, content.format(Colors=Colors), wait=True)


def save_config(args, filename: str):
    """Save scan configuration to JSON or YAML file"""
    import json
    from datetime import datetime
    
    config = {}
    
    for key, value in vars(args).items():
        if value is not None and value is not False and key not in ('target', 'save_config', 'load_config'):
            if isinstance(value, list) and len(value) == 0:
                continue
            config[key] = value
    
    config['_metadata'] = {
        'created': datetime.now().isoformat(),
        'version': '1.0'
    }
    
    try:
        if filename.endswith('.yaml') or filename.endswith('.yml'):
            try:
                import yaml
                with open(filename, 'w', encoding='utf-8') as f:
                    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            except ImportError:
                print(f"{Colors.YELLOW}[!] YAML not available, saving as JSON instead{Colors.RESET}")
                filename = filename.rsplit('.', 1)[0] + '.json'
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
        else:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}[+] Configuration saved to: {filename}{Colors.RESET}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Failed to save config: {e}{Colors.RESET}")
        return False


def load_config(filename: str):
    """Load scan configuration from JSON or YAML file"""
    import json
    
    try:
        if filename.endswith('.yaml') or filename.endswith('.yml'):
            try:
                import yaml
                with open(filename, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
            except ImportError:
                print(f"{Colors.YELLOW}[!] YAML not available, trying JSON{Colors.RESET}")
                with open(filename, 'r', encoding='utf-8') as f:
                    config = json.load(f)
        else:
            with open(filename, 'r', encoding='utf-8') as f:
                config = json.load(f)
        
        config.pop('_metadata', None)
        
        allowed_keys = set(NmapWrapper.COMMAND_OPTIONS.keys())
        allowed_keys.update(['target', 'profile', 'parallel', 'auto_output', 'save_log', 'dry_run'])
        
        invalid_keys = []
        for key in config.keys():
            if key not in allowed_keys and not key.startswith('_'):
                invalid_keys.append(key)
        
        if invalid_keys:
            print(f"{Colors.YELLOW}[!] Warning: Invalid keys in config (ignored): {', '.join(invalid_keys)}{Colors.RESET}")
            for key in invalid_keys:
                config.pop(key, None)
        
        print(f"{Colors.GREEN}[+] Configuration loaded from: {filename}{Colors.RESET}")
        return config
    except FileNotFoundError:
        print(f"{Colors.RED}[ERROR] Config file not found: {filename}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Failed to load config: {e}{Colors.RESET}")
        return None


def generate_auto_output(prefix: Optional[str] = None, target: Optional[str] = None) -> str:
    """Generate automatic output filename with timestamp"""
    from datetime import datetime
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if target:
        clean_target = re.sub(r'[^\w\-.]', '_', target)[:30]
        if prefix:
            return f"{prefix}_{timestamp}_{clean_target}"
        else:
            return f"scan_{timestamp}_{clean_target}"
    else:
        if prefix:
            return f"{prefix}_{timestamp}"
        else:
            return f"scan_{timestamp}"


def parallel_scan(targets: List[str], base_args: Any, max_workers: int = 4):
    """
    Execute parallel scans for multiple targets
    Returns: List of (target, returncode, execution_time) tuples
    """
    from types import SimpleNamespace
    
    def scan_target(target: str):
        """Scan a single target"""
        args = SimpleNamespace()
        for attr in dir(base_args):
            if not attr.startswith('_'):
                setattr(args, attr, getattr(base_args, attr, None))
        args.target = [target]
        
        command = NmapWrapper.build_command(args)
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Scanning {Colors.GREEN}{target}{Colors.RESET}...")
        returncode, exec_time = NmapWrapper.execute(command, args=args)
        return (target, returncode, exec_time)
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}Parallel Scan Mode{Colors.RESET}")
    print(f"{Colors.CYAN}Targets: {len(targets)}{Colors.RESET}")
    print(f"{Colors.CYAN}Workers: {max_workers}{Colors.RESET}\n")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(scan_target, target): target for target in targets}
        
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"{Colors.RED}[ERROR] Scan failed for {target}: {e}{Colors.RESET}")
                results.append((target, -1, 0.0))
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}Parallel Scan Summary{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    
    successful = sum(1 for _, rc, _ in results if rc == 0)
    total_time = sum(exec_time for _, _, exec_time in results)
    
    for target, returncode, exec_time in results:
        status = f"{Colors.GREEN}SUCCESS{Colors.RESET}" if returncode == 0 else f"{Colors.RED}FAILED{Colors.RESET}"
        print(f"  {Colors.CYAN}{target:30s}{Colors.RESET} : {status} ({exec_time:.2f}s)")
    
    print(f"\n{Colors.CYAN}Total: {successful}/{len(results)} successful, {total_time:.2f}s total{Colors.RESET}")
    
    return results


def get_nse_scripts(category: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Get NSE scripts by category
    Returns: Dict mapping category to list of script names
    """
    try:
        result = subprocess.run(['nmap', '--script-help', 'all'], capture_output=True, text=True, timeout=10)
        
        scripts_by_category = {}
        current_category = 'uncategorized'
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('Categories:'):
                cats = line.split('Categories:')[1].strip().split(',')
                current_category = cats[0].strip() if cats else 'uncategorized'
                if current_category not in scripts_by_category:
                    scripts_by_category[current_category] = []
            elif line.startswith('  ') and not line.startswith('   '):
                script_name = line.split()[0] if line.split() else None
                if script_name and script_name not in scripts_by_category.get(current_category, []):
                    if current_category not in scripts_by_category:
                        scripts_by_category[current_category] = []
                    scripts_by_category[current_category].append(script_name)
        
        if category:
            return {category: scripts_by_category.get(category, [])}
        
        return scripts_by_category
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not fetch NSE scripts: {e}{Colors.RESET}")
        return {
            'vuln': ['http-vuln-*', 'ssl-*', 'smb-vuln-*'],
            'exploit': ['exploit', 'exploit-*'],
            'auth': ['ssh-auth-methods', 'ftp-anon', 'mysql-empty-password'],
            'discovery': ['smb-os-discovery', 'snmp-info', 'dns-*'],
            'safe': ['http-title', 'http-server-header', 'ssh-hostkey'],
        }


def search_nse_scripts(query: str) -> List[str]:
    """Search NSE scripts by name or description"""
    try:
        result = subprocess.run(['nmap', '--script-help', 'all'], capture_output=True, text=True, timeout=10)
        
        matching_scripts = []
        current_script = None
        script_description = []
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line and not line.startswith(' ') and not line.startswith('Categories:'):
                if current_script and query.lower() in ' '.join(script_description).lower():
                    matching_scripts.append(current_script)
                current_script = line.split()[0] if line.split() else None
                script_description = [line]
            elif current_script:
                script_description.append(line)
        
        if current_script and query.lower() in ' '.join(script_description).lower():
            matching_scripts.append(current_script)
        
        return matching_scripts
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not search NSE scripts: {e}{Colors.RESET}")
        return []


def open_xml_in_browser(xml_file: str):
    """Open XML output file in default browser"""
    try:
        if sys.platform == 'win32':
            os.startfile(xml_file)
        elif sys.platform == 'darwin':
            subprocess.run(['open', xml_file])
        else:
            subprocess.run(['xdg-open', xml_file])
        print(f"{Colors.GREEN}[+] Opened {xml_file} in browser{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not open browser: {e}{Colors.RESET}")


def main():
    """Main function"""
    if sys.platform == 'win32':
        try:
            import ctypes
            try:
                amsi_dll = ctypes.windll.LoadLibrary("amsi.dll")
            except:
                pass
        except:
            pass
    try:
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
{'='*65}
           NMAP Complete Wrapper Script                        
           Version: 7.96SVN Compatible                         
           All Nmap Options Supported                          
{'='*65}
{Colors.RESET}
"""
        print(banner)
    except UnicodeEncodeError:
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*65}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}NMAP Complete Wrapper Script{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}Version: 7.96SVN Compatible{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*65}{Colors.RESET}\n")
    
    parser = create_parser()
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        interactive_menu()
        return
    
    
    if args.hall_of_fame:
        print(f"\n{Colors.CYAN}{Colors.BOLD}Hall of Fame - Famous Scans:{Colors.RESET}\n")
        for key, data in ScanProfile.HALL_OF_FAME.items():
            print(f"  {Colors.GREEN}{key:20s}{Colors.RESET} : {data['name']}")
            print(f"    {Colors.YELLOW}Description:{Colors.RESET} {data['description']}")
            print(f"    {Colors.CYAN}Options:{Colors.RESET} {' '.join(data['options'])}\n")
        return
    
    if args.list_profiles:
        print(f"\n{Colors.CYAN}{Colors.BOLD}Available Scan Profiles:{Colors.RESET}\n")
        print(f"{Colors.GREEN}Standard Profiles:{Colors.RESET}")
        for name, opts in ScanProfile.PROFILES.items():
            print(f"  {Colors.GREEN}{name:20s}{Colors.RESET} : {' '.join(opts)}")
        print(f"\n{Colors.MAGENTA}Hall of Fame Profiles:{Colors.RESET}")
        for key, data in ScanProfile.HALL_OF_FAME.items():
            print(f"  {Colors.MAGENTA}{key:20s}{Colors.RESET} : {data['name']}")
        print()
        return
    
    if args.load_plugin:
        _plugin_manager.load_plugin(args.load_plugin)
    
    if args.load_plugins:
        loaded = _plugin_manager.load_plugins_from_dir(args.load_plugins)
        print(f"{Colors.GREEN}[+] Loaded {loaded} plugins{Colors.RESET}")
    
    if args.list_plugins:
        _plugin_manager.list_plugins()
        return
    
    if args.list_nse:
        scripts = get_nse_scripts()
        print(f"\n{Colors.CYAN}{Colors.BOLD}NSE Scripts by Category:{Colors.RESET}\n")
        for category, script_list in scripts.items():
            print(f"{Colors.GREEN}{category:20s}{Colors.RESET} : {len(script_list)} scripts")
            if len(script_list) <= 10:
                for script in script_list:
                    print(f"  - {script}")
            else:
                for script in script_list[:10]:
                    print(f"  - {script}")
                print(f"  ... and {len(script_list) - 10} more")
            print()
        return
    
    if args.nse_category:
        scripts = get_nse_scripts(args.nse_category)
        print(f"\n{Colors.CYAN}{Colors.BOLD}NSE Scripts in '{args.nse_category}':{Colors.RESET}\n")
        for category, script_list in scripts.items():
            for script in script_list:
                print(f"  {Colors.GREEN}{script}{Colors.RESET}")
        print()
        return
    
    if args.search_nse:
        results = search_nse_scripts(args.search_nse)
        print(f"\n{Colors.CYAN}{Colors.BOLD}NSE Scripts matching '{args.search_nse}':{Colors.RESET}\n")
        if results:
            for script in results:
                print(f"  {Colors.GREEN}{script}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}No scripts found{Colors.RESET}")
        print()
        return
    
    if args.load_config:
        config = load_config(args.load_config)
        if config:
            for key, value in config.items():
                if hasattr(args, key):
                    setattr(args, key, value)
        else:
            sys.exit(1)
    
    if getattr(args, 'tor', False) or getattr(args, 'proxy', None):
        print(f"{Colors.YELLOW}[TIP] Using proxy for evasion. For maximum stealth, ensure proxy is properly configured.{Colors.RESET}")
        if getattr(args, 'tor', False):
            print(f"{Colors.CYAN}[*] Tor mode enabled. Make sure Tor is running on 127.0.0.1:9050{Colors.RESET}")
    
    if args.version:
        try:
            result = subprocess.run(['nmap', '-V'], capture_output=True, text=True)
            print(f"{Colors.CYAN}{result.stdout}{Colors.RESET}")
            return
        except FileNotFoundError:
            print(f"{Colors.RED}nmap not found{Colors.RESET}")
            return
    
    if not args.target and not args.input_list and not args.random_targets:
        print(f"{Colors.RED}{Colors.BOLD}[ERROR]{Colors.RESET} {Colors.YELLOW}target specification required{Colors.RESET}")
        print(f"\n{Colors.CYAN}Usage:{Colors.RESET}")
        print(f"  python nmap_wrapper.py <target> [options]")
        print(f"  python nmap_wrapper.py --profile <name> <target>")
        print(f"  python nmap_wrapper.py -iL <file> [options]")
        print(f"  python nmap_wrapper.py -iR <num> [options]")
        print(f"\n{Colors.YELLOW}Run without arguments for interactive guide:{Colors.RESET}")
        print(f"  python nmap_wrapper.py")
        print(f"\n{Colors.YELLOW}For help:{Colors.RESET}")
        print(f"  python nmap_wrapper.py --help")
        print(f"\n{Colors.YELLOW}List profiles:{Colors.RESET}")
        print(f"  python nmap_wrapper.py --list-profiles")
        sys.exit(1)
    
    if args.target:
        print(f"{Colors.CYAN}{Colors.BOLD}[*]{Colors.RESET} Validating targets...\n")
        validation_results = validate_targets_parallel(args.target)
        valid_targets = []
        
        for target, is_valid, message in validation_results:
            if is_valid:
                valid_targets.append(target)
                print(f"{Colors.GREEN}[✓]{Colors.RESET} Target validated: {Colors.CYAN}{target}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!]{Colors.RESET} Warning: {message} for {Colors.CYAN}{target}{Colors.RESET}")
                try:
                    continue_anyway = input(f"{Colors.YELLOW}Continue with this target anyway? (y/n): {Colors.RESET}").strip().lower()
                    if continue_anyway == 'y':
                        valid_targets.append(target)
                        print(f"{Colors.GREEN}[✓]{Colors.RESET} Continuing with target: {Colors.CYAN}{target}{Colors.RESET}")
                    else:
                        print(f"{Colors.YELLOW}Skipping target: {Colors.CYAN}{target}{Colors.RESET}")
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{Colors.RED}Cancelled.{Colors.RESET}")
                    sys.exit(0)
        
        if not valid_targets:
            print(f"{Colors.RED}{Colors.BOLD}[ERROR]{Colors.RESET} No valid targets to scan.{Colors.RESET}")
            sys.exit(1)
        
        args.target = valid_targets
    
    auto_output = getattr(args, 'auto_output', None)
    if auto_output:
        prefix = auto_output if auto_output != 'auto' else None
        target_str = args.target[0] if args.target else None
        base_name = generate_auto_output(prefix, target_str)
        
        args.output_all = base_name
        print(f"{Colors.CYAN}[*]{Colors.RESET} Auto-output enabled: {Colors.GREEN}{base_name}{Colors.RESET}")
    
    save_config_file = getattr(args, 'save_config', None)
    if save_config_file:
        save_config(args, save_config_file)
        if args.dry_run:
            return 
    
    parallel_workers = getattr(args, 'parallel', None)
    if parallel_workers is not None and args.target and len(args.target) > 1:
        if parallel_workers == 0:
            parallel_workers = 4
        parallel_scan(args.target, args, max_workers=parallel_workers)
        return
    
    profile = getattr(args, 'profile', None)
    command = NmapWrapper.build_command(args, profile=profile)
    
    if profile and profile not in ScanProfile.HALL_OF_FAME:
        print(f"{Colors.CYAN}{Colors.BOLD}[*]{Colors.RESET} Using profile: {Colors.GREEN}{profile}{Colors.RESET}")
    
    save_log = getattr(args, 'save_log', None)
    returncode, exec_time = NmapWrapper.execute(command, dry_run=args.dry_run, save_log=save_log, args=args)
    
    if not args.dry_run and returncode == 0 and auto_output:
        xml_file = f"{base_name}.xml"
        if os.path.exists(xml_file):
            try:
                open_xml_in_browser(xml_file)
            except:
                pass

if __name__ == '__main__':
    main()

