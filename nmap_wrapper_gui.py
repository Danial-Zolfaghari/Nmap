import sys
import os
import subprocess
import threading
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
import importlib.util

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox,
        QGroupBox, QTabWidget, QSpinBox, QFileDialog, QMessageBox,
        QProgressBar, QSplitter, QListWidget, QListWidgetItem, QScrollArea
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette
except ImportError:
    print("PyQt6 is required. Install it with: pip install PyQt6")
    sys.exit(1)

try:
    wrapper_file = "nmap_wrapper copy.py"
    if not os.path.exists(wrapper_file):
        wrapper_file = "nmap_wrapper.py"
    
    spec = importlib.util.spec_from_file_location("nmap_wrapper_module", wrapper_file)
    nmap_wrapper_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nmap_wrapper_module)
    NmapWrapper = nmap_wrapper_module.NmapWrapper
    ScanProfile = nmap_wrapper_module.ScanProfile
    Colors = nmap_wrapper_module.Colors
    create_parser = nmap_wrapper_module.create_parser
    save_config = nmap_wrapper_module.save_config
    load_config = nmap_wrapper_module.load_config
    generate_auto_output = nmap_wrapper_module.generate_auto_output
    validate_targets_parallel = nmap_wrapper_module.validate_targets_parallel
    get_nse_scripts = nmap_wrapper_module.get_nse_scripts
    check_target_with_nmap = nmap_wrapper_module.check_target_with_nmap
    open_xml_in_browser = nmap_wrapper_module.open_xml_in_browser
except Exception as e:
    print(f"Error importing nmap_wrapper: {e}")
    print(f"Make sure '{wrapper_file}' is in the same directory")
    sys.exit(1)



class ScanThread(QThread):
    """Thread for running nmap scans without blocking UI"""
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int, float)
    error_signal = pyqtSignal(str)
    
    def __init__(self, command: List[str], args: Any = None):
        super().__init__()
        self.command = command
        self.args = args
        self._stop = False
    
    def run(self):
        """Execute nmap command and emit signals"""
        try:
            self.start_time = time.time()
            
            if self.args is not None:
                try:
                    _plugin_manager = nmap_wrapper_module._plugin_manager
                    self.command = _plugin_manager.apply_plugins(self.command, self.args)
                except:
                    pass
            
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
            
            process = subprocess.Popen(self.command, **popen_kwargs)
            
            for line in process.stdout:
                if self._stop:
                    process.terminate()
                    break
                line = line.rstrip()
                if line:
                    self.output_signal.emit(line)
            
            if not self._stop:
                returncode = process.wait()
                execution_time = time.time() - self.start_time if hasattr(self, 'start_time') else 0.0
                self.finished_signal.emit(returncode, execution_time)
        except Exception as e:
            self.error_signal.emit(str(e))
    
    def stop(self):
        """Stop the scan"""
        self._stop = True


class NmapGUI(QMainWindow):
    """Main GUI window for Nmap Wrapper"""
    
    def __init__(self):
        super().__init__()
        self.scan_thread: Optional[ScanThread] = None
        self.scan_start_time: Optional[float] = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Nmap Wrapper - GUI Edition")
        self.setGeometry(100, 100, 1200, 800)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        quick_tab = self.create_quick_scan_tab()
        tabs.addTab(quick_tab, "Quick Scan")
        
        advanced_tab = self.create_advanced_tab()
        tabs.addTab(advanced_tab, "Advanced Options")
        
        profiles_tab = self.create_profiles_tab()
        tabs.addTab(profiles_tab, "Scan Profiles")
        
        output_tab = self.create_output_tab()
        tabs.addTab(output_tab, "Output & Results")
        
        help_tab = self.create_help_tab()
        tabs.addTab(help_tab, "Help & Guide")
        
        self.statusBar().showMessage("Ready")
        
        self.apply_dark_theme()
    
    def create_quick_scan_tab(self) -> QWidget:
        """Create quick scan tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        target_group = QGroupBox("Target Specification")
        target_layout = QVBoxLayout()
        
        target_input_layout = QHBoxLayout()
        target_input_layout.addWidget(QLabel("Target(s):"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.1, google.com, 192.168.1.0/24")
        target_input_layout.addWidget(self.target_input)
        
        validate_btn = QPushButton("Validate")
        validate_btn.clicked.connect(self.validate_targets)
        target_input_layout.addWidget(validate_btn)
        
        target_layout.addLayout(target_input_layout)
        
        quick_options_layout = QHBoxLayout()
        
        self.quick_syn = QCheckBox("SYN Scan (-sS)")
        self.quick_syn.setChecked(True)
        quick_options_layout.addWidget(self.quick_syn)
        
        self.quick_version = QCheckBox("Version Detection (-sV)")
        quick_options_layout.addWidget(self.quick_version)
        
        self.quick_scripts = QCheckBox("Default Scripts (-sC)")
        quick_options_layout.addWidget(self.quick_scripts)
        
        self.quick_os = QCheckBox("OS Detection (-O)")
        quick_options_layout.addWidget(self.quick_os)
        
        target_layout.addLayout(quick_options_layout)
        
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Ports:"))
        self.quick_ports = QLineEdit()
        self.quick_ports.setPlaceholderText("Leave empty for default, e.g., 22,80,443 or 1-1000")
        port_layout.addWidget(self.quick_ports)
        
        self.quick_fast = QCheckBox("Fast Scan (Top 100)")
        port_layout.addWidget(self.quick_fast)
        
        target_layout.addLayout(port_layout)
        
        port_adv_layout = QHBoxLayout()
        port_adv_layout.addWidget(QLabel("Top Ports:"))
        self.quick_top_ports = QSpinBox()
        self.quick_top_ports.setMinimum(1)
        self.quick_top_ports.setMaximum(65535)
        port_adv_layout.addWidget(self.quick_top_ports)
        
        port_adv_layout.addWidget(QLabel("Exclude Ports:"))
        self.quick_exclude_ports = QLineEdit()
        self.quick_exclude_ports.setPlaceholderText("e.g., 22,80")
        port_adv_layout.addWidget(self.quick_exclude_ports)
        
        self.quick_sequential = QCheckBox("Sequential (-r)")
        port_adv_layout.addWidget(self.quick_sequential)
        
        target_layout.addLayout(port_adv_layout)
        
        timing_layout = QHBoxLayout()
        timing_layout.addWidget(QLabel("Timing:"))
        self.quick_timing = QComboBox()
        self.quick_timing.addItems(["Paranoid (0)", "Sneaky (1)", "Polite (2)", "Normal (3)", "Aggressive (4)", "Insane (5)"])
        self.quick_timing.setCurrentIndex(3)
        timing_layout.addWidget(self.quick_timing)
        timing_layout.addStretch()
        
        target_layout.addLayout(timing_layout)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        scan_btn = QPushButton("Start Scan")
        scan_btn.setStyleSheet("background-color: #4CAF50; color: white; font-size: 14px; padding: 10px;")
        scan_btn.clicked.connect(self.start_quick_scan)
        layout.addWidget(scan_btn)
        
        layout.addStretch()
        
        return widget
    
    def create_advanced_tab(self) -> QWidget:
        """Create advanced options tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        target_adv_group = QGroupBox("Target Specification (Advanced)")
        target_adv_layout = QVBoxLayout()
        
        input_list_layout = QHBoxLayout()
        input_list_layout.addWidget(QLabel("Input List (-iL):"))
        self.adv_input_list = QLineEdit()
        self.adv_input_list.setPlaceholderText("File with list of targets")
        input_list_layout.addWidget(self.adv_input_list)
        
        browse_list_btn = QPushButton("Browse...")
        browse_list_btn.clicked.connect(lambda: self.browse_file(self.adv_input_list))
        input_list_layout.addWidget(browse_list_btn)
        target_adv_layout.addLayout(input_list_layout)
        
        random_targets_layout = QHBoxLayout()
        random_targets_label = QLabel("Random Targets (-iR):")
        random_targets_label.setToolTip("Choose random targets (0 to disable)")
        random_targets_layout.addWidget(random_targets_label)
        self.adv_random_targets = QSpinBox()
        self.adv_random_targets.setMinimum(0)
        self.adv_random_targets.setMaximum(1000000)
        self.adv_random_targets.setToolTip("Choose random targets (0 to disable)")
        random_targets_layout.addWidget(self.adv_random_targets)
        random_targets_layout.addStretch()
        target_adv_layout.addLayout(random_targets_layout)
        
        exclude_layout = QHBoxLayout()
        exclude_label = QLabel("Exclude:")
        exclude_label.setToolTip("Exclude hosts/networks (comma-separated)")
        exclude_layout.addWidget(exclude_label)
        self.adv_exclude = QLineEdit()
        self.adv_exclude.setPlaceholderText("Comma-separated hosts/networks")
        self.adv_exclude.setToolTip("Exclude hosts/networks (comma-separated)")
        exclude_layout.addWidget(self.adv_exclude)
        target_adv_layout.addLayout(exclude_layout)
        
        target_adv_group.setLayout(target_adv_layout)
        scroll_layout.addWidget(target_adv_group)
        
        discovery_group = QGroupBox("Host Discovery")
        discovery_layout = QVBoxLayout()
        
        self.adv_list_scan = QCheckBox("List Scan (-sL)")
        self.adv_list_scan.setToolTip("List scan - list targets only, don't scan")
        discovery_layout.addWidget(self.adv_list_scan)
        
        self.adv_ping_scan = QCheckBox("Ping Scan (-sn)")
        self.adv_ping_scan.setToolTip("Ping scan - disable port scan, only discover hosts")
        discovery_layout.addWidget(self.adv_ping_scan)
        
        self.adv_skip_discovery = QCheckBox("Skip Discovery (-Pn)")
        self.adv_skip_discovery.setToolTip("Skip host discovery - treat all hosts as online")
        discovery_layout.addWidget(self.adv_skip_discovery)
        
        tcp_syn_layout = QHBoxLayout()
        tcp_syn_label = QLabel("TCP SYN Discovery (-PS):")
        tcp_syn_label.setToolTip("TCP SYN discovery to ports (leave empty for default ports)")
        tcp_syn_layout.addWidget(tcp_syn_label)
        self.adv_tcp_syn_discovery = QLineEdit()
        self.adv_tcp_syn_discovery.setPlaceholderText("Port list or empty")
        self.adv_tcp_syn_discovery.setToolTip("TCP SYN discovery to ports (leave empty for default ports)")
        tcp_syn_layout.addWidget(self.adv_tcp_syn_discovery)
        discovery_layout.addLayout(tcp_syn_layout)
        
        tcp_ack_layout = QHBoxLayout()
        tcp_ack_label = QLabel("TCP ACK Discovery (-PA):")
        tcp_ack_label.setToolTip("TCP ACK discovery to ports (leave empty for default ports)")
        tcp_ack_layout.addWidget(tcp_ack_label)
        self.adv_tcp_ack_discovery = QLineEdit()
        self.adv_tcp_ack_discovery.setPlaceholderText("Port list or empty")
        self.adv_tcp_ack_discovery.setToolTip("TCP ACK discovery to ports (leave empty for default ports)")
        tcp_ack_layout.addWidget(self.adv_tcp_ack_discovery)
        discovery_layout.addLayout(tcp_ack_layout)
        
        udp_discovery_layout = QHBoxLayout()
        udp_discovery_label = QLabel("UDP Discovery (-PU):")
        udp_discovery_label.setToolTip("UDP discovery to ports (leave empty for default ports)")
        udp_discovery_layout.addWidget(udp_discovery_label)
        self.adv_udp_discovery = QLineEdit()
        self.adv_udp_discovery.setPlaceholderText("Port list or empty")
        self.adv_udp_discovery.setToolTip("UDP discovery to ports (leave empty for default ports)")
        udp_discovery_layout.addWidget(self.adv_udp_discovery)
        discovery_layout.addLayout(udp_discovery_layout)
        
        sctp_discovery_layout = QHBoxLayout()
        sctp_discovery_label = QLabel("SCTP Discovery (-PY):")
        sctp_discovery_label.setToolTip("SCTP discovery to ports (leave empty for default ports)")
        sctp_discovery_layout.addWidget(sctp_discovery_label)
        self.adv_sctp_discovery = QLineEdit()
        self.adv_sctp_discovery.setPlaceholderText("Port list or empty")
        self.adv_sctp_discovery.setToolTip("SCTP discovery to ports (leave empty for default ports)")
        sctp_discovery_layout.addWidget(self.adv_sctp_discovery)
        discovery_layout.addLayout(sctp_discovery_layout)
        
        self.adv_icmp_echo = QCheckBox("ICMP Echo (-PE)")
        self.adv_icmp_echo.setToolTip("ICMP echo discovery probe")
        discovery_layout.addWidget(self.adv_icmp_echo)
        
        self.adv_icmp_timestamp = QCheckBox("ICMP Timestamp (-PP)")
        self.adv_icmp_timestamp.setToolTip("ICMP timestamp discovery probe")
        discovery_layout.addWidget(self.adv_icmp_timestamp)
        
        self.adv_icmp_netmask = QCheckBox("ICMP Netmask (-PM)")
        self.adv_icmp_netmask.setToolTip("ICMP netmask request discovery probe")
        discovery_layout.addWidget(self.adv_icmp_netmask)
        
        self.adv_no_dns = QCheckBox("No DNS Resolution (-n)")
        self.adv_no_dns.setToolTip("Never do DNS resolution")
        discovery_layout.addWidget(self.adv_no_dns)
        
        self.adv_always_resolve = QCheckBox("Always Resolve DNS (-R)")
        self.adv_always_resolve.setToolTip("Always resolve DNS (opposite of -n)")
        discovery_layout.addWidget(self.adv_always_resolve)
        
        dns_servers_layout = QHBoxLayout()
        dns_servers_label = QLabel("DNS Servers:")
        dns_servers_label.setToolTip("Specify custom DNS servers (comma-separated)")
        dns_servers_layout.addWidget(dns_servers_label)
        self.adv_dns_servers = QLineEdit()
        self.adv_dns_servers.setPlaceholderText("Comma-separated DNS servers")
        self.adv_dns_servers.setToolTip("Specify custom DNS servers (comma-separated)")
        dns_servers_layout.addWidget(self.adv_dns_servers)
        discovery_layout.addLayout(dns_servers_layout)
        
        self.adv_traceroute = QCheckBox("Traceroute")
        self.adv_traceroute.setToolTip("Trace hop path to each host")
        discovery_layout.addWidget(self.adv_traceroute)
        
        ip_protocol_ping_layout = QHBoxLayout()
        ip_protocol_ping_label = QLabel("IP Protocol Ping (-PO):")
        ip_protocol_ping_label.setToolTip("IP Protocol Ping (leave empty for default protocols)")
        ip_protocol_ping_layout.addWidget(ip_protocol_ping_label)
        self.adv_ip_protocol_ping = QLineEdit()
        self.adv_ip_protocol_ping.setPlaceholderText("Protocol list or empty")
        self.adv_ip_protocol_ping.setToolTip("IP Protocol Ping (leave empty for default protocols)")
        ip_protocol_ping_layout.addWidget(self.adv_ip_protocol_ping)
        discovery_layout.addLayout(ip_protocol_ping_layout)
        
        self.adv_system_dns = QCheckBox("System DNS (--system-dns)")
        self.adv_system_dns.setToolTip("Use OS DNS resolver instead of Nmap's internal resolver")
        discovery_layout.addWidget(self.adv_system_dns)
        
        discovery_group.setLayout(discovery_layout)
        scroll_layout.addWidget(discovery_group)
        
        scan_group = QGroupBox("Scan Techniques")
        scan_layout = QVBoxLayout()
        
        scan_row1 = QHBoxLayout()
        self.adv_syn = QCheckBox("SYN Scan (-sS)")
        self.adv_connect = QCheckBox("Connect Scan (-sT)")
        scan_row1.addWidget(self.adv_syn)
        scan_row1.addWidget(self.adv_connect)
        scan_layout.addLayout(scan_row1)
        
        scan_row2 = QHBoxLayout()
        self.adv_udp = QCheckBox("UDP Scan (-sU)")
        self.adv_null = QCheckBox("Null Scan (-sN)")
        self.adv_fin = QCheckBox("FIN Scan (-sF)")
        scan_row2.addWidget(self.adv_udp)
        scan_row2.addWidget(self.adv_null)
        scan_row2.addWidget(self.adv_fin)
        scan_layout.addLayout(scan_row2)
        
        scan_row3 = QHBoxLayout()
        self.adv_xmas = QCheckBox("Xmas Scan (-sX)")
        self.adv_window = QCheckBox("Window Scan (-sW)")
        self.adv_ack = QCheckBox("ACK Scan (-sA)")
        scan_row3.addWidget(self.adv_xmas)
        scan_row3.addWidget(self.adv_window)
        scan_row3.addWidget(self.adv_ack)
        scan_layout.addLayout(scan_row3)
        
        scan_row4 = QHBoxLayout()
        self.adv_maimon = QCheckBox("Maimon Scan (-sM)")
        scan_row4.addWidget(self.adv_maimon)
        scan_row4.addStretch()
        scan_layout.addLayout(scan_row4)
        
        scan_group.setLayout(scan_layout)
        scroll_layout.addWidget(scan_group)
        
        version_group = QGroupBox("Service/Version Detection")
        version_layout = QVBoxLayout()
        
        self.adv_version_detect = QCheckBox("Version Detection (-sV)")
        version_layout.addWidget(self.adv_version_detect)
        
        version_intensity_layout = QHBoxLayout()
        version_intensity_label = QLabel("Version Intensity (0-9):")
        version_intensity_label.setToolTip("Set version detection intensity (0=light, 9=all probes)")
        version_intensity_layout.addWidget(version_intensity_label)
        self.adv_version_intensity = QSpinBox()
        self.adv_version_intensity.setMinimum(0)
        self.adv_version_intensity.setMaximum(9)
        self.adv_version_intensity.setValue(7)
        self.adv_version_intensity.setToolTip("Set version detection intensity (0=light, 9=all probes)")
        version_intensity_layout.addWidget(self.adv_version_intensity)
        version_intensity_layout.addStretch()
        version_layout.addLayout(version_intensity_layout)
        
        self.adv_version_light = QCheckBox("Version Light (intensity 2)")
        self.adv_version_light.setToolTip("Limit to most likely probes (intensity 2)")
        version_layout.addWidget(self.adv_version_light)
        
        self.adv_version_all = QCheckBox("Version All (intensity 9)")
        self.adv_version_all.setToolTip("Try every single probe (intensity 9)")
        version_layout.addWidget(self.adv_version_all)
        
        self.adv_version_trace = QCheckBox("Version Trace")
        self.adv_version_trace.setToolTip("Show detailed version scan activity")
        version_layout.addWidget(self.adv_version_trace)
        
        version_group.setLayout(version_layout)
        scroll_layout.addWidget(version_group)
        
        nse_group = QGroupBox("NSE Scripts")
        nse_layout = QVBoxLayout()
        
        self.adv_default_scripts = QCheckBox("Default Scripts (-sC)")
        self.adv_default_scripts.setToolTip("Equivalent to --script=default (safe and useful scripts)")
        nse_layout.addWidget(self.adv_default_scripts)
        
        script_layout = QHBoxLayout()
        script_label = QLabel("Custom Scripts:")
        script_label.setToolTip("Run specific scripts/categories (e.g., vuln,exploit,auth or script name)")
        script_layout.addWidget(script_label)
        self.adv_script = QLineEdit()
        self.adv_script.setPlaceholderText("vuln,exploit,auth or script name")
        self.adv_script.setToolTip("Run specific scripts/categories (e.g., vuln,exploit,auth or script name)")
        script_layout.addWidget(self.adv_script)
        nse_layout.addLayout(script_layout)
        
        script_args_layout = QHBoxLayout()
        script_args_label = QLabel("Script Args:")
        script_args_label.setToolTip("Provide arguments to scripts (key=value pairs, e.g., userdb=users.txt)")
        script_args_layout.addWidget(script_args_label)
        self.adv_script_args = QLineEdit()
        self.adv_script_args.setPlaceholderText("key=value pairs")
        self.adv_script_args.setToolTip("Provide arguments to scripts (key=value pairs, e.g., userdb=users.txt)")
        script_args_layout.addWidget(self.adv_script_args)
        nse_layout.addLayout(script_args_layout)
        
        nse_group.setLayout(nse_layout)
        scroll_layout.addWidget(nse_group)
        
        os_group = QGroupBox("OS Detection")
        os_layout = QVBoxLayout()
        
        self.adv_os_detect = QCheckBox("OS Detection (-O)")
        os_layout.addWidget(self.adv_os_detect)
        
        self.adv_osscan_limit = QCheckBox("OS Scan Limit")
        os_layout.addWidget(self.adv_osscan_limit)
        
        self.adv_osscan_guess = QCheckBox("OS Scan Guess")
        self.adv_osscan_guess.setToolTip("Guess OS more aggressively")
        os_layout.addWidget(self.adv_osscan_guess)
        
        max_os_tries_layout = QHBoxLayout()
        max_os_tries_label = QLabel("Max OS Tries:")
        max_os_tries_label.setToolTip("Maximum OS detection attempts")
        max_os_tries_layout.addWidget(max_os_tries_label)
        self.adv_max_os_tries = QSpinBox()
        self.adv_max_os_tries.setMinimum(1)
        self.adv_max_os_tries.setMaximum(100)
        self.adv_max_os_tries.setToolTip("Maximum OS detection attempts")
        max_os_tries_layout.addWidget(self.adv_max_os_tries)
        max_os_tries_layout.addStretch()
        os_layout.addLayout(max_os_tries_layout)
        
        os_group.setLayout(os_layout)
        scroll_layout.addWidget(os_group)
        
        timing_group = QGroupBox("Timing & Performance")
        timing_layout = QVBoxLayout()
        
        timing_template_layout = QHBoxLayout()
        timing_template_label = QLabel("Timing Template:")
        timing_template_label.setToolTip("Timing template: 0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane")
        timing_template_layout.addWidget(timing_template_label)
        self.adv_timing = QComboBox()
        self.adv_timing.addItems(["Paranoid (0)", "Sneaky (1)", "Polite (2)", "Normal (3)", "Aggressive (4)", "Insane (5)"])
        self.adv_timing.setCurrentIndex(3)
        self.adv_timing.setToolTip("Timing template: 0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane")
        timing_template_layout.addWidget(self.adv_timing)
        timing_template_layout.addStretch()
        timing_layout.addLayout(timing_template_layout)
        
        min_rate_layout = QHBoxLayout()
        min_rate_label = QLabel("Min Rate (packets/sec):")
        min_rate_label.setToolTip("Send packets no slower than N per second")
        min_rate_layout.addWidget(min_rate_label)
        self.adv_min_rate = QSpinBox()
        self.adv_min_rate.setMinimum(1)
        self.adv_min_rate.setMaximum(100000)
        self.adv_min_rate.setToolTip("Send packets no slower than N per second")
        min_rate_layout.addWidget(self.adv_min_rate)
        min_rate_layout.addStretch()
        timing_layout.addLayout(min_rate_layout)
        
        max_rate_layout = QHBoxLayout()
        max_rate_label = QLabel("Max Rate (packets/sec):")
        max_rate_label.setToolTip("Send packets no faster than N per second")
        max_rate_layout.addWidget(max_rate_label)
        self.adv_max_rate = QSpinBox()
        self.adv_max_rate.setMinimum(1)
        self.adv_max_rate.setMaximum(100000)
        self.adv_max_rate.setToolTip("Send packets no faster than N per second")
        max_rate_layout.addWidget(self.adv_max_rate)
        max_rate_layout.addStretch()
        timing_layout.addLayout(max_rate_layout)
        
        min_hostgroup_layout = QHBoxLayout()
        min_hostgroup_label = QLabel("Min Hostgroup:")
        min_hostgroup_label.setToolTip("Parallel host scan group sizes (minimum)")
        min_hostgroup_layout.addWidget(min_hostgroup_label)
        self.adv_min_hostgroup = QSpinBox()
        self.adv_min_hostgroup.setMinimum(1)
        self.adv_min_hostgroup.setMaximum(1000000)
        self.adv_min_hostgroup.setToolTip("Parallel host scan group sizes (minimum)")
        min_hostgroup_layout.addWidget(self.adv_min_hostgroup)
        min_hostgroup_layout.addStretch()
        timing_layout.addLayout(min_hostgroup_layout)
        
        max_hostgroup_layout = QHBoxLayout()
        max_hostgroup_label = QLabel("Max Hostgroup:")
        max_hostgroup_label.setToolTip("Parallel host scan group sizes (maximum)")
        max_hostgroup_layout.addWidget(max_hostgroup_label)
        self.adv_max_hostgroup = QSpinBox()
        self.adv_max_hostgroup.setMinimum(1)
        self.adv_max_hostgroup.setMaximum(1000000)
        self.adv_max_hostgroup.setToolTip("Parallel host scan group sizes (maximum)")
        max_hostgroup_layout.addWidget(self.adv_max_hostgroup)
        max_hostgroup_layout.addStretch()
        timing_layout.addLayout(max_hostgroup_layout)
        
        min_parallelism_layout = QHBoxLayout()
        min_parallelism_label = QLabel("Min Parallelism:")
        min_parallelism_label.setToolTip("Probe parallelization (minimum)")
        min_parallelism_layout.addWidget(min_parallelism_label)
        self.adv_min_parallelism = QSpinBox()
        self.adv_min_parallelism.setMinimum(1)
        self.adv_min_parallelism.setMaximum(10000)
        self.adv_min_parallelism.setToolTip("Probe parallelization (minimum)")
        min_parallelism_layout.addWidget(self.adv_min_parallelism)
        min_parallelism_layout.addStretch()
        timing_layout.addLayout(min_parallelism_layout)
        
        max_parallelism_layout = QHBoxLayout()
        max_parallelism_label = QLabel("Max Parallelism:")
        max_parallelism_label.setToolTip("Probe parallelization (maximum)")
        max_parallelism_layout.addWidget(max_parallelism_label)
        self.adv_max_parallelism = QSpinBox()
        self.adv_max_parallelism.setMinimum(1)
        self.adv_max_parallelism.setMaximum(10000)
        self.adv_max_parallelism.setToolTip("Probe parallelization (maximum)")
        max_parallelism_layout.addWidget(self.adv_max_parallelism)
        max_parallelism_layout.addStretch()
        timing_layout.addLayout(max_parallelism_layout)
        
        scan_delay_layout = QHBoxLayout()
        scan_delay_label = QLabel("Scan Delay:")
        scan_delay_label.setToolTip("Adjust delay between probes (e.g., 1s, 100ms, 5m)")
        scan_delay_layout.addWidget(scan_delay_label)
        self.adv_scan_delay = QLineEdit()
        self.adv_scan_delay.setPlaceholderText("e.g., 1s, 100ms, 5m")
        self.adv_scan_delay.setToolTip("Adjust delay between probes (e.g., 1s, 100ms, 5m)")
        scan_delay_layout.addWidget(self.adv_scan_delay)
        timing_layout.addLayout(scan_delay_layout)
        
        max_scan_delay_layout = QHBoxLayout()
        max_scan_delay_label = QLabel("Max Scan Delay:")
        max_scan_delay_label.setToolTip("Maximum delay between probes (e.g., 1s, 100ms)")
        max_scan_delay_layout.addWidget(max_scan_delay_label)
        self.adv_max_scan_delay = QLineEdit()
        self.adv_max_scan_delay.setPlaceholderText("e.g., 1s, 100ms")
        self.adv_max_scan_delay.setToolTip("Maximum delay between probes (e.g., 1s, 100ms)")
        max_scan_delay_layout.addWidget(self.adv_max_scan_delay)
        timing_layout.addLayout(max_scan_delay_layout)
        
        scan_delay_type_layout = QHBoxLayout()
        scan_delay_type_label = QLabel("Scan Delay Type:")
        scan_delay_type_label.setToolTip("Scan delay type: fixed or random")
        scan_delay_type_layout.addWidget(scan_delay_type_label)
        self.adv_scan_delay_type = QComboBox()
        self.adv_scan_delay_type.addItems(["fixed", "random"])
        self.adv_scan_delay_type.setToolTip("Scan delay type: fixed or random")
        scan_delay_type_layout.addWidget(self.adv_scan_delay_type)
        scan_delay_type_layout.addStretch()
        timing_layout.addLayout(scan_delay_type_layout)
        
        max_retries_layout = QHBoxLayout()
        max_retries_label = QLabel("Max Retries:")
        max_retries_label.setToolTip("Caps port scan probe retransmissions (0-100)")
        max_retries_layout.addWidget(max_retries_label)
        self.adv_max_retries = QSpinBox()
        self.adv_max_retries.setMinimum(0)
        self.adv_max_retries.setMaximum(100)
        self.adv_max_retries.setToolTip("Caps port scan probe retransmissions (0-100)")
        max_retries_layout.addWidget(self.adv_max_retries)
        max_retries_layout.addStretch()
        timing_layout.addLayout(max_retries_layout)
        
        host_timeout_layout = QHBoxLayout()
        host_timeout_label = QLabel("Host Timeout:")
        host_timeout_label.setToolTip("Give up on target after this long (e.g., 30m, 1h)")
        host_timeout_layout.addWidget(host_timeout_label)
        self.adv_host_timeout = QLineEdit()
        self.adv_host_timeout.setPlaceholderText("e.g., 30m, 1h")
        self.adv_host_timeout.setToolTip("Give up on target after this long (e.g., 30m, 1h)")
        host_timeout_layout.addWidget(self.adv_host_timeout)
        timing_layout.addLayout(host_timeout_layout)
        
        min_rtt_layout = QHBoxLayout()
        min_rtt_label = QLabel("Min RTT Timeout:")
        min_rtt_label.setToolTip("Minimum probe round trip time (e.g., 100ms, 1s)")
        min_rtt_layout.addWidget(min_rtt_label)
        self.adv_min_rtt_timeout = QLineEdit()
        self.adv_min_rtt_timeout.setPlaceholderText("e.g., 100ms, 1s")
        self.adv_min_rtt_timeout.setToolTip("Minimum probe round trip time (e.g., 100ms, 1s)")
        min_rtt_layout.addWidget(self.adv_min_rtt_timeout)
        timing_layout.addLayout(min_rtt_layout)
        
        max_rtt_layout = QHBoxLayout()
        max_rtt_label = QLabel("Max RTT Timeout:")
        max_rtt_label.setToolTip("Maximum probe round trip time (e.g., 1s, 5m)")
        max_rtt_layout.addWidget(max_rtt_label)
        self.adv_max_rtt_timeout = QLineEdit()
        self.adv_max_rtt_timeout.setPlaceholderText("e.g., 1s, 5m")
        self.adv_max_rtt_timeout.setToolTip("Maximum probe round trip time (e.g., 1s, 5m)")
        max_rtt_layout.addWidget(self.adv_max_rtt_timeout)
        timing_layout.addLayout(max_rtt_layout)
        
        initial_rtt_layout = QHBoxLayout()
        initial_rtt_label = QLabel("Initial RTT Timeout:")
        initial_rtt_label.setToolTip("Initial probe round trip time (e.g., 100ms, 1s)")
        initial_rtt_layout.addWidget(initial_rtt_label)
        self.adv_initial_rtt_timeout = QLineEdit()
        self.adv_initial_rtt_timeout.setPlaceholderText("e.g., 100ms, 1s")
        self.adv_initial_rtt_timeout.setToolTip("Initial probe round trip time (e.g., 100ms, 1s)")
        initial_rtt_layout.addWidget(self.adv_initial_rtt_timeout)
        timing_layout.addLayout(initial_rtt_layout)
        
        port_ratio_layout = QHBoxLayout()
        port_ratio_label = QLabel("Port Ratio:")
        port_ratio_label.setToolTip("Scan ports more common than ratio (e.g., 0.1)")
        port_ratio_layout.addWidget(port_ratio_label)
        self.adv_port_ratio = QLineEdit()
        self.adv_port_ratio.setPlaceholderText("e.g., 0.1")
        self.adv_port_ratio.setToolTip("Scan ports more common than ratio (e.g., 0.1)")
        port_ratio_layout.addWidget(self.adv_port_ratio)
        timing_layout.addLayout(port_ratio_layout)
        
        self.adv_defeat_rst = QCheckBox("Defeat RST Rate Limit")
        self.adv_defeat_rst.setToolTip("Defeat RST rate limiting")
        timing_layout.addWidget(self.adv_defeat_rst)
        
        self.adv_defeat_icmp = QCheckBox("Defeat ICMP Rate Limit")
        self.adv_defeat_icmp.setToolTip("Defeat ICMP rate limiting")
        timing_layout.addWidget(self.adv_defeat_icmp)
        
        timing_group.setLayout(timing_layout)
        scroll_layout.addWidget(timing_group)
        
        evasion_group = QGroupBox("Firewall/IDS Evasion & Spoofing")
        evasion_layout = QVBoxLayout()
        
        self.adv_fragment = QCheckBox("Fragment Packets (-f)")
        evasion_layout.addWidget(self.adv_fragment)
        
        mtu_layout = QHBoxLayout()
        mtu_layout.addWidget(QLabel("MTU:"))
        self.adv_mtu = QSpinBox()
        self.adv_mtu.setMinimum(8)
        self.adv_mtu.setMaximum(1500)
        mtu_layout.addWidget(self.adv_mtu)
        mtu_layout.addStretch()
        evasion_layout.addLayout(mtu_layout)
        
        decoy_layout = QHBoxLayout()
        decoy_layout.addWidget(QLabel("Decoys (-D):"))
        self.adv_decoys = QLineEdit()
        self.adv_decoys.setPlaceholderText("RND:10 or IP1,IP2,IP3")
        decoy_layout.addWidget(self.adv_decoys)
        evasion_layout.addLayout(decoy_layout)
        
        spoof_source_layout = QHBoxLayout()
        spoof_source_layout.addWidget(QLabel("Spoof Source (-S):"))
        self.adv_spoof_source = QLineEdit()
        self.adv_spoof_source.setPlaceholderText("IP address")
        spoof_source_layout.addWidget(self.adv_spoof_source)
        evasion_layout.addLayout(spoof_source_layout)
        
        source_port_layout = QHBoxLayout()
        source_port_layout.addWidget(QLabel("Source Port (-g):"))
        self.adv_source_port = QSpinBox()
        self.adv_source_port.setMinimum(1)
        self.adv_source_port.setMaximum(65535)
        source_port_layout.addWidget(self.adv_source_port)
        source_port_layout.addStretch()
        evasion_layout.addLayout(source_port_layout)
        
        proxy_layout = QHBoxLayout()
        proxy_label = QLabel("Proxy:")
        proxy_label.setToolTip("SOCKS5 proxy for evasion (e.g., socks5://127.0.0.1:9050 for Tor)")
        proxy_layout.addWidget(proxy_label)
        self.adv_proxy = QLineEdit()
        self.adv_proxy.setPlaceholderText("socks5://127.0.0.1:9050")
        self.adv_proxy.setToolTip("SOCKS5 proxy for evasion (e.g., socks5://127.0.0.1:9050 for Tor)")
        proxy_layout.addWidget(self.adv_proxy)
        
        self.adv_tor = QCheckBox("Use Tor")
        self.adv_tor.setToolTip("Use Tor proxy (socks5://127.0.0.1:9050)")
        proxy_layout.addWidget(self.adv_tor)
        evasion_layout.addLayout(proxy_layout)
        
        data_length_layout = QHBoxLayout()
        data_length_label = QLabel("Data Length:")
        data_length_label.setToolTip("Append random data to packets (0-65535 bytes)")
        data_length_layout.addWidget(data_length_label)
        self.adv_data_length = QSpinBox()
        self.adv_data_length.setMinimum(0)
        self.adv_data_length.setMaximum(65535)
        self.adv_data_length.setToolTip("Append random data to packets (0-65535 bytes)")
        data_length_layout.addWidget(self.adv_data_length)
        data_length_layout.addStretch()
        evasion_layout.addLayout(data_length_layout)
        
        ttl_layout = QHBoxLayout()
        ttl_label = QLabel("TTL:")
        ttl_label.setToolTip("Set IP time-to-live field (1-255)")
        ttl_layout.addWidget(ttl_label)
        self.adv_ttl = QSpinBox()
        self.adv_ttl.setMinimum(1)
        self.adv_ttl.setMaximum(255)
        self.adv_ttl.setToolTip("Set IP time-to-live field (1-255)")
        ttl_layout.addWidget(self.adv_ttl)
        ttl_layout.addStretch()
        evasion_layout.addLayout(ttl_layout)
        
        spoof_mac_layout = QHBoxLayout()
        spoof_mac_label = QLabel("Spoof MAC:")
        spoof_mac_label.setToolTip("Spoof MAC address (MAC address, prefix, or vendor name)")
        spoof_mac_layout.addWidget(spoof_mac_label)
        self.adv_spoof_mac = QLineEdit()
        self.adv_spoof_mac.setPlaceholderText("MAC address or vendor name")
        self.adv_spoof_mac.setToolTip("Spoof MAC address (MAC address, prefix, or vendor name)")
        spoof_mac_layout.addWidget(self.adv_spoof_mac)
        evasion_layout.addLayout(spoof_mac_layout)
        
        self.adv_badsum = QCheckBox("Bad Checksum (--badsum)")
        self.adv_badsum.setToolTip("Send packets with bogus checksum (for testing)")
        evasion_layout.addWidget(self.adv_badsum)
        
        self.adv_randomize_hosts = QCheckBox("Randomize Hosts")
        self.adv_randomize_hosts.setToolTip("Randomize target host order")
        evasion_layout.addWidget(self.adv_randomize_hosts)
        
        self.adv_silent_mode = QCheckBox("Silent Mode (No DNS, Non-interactive)")
        self.adv_silent_mode.setChecked(True)
        self.adv_silent_mode.setToolTip("Enable silent mode: no DNS resolution and non-interactive (reduces footprint)")
        evasion_layout.addWidget(self.adv_silent_mode)
        
        evasion_group.setLayout(evasion_layout)
        scroll_layout.addWidget(evasion_group)
        
        output_group = QGroupBox("Output Options")
        output_layout = QVBoxLayout()
        
        output_type_layout = QHBoxLayout()
        output_type_layout.addWidget(QLabel("Output Type:"))
        self.adv_output_normal = QLineEdit()
        self.adv_output_normal.setPlaceholderText("Normal format (-oN)")
        output_type_layout.addWidget(QLabel("Normal:"))
        output_type_layout.addWidget(self.adv_output_normal)
        
        self.adv_output_xml = QLineEdit()
        self.adv_output_xml.setPlaceholderText("XML format (-oX)")
        output_type_layout.addWidget(QLabel("XML:"))
        output_type_layout.addWidget(self.adv_output_xml)
        output_layout.addLayout(output_type_layout)
        
        output_file_layout = QHBoxLayout()
        output_file_layout.addWidget(QLabel("Output All (-oA):"))
        self.adv_output = QLineEdit()
        output_file_layout.addWidget(self.adv_output)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_output_file)
        output_file_layout.addWidget(browse_btn)
        
        output_layout.addLayout(output_file_layout)
        
        self.adv_auto_output = QCheckBox("Auto-generate filename")
        output_layout.addWidget(self.adv_auto_output)
        
        self.adv_verbose = QSpinBox()
        self.adv_verbose.setMinimum(0)
        self.adv_verbose.setMaximum(3)
        self.adv_verbose.setValue(0)
        verbose_layout = QHBoxLayout()
        verbose_layout.addWidget(QLabel("Verbosity Level:"))
        verbose_layout.addWidget(self.adv_verbose)
        output_layout.addLayout(verbose_layout)
        
        self.adv_debug = QSpinBox()
        self.adv_debug.setMinimum(0)
        self.adv_debug.setMaximum(3)
        self.adv_debug.setValue(0)
        debug_layout = QHBoxLayout()
        debug_layout.addWidget(QLabel("Debug Level:"))
        debug_layout.addWidget(self.adv_debug)
        output_layout.addLayout(debug_layout)
        
        self.adv_reason = QCheckBox("Show Reason (--reason)")
        self.adv_reason.setToolTip("Display reason port is in particular state")
        output_layout.addWidget(self.adv_reason)
        
        self.adv_open_only = QCheckBox("Open Ports Only (--open)")
        self.adv_open_only.setToolTip("Only show open (or possibly open) ports")
        output_layout.addWidget(self.adv_open_only)
        
        self.adv_packet_trace = QCheckBox("Packet Trace (--packet-trace)")
        self.adv_packet_trace.setToolTip("Show all packets sent and received (verbose)")
        output_layout.addWidget(self.adv_packet_trace)
        
        self.adv_iflist = QCheckBox("Interface List (--iflist)")
        self.adv_iflist.setToolTip("Print host interfaces and routes")
        output_layout.addWidget(self.adv_iflist)
        
        self.adv_append_output = QCheckBox("Append Output")
        self.adv_append_output.setToolTip("Append to output files instead of overwriting")
        output_layout.addWidget(self.adv_append_output)
        
        resume_layout = QHBoxLayout()
        resume_label = QLabel("Resume:")
        resume_label.setToolTip("Resume an aborted scan from file")
        resume_layout.addWidget(resume_label)
        self.adv_resume = QLineEdit()
        self.adv_resume.setPlaceholderText("Resume file")
        self.adv_resume.setToolTip("Resume an aborted scan from file")
        resume_layout.addWidget(self.adv_resume)
        
        browse_resume_btn = QPushButton("Browse...")
        browse_resume_btn.clicked.connect(lambda: self.browse_file(self.adv_resume))
        resume_layout.addWidget(browse_resume_btn)
        output_layout.addLayout(resume_layout)
        
        resume_control_layout = QHBoxLayout()
        resume_control_label = QLabel("Resume Control:")
        resume_control_label.setToolTip("Resume scan with control file")
        resume_control_layout.addWidget(resume_control_label)
        self.adv_resume_control = QLineEdit()
        self.adv_resume_control.setPlaceholderText("Resume control file")
        self.adv_resume_control.setToolTip("Resume scan with control file")
        resume_control_layout.addWidget(self.adv_resume_control)
        
        browse_resume_control_btn = QPushButton("Browse...")
        browse_resume_control_btn.clicked.connect(lambda: self.browse_file(self.adv_resume_control))
        resume_control_layout.addWidget(browse_resume_control_btn)
        output_layout.addLayout(resume_control_layout)
        
        stylesheet_layout = QHBoxLayout()
        stylesheet_label = QLabel("Stylesheet:")
        stylesheet_label.setToolTip("XSL stylesheet for XML output (path or URL)")
        stylesheet_layout.addWidget(stylesheet_label)
        self.adv_stylesheet = QLineEdit()
        self.adv_stylesheet.setPlaceholderText("XSL stylesheet path/URL")
        self.adv_stylesheet.setToolTip("XSL stylesheet for XML output (path or URL)")
        stylesheet_layout.addWidget(self.adv_stylesheet)
        output_layout.addLayout(stylesheet_layout)
        
        self.adv_webxml = QCheckBox("Web XML (--webxml)")
        self.adv_webxml.setToolTip("Reference stylesheet from Nmap.Org")
        output_layout.addWidget(self.adv_webxml)
        
        self.adv_no_stylesheet = QCheckBox("No Stylesheet")
        self.adv_no_stylesheet.setToolTip("Prevent XSL stylesheet association")
        output_layout.addWidget(self.adv_no_stylesheet)
        
        http_useragent_layout = QHBoxLayout()
        http_useragent_label = QLabel("HTTP User-Agent:")
        http_useragent_label.setToolTip("Set HTTP User-Agent string")
        http_useragent_layout.addWidget(http_useragent_label)
        self.adv_http_useragent = QLineEdit()
        self.adv_http_useragent.setPlaceholderText("Custom User-Agent string")
        self.adv_http_useragent.setToolTip("Set HTTP User-Agent string")
        http_useragent_layout.addWidget(self.adv_http_useragent)
        output_layout.addLayout(http_useragent_layout)
        
        output_group.setLayout(output_layout)
        scroll_layout.addWidget(output_group)
        
        misc_group = QGroupBox("Miscellaneous Options")
        misc_layout = QVBoxLayout()
        
        self.adv_ipv6 = QCheckBox("IPv6 Scanning (-6)")
        self.adv_ipv6.setToolTip("Enable IPv6 scanning")
        misc_layout.addWidget(self.adv_ipv6)
        
        self.adv_aggressive = QCheckBox("Aggressive Scan (-A)")
        self.adv_aggressive.setToolTip("Enable OS detection, version detection, script scanning, and traceroute")
        misc_layout.addWidget(self.adv_aggressive)
        
        datadir_layout = QHBoxLayout()
        datadir_label = QLabel("Data Directory:")
        datadir_label.setToolTip("Specify custom Nmap data file location")
        datadir_layout.addWidget(datadir_label)
        self.adv_datadir = QLineEdit()
        self.adv_datadir.setPlaceholderText("Custom Nmap data directory")
        self.adv_datadir.setToolTip("Specify custom Nmap data file location")
        datadir_layout.addWidget(self.adv_datadir)
        
        browse_datadir_btn = QPushButton("Browse...")
        browse_datadir_btn.clicked.connect(lambda: self.browse_directory(self.adv_datadir))
        datadir_layout.addWidget(browse_datadir_btn)
        misc_layout.addLayout(datadir_layout)
        
        self.adv_send_eth = QCheckBox("Send Ethernet Frames (--send-eth)")
        self.adv_send_eth.setToolTip("Send using raw ethernet frames")
        misc_layout.addWidget(self.adv_send_eth)
        
        self.adv_send_ip = QCheckBox("Send IP Packets (--send-ip)")
        self.adv_send_ip.setToolTip("Send using IP packets")
        misc_layout.addWidget(self.adv_send_ip)
        
        self.adv_privileged = QCheckBox("Privileged Mode (--privileged)")
        self.adv_privileged.setToolTip("Assume user is fully privileged")
        misc_layout.addWidget(self.adv_privileged)
        
        self.adv_unprivileged = QCheckBox("Unprivileged Mode (--unprivileged)")
        self.adv_unprivileged.setToolTip("Assume user lacks raw socket privileges")
        misc_layout.addWidget(self.adv_unprivileged)
        
        misc_group.setLayout(misc_layout)
        scroll_layout.addWidget(misc_group)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
        
        adv_scan_btn = QPushButton("Start Advanced Scan")
        adv_scan_btn.setStyleSheet("background-color: #4CAF50; color: white; font-size: 14px; padding: 10px;")
        adv_scan_btn.clicked.connect(self.start_advanced_scan)
        layout.addWidget(adv_scan_btn)
        
        return widget
    
    def create_profiles_tab(self) -> QWidget:
        """Create profiles tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        profile_group = QGroupBox("Select Profile")
        profile_layout = QVBoxLayout()
        
        profile_select_layout = QHBoxLayout()
        profile_select_layout.addWidget(QLabel("Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("None (Custom)")
        
        for name in ScanProfile.PROFILES.keys():
            self.profile_combo.addItem(f"Standard: {name}")
        
        for key, data in ScanProfile.HALL_OF_FAME.items():
            self.profile_combo.addItem(f"Hall of Fame: {data['name']}")
        
        profile_select_layout.addWidget(self.profile_combo)
        profile_group.setLayout(profile_select_layout)
        layout.addWidget(profile_group)
        
        self.profile_desc = QTextEdit()
        self.profile_desc.setReadOnly(True)
        self.profile_desc.setMaximumHeight(150)
        self.profile_desc.setPlaceholderText("Profile description will appear here...")
        layout.addWidget(QLabel("Profile Description:"))
        layout.addWidget(self.profile_desc)
        
        self.profile_combo.currentIndexChanged.connect(self.update_profile_description)
        
        profile_scan_btn = QPushButton("Start Profile Scan")
        profile_scan_btn.setStyleSheet("background-color: #2196F3; color: white; font-size: 14px; padding: 10px;")
        profile_scan_btn.clicked.connect(self.start_profile_scan)
        layout.addWidget(profile_scan_btn)
        
        config_group = QGroupBox("Configuration Management")
        config_layout = QHBoxLayout()
        
        save_config_btn = QPushButton("Save Config")
        save_config_btn.clicked.connect(self.save_current_config)
        config_layout.addWidget(save_config_btn)
        
        load_config_btn = QPushButton("Load Config")
        load_config_btn.clicked.connect(self.load_saved_config)
        config_layout.addWidget(load_config_btn)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        layout.addStretch()
        
        return widget
    
    def create_output_tab(self) -> QWidget:
        """Create output tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        output_label = QLabel("Scan Output:")
        layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.output_text)
        
        control_layout = QHBoxLayout()
        
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(self.output_text.clear)
        control_layout.addWidget(clear_btn)
        
        save_output_btn = QPushButton("Save Output")
        save_output_btn.clicked.connect(self.save_output)
        control_layout.addWidget(save_output_btn)
        
        control_layout.addStretch()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        control_layout.addWidget(self.progress_bar)
        
        layout.addLayout(control_layout)
        
        return widget
    
    def create_help_tab(self) -> QWidget:
        """Create help and guide tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        intro_group = QGroupBox("Introduction")
        intro_layout = QVBoxLayout()
        intro_text = QTextEdit()
        intro_text.setReadOnly(True)
        intro_text.setMaximumHeight(150)
        intro_text.setText("""
This is a complete Nmap wrapper with graphical interface. It supports all Nmap options and features.

<b>Quick Start:</b>
1. Enter target(s) in Quick Scan tab
2. Select scan options
3. Click "Start Scan"
4. View results in Output & Results tab

<b>Advanced Usage:</b>
- Use Advanced Options tab for full control
- Use Scan Profiles for predefined configurations
- Save/Load configurations for reuse
        """)
        intro_layout.addWidget(intro_text)
        intro_group.setLayout(intro_layout)
        scroll_layout.addWidget(intro_group)
        
        categories = [
            ("Target Specification", """
<b>-iL &lt;file&gt;</b>: Input from list of hosts/networks<br>
<b>-iR &lt;num&gt;</b>: Choose random targets<br>
<b>--exclude &lt;hosts&gt;</b>: Exclude hosts/networks (comma-separated)<br>
<b>--excludefile &lt;file&gt;</b>: Exclude list from file
            """),
            ("Host Discovery", """
<b>-sL</b>: List scan - list targets only<br>
<b>-sn</b>: Ping scan - disable port scan<br>
<b>-Pn</b>: Skip host discovery - treat all hosts as online<br>
<b>-PS &lt;portlist&gt;</b>: TCP SYN discovery to ports<br>
<b>-PA &lt;portlist&gt;</b>: TCP ACK discovery to ports<br>
<b>-PU &lt;portlist&gt;</b>: UDP discovery to ports<br>
<b>-PY &lt;portlist&gt;</b>: SCTP discovery to ports<br>
<b>-PE</b>: ICMP echo discovery probe<br>
<b>-PP</b>: ICMP timestamp discovery probe<br>
<b>-PM</b>: ICMP netmask request discovery probe<br>
<b>-PO &lt;protocols&gt;</b>: IP Protocol Ping<br>
<b>-n</b>: Never do DNS resolution<br>
<b>-R</b>: Always resolve DNS<br>
<b>--dns-servers &lt;servers&gt;</b>: Specify custom DNS servers<br>
<b>--system-dns</b>: Use OS DNS resolver<br>
<b>--traceroute</b>: Trace hop path to each host
            """),
            ("Scan Techniques", """
<b>-sS</b>: TCP SYN scan (stealth scan) - default, fast, stealthy<br>
<b>-sT</b>: TCP Connect() scan - no root required, slower<br>
<b>-sA</b>: TCP ACK scan - map firewall rules<br>
<b>-sW</b>: TCP Window scan - similar to ACK scan<br>
<b>-sM</b>: TCP Maimon scan - FIN/ACK probe<br>
<b>-sU</b>: UDP scan - slow but important<br>
<b>-sN</b>: TCP Null scan - no flags set<br>
<b>-sF</b>: TCP FIN scan - FIN flag only<br>
<b>-sX</b>: TCP Xmas scan - FIN, PSH, URG flags<br>
<b>-sY</b>: SCTP INIT scan<br>
<b>-sZ</b>: SCTP COOKIE-ECHO scan<br>
<b>-sO</b>: IP protocol scan<br>
<b>-sI &lt;zombie&gt;</b>: Idle scan using zombie host<br>
<b>--scanflags &lt;flags&gt;</b>: Customize TCP scan flags<br>
<b>-b &lt;relay&gt;</b>: FTP bounce scan
            """),
            ("Port Specification", """
<b>-p &lt;ranges&gt;</b>: Only scan specified ports (e.g., 22,80,443 or 1-1000)<br>
<b>--exclude-ports &lt;ranges&gt;</b>: Exclude specified ports<br>
<b>-F</b>: Fast mode - scan fewer ports (top 100)<br>
<b>-r</b>: Scan ports sequentially - don't randomize<br>
<b>--randomize-hosts</b>: Randomize target host order<br>
<b>--top-ports &lt;num&gt;</b>: Scan N most common ports<br>
<b>--port-ratio &lt;ratio&gt;</b>: Scan ports more common than ratio
            """),
            ("Service/Version Detection", """
<b>-sV</b>: Probe open ports to determine service/version<br>
<b>--version-intensity &lt;0-9&gt;</b>: Set version detection intensity (0=light, 9=all)<br>
<b>--version-light</b>: Limit to most likely probes (intensity 2)<br>
<b>--version-all</b>: Try every single probe (intensity 9)<br>
<b>--version-trace</b>: Show detailed version scan activity
            """),
            ("Script Scan (NSE)", """
<b>-sC</b>: Equivalent to --script=default<br>
<b>--script &lt;scripts&gt;</b>: Run specific scripts/categories (comma-separated)<br>
<b>--script-args &lt;args&gt;</b>: Provide arguments to scripts (key=value pairs)<br>
<b>--script-args-file &lt;file&gt;</b>: Provide NSE script args in a file<br>
<b>--script-trace</b>: Show all data sent and received<br>
<b>--script-updatedb</b>: Update the script database<br>
<b>--script-timeout &lt;time&gt;</b>: Set script timeout (e.g., 30s, 5m)<br>
<b>--lua-exec &lt;script&gt;</b>: Execute Lua script<br>
<b>Categories:</b> default, vuln, exploit, auth, brute, discovery, dos, malware, safe
            """),
            ("OS Detection", """
<b>-O</b>: Enable OS detection<br>
<b>--osscan-limit</b>: Limit OS detection to promising targets<br>
<b>--osscan-guess</b>: Guess OS more aggressively<br>
<b>--max-os-tries &lt;num&gt;</b>: Maximum OS detection attempts
            """),
            ("Timing & Performance", """
<b>-T&lt;0-5&gt;</b>: Timing template (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)<br>
<b>--min-hostgroup &lt;size&gt;</b>: Parallel host scan group sizes (minimum)<br>
<b>--max-hostgroup &lt;size&gt;</b>: Parallel host scan group sizes (maximum)<br>
<b>--min-parallelism &lt;num&gt;</b>: Probe parallelization (minimum)<br>
<b>--max-parallelism &lt;num&gt;</b>: Probe parallelization (maximum)<br>
<b>--min-rtt-timeout &lt;time&gt;</b>: Minimum probe round trip time<br>
<b>--max-rtt-timeout &lt;time&gt;</b>: Maximum probe round trip time<br>
<b>--initial-rtt-timeout &lt;time&gt;</b>: Initial probe round trip time<br>
<b>--max-retries &lt;num&gt;</b>: Caps port scan probe retransmissions<br>
<b>--host-timeout &lt;time&gt;</b>: Give up on target after this long<br>
<b>--scan-delay &lt;time&gt;</b>: Adjust delay between probes<br>
<b>--max-scan-delay &lt;time&gt;</b>: Maximum delay between probes<br>
<b>--scan-delay-type &lt;type&gt;</b>: Scan delay type (fixed or random)<br>
<b>--min-rate &lt;num&gt;</b>: Send packets no slower than N per second<br>
<b>--max-rate &lt;num&gt;</b>: Send packets no faster than N per second<br>
<b>--defeat-rst-ratelimit</b>: Defeat RST rate limiting<br>
<b>--defeat-icmp-ratelimit</b>: Defeat ICMP rate limiting
            """),
            ("Firewall/IDS Evasion", """
<b>-f</b>: Fragment packets<br>
<b>--mtu &lt;val&gt;</b>: Fragment packets with given MTU<br>
<b>-D &lt;decoys&gt;</b>: Cloak scan with decoys (comma-separated or RND:N)<br>
<b>-S &lt;IP&gt;</b>: Spoof source address<br>
<b>-e &lt;iface&gt;</b>: Use specified interface<br>
<b>-g &lt;port&gt;</b>: Use given source port<br>
<b>--proxies &lt;urls&gt;</b>: Relay through HTTP/SOCKS4 proxies<br>
<b>--proxy &lt;url&gt;</b>: SOCKS5 proxy for evasion<br>
<b>--data &lt;hex&gt;</b>: Append custom hex payload<br>
<b>--data-string &lt;string&gt;</b>: Append custom ASCII string<br>
<b>--data-length &lt;num&gt;</b>: Append random data<br>
<b>--ip-options &lt;options&gt;</b>: Send packets with IP options<br>
<b>--ttl &lt;val&gt;</b>: Set IP time-to-live field<br>
<b>--spoof-mac &lt;mac&gt;</b>: Spoof MAC address<br>
<b>--badsum</b>: Send packets with bogus checksum<br>
<b>--randomize-hosts</b>: Randomize target host order
            """),
            ("Output", """
<b>-oN &lt;file&gt;</b>: Output in normal format<br>
<b>-oX &lt;file&gt;</b>: Output in XML format<br>
<b>-oS &lt;file&gt;</b>: Output in Script Kiddie format<br>
<b>-oG &lt;file&gt;</b>: Output in Grepable format<br>
<b>-oA &lt;basename&gt;</b>: Output in all three major formats<br>
<b>-v</b>: Increase verbosity level (use -vv or more)<br>
<b>-d</b>: Increase debugging level (use -dd or more)<br>
<b>--reason</b>: Display reason port is in particular state<br>
<b>--open</b>: Only show open (or possibly open) ports<br>
<b>--packet-trace</b>: Show all packets sent and received<br>
<b>--iflist</b>: Print host interfaces and routes<br>
<b>--append-output</b>: Append to output files<br>
<b>--resume &lt;file&gt;</b>: Resume an aborted scan<br>
<b>--resume-control &lt;file&gt;</b>: Resume scan with control file<br>
<b>--stylesheet &lt;path/url&gt;</b>: XSL stylesheet for XML output<br>
<b>--webxml</b>: Reference stylesheet from Nmap.Org<br>
<b>--no-stylesheet</b>: Prevent XSL stylesheet association<br>
<b>--http-useragent &lt;string&gt;</b>: Set HTTP User-Agent string
            """),
            ("Miscellaneous", """
<b>-6</b>: Enable IPv6 scanning<br>
<b>-A</b>: Enable OS detection, version detection, script scanning, and traceroute<br>
<b>--datadir &lt;dirname&gt;</b>: Specify custom Nmap data file location<br>
<b>--send-eth</b>: Send using raw ethernet frames<br>
<b>--send-ip</b>: Send using IP packets<br>
<b>--privileged</b>: Assume user is fully privileged<br>
<b>--unprivileged</b>: Assume user lacks raw socket privileges
            """)
        ]
        
        for category, description in categories:
            cat_group = QGroupBox(category)
            cat_layout = QVBoxLayout()
            cat_text = QTextEdit()
            cat_text.setReadOnly(True)
            cat_text.setMaximumHeight(200)
            cat_text.setHtml(description)
            cat_layout.addWidget(cat_text)
            cat_group.setLayout(cat_layout)
            scroll_layout.addWidget(cat_group)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
        
        return widget
    
    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #3c3c3c;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px;
                color: #ffffff;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QCheckBox {
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px 20px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #4CAF50;
            }
        """)
    
    def validate_targets(self):
        """Validate target input"""
        targets_text = self.target_input.text().strip()
        if not targets_text:
            QMessageBox.warning(self, "Warning", "Please enter a target")
            return
        
        targets = [t.strip() for t in targets_text.split(',')]
        self.statusBar().showMessage("Validating targets...")
        
        def validate():
            results = validate_targets_parallel(targets)
            valid_count = sum(1 for _, is_valid, _ in results if is_valid)
            self.statusBar().showMessage(f"Validation complete: {valid_count}/{len(targets)} targets valid")
        
        threading.Thread(target=validate, daemon=True).start()
    
    def start_quick_scan(self):
        """Start a quick scan"""
        targets_text = self.target_input.text().strip()
        if not targets_text:
            QMessageBox.warning(self, "Warning", "Please enter a target")
            return
        
        from types import SimpleNamespace
        args = SimpleNamespace()
        args.target = [t.strip() for t in targets_text.split(',')]
        
        if self.quick_syn.isChecked():
            args.syn_scan = True
        if self.quick_version.isChecked():
            args.version_detect = True
        if self.quick_scripts.isChecked():
            args.default_scripts = True
        if self.quick_os.isChecked():
            args.os_detect = True
        
        if self.quick_ports.text().strip():
            args.ports = self.quick_ports.text().strip()
        if self.quick_fast.isChecked():
            args.fast_scan = True
        
        timing_map = {"Paranoid (0)": 0, "Sneaky (1)": 1, "Polite (2)": 2, "Normal (3)": 3, "Aggressive (4)": 4, "Insane (5)": 5}
        args.timing = timing_map[self.quick_timing.currentText()]
        
        args.silent_mode = True
        args.always_resolve = False
        args.no_dns = False
        
        self.execute_scan(args)
    
    def start_advanced_scan(self):
        """Start an advanced scan"""
        targets_text = self.target_input.text().strip()
        if not targets_text:
            QMessageBox.warning(self, "Warning", "Please enter a target in Quick Scan tab")
            return
        
        args = self.get_current_args()
        self.execute_scan(args)
    
    def start_profile_scan(self):
        """Start a profile scan"""
        targets_text = self.target_input.text().strip()
        if not targets_text:
            QMessageBox.warning(self, "Warning", "Please enter a target in Quick Scan tab")
            return
        
        profile_text = self.profile_combo.currentText()
        if profile_text == "None (Custom)":
            QMessageBox.warning(self, "Warning", "Please select a profile")
            return
        
        args = self.get_current_args()
        self.execute_scan(args)
    
    def execute_scan(self, args):
        """Execute nmap scan"""
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, "Warning", "A scan is already running")
            return
        
        if hasattr(args, 'auto_output') and args.auto_output:
            target_str = args.target[0] if args.target else None
            prefix = getattr(args, 'auto_output', None) if hasattr(args, 'auto_output') else None
            base_name = generate_auto_output(prefix, target_str)
            args.output_all = base_name
        
        profile = None
        if hasattr(args, 'profile'):
            profile = args.profile
        
        command = NmapWrapper.build_command(args, profile=profile)
        
        self.output_text.clear()
        self.output_text.append(f"[*] Starting scan: {' '.join(command)}\n")
        self.output_text.append("=" * 70 + "\n")
        
        self.scan_thread = ScanThread(command, args)
        self.scan_thread.output_signal.connect(self.append_output)
        self.scan_thread.finished_signal.connect(self.scan_finished)
        self.scan_thread.error_signal.connect(self.scan_error)
        
        self.scan_start_time = time.time()
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.statusBar().showMessage("Scanning...")
        
        self.scan_thread.start()
    
    def append_output(self, text: str):
        """Append text to output"""
        self.output_text.moveCursor(QTextCursor.MoveOperation.End)
        self.output_text.insertPlainText(text + "\n")
        self.output_text.moveCursor(QTextCursor.MoveOperation.End)
    
    def scan_finished(self, returncode: int, execution_time: float):
        """Handle scan completion"""
        self.progress_bar.setVisible(False)
        
        status = "SUCCESS" if returncode == 0 else f"FAILED (exit code: {returncode})"
        self.append_output("\n" + "=" * 70)
        self.append_output(f"[*] Scan {status}")
        self.append_output(f"[*] Execution time: {execution_time:.2f} seconds")
        self.append_output("=" * 70)
        
        self.statusBar().showMessage(f"Scan completed: {status}")
        
        if returncode == 0 and hasattr(self, 'scan_thread') and self.scan_thread.args:
            args = self.scan_thread.args
            if hasattr(args, 'output_all') and args.output_all:
                xml_file = f"{args.output_all}.xml"
                if os.path.exists(xml_file):
                    try:
                        open_xml_in_browser(xml_file)
                        self.append_output(f"\n[*] Opened XML output in browser: {xml_file}")
                    except:
                        pass
    
    def scan_error(self, error: str):
        """Handle scan error"""
        self.progress_bar.setVisible(False)
        self.append_output(f"\n[ERROR] {error}")
        self.statusBar().showMessage(f"Error: {error}")
        QMessageBox.critical(self, "Error", f"Scan failed: {error}")
    
    def update_profile_description(self, index: int):
        """Update profile description"""
        if index == 0:
            self.profile_desc.clear()
            return
        
        profile_text = self.profile_combo.currentText()
        
        if profile_text.startswith("Standard:"):
            profile_name = profile_text.replace("Standard: ", "")
            if profile_name in ScanProfile.PROFILES:
                opts = ScanProfile.PROFILES[profile_name]
                self.profile_desc.setText(f"Profile: {profile_name}\n\nOptions: {' '.join(opts)}")
        elif profile_text.startswith("Hall of Fame:"):
            profile_name = profile_text.replace("Hall of Fame: ", "")
            for key, data in ScanProfile.HALL_OF_FAME.items():
                if data['name'] == profile_name:
                    self.profile_desc.setText(f"Name: {data['name']}\n\nDescription: {data['description']}\n\nOptions: {' '.join(data['options'])}")
                    break
    
    def save_current_config(self):
        """Save current configuration"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "", "JSON Files (*.json);;YAML Files (*.yaml *.yml);;All Files (*)"
        )
        
        if filename:
            from types import SimpleNamespace
            args = self.get_current_args()
            if save_config(args, filename):
                QMessageBox.information(self, "Success", f"Configuration saved to {filename}")
    
    def load_saved_config(self):
        """Load saved configuration"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "JSON Files (*.json);;YAML Files (*.yaml *.yml);;All Files (*)"
        )
        
        if filename:
            config = load_config(filename)
            if config:
                self.apply_config_to_ui(config)
                QMessageBox.information(self, "Success", f"Configuration loaded from {filename}")
    
    def get_current_args(self):
        """Get current UI state as args"""
        from types import SimpleNamespace
        args = SimpleNamespace()
        
        targets_text = self.target_input.text().strip()
        if targets_text:
            args.target = [t.strip() for t in targets_text.split(',')]
        
        args.syn_scan = self.quick_syn.isChecked()
        args.version_detect = self.quick_version.isChecked()
        args.default_scripts = self.quick_scripts.isChecked()
        args.os_detect = self.quick_os.isChecked()
        
        if self.quick_ports.text().strip():
            args.ports = self.quick_ports.text().strip()
        if self.quick_fast.isChecked():
            args.fast_scan = True
        
        timing_map = {"Paranoid (0)": 0, "Sneaky (1)": 1, "Polite (2)": 2, "Normal (3)": 3, "Aggressive (4)": 4, "Insane (5)": 5}
        args.timing = timing_map[self.quick_timing.currentText()]
        
        if hasattr(self, 'adv_input_list') and self.adv_input_list.text().strip():
            args.input_list = self.adv_input_list.text().strip()
        if hasattr(self, 'adv_random_targets') and self.adv_random_targets.value() > 0:
            args.random_targets = self.adv_random_targets.value()
        if hasattr(self, 'adv_exclude') and self.adv_exclude.text().strip():
            args.exclude = self.adv_exclude.text().strip()
        
        if hasattr(self, 'quick_top_ports') and self.quick_top_ports.value() > 0:
            args.top_ports = self.quick_top_ports.value()
        if hasattr(self, 'quick_exclude_ports') and self.quick_exclude_ports.text().strip():
            args.exclude_ports = self.quick_exclude_ports.text().strip()
        if hasattr(self, 'quick_sequential') and self.quick_sequential.isChecked():
            args.sequential = True
        
        if hasattr(self, 'adv_list_scan') and self.adv_list_scan.isChecked():
            args.list_scan = True
        args.ping_scan = self.adv_ping_scan.isChecked()
        args.skip_discovery = self.adv_skip_discovery.isChecked()
        if hasattr(self, 'adv_tcp_syn_discovery') and self.adv_tcp_syn_discovery.text().strip() is not None:
            tcp_syn_val = self.adv_tcp_syn_discovery.text().strip()
            args.tcp_syn_discovery = tcp_syn_val if tcp_syn_val else True
        if hasattr(self, 'adv_tcp_ack_discovery') and self.adv_tcp_ack_discovery.text().strip() is not None:
            tcp_ack_val = self.adv_tcp_ack_discovery.text().strip()
            args.tcp_ack_discovery = tcp_ack_val if tcp_ack_val else True
        if hasattr(self, 'adv_udp_discovery') and self.adv_udp_discovery.text().strip() is not None:
            udp_val = self.adv_udp_discovery.text().strip()
            args.udp_discovery = udp_val if udp_val else True
        if hasattr(self, 'adv_icmp_echo') and self.adv_icmp_echo.isChecked():
            args.icmp_echo = True
        if hasattr(self, 'adv_icmp_timestamp') and self.adv_icmp_timestamp.isChecked():
            args.icmp_timestamp = True
        if hasattr(self, 'adv_icmp_netmask') and self.adv_icmp_netmask.isChecked():
            args.icmp_netmask = True
        args.no_dns = self.adv_no_dns.isChecked()
        if hasattr(self, 'adv_always_resolve') and self.adv_always_resolve.isChecked():
            args.always_resolve = True
        if hasattr(self, 'adv_dns_servers') and self.adv_dns_servers.text().strip():
            args.dns_servers = self.adv_dns_servers.text().strip()
        if hasattr(self, 'adv_traceroute') and self.adv_traceroute.isChecked():
            args.traceroute = True
        if hasattr(self, 'adv_sctp_discovery') and self.adv_sctp_discovery.text().strip() is not None:
            sctp_val = self.adv_sctp_discovery.text().strip()
            args.sctp_discovery = sctp_val if sctp_val else True
        if hasattr(self, 'adv_ip_protocol_ping') and self.adv_ip_protocol_ping.text().strip() is not None:
            ip_proto_val = self.adv_ip_protocol_ping.text().strip()
            args.ip_protocol_ping = ip_proto_val if ip_proto_val else True
        if hasattr(self, 'adv_system_dns') and self.adv_system_dns.isChecked():
            args.system_dns = True
        
        args.syn_scan = self.adv_syn.isChecked() if hasattr(self, 'adv_syn') else False
        args.connect_scan = self.adv_connect.isChecked()
        args.ack_scan = self.adv_ack.isChecked() if hasattr(self, 'adv_ack') else False
        args.udp_scan = self.adv_udp.isChecked()
        args.null_scan = self.adv_null.isChecked()
        args.fin_scan = self.adv_fin.isChecked() if hasattr(self, 'adv_fin') else False
        args.xmas_scan = self.adv_xmas.isChecked() if hasattr(self, 'adv_xmas') else False
        args.window_scan = self.adv_window.isChecked() if hasattr(self, 'adv_window') else False
        args.maimon_scan = self.adv_maimon.isChecked() if hasattr(self, 'adv_maimon') else False
        
        args.version_detect = self.adv_version_detect.isChecked() if hasattr(self, 'adv_version_detect') else False
        if hasattr(self, 'adv_version_intensity') and self.adv_version_intensity.value() != 7:
            args.version_intensity = self.adv_version_intensity.value()
        if hasattr(self, 'adv_version_light') and self.adv_version_light.isChecked():
            args.version_light = True
        if hasattr(self, 'adv_version_all') and self.adv_version_all.isChecked():
            args.version_all = True
        if hasattr(self, 'adv_version_trace') and self.adv_version_trace.isChecked():
            args.version_trace = True
        
        if hasattr(self, 'adv_default_scripts') and self.adv_default_scripts.isChecked():
            args.default_scripts = True
        if hasattr(self, 'adv_script') and self.adv_script.text().strip():
            args.script = self.adv_script.text().strip()
        if hasattr(self, 'adv_script_args') and self.adv_script_args.text().strip():
            args.script_args = self.adv_script_args.text().strip()
        if hasattr(self, 'adv_script_args_file') and self.adv_script_args_file.text().strip():
            args.script_args_file = self.adv_script_args_file.text().strip()
        if hasattr(self, 'adv_script_trace') and self.adv_script_trace.isChecked():
            args.script_trace = True
        if hasattr(self, 'adv_script_updatedb') and self.adv_script_updatedb.isChecked():
            args.script_updatedb = True
        if hasattr(self, 'adv_script_timeout') and self.adv_script_timeout.text().strip():
            args.script_timeout = self.adv_script_timeout.text().strip()
        if hasattr(self, 'adv_lua_exec') and self.adv_lua_exec.text().strip():
            args.lua_exec = self.adv_lua_exec.text().strip()
        
        if hasattr(self, 'adv_os_detect') and self.adv_os_detect.isChecked():
            args.os_detect = True
        if hasattr(self, 'adv_osscan_limit') and self.adv_osscan_limit.isChecked():
            args.osscan_limit = True
        if hasattr(self, 'adv_osscan_guess') and self.adv_osscan_guess.isChecked():
            args.osscan_guess = True
        if hasattr(self, 'adv_max_os_tries') and self.adv_max_os_tries.value() > 0:
            args.max_os_tries = self.adv_max_os_tries.value()
        
        if hasattr(self, 'adv_timing'):
            timing_map = {"Paranoid (0)": 0, "Sneaky (1)": 1, "Polite (2)": 2, "Normal (3)": 3, "Aggressive (4)": 4, "Insane (5)": 5}
            args.timing = timing_map[self.adv_timing.currentText()]
        if hasattr(self, 'adv_min_rate') and self.adv_min_rate.value() > 1:
            args.min_rate = self.adv_min_rate.value()
        if hasattr(self, 'adv_max_rate') and self.adv_max_rate.value() < 100000:
            args.max_rate = self.adv_max_rate.value()
        if hasattr(self, 'adv_min_hostgroup') and self.adv_min_hostgroup.value() > 1:
            args.min_hostgroup = self.adv_min_hostgroup.value()
        if hasattr(self, 'adv_max_hostgroup') and self.adv_max_hostgroup.value() < 1000000:
            args.max_hostgroup = self.adv_max_hostgroup.value()
        if hasattr(self, 'adv_min_parallelism') and self.adv_min_parallelism.value() > 1:
            args.min_parallelism = self.adv_min_parallelism.value()
        if hasattr(self, 'adv_max_parallelism') and self.adv_max_parallelism.value() < 10000:
            args.max_parallelism = self.adv_max_parallelism.value()
        if hasattr(self, 'adv_min_rtt_timeout') and self.adv_min_rtt_timeout.text().strip():
            args.min_rtt_timeout = self.adv_min_rtt_timeout.text().strip()
        if hasattr(self, 'adv_max_rtt_timeout') and self.adv_max_rtt_timeout.text().strip():
            args.max_rtt_timeout = self.adv_max_rtt_timeout.text().strip()
        if hasattr(self, 'adv_initial_rtt_timeout') and self.adv_initial_rtt_timeout.text().strip():
            args.initial_rtt_timeout = self.adv_initial_rtt_timeout.text().strip()
        if hasattr(self, 'adv_max_retries') and self.adv_max_retries.value() > 0:
            args.max_retries = self.adv_max_retries.value()
        if hasattr(self, 'adv_host_timeout') and self.adv_host_timeout.text().strip():
            args.host_timeout = self.adv_host_timeout.text().strip()
        if hasattr(self, 'adv_scan_delay') and self.adv_scan_delay.text().strip():
            args.scan_delay = self.adv_scan_delay.text().strip()
        if hasattr(self, 'adv_max_scan_delay') and self.adv_max_scan_delay.text().strip():
            args.max_scan_delay = self.adv_max_scan_delay.text().strip()
        if hasattr(self, 'adv_scan_delay_type') and self.adv_scan_delay_type.currentText():
            args.scan_delay_type = self.adv_scan_delay_type.currentText()
        if hasattr(self, 'adv_port_ratio') and self.adv_port_ratio.text().strip():
            args.port_ratio = self.adv_port_ratio.text().strip()
        if hasattr(self, 'adv_defeat_rst') and self.adv_defeat_rst.isChecked():
            args.defeat_rst_ratelimit = True
        if hasattr(self, 'adv_defeat_icmp') and self.adv_defeat_icmp.isChecked():
            args.defeat_icmp_ratelimit = True
        
        args.fragment = self.adv_fragment.isChecked()
        if hasattr(self, 'adv_mtu') and self.adv_mtu.value() != 1500:
            args.mtu = self.adv_mtu.value()
        if self.adv_decoys.text().strip():
            args.decoys = self.adv_decoys.text().strip()
        if hasattr(self, 'adv_spoof_source') and self.adv_spoof_source.text().strip():
            args.spoof_source = self.adv_spoof_source.text().strip()
        if hasattr(self, 'adv_interface') and self.adv_interface.text().strip():
            args.interface = self.adv_interface.text().strip()
        if hasattr(self, 'adv_source_port') and self.adv_source_port.value() != 0:
            args.source_port = self.adv_source_port.value()
        if hasattr(self, 'adv_data') and self.adv_data.text().strip():
            args.data = self.adv_data.text().strip()
        if hasattr(self, 'adv_data_string') and self.adv_data_string.text().strip():
            args.data_string = self.adv_data_string.text().strip()
        if hasattr(self, 'adv_ip_options') and self.adv_ip_options.text().strip():
            args.ip_options = self.adv_ip_options.text().strip()
        if self.adv_proxy.text().strip():
            args.proxy = self.adv_proxy.text().strip()
        args.tor = self.adv_tor.isChecked()
        if hasattr(self, 'adv_data_length') and self.adv_data_length.value() > 0:
            args.data_length = self.adv_data_length.value()
        if hasattr(self, 'adv_ttl') and self.adv_ttl.value() != 64:
            args.ttl = self.adv_ttl.value()
        if hasattr(self, 'adv_spoof_mac') and self.adv_spoof_mac.text().strip():
            args.spoof_mac = self.adv_spoof_mac.text().strip()
        if hasattr(self, 'adv_badsum') and self.adv_badsum.isChecked():
            args.badsum = True
        if hasattr(self, 'adv_randomize_hosts') and self.adv_randomize_hosts.isChecked():
            args.randomize_hosts = True
        args.silent_mode = self.adv_silent_mode.isChecked()
        
        if hasattr(self, 'adv_output_normal') and self.adv_output_normal.text().strip():
            args.output_normal = self.adv_output_normal.text().strip()
        if hasattr(self, 'adv_output_xml') and self.adv_output_xml.text().strip():
            args.output_xml = self.adv_output_xml.text().strip()
        if hasattr(self, 'adv_output_grepable') and self.adv_output_grepable.text().strip():
            args.output_grepable = self.adv_output_grepable.text().strip()
        if hasattr(self, 'adv_output_script') and self.adv_output_script.text().strip():
            args.output_script = self.adv_output_script.text().strip()
        if self.adv_output.text().strip():
            args.output_all = self.adv_output.text().strip()
        args.auto_output = self.adv_auto_output.isChecked()
        args.verbose = self.adv_verbose.value()
        if hasattr(self, 'adv_debug') and self.adv_debug.value() > 0:
            args.debug = self.adv_debug.value()
        if hasattr(self, 'adv_reason') and self.adv_reason.isChecked():
            args.reason = True
        if hasattr(self, 'adv_open_only') and self.adv_open_only.isChecked():
            args.open_only = True
        if hasattr(self, 'adv_packet_trace') and self.adv_packet_trace.isChecked():
            args.packet_trace = True
        if hasattr(self, 'adv_iflist') and self.adv_iflist.isChecked():
            args.iflist = True
        if hasattr(self, 'adv_append_output') and self.adv_append_output.isChecked():
            args.append_output = True
        if hasattr(self, 'adv_resume') and self.adv_resume.text().strip():
            args.resume = self.adv_resume.text().strip()
        if hasattr(self, 'adv_stylesheet') and self.adv_stylesheet.text().strip():
            args.stylesheet = self.adv_stylesheet.text().strip()
        if hasattr(self, 'adv_webxml') and self.adv_webxml.isChecked():
            args.webxml = True
        if hasattr(self, 'adv_no_stylesheet') and self.adv_no_stylesheet.isChecked():
            args.no_stylesheet = True
        if hasattr(self, 'adv_http_useragent') and self.adv_http_useragent.text().strip():
            args.http_useragent = self.adv_http_useragent.text().strip()
        
        if hasattr(self, 'adv_ipv6') and self.adv_ipv6.isChecked():
            args.ipv6 = True
        if hasattr(self, 'adv_aggressive') and self.adv_aggressive.isChecked():
            args.aggressive = True
        if hasattr(self, 'adv_datadir') and self.adv_datadir.text().strip():
            args.datadir = self.adv_datadir.text().strip()
        if hasattr(self, 'adv_send_eth') and self.adv_send_eth.isChecked():
            args.send_eth = True
        if hasattr(self, 'adv_send_ip') and self.adv_send_ip.isChecked():
            args.send_ip = True
        if hasattr(self, 'adv_privileged') and self.adv_privileged.isChecked():
            args.privileged = True
        if hasattr(self, 'adv_unprivileged') and self.adv_unprivileged.isChecked():
            args.unprivileged = True
        
        profile_text = self.profile_combo.currentText()
        if profile_text != "None (Custom)":
            if profile_text.startswith("Standard:"):
                args.profile = profile_text.replace("Standard: ", "")
            elif profile_text.startswith("Hall of Fame:"):
                profile_name = profile_text.replace("Hall of Fame: ", "")
                for key, data in ScanProfile.HALL_OF_FAME.items():
                    if data['name'] == profile_name:
                        args.profile = key
                        break
        
        return args
    
    def apply_config_to_ui(self, config: Dict):
        """Apply loaded config to UI"""
        if 'target' in config:
            target_val = config['target']
            if isinstance(target_val, list):
                self.target_input.setText(','.join(target_val))
            else:
                self.target_input.setText(str(target_val))
        
        if 'syn_scan' in config:
            self.quick_syn.setChecked(bool(config['syn_scan']))
        if 'version_detect' in config:
            self.quick_version.setChecked(bool(config['version_detect']))
        if 'default_scripts' in config:
            self.quick_scripts.setChecked(bool(config['default_scripts']))
        if 'os_detect' in config:
            self.quick_os.setChecked(bool(config['os_detect']))
        
        if 'ports' in config:
            self.quick_ports.setText(str(config['ports']))
        if 'fast_scan' in config:
            self.quick_fast.setChecked(bool(config['fast_scan']))
        
        if 'timing' in config:
            timing_val = config['timing']
            timing_map = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5}
            if timing_val in timing_map:
                self.quick_timing.setCurrentIndex(timing_val)
        
        if 'ping_scan' in config:
            self.adv_ping_scan.setChecked(bool(config['ping_scan']))
        if 'skip_discovery' in config:
            self.adv_skip_discovery.setChecked(bool(config['skip_discovery']))
        if 'no_dns' in config:
            self.adv_no_dns.setChecked(bool(config['no_dns']))
        
        if 'fragment' in config:
            self.adv_fragment.setChecked(bool(config['fragment']))
        if 'decoys' in config:
            self.adv_decoys.setText(str(config['decoys']))
        if 'proxy' in config:
            self.adv_proxy.setText(str(config['proxy']))
        if 'tor' in config:
            self.adv_tor.setChecked(bool(config['tor']))
        if 'silent_mode' in config:
            self.adv_silent_mode.setChecked(bool(config['silent_mode']))
        
        if 'output_all' in config:
            self.adv_output.setText(str(config['output_all']))
        if 'auto_output' in config:
            self.adv_auto_output.setChecked(bool(config['auto_output']))
        if 'verbose' in config:
            self.adv_verbose.setValue(int(config['verbose']))
        
        if 'profile' in config:
            profile_name = config['profile']
            for i in range(self.profile_combo.count()):
                item_text = self.profile_combo.itemText(i)
                if profile_name in item_text or item_text.endswith(profile_name):
                    self.profile_combo.setCurrentIndex(i)
                    break
    
    def browse_output_file(self):
        """Browse for output file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Output As", "", "All Files (*)"
        )
        if filename:
            self.adv_output.setText(filename)
    
    def save_output(self):
        """Save output to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Output", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.output_text.toPlainText())
                QMessageBox.information(self, "Success", f"Output saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save output: {e}")


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = NmapGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
