#!/usr/bin/env python3
"""
System Safety Monitor - Improved Version
"""

import os
import sys
import time
import json
import logging
import argparse
import subprocess
import psutil
import smtplib
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging.handlers import RotatingFileHandler
import configparser

class SystemSafetyMonitor:
    def __init__(self, config_path: str = "config.ini"):
        """Initialize the safety monitor with configuration."""
        self.config_path = config_path
        self.config = self._load_config()
        self.setup_logging()
        self.alerts = []
        self.alert_cooldown = {}  # Prevent spam alerts
        
        # Whitelist for known safe processes
        self.safe_processes = {
            'kernel_threads': {'kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog', 'kworker', 'kcompactd'},
            'systemd': {'systemd', 'systemd-', 'dbus'},
            'system_services': {
                'networkd', 'resolved', 'timesyncd', 'logind', 'udevd', 'ModemManager',
                'NetworkManager', 'wpa_supplicant', 'dhclient', 'chronyd', 'ntpd'
            },
            'desktop_environment': {
                'gnome-', 'kde-', 'xfce', 'lxde', 'mate-', 'cinnamon',
                'at-spi', 'dconf', 'gvfs', 'pulseaudio', 'pipewire'
            },
            'security_tools': {'fail2ban', 'ufw', 'iptables', 'firewalld'},
            'common_apps': {'firefox', 'chrome', 'thunderbird', 'libreoffice', 'code', 'vim', 'nano'},
        }
        
        # Improved suspicious process patterns
        self.suspicious_patterns = {
            'reverse_shells': [r'nc\s+.*-[le]', r'bash\s+-i', r'/dev/tcp/', r'sh\s+-i'],
            'crypto_miners': [r'xmrig', r'cpuminer', r'cgminer', r'bfgminer', r'ethminer'],
            'malware_names': [r'rootkit', r'backdoor', r'trojan', r'keylogger'],
            'suspicious_network': [r'netcat', r'socat.*EXEC', r'python.*socket'],
            'privilege_escalation': [r'sudo\s+su', r'chmod\s+\+s', r'setuid'],
        }
        
    def _load_config(self) -> configparser.ConfigParser:
        """Load configuration from file or create default."""
        config = configparser.ConfigParser()
        
        if os.path.exists(self.config_path):
            config.read(self.config_path)
        else:
            # Create default configuration
            config['THRESHOLDS'] = {
                'cpu_percent': '85',
                'memory_percent': '90',
                'disk_percent': '95',
                'temp_celsius': '75',
                'load_average': '3.0',
                'failed_login_threshold': '10'
            }
            config['MONITORING'] = {
                'check_interval': '300',  # 5 minutes
                'log_level': 'INFO',
                'enable_email_alerts': 'false',
                'enable_desktop_notifications': 'true',
                'alert_cooldown_minutes': '30'
            }
            config['EMAIL'] = {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': '587',
                'sender_email': '',
                'sender_password': '',
                'recipient_email': ''
            }
            config['SECURITY'] = {
                'check_failed_logins': 'true',
                'check_suspicious_processes': 'true',
                'check_network_connections': 'true',
                'check_open_ports': 'true',
                'whitelist_known_good_processes': 'true'
            }
            config['ADVANCED'] = {
                'enable_process_analysis': 'true',
                'check_process_network_activity': 'true',
                'monitor_file_changes': 'false',
                'suspicious_cpu_threshold': '80'  # CPU usage für einzelne Prozesse
            }
            
            # Save default configuration
            with open(self.config_path, 'w') as f:
                config.write(f)
                
        return config
    
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config['MONITORING']['log_level'])
        
        # Create logs directory if it doesn't exist
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'safety_monitor.log'),
                logging.handlers.RotatingFileHandler(
                    log_dir / 'safety_monitor_rotating.log',
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                ),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _is_alert_in_cooldown(self, alert_key: str) -> bool:
        """Check if alert is in cooldown period."""
        cooldown_minutes = int(self.config['MONITORING']['alert_cooldown_minutes'])
        if alert_key in self.alert_cooldown:
            time_diff = datetime.now() - self.alert_cooldown[alert_key]
            return time_diff.total_seconds() < (cooldown_minutes * 60)
        return False
    
    def _set_alert_cooldown(self, alert_key: str):
        """Set alert cooldown timestamp."""
        self.alert_cooldown[alert_key] = datetime.now()
    
    def check_system_resources(self) -> Dict:
        """Monitor system resource usage with improved accuracy."""
        results = {}
        
        # CPU Usage (multiple samples for accuracy)
        cpu_samples = []
        for _ in range(3):
            cpu_samples.append(psutil.cpu_percent(interval=0.5))
        cpu_percent = sum(cpu_samples) / len(cpu_samples)
        
        cpu_threshold = float(self.config['THRESHOLDS']['cpu_percent'])
        results['cpu'] = {
            'usage': round(cpu_percent, 1),
            'threshold': cpu_threshold,
            'alert': cpu_percent > cpu_threshold,
            'per_core': psutil.cpu_percent(percpu=True)
        }
        
        # Memory Usage with more details
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        memory_threshold = float(self.config['THRESHOLDS']['memory_percent'])
        
        results['memory'] = {
            'usage': round(memory.percent, 1),
            'threshold': memory_threshold,
            'alert': memory.percent > memory_threshold,
            'available_gb': round(memory.available / (1024**3), 2),
            'total_gb': round(memory.total / (1024**3), 2),
            'swap_usage': round(swap.percent, 1) if swap.total > 0 else 0,
            'swap_alert': swap.percent > 50 if swap.total > 0 else False
        }
        
        # Disk Usage for all mounted filesystems
        disk_threshold = float(self.config['THRESHOLDS']['disk_percent'])
        disk_results = {}
        
        for partition in psutil.disk_partitions():
            if partition.fstype:  # Skip special filesystems
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    usage_percent = (usage.used / usage.total) * 100
                    
                    disk_results[partition.mountpoint] = {
                        'usage': round(usage_percent, 1),
                        'threshold': disk_threshold,
                        'alert': usage_percent > disk_threshold,
                        'free_gb': round(usage.free / (1024**3), 2),
                        'total_gb': round(usage.total / (1024**3), 2),
                        'filesystem': partition.fstype
                    }
                except (PermissionError, OSError):
                    continue
                    
        results['disk'] = disk_results
        
        # Load Average
        try:
            load_avgs = os.getloadavg()
            load_threshold = float(self.config['THRESHOLDS']['load_average'])
            cpu_count = psutil.cpu_count()
            
            results['load_average'] = {
                '1min': round(load_avgs[0], 2),
                '5min': round(load_avgs[1], 2),
                '15min': round(load_avgs[2], 2),
                'threshold': load_threshold,
                'cpu_count': cpu_count,
                'alert': load_avgs[0] > load_threshold,
                'normalized_1min': round(load_avgs[0] / cpu_count, 2)
            }
        except OSError:
            results['load_average'] = {'error': 'Load average not available on this system'}
        
        return results
    
    def check_temperature(self) -> Dict:
        """Monitor system temperature with improved sensor detection."""
        results = {}
        temp_threshold = float(self.config['THRESHOLDS']['temp_celsius'])
        
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                sensor_data = {}
                max_temp = 0
                critical_temps = []
                
                for sensor_name, entries in temps.items():
                    sensor_temps = []
                    for entry in entries:
                        if entry.current is not None:
                            sensor_temps.append({
                                'current': entry.current,
                                'high': entry.high,
                                'critical': entry.critical,
                                'label': entry.label or 'Unknown'
                            })
                            
                            if entry.current > max_temp:
                                max_temp = entry.current
                                
                            if entry.critical and entry.current > entry.critical * 0.9:
                                critical_temps.append({
                                    'sensor': sensor_name,
                                    'label': entry.label,
                                    'temp': entry.current,
                                    'critical': entry.critical
                                })
                    
                    if sensor_temps:
                        sensor_data[sensor_name] = sensor_temps
                
                results['temperature'] = {
                    'sensors': sensor_data,
                    'max_temp': round(max_temp, 1),
                    'threshold': temp_threshold,
                    'alert': max_temp > temp_threshold,
                    'critical_warnings': critical_temps
                }
            else:
                results['temperature'] = {'error': 'No temperature sensors found'}
                
        except Exception as e:
            results['temperature'] = {'error': f'Temperature check failed: {str(e)}'}
            
        return results
    
    def _is_process_whitelisted(self, process_name: str, cmdline: str) -> bool:
        """Check if process is in whitelist."""
        if not self.config['SECURITY'].getboolean('whitelist_known_good_processes'):
            return False
            
        process_name_lower = process_name.lower()
        cmdline_lower = cmdline.lower()
        
        # Check against all whitelist categories
        for category, processes in self.safe_processes.items():
            for safe_process in processes:
                if safe_process.lower() in process_name_lower or safe_process.lower() in cmdline_lower:
                    return True
                    
        # Check for kernel threads (usually in brackets)
        if process_name.startswith('[') and process_name.endswith(']'):
            return True
            
        return False
    
    def _analyze_process_suspicion(self, process_info: Dict) -> Dict:
        """Analyze process for suspicious behavior."""
        suspicion_score = 0
        reasons = []
        
        name = process_info['name']
        cmdline = process_info.get('cmdline', '')
        
        # Check against suspicious patterns
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    suspicion_score += 3
                    reasons.append(f"Matches {category} pattern: {pattern}")
        
        # Check for unusual network activity
        if self.config['ADVANCED'].getboolean('check_process_network_activity'):
            try:
                proc = psutil.Process(process_info['pid'])
                connections = proc.connections()
                
                for conn in connections:
                    if conn.raddr and conn.raddr.port in [4444, 5555, 6666, 7777, 8888, 9999]:
                        suspicion_score += 2
                        reasons.append(f"Connected to suspicious port: {conn.raddr.port}")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Check CPU usage
        try:
            proc = psutil.Process(process_info['pid'])
            cpu_percent = proc.cpu_percent(interval=0.1)
            cpu_threshold = float(self.config['ADVANCED']['suspicious_cpu_threshold'])
            
            if cpu_percent > cpu_threshold:
                suspicion_score += 1
                reasons.append(f"High CPU usage: {cpu_percent:.1f}%")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return {
            'score': suspicion_score,
            'reasons': reasons,
            'is_suspicious': suspicion_score >= 3
        }
    
    def _check_suspicious_processes(self) -> Dict:
        """Check for potentially suspicious processes with improved detection."""
        suspicious_processes = []
        analyzed_count = 0
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'ppid']):
            try:
                analyzed_count += 1
                proc_info = proc.info
                proc_name = proc_info['name'] or 'Unknown'
                cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                
                # Skip whitelisted processes
                if self._is_process_whitelisted(proc_name, cmdline):
                    continue
                
                # Analyze process for suspicious behavior
                if self.config['ADVANCED'].getboolean('enable_process_analysis'):
                    analysis = self._analyze_process_suspicion(proc_info)
                    
                    if analysis['is_suspicious']:
                        suspicious_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_name,
                            'cmdline': cmdline[:200] + '...' if len(cmdline) > 200 else cmdline,
                            'ppid': proc_info['ppid'],
                            'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                            'suspicion_score': analysis['score'],
                            'reasons': analysis['reasons']
                        })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        return {
            'processes': suspicious_processes,
            'analyzed_count': analyzed_count,
            'alert': len(suspicious_processes) > 0
        }
    
    def _check_failed_logins(self) -> Dict:
        """Check for excessive failed login attempts with improved detection."""
        try:
            failed_attempts = 0
            failed_ips = {}
            
            # Try multiple log sources
            log_sources = [
                # SSH logs via journalctl
                ['journalctl', '-u', 'ssh', '--since', '1 hour ago', '--no-pager'],
                ['journalctl', '-u', 'sshd', '--since', '1 hour ago', '--no-pager'],
                # System auth logs
                ['grep', 'Failed password', '/var/log/auth.log'],
                ['grep', 'Failed password', '/var/log/secure'],
            ]
            
            for cmd in log_sources:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        
                        for line in lines:
                            if 'Failed password' in line or 'authentication failure' in line:
                                failed_attempts += 1
                                
                                # Extract IP address
                                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                                if ip_match:
                                    ip = ip_match.group(1)
                                    failed_ips[ip] = failed_ips.get(ip, 0) + 1
                        
                        if failed_attempts > 0:
                            break  # Found logs, no need to try other sources
                            
                except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
                    continue
            
            threshold = int(self.config['THRESHOLDS']['failed_login_threshold'])
            
            # Find top attacking IPs
            top_attackers = sorted(failed_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                'count': failed_attempts,
                'threshold': threshold,
                'alert': failed_attempts > threshold,
                'attacking_ips': dict(top_attackers),
                'unique_ips': len(failed_ips)
            }
            
        except Exception as e:
            self.logger.error(f"Failed login check error: {e}")
            return {'error': f'Failed login check error: {str(e)}', 'alert': False}
    
    def _check_network_connections(self) -> Dict:
        """Check for unusual network connections with improved analysis."""
        unusual_connections = []
        listening_ports = []
        
        # Suspicious ports (commonly used by malware/backdoors)
        suspicious_ports = {
            4444: 'Metasploit default',
            5555: 'Android Debug Bridge / Backdoors',
            6666: 'IRC/Backdoors',
            7777: 'Backdoors',
            8888: 'Alternative HTTP/Backdoors',
            9999: 'Backdoors',
            31337: 'Elite/Backdoors',
            12345: 'NetBus backdoor',
            54321: 'Backdoors'
        }
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Check listening ports
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'pid': conn.pid
                    }
                    
                    if conn.laddr.port in suspicious_ports:
                        port_info['suspicious'] = True
                        port_info['reason'] = suspicious_ports[conn.laddr.port]
                        
                    listening_ports.append(port_info)
                
                # Check established connections
                elif conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in suspicious_ports:
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            proc_name = proc.name() if proc else 'Unknown'
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = 'Unknown'
                            
                        unusual_connections.append({
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'process': proc_name,
                            'pid': conn.pid,
                            'suspicious_reason': suspicious_ports[conn.raddr.port]
                        })
        
        except Exception as e:
            self.logger.error(f"Network connection check error: {e}")
            return {'error': f'Network check failed: {str(e)}'}
        
        return {
            'unusual_connections': unusual_connections,
            'listening_ports': listening_ports,
            'suspicious_listeners': [p for p in listening_ports if p.get('suspicious', False)],
            'alert': len(unusual_connections) > 0 or any(p.get('suspicious', False) for p in listening_ports)
        }
    
    def check_security_issues(self) -> Dict:
        """Check for security-related issues."""
        results = {}
        
        if self.config['SECURITY'].getboolean('check_failed_logins'):
            results['failed_logins'] = self._check_failed_logins()
            
        if self.config['SECURITY'].getboolean('check_suspicious_processes'):
            results['suspicious_processes'] = self._check_suspicious_processes()
            
        if self.config['SECURITY'].getboolean('check_network_connections'):
            results['network_connections'] = self._check_network_connections()
            
        return results
    
    def check_system_services(self) -> Dict:
        """Check status of critical system services."""
        critical_services = ['ssh', 'sshd', 'systemd-resolved', 'systemd-networkd', 'cron', 'crond']
        optional_services = ['ufw', 'fail2ban', 'firewalld', 'iptables']
        results = {}
        
        all_services = critical_services + optional_services
        
        for service in all_services:
            try:
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True, timeout=5)
                status = result.stdout.strip()
                
                # Critical services should be active
                is_critical = service in critical_services
                should_alert = False
                
                if is_critical:
                    should_alert = status not in ['active']
                else:
                    # Optional services: only alert if they exist but are failed
                    should_alert = status in ['failed', 'error']
                
                results[service] = {
                    'status': status,
                    'is_critical': is_critical,
                    'alert': should_alert
                }
                
            except subprocess.TimeoutExpired:
                results[service] = {'error': 'Service check timeout', 'alert': True}
            except FileNotFoundError:
                results[service] = {'error': 'systemctl not found', 'alert': False}
            except Exception as e:
                results[service] = {'error': f'Service check failed: {str(e)}', 'alert': False}
                
        return results
    
    def send_alert(self, alert_type: str, message: str, severity: str = 'WARNING'):
        """Send alert notification with cooldown protection."""
        alert_key = f"{alert_type}_{hash(message) % 1000}"
        
        # Check cooldown
        if self._is_alert_in_cooldown(alert_key):
            self.logger.debug(f"Alert {alert_type} is in cooldown, skipping")
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = f"[{timestamp}] {severity}: {alert_type}: {message}"
        self.alerts.append(alert)
        
        # Log based on severity
        if severity == 'CRITICAL':
            self.logger.critical(alert)
        elif severity == 'ERROR':
            self.logger.error(alert)
        else:
            self.logger.warning(alert)
        
        # Set cooldown
        self._set_alert_cooldown(alert_key)
        
        # Desktop notification
        if self.config['MONITORING'].getboolean('enable_desktop_notifications'):
            self._send_desktop_notification(f'{severity}: {alert_type}', message)
        
        # Email notification
        if self.config['MONITORING'].getboolean('enable_email_alerts'):
            self._send_email_alert(alert_type, message, severity)
    
    def _send_desktop_notification(self, title: str, message: str):
        """Send desktop notification."""
        try:
            if os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'):
                # Try notify-send first
                try:
                    subprocess.run(['notify-send', '--urgency=critical', title, message], 
                                 timeout=5, check=False)
                    return
                except FileNotFoundError:
                    pass
                
                # Try other notification methods
                try:
                    subprocess.run(['zenity', '--warning', '--text', f"{title}\n{message}"], 
                                 timeout=5, check=False)
                except FileNotFoundError:
                    pass
                    
        except Exception as e:
            self.logger.debug(f"Desktop notification failed: {e}")
    
    def _process_alerts(self, results: Dict):
        """Process and send alerts based on monitoring results with improved logic."""
        # Resource alerts
        if 'resources' in results:
            res = results['resources']
            
            if res['cpu']['alert']:
                self.send_alert('HIGH_CPU', 
                              f"CPU usage: {res['cpu']['usage']}% (threshold: {res['cpu']['threshold']}%)", 
                              'WARNING')
            
            if res['memory']['alert']:
                severity = 'CRITICAL' if res['memory']['usage'] > 95 else 'WARNING'
                self.send_alert('HIGH_MEMORY', 
                              f"Memory usage: {res['memory']['usage']}% (available: {res['memory']['available_gb']}GB)", 
                              severity)
            
            if res['memory']['swap_alert']:
                self.send_alert('HIGH_SWAP', 
                              f"Swap usage: {res['memory']['swap_usage']}%", 
                              'WARNING')
            
            # Disk alerts for each partition
            if 'disk' in res:
                for mountpoint, disk_info in res['disk'].items():
                    if disk_info['alert']:
                        severity = 'CRITICAL' if disk_info['usage'] > 98 else 'WARNING'
                        self.send_alert('HIGH_DISK', 
                                      f"Disk usage on {mountpoint}: {disk_info['usage']}% (free: {disk_info['free_gb']}GB)", 
                                      severity)
            
            if 'load_average' in res and res['load_average'].get('alert', False):
                load_1min = res['load_average']['1min']
                cpu_count = res['load_average']['cpu_count']
                self.send_alert('HIGH_LOAD', 
                              f"Load average: {load_1min} (CPUs: {cpu_count}, normalized: {load_1min/cpu_count:.2f})", 
                              'WARNING')
        
        # Temperature alerts
        if 'temperature' in results and results['temperature'].get('alert', False):
            temp_info = results['temperature']
            max_temp = temp_info.get('max_temp', 0)
            severity = 'CRITICAL' if max_temp > 85 else 'WARNING'
            self.send_alert('HIGH_TEMPERATURE', 
                          f"System temperature: {max_temp}°C", 
                          severity)
            
            # Critical temperature warnings
            if 'critical_warnings' in temp_info:
                for warning in temp_info['critical_warnings']:
                    self.send_alert('CRITICAL_TEMPERATURE', 
                                  f"Sensor {warning['sensor']} ({warning['label']}): {warning['temp']}°C approaching critical {warning['critical']}°C", 
                                  'CRITICAL')
        
        # Security alerts
        if 'security' in results:
            sec = results['security']
            
            if 'failed_logins' in sec and sec['failed_logins'].get('alert', False):
                login_info = sec['failed_logins']
                severity = 'CRITICAL' if login_info['count'] > 50 else 'WARNING'
                
                message = f"Failed logins: {login_info['count']} from {login_info['unique_ips']} IPs"
                if login_info.get('attacking_ips'):
                    top_attacker = max(login_info['attacking_ips'].items(), key=lambda x: x[1])
                    message += f" (top: {top_attacker[0]} with {top_attacker[1]} attempts)"
                
                self.send_alert('FAILED_LOGINS', message, severity)
                
            if 'suspicious_processes' in sec and sec['suspicious_processes'].get('alert', False):
                procs = sec['suspicious_processes']['processes']
                
                for proc in procs:
                    severity = 'CRITICAL' if proc['suspicion_score'] >= 5 else 'WARNING'
                    reasons = ', '.join(proc['reasons'][:3])  # Limit reasons shown
                    
                    self.send_alert('SUSPICIOUS_PROCESS', 
                                  f"Process {proc['name']} (PID: {proc['pid']}) - Score: {proc['suspicion_score']} - {reasons}", 
                                  severity)
            
            if 'network_connections' in sec and sec['network_connections'].get('alert', False):
                net_info = sec['network_connections']
                
                for conn in net_info.get('unusual_connections', []):
                    self.send_alert('SUSPICIOUS_CONNECTION', 
                                  f"Process {conn['process']} connected to {conn['remote']} ({conn['suspicious_reason']})", 
                                  'WARNING')
                
                for listener in net_info.get('suspicious_listeners', []):
                    self.send_alert('SUSPICIOUS_LISTENER', 
                                  f"Process listening on suspicious port {listener['port']} ({listener['reason']})", 
                                  'WARNING')
        
        # Service alerts
        if 'services' in results:
            for service, status in results['services'].items():
                if status.get('alert', False) and status.get('is_critical', False):
                    self.send_alert('SERVICE_DOWN', 
                                  f"Critical service {service}: {status.get('status', 'unknown')}", 
                                  'ERROR')

    def _send_email_alert(self, alert_type: str, message: str, severity: str = 'WARNING'):
        """Send email alert."""
        try:
            sender = self.config['EMAIL']['sender_email']
            password = self.config['EMAIL']['sender_password']
            recipient = self.config['EMAIL']['recipient_email']
            
            if not all([sender, password, recipient]):
                return
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = f"[{severity}] Safety Monitor Alert: {alert_type}"
            
            body = f"""System Safety Monitor Alert

Severity: {severity}
Alert Type: {alert_type}
Message: {message}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Hostname: {os.uname().nodename}

This is an automated alert from the System Safety Monitor.
Please investigate the issue as soon as possible.
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.config['EMAIL']['smtp_server'], 
                                int(self.config['EMAIL']['smtp_port']))
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for {alert_type}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def check_disk_health(self) -> Dict:
        """Check disk health using SMART data with improved error handling."""
        results = {}
        
        try:
            # Get list of drives
            result = subprocess.run(['lsblk', '-d', '-n', '-o', 'NAME,TYPE'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                results['error'] = 'lsblk command failed'
                return results
                
            lines = result.stdout.strip().split('\n')
            drives = []
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    name, drive_type = parts[0], parts[1]
                    if drive_type == 'disk' and name.startswith(('sd', 'nvme', 'hd')):
                        drives.append(name)
            
            for drive in drives:
                try:
                    # Check if smartctl is available
                    smart_result = subprocess.run(['smartctl', '-H', f'/dev/{drive}'], 
                                                capture_output=True, text=True, timeout=15)
                    
                    if smart_result.returncode == 127:  # Command not found
                        results[drive] = {'error': 'smartctl not installed', 'alert': False}
                        continue
                    
                    health_status = 'UNKNOWN'
                    smart_info = {}
                    
                    # Parse health status
                    if 'PASSED' in smart_result.stdout:
                        health_status = 'PASSED'
                    elif 'FAILED' in smart_result.stdout:
                        health_status = 'FAILED'
                    elif smart_result.returncode != 0:
                        health_status = 'ERROR'
                    
                    # Get additional SMART info
                    try:
                        info_result = subprocess.run(['smartctl', '-A', f'/dev/{drive}'], 
                                                   capture_output=True, text=True, timeout=15)
                        if info_result.returncode == 0:
                            # Parse important SMART attributes
                            for line in info_result.stdout.split('\n'):
                                if 'Temperature_Celsius' in line or 'Airflow_Temperature_Cel' in line:
                                    parts = line.split()
                                    if len(parts) >= 10:
                                        try:
                                            smart_info['temperature'] = int(parts[9])
                                        except (ValueError, IndexError):
                                            pass
                                elif 'Reallocated_Sector_Ct' in line:
                                    parts = line.split()
                                    if len(parts) >= 10:
                                        try:
                                            smart_info['reallocated_sectors'] = int(parts[9])
                                        except (ValueError, IndexError):
                                            pass
                                elif 'Power_On_Hours' in line:
                                    parts = line.split()
                                    if len(parts) >= 10:
                                        try:
                                            smart_info['power_on_hours'] = int(parts[9])
                                        except (ValueError, IndexError):
                                            pass
                    except subprocess.TimeoutExpired:
                        pass
                    
                    results[drive] = {
                        'health': health_status,
                        'alert': health_status == 'FAILED',
                        'smart_info': smart_info
                    }
                    
                except subprocess.TimeoutExpired:
                    results[drive] = {'error': 'SMART check timeout', 'alert': False}
                except Exception as e:
                    results[drive] = {'error': f'SMART check failed: {str(e)}', 'alert': False}
                        
        except Exception as e:
            results['error'] = f'Disk health check failed: {str(e)}'
            
        return results
    
    def generate_report(self, results: Dict) -> str:
        """Generate comprehensive system report with improved formatting."""
        report = []
        report.append("=" * 80)
        report.append("SYSTEM SAFETY MONITOR REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Hostname: {os.uname().nodename}")
        report.append(f"System: {os.uname().sysname} {os.uname().release}")
        report.append("")
        
        # System Resources
        if 'resources' in results:
            report.append("SYSTEM RESOURCES:")
            report.append("-" * 40)
            res = results['resources']
            
            # CPU
            cpu = res['cpu']
            status = "⚠️ ALERT" if cpu['alert'] else "✅ OK"
            report.append(f"  CPU Usage: {cpu['usage']}% {status}")
            report.append(f"    Threshold: {cpu['threshold']}%")
            
            # Memory
            mem = res['memory']
            mem_status = "⚠️ ALERT" if mem['alert'] else "✅ OK"
            report.append(f"  Memory Usage: {mem['usage']}% {mem_status}")
            report.append(f"    Available: {mem['available_gb']}GB / {mem['total_gb']}GB")
            
            if mem['swap_usage'] > 0:
                swap_status = "⚠️ HIGH" if mem['swap_alert'] else "✅ OK"
                report.append(f"    Swap Usage: {mem['swap_usage']}% {swap_status}")
            
            # Disk
            if 'disk' in res:
                report.append("  Disk Usage:")
                for mount, disk in res['disk'].items():
                    disk_status = "⚠️ ALERT" if disk['alert'] else "✅ OK"
                    report.append(f"    {mount}: {disk['usage']}% (Free: {disk['free_gb']}GB) {disk_status}")
            
            # Load Average
            if 'load_average' in res and '1min' in res['load_average']:
                load = res['load_average']
                load_status = "⚠️ HIGH" if load['alert'] else "✅ OK"
                report.append(f"  Load Average: {load['1min']} / {load['5min']} / {load['15min']} {load_status}")
                report.append(f"    CPU Cores: {load['cpu_count']}, Normalized: {load['normalized_1min']}")
            
            report.append("")
        
        # Temperature
        if 'temperature' in results:
            temp = results['temperature']
            if 'max_temp' in temp:
                temp_status = "⚠️ HIGH" if temp['alert'] else "✅ OK"
                report.append(f"TEMPERATURE: {temp['max_temp']}°C {temp_status}")
                report.append(f"  Threshold: {temp['threshold']}°C")
                
                if temp.get('critical_warnings'):
                    report.append("  ⚠️ Critical Temperature Warnings:")
                    for warning in temp['critical_warnings']:
                        report.append(f"    {warning['sensor']}: {warning['temp']}°C (Critical: {warning['critical']}°C)")
                report.append("")
            elif 'error' in temp:
                report.append(f"TEMPERATURE: ❌ {temp['error']}")
                report.append("")
        
        # Security Status
        if 'security' in results:
            report.append("SECURITY STATUS:")
            report.append("-" * 40)
            sec = results['security']
            
            if 'failed_logins' in sec:
                login = sec['failed_logins']
                if 'count' in login:
                    login_status = "⚠️ ALERT" if login['alert'] else "✅ OK"
                    report.append(f"  Failed Logins (1h): {login['count']} {login_status}")
                    if login.get('attacking_ips'):
                        report.append("    Top attacking IPs:")
                        for ip, count in list(login['attacking_ips'].items())[:3]:
                            report.append(f"      {ip}: {count} attempts")
                elif 'error' in login:
                    report.append(f"  Failed Logins: ❌ {login['error']}")
            
            if 'suspicious_processes' in sec:
                susp = sec['suspicious_processes']
                proc_count = len(susp.get('processes', []))
                proc_status = "⚠️ FOUND" if susp['alert'] else "✅ CLEAN"
                report.append(f"  Suspicious Processes: {proc_count} {proc_status}")
                
                if proc_count > 0:
                    report.append("    Detected processes:")
                    for proc in susp['processes'][:5]:  # Show top 5
                        report.append(f"      PID {proc['pid']}: {proc['name']} (Score: {proc['suspicion_score']})")
                        report.append(f"        Reasons: {', '.join(proc['reasons'][:2])}")
            
            if 'network_connections' in sec:
                net = sec['network_connections']
                if 'error' not in net:
                    unusual_count = len(net.get('unusual_connections', []))
                    suspicious_listeners = len(net.get('suspicious_listeners', []))
                    net_status = "⚠️ SUSPICIOUS" if net['alert'] else "✅ CLEAN"
                    report.append(f"  Network: {unusual_count} unusual connections, {suspicious_listeners} suspicious listeners {net_status}")
                else:
                    report.append(f"  Network: ❌ {net['error']}")
            
            report.append("")
        
        # System Services
        if 'services' in results:
            report.append("CRITICAL SERVICES:")
            report.append("-" * 40)
            services = results['services']
            
            for service, status in services.items():
                if 'status' in status:
                    service_status = "❌ DOWN" if status['alert'] else "✅ UP"
                    criticality = "CRITICAL" if status.get('is_critical', False) else "OPTIONAL"
                    report.append(f"  {service} ({criticality}): {status['status']} {service_status}")
                elif 'error' in status:
                    report.append(f"  {service}: ❌ {status['error']}")
            
            report.append("")
        
        # Disk Health
        if 'disk_health' in results:
            report.append("DISK HEALTH:")
            report.append("-" * 40)
            disk_health = results['disk_health']
            
            if 'error' not in disk_health:
                for drive, health in disk_health.items():
                    if 'health' in health:
                        health_status = "❌ FAILED" if health['alert'] else "✅ HEALTHY"
                        report.append(f"  /dev/{drive}: {health['health']} {health_status}")
                        
                        if 'smart_info' in health and health['smart_info']:
                            info = health['smart_info']
                            if 'temperature' in info:
                                report.append(f"    Temperature: {info['temperature']}°C")
                            if 'power_on_hours' in info:
                                days = info['power_on_hours'] // 24
                                report.append(f"    Power-on time: {info['power_on_hours']}h ({days} days)")
                            if 'reallocated_sectors' in info:
                                report.append(f"    Reallocated sectors: {info['reallocated_sectors']}")
                    elif 'error' in health:
                        report.append(f"  /dev/{drive}: ❌ {health['error']}")
            else:
                report.append(f"  ❌ {disk_health['error']}")
            
            report.append("")
        
        # Recent Alerts
        if self.alerts:
            report.append("RECENT ALERTS:")
            report.append("-" * 40)
            for alert in self.alerts[-10:]:  # Show last 10 alerts
                report.append(f"  {alert}")
            report.append("")
        
        # Summary
        total_alerts = sum(1 for category in results.values() 
                          if isinstance(category, dict) and self._has_alerts(category))
        
        if total_alerts > 0:
            report.append(f"⚠️  SUMMARY: {total_alerts} categories with alerts detected!")
        else:
            report.append("✅ SUMMARY: All systems operating normally.")
        
        report.append("=" * 80)
        return "\n".join(report)
    
    def _has_alerts(self, category_data: Dict) -> bool:
        """Recursively check if a category has any alerts."""
        if isinstance(category_data, dict):
            if category_data.get('alert', False):
                return True
            for value in category_data.values():
                if isinstance(value, dict) and self._has_alerts(value):
                    return True
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and self._has_alerts(item):
                            return True
        return False
    
    def run_monitoring_cycle(self) -> Dict:
        """Run a complete monitoring cycle with improved error handling."""
        self.logger.info("Starting monitoring cycle")
        results = {}
        
        try:
            # Check system resources
            self.logger.debug("Checking system resources")
            results['resources'] = self.check_system_resources()
        except Exception as e:
            self.logger.error(f"Error checking system resources: {e}")
            results['resources'] = {'error': str(e)}
        
        try:
            # Check temperature
            self.logger.debug("Checking temperature")
            results['temperature'] = self.check_temperature()
        except Exception as e:
            self.logger.error(f"Error checking temperature: {e}")
            results['temperature'] = {'error': str(e)}
        
        try:
            # Check security issues
            self.logger.debug("Checking security issues")
            results['security'] = self.check_security_issues()
        except Exception as e:
            self.logger.error(f"Error checking security: {e}")
            results['security'] = {'error': str(e)}
        
        try:
            # Check system services
            self.logger.debug("Checking system services")
            results['services'] = self.check_system_services()
        except Exception as e:
            self.logger.error(f"Error checking services: {e}")
            results['services'] = {'error': str(e)}
        
        try:
            # Check disk health
            self.logger.debug("Checking disk health")
            results['disk_health'] = self.check_disk_health()
        except Exception as e:
            self.logger.error(f"Error checking disk health: {e}")
            results['disk_health'] = {'error': str(e)}
        
        # Process alerts
        try:
            self._process_alerts(results)
        except Exception as e:
            self.logger.error(f"Error processing alerts: {e}")
        
        self.logger.info("Monitoring cycle completed")
        return results

def main():
    parser = argparse.ArgumentParser(
        description='System Safety Monitor - Advanced system monitoring and alerting tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --report                    # Generate single report
  %(prog)s --daemon                    # Run continuously
  %(prog)s --setup                     # Interactive setup
  %(prog)s --config custom.ini         # Use custom config file
        """
    )
    parser.add_argument('--config', default='config.ini', 
                       help='Configuration file path (default: config.ini)')
    parser.add_argument('--daemon', action='store_true', 
                       help='Run in daemon mode (continuous monitoring)')
    parser.add_argument('--report', action='store_true', 
                       help='Generate single report and exit')
    parser.add_argument('--setup', action='store_true', 
                       help='Setup configuration interactively')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--test-alerts', action='store_true',
                       help='Send test alerts to verify notification setup')
    
    args = parser.parse_args()
    
    if args.setup:
        print("=" * 60)
        print("SYSTEM SAFETY MONITOR SETUP")
        print("=" * 60)
        print()
        print("This will create a default configuration file.")
        print("You can then edit the config file to customize settings:")
        print()
        print("• Monitoring thresholds")
        print("• Email alert settings") 
        print("• Security monitoring options")
        print("• Check intervals and logging")
        print()
        
        # Create a temporary monitor instance to generate config
        try:
            temp_config_path = 'setup_config.ini'
            monitor = SystemSafetyMonitor(temp_config_path)
            
            if os.path.exists(temp_config_path):
                final_path = input(f"Config file path [{args.config}]: ").strip() or args.config
                
                if final_path != temp_config_path:
                    import shutil
                    shutil.move(temp_config_path, final_path)
                    print(f"Configuration saved to: {final_path}")
                else:
                    print(f"Configuration saved to: {temp_config_path}")
                
                print()
                print("Setup complete! Next steps:")
                print(f"1. Edit the configuration file: {final_path}")
                print("2. Run a test: python3 safety_monitor.py --report")
                print("3. Start monitoring: python3 safety_monitor.py --daemon")
            else:
                print("Error: Could not create configuration file.")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error during setup: {e}")
            sys.exit(1)
        
        return
    
    # Initialize monitor
    try:
        monitor = SystemSafetyMonitor(args.config)
        
        if args.verbose:
            monitor.logger.setLevel(logging.DEBUG)
            
    except Exception as e:
        print(f"Error initializing monitor: {e}")
        print("Run with --setup to create a default configuration file.")
        sys.exit(1)
    
    # Test alerts
    if args.test_alerts:
        print("Sending test alerts...")
        monitor.send_alert('TEST_ALERT', 'This is a test alert to verify your notification setup.', 'INFO')
        monitor.send_alert('TEST_WARNING', 'This is a test warning alert.', 'WARNING') 
        monitor.send_alert('TEST_CRITICAL', 'This is a test critical alert.', 'CRITICAL')
        print("Test alerts sent. Check your notifications!")
        return
    
    # Single report mode
    if args.report:
        try:
            print("Generating system safety report...")
            results = monitor.run_monitoring_cycle()
            print()
            print(monitor.generate_report(results))
        except Exception as e:
            print(f"Error generating report: {e}")
            sys.exit(1)
            
    # Daemon mode
    elif args.daemon:
        try:
            check_interval = int(monitor.config['MONITORING']['check_interval'])
            monitor.logger.info(f"Starting daemon mode with {check_interval}s intervals")
            print(f"System Safety Monitor started in daemon mode (interval: {check_interval}s)")
            print("Press Ctrl+C to stop...")
            
            while True:
                try:
                    results = monitor.run_monitoring_cycle()
                    
                    # Log summary
                    alert_count = sum(1 for category in results.values() 
                                    if isinstance(category, dict) and monitor._has_alerts(category))
                    
                    if alert_count > 0:
                        monitor.logger.warning(f"Monitoring cycle completed with {alert_count} alert categories")
                    else:
                        monitor.logger.info("Monitoring cycle completed - all systems normal")
                    
                    time.sleep(check_interval)
                    
                except Exception as e:
                    monitor.logger.error(f"Error in monitoring cycle: {e}")
                    time.sleep(min(check_interval, 60))  # Don't wait too long if there's an error
                    
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
            monitor.logger.info("Monitoring stopped by user")
        except Exception as e:
            print(f"Fatal error in daemon mode: {e}")
            monitor.logger.error(f"Fatal error in daemon mode: {e}")
            sys.exit(1)
            
    # Interactive mode
    else:
        try:
            print("System Safety Monitor - Interactive Mode")
            print("=" * 50)
            
            while True:
                print("\nOptions:")
                print("1. Run monitoring cycle")
                print("2. Generate detailed report")
                print("3. View recent alerts")
                print("4. Test notifications")
                print("5. System information")
                print("6. Exit")
                
                try:
                    choice = input("\nSelect option (1-6): ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nGoodbye!")
                    break
                
                if choice == '1':
                    try:
                        print("\nRunning monitoring cycle...")
                        results = monitor.run_monitoring_cycle()
                        
                        # Show quick summary
                        alert_count = sum(1 for category in results.values() 
                                        if isinstance(category, dict) and monitor._has_alerts(category))
                        
                        if alert_count > 0:
                            print(f"⚠️  Monitoring completed with {alert_count} alert categories")
                        else:
                            print("✅ Monitoring completed - all systems normal")
                            
                    except Exception as e:
                        print(f"❌ Error during monitoring: {e}")
                        
                elif choice == '2':
                    try:
                        print("\nGenerating detailed report...")
                        results = monitor.run_monitoring_cycle()
                        print()
                        print(monitor.generate_report(results))
                    except Exception as e:
                        print(f"❌ Error generating report: {e}")
                        
                elif choice == '3':
                    if monitor.alerts:
                        print(f"\nRecent Alerts ({len(monitor.alerts)}):")
                        print("-" * 50)
                        for alert in monitor.alerts[-15:]:  # Show last 15
                            print(f"  {alert}")
                    else:
                        print("\n✅ No recent alerts.")
                        
                elif choice == '4':
                    print("\nSending test notifications...")
                    monitor.send_alert('INTERACTIVE_TEST', 'Test alert from interactive mode', 'INFO')
                    print("✅ Test notification sent!")
                    
                elif choice == '5':
                    print(f"\nSystem Information:")
                    print(f"  Hostname: {os.uname().nodename}")
                    print(f"  OS: {os.uname().sysname} {os.uname().release}")
                    print(f"  Python: {sys.version.split()[0]}")
                    print(f"  Config: {monitor.config_path}")
                    print(f"  CPU Cores: {psutil.cpu_count()}")
                    print(f"  Memory: {round(psutil.virtual_memory().total / (1024**3), 1)}GB")
                    
                elif choice == '6':
                    print("Goodbye!")
                    break
                    
                else:
                    print("❌ Invalid option. Please choose 1-6.")
                    
        except Exception as e:
            print(f"❌ Error in interactive mode: {e}")
            sys.exit(1)

if __name__ == '__main__':
    main()
