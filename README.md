# System Safety Monitor - Improved Version

An intelligent Python-based system monitor for Linux that monitors your system's health and security. Tracks CPU usage, memory, disk space, temperature, and detects security threats like failed logins and suspicious processes with advanced filtering to eliminate false positives.

## ✨ New Features (Improved Version)

- **Intelligent Process Whitelist**: No more false alarms from normal system processes
- **Alert Cooldown System**: Prevents notification spam
- **Advanced Security Analysis**: Pattern-based detection of real threats
- **Better Reports**: Clean reports with status icons (✅❌⚠️)
- **Robust Error Handling**: Each monitoring area runs independently
- **Test Functionality**: Test your notification setup
- **Rotating Logs**: Automatic log rotation with size limits
- **Enhanced Detection**: Improved suspicious process detection with scoring system

## 🔧 System Requirements

- **Linux**: Ubuntu, Debian, CentOS, RHEL, Arch Linux, etc.
- **Python**: 3.6 or newer
- **Permissions**: Root access (sudo) for full functionality
- **Memory**: ~50MB for the process
- **Disk**: ~10MB for logs and config files

## 📦 Installation

### Quick Installation
```bash
# Clone repository
git clone https://github.com/Alex-code-sudo/System-Safety-Monitor.git
cd System-Safety-Monitor

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x safety_monitor.py

# Optional: Install system tools for full functionality
sudo apt install smartmontools libnotify-bin lm-sensors
```

### Requirements.txt Content
```
psutil>=5.8.0
configparser>=5.0.0
```

## 🚀 Quick Start

### 1. Interactive Setup
```bash
python3 safety_monitor.py --setup
```
Creates a `config.ini` file with optimized default values.

### 2. Test Notifications
```bash
python3 safety_monitor.py --test-alerts
```
Sends test notifications to verify your setup is working.

### 3. Single System Check
```bash
python3 safety_monitor.py --report
```
Runs a complete system check and displays a detailed report.

## 💻 Usage Modes

### Interactive Mode (Recommended for beginners)
```bash
python3 safety_monitor.py
```
**New Menu Options:**
1. Run monitoring cycle
2. Generate detailed report  
3. View recent alerts
4. Test notifications
5. System information
6. Exit

### Daemon Mode (Continuous Monitoring)
```bash
python3 safety_monitor.py --daemon
```
- Runs continuously in background
- Default interval: 5 minutes (configurable)
- Automatic recovery from errors
- Press Ctrl+C to stop

### Advanced Options
```bash
# Verbose mode for debugging
python3 safety_monitor.py --verbose --report

# Use custom config file
python3 safety_monitor.py --config production.ini --daemon

# Show help
python3 safety_monitor.py --help
```

## ⚙️ Configuration (Enhanced)

### Example config.ini with new options:

```ini
[THRESHOLDS]
cpu_percent = 85                    # Higher threshold to reduce false positives
memory_percent = 90                 # Only alert on critical memory usage
disk_percent = 95                   # Warning only when disk is nearly full
temp_celsius = 75                   # More realistic temperature threshold
load_average = 3.0                  # Adapted for multi-core CPUs
failed_login_threshold = 10         # Less sensitive to avoid spam

[MONITORING]
check_interval = 300                # 5 minutes instead of 1 minute
log_level = INFO                    # DEBUG, INFO, WARNING, ERROR
enable_email_alerts = false
enable_desktop_notifications = true
alert_cooldown_minutes = 30         # NEW: Spam protection

[SECURITY]
check_failed_logins = true
check_suspicious_processes = true
check_network_connections = true
check_open_ports = true             # NEW
whitelist_known_good_processes = true  # NEW: Intelligent filtering

[ADVANCED]                          # NEW: Advanced options
enable_process_analysis = true
check_process_network_activity = true
monitor_file_changes = false
suspicious_cpu_threshold = 80
```

## 📊 What It Monitors (Enhanced)

### **System Resources**
- **CPU Usage**: Multi-sample measurement for higher accuracy
- **Memory**: RAM + Swap usage with detailed information  
- **Disk Space**: All mounted filesystems individually monitored
- **Load Average**: 1/5/15 minute averages with CPU normalization
- **Per-core CPU**: Individual core usage tracking

### **Temperature Monitoring**
- **All Sensors**: CPU, GPU, motherboard sensors
- **Critical Thresholds**: Warns before hardware damage
- **Sensor Details**: Individual sensor readings with labels

### **Security Monitoring (Improved)**
- **Failed Logins**: Track failed SSH/login attempts with IP analysis
- **Suspicious Processes**: Pattern-based detection with scoring system
- **Network Connections**: Monitor unusual network activity
- **Open Ports**: Detect suspicious listening ports
- **Process Whitelisting**: Ignores known-good system processes

### **System Services**
- **Critical Services**: SSH, networking, cron, logging services
- **Optional Services**: Firewall, security tools (fail2ban, etc.)
- **Service Health**: Active/inactive status monitoring

### **Disk Health**
- **SMART Data**: Hard drive health monitoring
- **Temperature**: Disk temperature tracking
- **Wear Indicators**: Reallocated sectors, power-on hours

## 🔔 Alert Types (Enhanced)

### **Resource Alerts**
- `HIGH_CPU`: Processor usage too high
- `HIGH_MEMORY`: Running out of RAM  
- `HIGH_SWAP`: Excessive swap usage
- `HIGH_DISK`: Disk space critical on specific partition
- `HIGH_LOAD`: System load average too high
- `HIGH_TEMPERATURE`: Overheating detected

### **Security Alerts**
- `FAILED_LOGINS`: Too many failed login attempts (with IP tracking)
- `SUSPICIOUS_PROCESS`: Potentially dangerous programs (with analysis)
- `SUSPICIOUS_CONNECTION`: Unusual network connections
- `SUSPICIOUS_LISTENER`: Processes listening on dangerous ports

### **System Alerts**
- `SERVICE_DOWN`: Important services stopped
- `DISK_HEALTH`: Hard drive showing signs of failure
- `CRITICAL_TEMPERATURE`: Hardware damage risk

## 🛠 Running as a System Service

### Create systemd service for automatic startup:

1. **Copy files to system location:**
```bash
sudo cp safety_monitor.py /usr/local/bin/
sudo cp config.ini /usr/local/bin/
sudo chmod +x /usr/local/bin/safety_monitor.py
```

2. **Create service file:**
```bash
sudo nano /etc/systemd/system/safety-monitor.service
```

3. **Add service configuration:**
```ini
[Unit]
Description=System Safety Monitor - Enhanced Security Monitoring
After=network.target multi-user.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
ExecStart=/usr/bin/python3 /usr/local/bin/safety_monitor.py --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

# Resource limits
MemoryLimit=100M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
```

4. **Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable safety-monitor.service
sudo systemctl start safety-monitor.service

# Check status
sudo systemctl status safety-monitor.service
```

## 📝 Log Management

### **Log Files**
```bash
# Main log file
tail -f logs/safety_monitor.log

# Rotating log (limited size)  
tail -f logs/safety_monitor_rotating.log

# System journal (if running as service)
sudo journalctl -u safety-monitor.service -f
```

### **Log Levels**
- `DEBUG`: Detailed troubleshooting information
- `INFO`: Normal operation messages  
- `WARNING`: Alerts and important events
- `ERROR`: Error conditions
- `CRITICAL`: Severe problems requiring immediate attention

## 🔧 Troubleshooting

### **Common Issues**

**Permission Errors**
```bash
# Run with sudo for full system access
sudo python3 safety_monitor.py --report
```

**False Process Alerts (Fixed in improved version)**
- The improved version has extensive whitelisting
- Normal system processes are automatically ignored
- Configure additional whitelist in [SECURITY] section

**No Temperature Sensors**
```bash
sudo apt install lm-sensors
sudo sensors-detect
sudo sensors  # Test sensors
```

**Email Notifications Not Working**
- Check email settings in config.ini
- Enable "Less secure app access" for Gmail
- Use app passwords for 2FA accounts

**SMART Data Unavailable**
```bash
sudo apt install smartmontools
sudo smartctl -a /dev/sda  # Test SMART access
```

**High Resource Usage**
- Increase check_interval in config
- Disable unnecessary monitoring features
- Check for system issues causing high load

### **Debugging Mode**
```bash
# Enable verbose logging
python3 safety_monitor.py --verbose --report

# Check configuration
python3 safety_monitor.py --setup

# Test specific features
python3 safety_monitor.py --test-alerts
```

## 📊 Sample Output

### **Normal Report**
```
================================================================================
SYSTEM SAFETY MONITOR REPORT
================================================================================
Timestamp: 2024-08-07 14:30:15
Hostname: server01
System: Linux 5.15.0-56-generic

SYSTEM RESOURCES:
----------------------------------------
  CPU Usage: 23.5% ✅ OK
    Threshold: 85%
  Memory Usage: 67.2% ✅ OK
    Available: 2.1GB / 8.0GB
  Disk Usage:
    /: 78.3% (Free: 15.2GB) ✅ OK
    /home: 45.1% (Free: 120.5GB) ✅ OK
  Load Average: 0.85 / 0.92 / 1.05 ✅ OK
    CPU Cores: 4, Normalized: 0.21

TEMPERATURE: 42.5°C ✅ OK
  Threshold: 75°C

SECURITY STATUS:
----------------------------------------
  Failed Logins (1h): 0 ✅ OK
  Suspicious Processes: 0 ✅ CLEAN
  Network: 0 unusual connections, 0 suspicious listeners ✅ CLEAN

CRITICAL SERVICES:
----------------------------------------
  ssh (CRITICAL): active ✅ UP
  systemd-resolved (CRITICAL): active ✅ UP
  cron (CRITICAL): active ✅ UP

✅ SUMMARY: All systems operating normally.
================================================================================
```

## 🔄 Update Guide

### **From Original Version**
1. Backup your current config.ini
2. Download the improved version
3. Run `--setup` to create new config with enhanced options
4. Merge your old settings with new config
5. Test with `--report` and `--test-alerts`

### **Configuration Migration**
The improved version is backward compatible but adds new options:
- `alert_cooldown_minutes`
- `whitelist_known_good_processes`  
- `[ADVANCED]` section
- Enhanced thresholds





## ⚠️ Disclaimer

This software is provided "AS IS" without warranty of any kind.
Use at your own risk. The authors are not liable for any damages
caused by the use of this software.
