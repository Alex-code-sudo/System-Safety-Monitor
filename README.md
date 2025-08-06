# System Safety Monitor

A Python script that monitors your Linux system's health and security. It checks CPU usage, memory, disk space, temperature, and watches for security threats like failed logins and suspicious processes. Sends alerts when problems are detected.

## What You Need

- Ubuntu or Debian Linux system
- Python 3.6 or newer
- Root access (sudo) for some features

## Installation

1. Download the script:
```bash
git clone https://github.com/yourusername/system-safety-monitor.git
cd system-safety-monitor
```

2. Install required packages:
```bash
pip3 install -r requirements.txt
```

3. Make it executable:
```bash
chmod +x safety_monitor.py
```

4. Install system tools (optional but recommended):
```bash
sudo apt install smartmontools libnotify-bin
```

## How to Use

### First Time Setup
Run this to create a configuration file:
```bash
python3 safety_monitor.py --setup
```

### Interactive Mode
Start the script and use the menu:
```bash
python3 safety_monitor.py
```

### Check System Once
Get a single report and exit:
```bash
python3 safety_monitor.py --report
```

### Background Monitoring
Run continuously in the background:
```bash
python3 safety_monitor.py --daemon
```

### Custom Settings
Use a different configuration file:
```bash
python3 safety_monitor.py --config my_settings.ini
```

## Configuration

The script creates a `config.ini` file automatically. You can edit it to change settings:

### Alert Thresholds
```ini
[THRESHOLDS]
cpu_percent = 80          # Alert when CPU > 80%
memory_percent = 85       # Alert when memory > 85%
disk_percent = 90         # Alert when disk > 90%
temp_celsius = 70         # Alert when temperature > 70°C
load_average = 2.0        # Alert when load > 2.0
```

### Monitoring Settings
```ini
[MONITORING]
check_interval = 60       # Check every 60 seconds
enable_email_alerts = false
enable_desktop_notifications = true
```

### Email Alerts (Optional)
```ini
[EMAIL]
smtp_server = smtp.gmail.com
smtp_port = 587
sender_email = your@email.com
sender_password = your_password
recipient_email = admin@email.com
```

### Security Monitoring
```ini
[SECURITY]
check_failed_logins = true
check_suspicious_processes = true
check_network_connections = true
failed_login_threshold = 5
```

## What It Monitors

- **CPU Usage**: How much of your processor is being used
- **Memory Usage**: How much RAM is being used
- **Disk Space**: How full your hard drive is
- **System Temperature**: How hot your computer is running
- **Failed Logins**: Too many wrong password attempts
- **Suspicious Processes**: Programs that might be malicious
- **System Services**: Important services like SSH, firewall, etc.
- **Disk Health**: Hard drive condition using SMART data

## Running as a Service

To start monitoring automatically when your computer boots:

1. Copy the script to a system location:
```bash
sudo cp safety_monitor.py /usr/local/bin/
sudo cp config.ini /usr/local/bin/
```

2. Create a service file:
```bash
sudo nano /etc/systemd/system/safety-monitor.service
```

3. Add this content:
```ini
[Unit]
Description=System Safety Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
ExecStart=/usr/bin/python3 /usr/local/bin/safety_monitor.py --daemon
Restart=always

[Install]
WantedBy=multi-user.target
```

4. Enable and start:
```bash
sudo systemctl enable safety-monitor.service
sudo systemctl start safety-monitor.service
```

## Checking Logs

The script saves logs to `safety_monitor.log`. View recent activity:
```bash
tail -f safety_monitor.log
```

## Common Problems

**Permission errors**: Run with sudo for full system access
```bash
sudo python3 safety_monitor.py
```

**No temperature sensors found**: Install sensor tools
```bash
sudo apt install lm-sensors
sudo sensors-detect
```

**Email not working**: Check your email settings in config.ini

**SMART data unavailable**: Install smartmontools
```bash
sudo apt install smartmontools
```

## Alert Types

The script will warn you about:
- HIGH_CPU: Processor usage too high
- HIGH_MEMORY: Running out of memory
- HIGH_DISK: Hard drive getting full
- HIGH_TEMPERATURE: Computer overheating
- FAILED_LOGINS: Someone trying wrong passwords
- SUSPICIOUS_PROCESS: Potentially dangerous programs running
- SERVICE_DOWN: Important services stopped
- DISK_HEALTH: Hard drive showing signs of failure

## Examples

Check system status once:
```bash
python3 safety_monitor.py --report
```

Monitor continuously with custom settings:
```bash
python3 safety_monitor.py --config server.ini --daemon
```

Run interactively to troubleshoot:
```bash
python3 safety_monitor.py
# Choose option 1 or 2 from the menu
```
