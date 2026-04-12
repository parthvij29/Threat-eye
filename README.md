# Threat - Eye - Linux Threat Monitoring Tool

A comprehensive Linux monitoring and threat detection tool with a graphical user interface.

## Features

- **File Inspector**: Browse and inspect files for potential threats
- **Malicious Scan**: Run system-wide malicious content scans
- **Network Monitor**: Monitor active connections, open ports, and capture packets
- **System Monitor**: View running processes, CPU/memory usage, and startup services
- **Real-Time Monitor**: Live monitoring with streaming output
- **Correlator**: Advanced event correlation and alerting
- **Logs Viewer**: View and manage all logged activities

## Database Logging

All activities are automatically logged to a SQLite database (`threat_eye_logs.db`) for persistence and analysis:

### Database Tables

- **file_inspections**: File inspection results with timestamps and file paths
- **malicious_scans**: Results from malicious content scans
- **network_logs**: Network monitoring data (connections, ports, captures)
- **system_logs**: System monitoring data (processes, usage, startup services)
- **realtime_events**: Live monitoring events and messages
- **correlator_events**: Correlated security events with alert levels

### Log Viewer

Use the "Logs Viewer" tab to:
- Select different log types from the dropdown
- View recent log entries (limited to prevent UI slowdown)
- Clear all logs when needed

## Requirements

- Python 3.x
- Tkinter (usually included with Python)
- SQLite3 (included with Python)
- Linux environment (scripts are designed for Linux)

## Usage

1. Run the GUI: `python ui/app.py`
2. Use the various tabs to perform monitoring tasks
3. All actions are automatically logged to the database
4. Review logs in the "Logs Viewer" tab

## Scripts

Located in the `scripts/` directory:
- `file_inspector.sh`: File analysis script
- `malicious_scan.sh`: Malicious content scanner
- `net_monitor.sh`: Network monitoring tool
- `realtime_monitor.sh`: Real-time system monitor
- `realtime_correlator.sh`: Event correlation engine
- `sys_monitor.sh`: System monitoring utilities

## Database Schema

The SQLite database automatically creates tables as needed. Each table includes:
- `id`: Auto-incrementing primary key
- `timestamp`: ISO format timestamp of when the log was created
- Additional fields specific to each log type</content>
<parameter name="filePath">c:\Users\Parth\OneDrive\Desktop\dti project\threat eye\README.md
