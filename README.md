# Sentinel-AV: Self-Hosted Antivirus System

## Overview

Sentinel-AV is a self-hosted antivirus solution built with Python that provides file scanning, threat detection, and quarantine capabilities through an intuitive web interface. This system allows organizations to maintain complete control over their antivirus infrastructure while providing effective protection against malware.

## Features

### Core Capabilities
- **File Scanning**: On-demand and scheduled scanning of files and directories
- **Signature-Based Detection**: Custom virus definition database with regular updates
- **Threat Quarantine**: Isolate and manage detected threats
- **Web Dashboard**: Centralized management interface for scans and threats
- **Multi-Platform Support**: Agents for Windows, Linux, and macOS
- **Flexible Scheduling**: Configure automated scans based on your needs


This system follows a client-server architecture with lightweight agents:

### Central Server
- **Web UI**: Built with React.js and Flask
- **AGENT**: Python Flask/FastAPI with REST endpoints
- **Database**: PostgreSQL for storing scan results, threats, and configurations
- **Definition Manager**: Service for updating and distributing virus signatures
- **Task Scheduler**: Celery with Redis for managing scan jobs

### Agent Components
- **Lsentinal-edrightweight Agents**: Python-based for each supported OS
- **Scanning Engine**: Local file scanning with signature matching
- **Communication Module**: Secure API communication with central server
- **Quarantine Storage**: Local storage for infected files
- **Configuration Management**: Remote configuration updates

### Antivirus Components
- Custom signature matching engine (yara)
- PyFilesystem for cross-platform file operations
- psutil for system process monitoring

## Installation

### Prerequisites
- Python 3.9+
- SQLite
- Docker 

## Tests
- Docker images for windows , linux ,MacOs
- Mount the Agent 
- Copy Publicly avaible malware to the VM and run tests  


### Docker Deployment

```bash
docker-compose up -d
```

## System Components

### Agent Deployment

1. **Windows**: Download and run the agent installer
2. **Linux**: Install via package manager or Python uv
3. **macOS**: Install via package manager or Python uv



### Virus Definitions

The system maintains a local database of virus signatures that can be:
- Updated automatically from the central repository
- Managed manually through the web interface
- Custom definitions can be added for organization-specific threats

## Configuration

### Server Configuration

The main server configuration file contains settings for:
- Database connections
- Security parameters
- Scan scheduling settings
- External service integrations
- Virus definition update intervals

### Agent Configuration

Agents receive configuration from the central server, including:
- Scan schedules and patterns
- Exclusion rules for sensitive files/directories
- Reporting intervals
- Update behavior

## Usage
### Running Scans

Scans can be initiated:
- On-demand through the web interface
- Scheduled automatically (daily, weekly, monthly)
- Triggered by specific events (file creation, access patterns)

### Threat Management

When a threat is detected:
1. File is automatically quarantined
2. Alert appears in the dashboard
3. Admin can review the threat and choose to clean, delete, or restore
4. Action is logged for compliance and audit purposes

## Development
### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Roadmap

### Phase 1 (Current)
- Basic file scanning functionality
- Signature-based detection
- Web interface for management

### Phase 2
- Scheduled scan capabilities
- Enhanced reporting features
- Advanced quarantine options

### Phase 3
- Heuristic analysis capabilities
- Behavior-based detection
- Machine learning integration

## License

This project is licensed under the MIT License - see the LICENSE file for details.
