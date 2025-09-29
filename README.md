# 🚀 Google Drive MCP Connector

**Maximum Control Point Integration for Google Drive with Enterprise Features**

[![CI](https://github.com/GlacierEQ/google-drive-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/GlacierEQ/google-drive-mcp/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-SOC%202-blue)](SECURITY.md)

Enterprise-grade Google Drive connector with OAuth management, health monitoring, forensic logging, and MemoryPlugin integration for AI-powered workflows.

## ✨ Features

- 🔐 **Secure OAuth Management** - Automatic token refresh and secure storage
- 🏥 **Health Monitoring** - Continuous connectivity checks with intelligent fallback
- 🧠 **MemoryPlugin Integration** - Forensic logging and cross-session continuity  
- 📊 **Enterprise Logging** - Complete audit trail with priority scoring
- 🔄 **Automated Scheduling** - Cron and systemd timer support
- 🛡️ **Fallback Architecture** - Automatic Dropbox failover on Google Drive issues
- 📁 **Target Folder Sync** - Configured for specific folder monitoring

## ⚡ Quick Start

```bash
# Clone and activate
git clone https://github.com/GlacierEQ/google-drive-mcp.git
cd google-drive-mcp
./activate.sh

# Configure OAuth credentials  
cp config/.env.template config/.env
nano config/.env  # Add your Google OAuth credentials

# Test the system
./scripts/google_drive_mcp.sh

# Enable automation
crontab -e  # Add lines from config/cron_schedule.txt
```

## 🏗️ Architecture

```
google_drive_mcp/
├── 📜 scripts/
│   ├── google_drive_mcp.sh           # Main MCP connector with OAuth
│   ├── memory_plugin_feed.sh         # MemoryPlugin forensic integration
│   ├── health_check_with_fallback.sh # Health monitoring + Dropbox fallback
│   └── validate_config.sh            # Configuration validation
├── ⚙️  config/
│   ├── .env.template                 # OAuth credentials template
│   ├── cron_schedule.txt             # Automated scheduling config
│   ├── google-drive-mcp.service      # Systemd service definition
│   └── google-drive-mcp.timer        # Systemd timer configuration
├── 📊 logs/
│   ├── google_drive_mcp.log          # Main operation logs
│   ├── memory_plugin_feed.log        # MemoryPlugin forensic data
│   └── deployment_status.json        # System status tracking
└── 📖 docs/
    ├── API_REFERENCE.md               # Complete API documentation
    ├── DEPLOYMENT_GUIDE.md            # Enterprise deployment guide
    └── TROUBLESHOOTING.md             # Common issues and solutions
```

## 🔧 Configuration

### Required OAuth Credentials

1. **Google Cloud Console Setup:**
   - Create project → Enable Drive API → Create OAuth credentials
   - Download credentials JSON

2. **Environment Configuration:**
   ```env
   GOOGLE_CLIENT_ID=your-oauth-client-id
   GOOGLE_CLIENT_SECRET=your-oauth-client-secret
   GOOGLE_REFRESH_TOKEN=your-refresh-token
   GOOGLE_ACCESS_TOKEN=your-current-access-token
   ```

3. **Target Folder Configuration:**
   ```env
   GOOGLE_DRIVE_TARGET_FOLDER=1YjaCFiKAduINrdq750dqtr6r9x2fb6JO
   ```

## 📊 Monitoring & Logging

### Log Files
- **Main Operations**: `logs/google_drive_mcp.log`
- **MemoryPlugin Feed**: `logs/memory_plugin_feed.log`  
- **Health Checks**: Health status in main log with priority scoring
- **File Sync Data**: `logs/target_folder_files.json`

### Priority Scoring
- **Priority 10**: Critical failures requiring immediate attention
- **Priority 9**: Connection failures, attempting recovery
- **Priority 8**: Token refresh events
- **Priority 7**: Successful operations and sync completions
- **Priority 6**: Routine health check confirmations

## 🔄 Automation

### Cron Scheduling
```bash
# Hourly health checks and token refresh
0 * * * * /path/to/google_drive_mcp/scripts/google_drive_mcp.sh

# MemoryPlugin feed every 30 minutes  
*/30 * * * * /path/to/google_drive_mcp/scripts/memory_plugin_feed.sh
```

### Systemd Timer
```bash
# Install systemd files
sudo cp config/google-drive-mcp.* /etc/systemd/system/
sudo systemctl enable google-drive-mcp.timer
sudo systemctl start google-drive-mcp.timer
```

## 🛡️ Security Features

- **SOC 2 Compliance**: Enterprise-grade security practices
- **Encrypted Credentials**: Secure .env file storage
- **Audit Logging**: Complete forensic trail of all operations
- **Access Control**: OAuth-based authentication only
- **No Data Training**: Files never used for AI model training
- **Automatic Fallback**: Secondary storage activation on primary failure

## 🧪 Testing

```bash
# Validate configuration
./scripts/validate_config.sh

# Test connectivity (dry run)
./scripts/health_check_with_fallback.sh --dry-run

# Monitor logs in real-time
tail -f logs/google_drive_mcp.log
```

## 🎆 Success Indicators

When operational, you'll see:
- ✅ Token refresh successful
- ✅ Connected to Google Drive user: [Your Name]  
- ✅ Found [N] files in target folder
- ✅ Google Drive MCP health check cycle completed

## 📚 Documentation

- [Security Policy](SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Issue Templates](.github/ISSUE_TEMPLATE/)

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built for Maximum Control Point (MCP) Architecture**  
*Enterprise automation with forensic reliability and AI integration*

**⭐ Star this repository if it helps your automation workflows!**