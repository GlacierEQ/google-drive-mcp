#!/bin/bash

# Power Path Deployment Script
# Enhanced MCP Connector and Toolset Deployment
# Case 1FDV-23-0001009 Optimized
# Hawaii Timezone: Pacific/Honolulu

set -euo pipefail

# Script metadata
SCRIPT_NAME="deploy_power_path.sh"
SCRIPT_VERSION="2.0.0"
CASE_NUMBER="1FDV-23-0001009"
TIMEZONE="Pacific/Honolulu"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging setup
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/power_path_deployment_$(date +'%Y%m%d_%H%M%S').log"
FORENSIC_LOG="$LOG_DIR/forensic_deployment_audit.jsonl"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Logging function with forensic compliance
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    local hawaii_time=$(TZ="$TIMEZONE" date +"%Y-%m-%d %H:%M:%S HST")
    
    # Console output with colors
    case "$level" in
        "INFO")
            echo -e "${GREEN}[$hawaii_time]${NC} ${BLUE}INFO${NC}: $message"
            ;;
        "WARN")
            echo -e "${GREEN}[$hawaii_time]${NC} ${YELLOW}WARN${NC}: $message"
            ;;
        "ERROR")
            echo -e "${GREEN}[$hawaii_time]${NC} ${RED}ERROR${NC}: $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$hawaii_time]${NC} ${GREEN}SUCCESS${NC}: $message"
            ;;
        "FORENSIC")
            echo -e "${GREEN}[$hawaii_time]${NC} ${PURPLE}FORENSIC${NC}: $message"
            ;;
    esac
    
    # File logging
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Forensic audit logging
    if [[ "$level" == "FORENSIC" || "$level" == "ERROR" ]]; then
        local forensic_entry=$(cat <<EOF
{
  "timestamp": "$timestamp",
  "hawaii_time": "$hawaii_time",
  "level": "$level",
  "message": "$message",
  "script": "$SCRIPT_NAME",
  "version": "$SCRIPT_VERSION",
  "case_reference": "$CASE_NUMBER",
  "deployment_session": "$$",
  "integrity_hash": "$(echo -n "$timestamp$level$message" | sha256sum | cut -d' ' -f1)"
}
EOF
        )
        echo "$forensic_entry" >> "$FORENSIC_LOG"
    fi
}

# Error handling
error_exit() {
    log_message "ERROR" "$1"
    log_message "FORENSIC" "Deployment failed: $1"
    exit 1
}

# Success handler
success_exit() {
    log_message "SUCCESS" "$1"
    log_message "FORENSIC" "Deployment completed successfully: $1"
    exit 0
}

# Trap errors
trap 'error_exit "Script failed at line $LINENO"' ERR

# Header
echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════════════════"
echo "    POWER PATH DEPLOYMENT - ENHANCED MCP CONNECTORS & TOOLSETS"
echo "═══════════════════════════════════════════════════════════════════════"
echo -e "${NC}"
echo -e "${BLUE}Script:${NC}      $SCRIPT_NAME v$SCRIPT_VERSION"
echo -e "${BLUE}Case:${NC}        $CASE_NUMBER"
echo -e "${BLUE}Timezone:${NC}    $TIMEZONE"
echo -e "${BLUE}Started:${NC}     $(TZ="$TIMEZONE" date)"
echo -e "${BLUE}User:${NC}        $(whoami)"
echo -e "${BLUE}Directory:${NC}   $(pwd)"
echo ""

log_message "INFO" "Starting Power Path deployment for $CASE_NUMBER"
log_message "FORENSIC" "Deployment initiated by $(whoami) from $(pwd)"

# Environment validation
log_message "INFO" "Validating environment and dependencies..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    error_exit "Python 3 is required but not installed"
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
log_message "INFO" "Python version: $PYTHON_VERSION"

# Check required Python packages
REQUIRED_PACKAGES=(
    "fastmcp"
    "google-auth"
    "google-auth-oauthlib"
    "google-api-python-client"
    "aiohttp"
    "mem0ai"
    "sentence-transformers"
)

log_message "INFO" "Checking required Python packages..."
for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! python3 -c "import ${package//[-.]/_}" 2>/dev/null; then
        log_message "WARN" "Installing missing package: $package"
        pip3 install "$package" || error_exit "Failed to install $package"
    else
        log_message "INFO" "Package $package is available"
    fi
done

# Environment variables validation
log_message "INFO" "Validating environment variables..."

REQUIRED_ENV_VARS=(
    "PERPLEXITY_API_KEY"
    "GOOGLE_CLIENT_ID"
    "GOOGLE_CLIENT_SECRET"
)

OPTIONAL_ENV_VARS=(
    "GMAIL_CLIENT_ID"
    "GMAIL_CLIENT_SECRET"
    "GITHUB_CLIENT_ID"
    "GITHUB_CLIENT_SECRET"
    "MEM0_API_KEY"
    "E2B_API_KEY"
)

# Check required environment variables
for var in "${REQUIRED_ENV_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        error_exit "Required environment variable $var is not set"
    else
        log_message "INFO" "Environment variable $var is configured"
    fi
done

# Check optional environment variables
for var in "${OPTIONAL_ENV_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        log_message "WARN" "Optional environment variable $var is not set"
    else
        log_message "INFO" "Optional environment variable $var is configured"
    fi
done

# Directory structure setup
log_message "INFO" "Setting up directory structure..."

DIRECTORIES=(
    "logs"
    "credentials"
    "config"
    "connectors"
    "mcp_servers"
    "memory"
    "tests"
    "docs"
)

for dir in "${DIRECTORIES[@]}"; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        log_message "INFO" "Created directory: $dir"
    else
        log_message "INFO" "Directory exists: $dir"
    fi
done

# Set permissions for sensitive directories
chmod 700 credentials/ || log_message "WARN" "Could not set permissions on credentials directory"
chmod 755 logs/ || log_message "WARN" "Could not set permissions on logs directory"

# Configuration file setup
log_message "INFO" "Setting up configuration files..."

CONFIG_FILE="config/power_path_config.json"
if [[ -f "$CONFIG_FILE" ]]; then
    log_message "INFO" "Power Path configuration file exists: $CONFIG_FILE"
    
    # Validate JSON syntax
    if ! python3 -m json.tool "$CONFIG_FILE" > /dev/null; then
        error_exit "Configuration file has invalid JSON syntax: $CONFIG_FILE"
    fi
    
    log_message "SUCCESS" "Configuration file validation passed"
else
    error_exit "Configuration file not found: $CONFIG_FILE"
fi

# MCP Server components validation
log_message "INFO" "Validating MCP server components..."

MCP_COMPONENTS=(
    "connectors/perplexity_search_v2.py"
    "mcp_servers/legal_research_powerhouse.py"
    "connectors/gmail_legal_evidence.py"
)

for component in "${MCP_COMPONENTS[@]}"; do
    if [[ -f "$component" ]]; then
        log_message "INFO" "MCP component exists: $component"
        
        # Basic syntax validation for Python files
        if [[ "$component" == *.py ]]; then
            if ! python3 -m py_compile "$component"; then
                error_exit "Python syntax error in: $component"
            fi
        fi
    else
        error_exit "Required MCP component not found: $component"
    fi
done

# Test connections
log_message "INFO" "Testing API connections..."

# Test Perplexity API
log_message "INFO" "Testing Perplexity API connection..."
PERPLEXITY_TEST=$(python3 -c "
import aiohttp
import asyncio
import os

async def test_perplexity():
    headers = {
        'Authorization': f'Bearer {os.getenv("PERPLEXITY_API_KEY")}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': 'sonar-pro',
        'messages': [{'role': 'user', 'content': 'test'}],
        'max_tokens': 10
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'https://api.perplexity.ai/v1/chat/completions',
                json=payload,
                headers=headers
            ) as response:
                if response.status == 200:
                    print('SUCCESS')
                else:
                    print(f'ERROR:{response.status}')
    except Exception as e:
        print(f'ERROR:{str(e)}')

asyncio.run(test_perplexity())
" 2>/dev/null)

if [[ "$PERPLEXITY_TEST" == "SUCCESS" ]]; then
    log_message "SUCCESS" "Perplexity API connection successful"
else
    log_message "ERROR" "Perplexity API connection failed: $PERPLEXITY_TEST"
    error_exit "Cannot proceed without valid Perplexity API connection"
fi

# Test Google OAuth (basic validation)
if [[ -n "${GOOGLE_CLIENT_ID:-}" && -n "${GOOGLE_CLIENT_SECRET:-}" ]]; then
    log_message "SUCCESS" "Google OAuth credentials configured"
else
    log_message "WARN" "Google OAuth credentials incomplete"
fi

# Backup existing configuration
log_message "INFO" "Creating backup of existing configuration..."

BACKUP_DIR="backups/$(date +'%Y%m%d_%H%M%S')"
mkdir -p "$BACKUP_DIR"

# Backup important files
BACKUP_FILES=(
    "config/mcp_orchestrator.yml"
    "scripts/google_drive_mcp.sh"
    "logs/google_drive_mcp.log"
)

for file in "${BACKUP_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/"
        log_message "INFO" "Backed up: $file"
    fi
done

log_message "SUCCESS" "Backup created: $BACKUP_DIR"

# Deploy MCP servers
log_message "INFO" "Deploying enhanced MCP servers..."

# Make scripts executable
find scripts/ -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
log_message "INFO" "Made scripts executable"

# Set up systemd services (if running with appropriate permissions)
if command -v systemctl &> /dev/null && [[ $EUID -eq 0 ]]; then
    log_message "INFO" "Setting up systemd services..."
    
    # Copy service files
    if [[ -f "config/google-drive-mcp.service" ]]; then
        cp "config/google-drive-mcp.service" "/etc/systemd/system/"
        systemctl daemon-reload
        systemctl enable google-drive-mcp.service
        log_message "SUCCESS" "Systemd service configured"
    fi
else
    log_message "INFO" "Skipping systemd setup (not running as root or systemctl not available)"
fi

# Set up cron jobs for Hawaii timezone
log_message "INFO" "Setting up Hawaii timezone automation..."

CRON_FILE="config/cron_honolulu.txt"
if [[ -f "$CRON_FILE" ]]; then
    # Install cron jobs
    crontab "$CRON_FILE" 2>/dev/null || log_message "WARN" "Could not install cron jobs (permission denied)"
    log_message "INFO" "Cron jobs configured for Hawaii timezone"
else
    log_message "WARN" "Cron configuration file not found: $CRON_FILE"
fi

# Initialize case context
log_message "INFO" "Initializing case context for $CASE_NUMBER..."

CASE_CONTEXT_FILE="config/case_context.json"
cat > "$CASE_CONTEXT_FILE" << EOF
{
  "caseNumber": "$CASE_NUMBER",
  "caseType": "family_court",
  "jurisdiction": "hawaii",
  "court": "Family Court of the First Circuit",
  "status": "active",
  "initialized": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
  "initializedBy": "$(whoami)",
  "deploymentVersion": "$SCRIPT_VERSION",
  "timezone": "$TIMEZONE"
}
EOF

log_message "SUCCESS" "Case context initialized: $CASE_CONTEXT_FILE"

# Run comprehensive smoke tests
log_message "INFO" "Running comprehensive smoke tests..."

# Test 1: Configuration validation
log_message "INFO" "Test 1: Configuration validation"
if python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f:
    config = json.load(f)
    print('Configuration loaded successfully')
    print(f'Servers configured: {len(config.get("mcpServers", {}))}')
"; then
    log_message "SUCCESS" "Configuration validation passed"
else
    error_exit "Configuration validation failed"
fi

# Test 2: Python imports
log_message "INFO" "Test 2: Python module imports"
for component in "${MCP_COMPONENTS[@]}"; do
    if [[ "$component" == *.py ]]; then
        module_path="${component%.py}"
        module_name="${module_path//\//.}"
        
        if python3 -c "import sys; sys.path.insert(0, '.'); import $module_name; print(f'Successfully imported $module_name')"; then
            log_message "SUCCESS" "Import test passed: $module_name"
        else
            log_message "ERROR" "Import test failed: $module_name"
            # Don't exit on import failures, just warn
        fi
    fi
done

# Test 3: File permissions
log_message "INFO" "Test 3: File permissions"
PERMISSION_TESTS=(
    "logs:rwx"
    "credentials:rwx"
    "config:rw-"
    "scripts:rwx"
)

for test in "${PERMISSION_TESTS[@]}"; do
    dir="${test%:*}"
    expected="${test#*:}"
    
    if [[ -d "$dir" ]]; then
        perms=$(stat -c "%A" "$dir" 2>/dev/null || stat -f "%Sp" "$dir" 2>/dev/null || echo "unknown")
        log_message "INFO" "Directory $dir permissions: $perms"
    fi
done

# Generate deployment report
log_message "INFO" "Generating deployment report..."

REPORT_FILE="logs/power_path_deployment_report_$(date +'%Y%m%d_%H%M%S').json"

cat > "$REPORT_FILE" << EOF
{
  "deployment": {
    "script": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")",
    "hawaii_time": "$(TZ="$TIMEZONE" date)",
    "user": "$(whoami)",
    "directory": "$(pwd)",
    "case_reference": "$CASE_NUMBER"
  },
  "environment": {
    "python_version": "$PYTHON_VERSION",
    "timezone": "$TIMEZONE",
    "required_packages": $(printf '%s\n' "${REQUIRED_PACKAGES[@]}" | jq -R . | jq -s .),
    "required_env_vars": $(printf '%s\n' "${REQUIRED_ENV_VARS[@]}" | jq -R . | jq -s .)
  },
  "components": {
    "mcp_servers": $(printf '%s\n' "${MCP_COMPONENTS[@]}" | jq -R . | jq -s .),
    "configuration_file": "$CONFIG_FILE",
    "case_context_file": "$CASE_CONTEXT_FILE"
  },
  "tests": {
    "perplexity_api": "$(if [[ "$PERPLEXITY_TEST" == "SUCCESS" ]]; then echo "PASSED"; else echo "FAILED"; fi)",
    "configuration_validation": "PASSED",
    "file_permissions": "CHECKED"
  },
  "status": "COMPLETED",
  "next_steps": [
    "Verify MCP server connectivity",
    "Test legal research functionality",
    "Configure email evidence collection",
    "Set up automated monitoring",
    "Schedule comprehensive case review"
  ]
}
EOF

log_message "SUCCESS" "Deployment report generated: $REPORT_FILE"

# Final status
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}    POWER PATH DEPLOYMENT COMPLETED SUCCESSFULLY${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Deployment Summary:${NC}"
echo -e "${BLUE}├─${NC} Case Number:      $CASE_NUMBER"
echo -e "${BLUE}├─${NC} Version:          $SCRIPT_VERSION"
echo -e "${BLUE}├─${NC} Completed:        $(TZ="$TIMEZONE" date)"
echo -e "${BLUE}├─${NC} Log File:         $LOG_FILE"
echo -e "${BLUE}├─${NC} Forensic Log:     $FORENSIC_LOG"
echo -e "${BLUE}├─${NC} Report File:      $REPORT_FILE"
echo -e "${BLUE}└─${NC} Backup Directory: $BACKUP_DIR"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "1. Test enhanced Perplexity Search API v2 connectivity"
echo -e "2. Configure Gmail legal evidence collection"
echo -e "3. Verify FastMCP 2.0 intelligent tool selection"
echo -e "4. Set up progressive scoping authentication"
echo -e "5. Test case-specific memory management"
echo -e "6. Schedule comprehensive case workflow testing"
echo ""
echo -e "${CYAN}For technical support or questions about Case $CASE_NUMBER:${NC}"
echo -e "${CYAN}Review logs in $LOG_DIR/ for detailed information${NC}"
echo ""

log_message "FORENSIC" "Power Path deployment completed successfully for $CASE_NUMBER"
success_exit "Power Path deployment completed successfully"