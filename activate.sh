#!/bin/bash
# 🚀 Google Drive MCP Connector - Activation Script
# Complete setup and deployment automation

echo "🚀 ACTIVATING GOOGLE DRIVE MCP CONNECTOR"
echo "======================================="

# Set up environment
if [ ! -f "$(dirname "$0")/config/.env" ]; then
  echo "⚠️  Creating .env from template..."
  cp "$(dirname "$0")/config/.env.template" "$(dirname "$0")/config/.env"
  echo "📝 Please edit $(dirname "$0")/config/.env with your OAuth credentials"
  echo "🔑 Required: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN"
fi

# Create logs directory if needed
mkdir -p "$(dirname "$0")/logs"
echo "✅ Logs directory ready"

# Make all scripts executable
chmod +x "$(dirname "$0")/scripts/"*.sh
echo "✅ Scripts made executable"

# Check dependencies
echo "🔍 Checking dependencies..."

# Check curl
if command -v curl >/dev/null 2>&1; then
  echo "✅ curl available"
else
  echo "❌ curl not found - installing..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y curl
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y curl
  elif command -v brew >/dev/null 2>&1; then
    brew install curl
  else
    echo "❌ Cannot install curl automatically - please install manually"
    exit 1
  fi
fi

# Check jq for JSON processing
if command -v jq >/dev/null 2>&1; then
  echo "✅ jq available"
else
  echo "⚠️  Installing jq for JSON processing..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y jq
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y jq
  elif command -v brew >/dev/null 2>&1; then
    brew install jq
  else
    echo "❌ Cannot install jq automatically - please install manually"
    exit 1
  fi
fi

# Check GitHub CLI (optional)
if command -v gh >/dev/null 2>&1; then
  echo "✅ GitHub CLI available"
else
  echo "⚠️  GitHub CLI not found - some features may be limited"
  echo "📝 Install with: curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg"
fi

# Initialize log files
touch "$(dirname "$0")/logs/google_drive_mcp.log"
touch "$(dirname "$0")/logs/memory_plugin_feed.log"
echo "✅ Log files initialized"

# Run initial configuration validation
if [ -f "$(dirname "$0")/scripts/validate_config.sh" ]; then
  echo "🔍 Running configuration validation..."
  "$(dirname "$0")/scripts/validate_config.sh"
fi

echo ""
echo "🎉 GOOGLE DRIVE MCP CONNECTOR ACTIVATED!"
echo ""
echo "📋 NEXT STEPS:"
echo "1. Edit config/.env with your Google OAuth credentials"
echo "2. Run: ./scripts/google_drive_mcp.sh (test connection)"
echo "3. Add to cron: crontab -e (see config/cron_schedule.txt)"
echo "4. Monitor: tail -f logs/google_drive_mcp.log"
echo ""
echo "🎯 Target folder: 1YjaCFiKAduINrdq750dqtr6r9x2fb6JO"
echo "🛡️  Health monitoring: ./scripts/health_check_with_fallback.sh"
echo "🧠 MemoryPlugin: ./scripts/memory_plugin_feed.sh"
echo "🔗 Repository: https://github.com/GlacierEQ/google-drive-mcp"
echo ""
echo "✅ READY FOR OPERATION!"
echo "🚀 Your Maximum Control Point Google Drive Connector is LIVE!"