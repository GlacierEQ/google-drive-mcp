#!/bin/bash
# Google Drive MCP Connector - Maximum Control Point Integration
# Handles: OAuth refresh, health checks, file sync, forensic logging

LOGFILE="$(dirname "$0")/../logs/google_drive_mcp.log"
ENV_FILE="$(dirname "$0")/../config/.env"
MEMORY_PLUGIN_LOG="$(dirname "$0")/../logs/memory_plugin_feed.log"

# Source environment variables
set -a
source "$ENV_FILE" 2>/dev/null || {
  echo "[$(date)] ERROR: Cannot load environment file: $ENV_FILE" | tee -a "$LOGFILE"
  exit 1
}
set +a

echo "[$(date)] 🚀 Google Drive MCP Connector starting..." | tee -a "$LOGFILE"

# Function: Refresh Google OAuth token
refresh_token() {
  echo "[$(date)] 🔄 Refreshing Google Drive OAuth token..." | tee -a "$LOGFILE"
  
  RESPONSE=$(curl --silent --request POST \\
    --data "client_id=$GOOGLE_CLIENT_ID&client_secret=$GOOGLE_CLIENT_SECRET&refresh_token=$GOOGLE_REFRESH_TOKEN&grant_type=refresh_token" \\
    https://oauth2.googleapis.com/token)
    
  if [ $? -ne 0 ]; then
    echo "[$(date)] ❌ Failed to make token refresh request" | tee -a "$LOGFILE"
    return 1
  fi
  
  NEW_ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token // empty')
  EXPIRES_IN=$(echo "$RESPONSE" | jq -r '.expires_in // empty')
  
  if [ -n "$NEW_ACCESS_TOKEN" ] && [ "$NEW_ACCESS_TOKEN" != "null" ]; then
    echo "[$(date)] ✅ Successfully refreshed Google Drive access token" | tee -a "$LOGFILE"
    
    # Update .env file with new token
    sed -i "s|^GOOGLE_ACCESS_TOKEN=.*|GOOGLE_ACCESS_TOKEN=$NEW_ACCESS_TOKEN|" "$ENV_FILE"
    
    NEW_EXPIRY=$(($(date +%s) + $EXPIRES_IN))
    sed -i "s|^GOOGLE_TOKEN_EXPIRY=.*|GOOGLE_TOKEN_EXPIRY=$NEW_EXPIRY|" "$ENV_FILE"
    
    export GOOGLE_ACCESS_TOKEN=$NEW_ACCESS_TOKEN
    
    # Log to MemoryPlugin
    echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:8 Google Drive token refreshed successfully" >> "$MEMORY_PLUGIN_LOG"
    
    return 0
  else
    echo "[$(date)] ❌ Token refresh failed: $RESPONSE" | tee -a "$LOGFILE"
    echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:10 Google Drive token refresh FAILED - requires manual intervention" >> "$MEMORY_PLUGIN_LOG"
    return 1
  fi
}

# Function: Test Google Drive connectivity
test_connectivity() {
  echo "[$(date)] 🔍 Testing Google Drive API connectivity..." | tee -a "$LOGFILE"
  
  DRIVE_INFO=$(curl -s -H "Authorization: Bearer $GOOGLE_ACCESS_TOKEN" \\
    "https://www.googleapis.com/drive/v3/about?fields=user,storageQuota")
    
  if [ $? -eq 0 ] && echo "$DRIVE_INFO" | jq -e '.user' > /dev/null; then
    DRIVE_USER=$(echo "$DRIVE_INFO" | jq -r '.user.displayName')
    STORAGE_USED=$(echo "$DRIVE_INFO" | jq -r '.storageQuota.usage // "N/A"')
    STORAGE_LIMIT=$(echo "$DRIVE_INFO" | jq -r '.storageQuota.limit // "N/A"')
    
    echo "[$(date)] ✅ Connected to Google Drive user: $DRIVE_USER" | tee -a "$LOGFILE"
    echo "[$(date)] 📊 Storage: $STORAGE_USED / $STORAGE_LIMIT bytes used" | tee -a "$LOGFILE"
    
    # Log to MemoryPlugin
    echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:6 Google Drive connection healthy - user: $DRIVE_USER" >> "$MEMORY_PLUGIN_LOG"
    
    return 0
  else
    echo "[$(date)] ❌ Google Drive API connectivity test failed" | tee -a "$LOGFILE"
    echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:9 Google Drive connectivity FAILED - attempting repair" >> "$MEMORY_PLUGIN_LOG"
    return 1
  fi
}

# Function: Sync specific folder (your shared folder)
sync_target_folder() {
  local FOLDER_ID="${GOOGLE_DRIVE_TARGET_FOLDER:-1YjaCFiKAduINrdq750dqtr6r9x2fb6JO}"
  echo "[$(date)] 📂 Syncing target folder: $FOLDER_ID" | tee -a "$LOGFILE"
  
  # List files in the target folder
  FILES_RESPONSE=$(curl -s -H "Authorization: Bearer $GOOGLE_ACCESS_TOKEN" \\
    "https://www.googleapis.com/drive/v3/files?q='$FOLDER_ID'+in+parents&fields=files(name,id,modifiedTime,size,mimeType)")
    
  if [ $? -eq 0 ] && echo "$FILES_RESPONSE" | jq -e '.files' > /dev/null; then
    FILE_COUNT=$(echo "$FILES_RESPONSE" | jq '.files | length')
    echo "[$(date)] ✅ Found $FILE_COUNT files in target folder" | tee -a "$LOGFILE"
    
    # Save file list for processing
    echo "$FILES_RESPONSE" | jq '.files' > "$(dirname "$0")/../logs/target_folder_files.json"
    
    # Log significant files to MemoryPlugin
    echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:7 Google Drive folder sync completed - $FILE_COUNT files available" >> "$MEMORY_PLUGIN_LOG"
    
    return 0
  else
    echo "[$(date)] ❌ Failed to sync target folder" | tee -a "$LOGFILE"
    echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:9 Google Drive folder sync FAILED" >> "$MEMORY_PLUGIN_LOG"
    return 1
  fi
}

# Main execution flow
echo "[$(date)] 🏗️ Starting Google Drive MCP health check and sync..." | tee -a "$LOGFILE"

# Check if token needs refresh
NOW=$(date +%s)
EXPIRY=${GOOGLE_TOKEN_EXPIRY:-0}
if [ "$NOW" -ge "$EXPIRY" ]; then
  refresh_token || {
    echo "[$(date)] ❌ Token refresh failed - cannot proceed" | tee -a "$LOGFILE"
    exit 1
  }
fi

# Test connectivity
test_connectivity || {
  echo "[$(date)] 🔄 Connectivity failed, attempting token refresh..." | tee -a "$LOGFILE"
  refresh_token || {
    echo "[$(date)] ❌ Both connectivity and token refresh failed" | tee -a "$LOGFILE"
    exit 1
  }
  
  # Retry connectivity after refresh
  test_connectivity || {
    echo "[$(date)] ❌ Connectivity still failed after token refresh" | tee -a "$LOGFILE"
    exit 1
  }
}

# Sync target folder
sync_target_folder

echo "[$(date)] ✅ Google Drive MCP Connector check complete." | tee -a "$LOGFILE"
echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:6 Google Drive MCP health check cycle completed successfully" >> "$MEMORY_PLUGIN_LOG"