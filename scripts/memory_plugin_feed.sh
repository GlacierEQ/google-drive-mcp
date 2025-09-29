#!/bin/bash
# MemoryPlugin Integration for Google Drive MCP
# Processes logs and feeds forensic data with PII redaction

LOGFILE="$(dirname "$0")/../logs/google_drive_mcp.log"
MEMORY_LOG="$(dirname "$0")/../logs/memory_plugin_feed.log"
PROCESSED_LOG="$(dirname "$0")/../logs/memory_processed.log"

echo "[$(date)] 🧠 MemoryPlugin Feed Processing Started" | tee -a "$MEMORY_LOG"

# Function: Redact PII from log entries
redact_pii() {
    local line="$1"
    
    # Redact file names and paths (keep first 3 chars + ***)
    line=$(echo "$line" | sed -E 's/([a-zA-Z0-9]{3})[a-zA-Z0-9._-]{4,}/\1***/g')
    
    # Redact access tokens (keep first 6 chars)
    line=$(echo "$line" | sed -E 's/(ya29\.[a-zA-Z0-9_-]{6})[a-zA-Z0-9_-]+/\1***/g')
    
    # Redact folder IDs (keep first 4 chars)
    line=$(echo "$line" | sed -E 's/([0-9a-zA-Z]{4})[0-9a-zA-Z_-]{20,}/\1***/g')
    
    echo "$line"
}

# Function: Extract and categorize log events
process_log_entry() {
    local line="$1"
    local timestamp=$(echo "$line" | grep -o '\[.*\]' | head -1)
    
    # Skip if already processed (avoid duplicates)
    if grep -q "$timestamp" "$PROCESSED_LOG" 2>/dev/null; then
        return
    fi
    
    # Process different types of events
    if [[ "$line" == *"Successfully refreshed"* ]]; then
        redacted=$(redact_pii "$line")
        echo "$timestamp CATEGORY:TECHNICAL_SYSTEMS PRIORITY:8 OAuth token refreshed - $redacted" >> "$MEMORY_LOG"
        
    elif [[ "$line" == *"Failed to refresh"* ]]; then
        redacted=$(redact_pii "$line")
        echo "$timestamp CATEGORY:TECHNICAL_SYSTEMS PRIORITY:10 OAuth token refresh FAILED - $redacted" >> "$MEMORY_LOG"
        
    elif [[ "$line" == *"Connected to Google Drive user"* ]]; then
        # Extract username but redact for privacy
        user=$(echo "$line" | grep -o 'user: [^"]*' | cut -d' ' -f2 | head -c3)
        echo "$timestamp CATEGORY:TECHNICAL_SYSTEMS PRIORITY:6 Google Drive connection verified - user: ${user}***" >> "$MEMORY_LOG"
        
    elif [[ "$line" == *"Found"*"files in target folder"* ]]; then
        file_count=$(echo "$line" | grep -o '[0-9]\+ files')
        echo "$timestamp CATEGORY:STORAGE_OPERATIONS PRIORITY:7 Target folder sync completed - $file_count" >> "$MEMORY_LOG"
        
    elif [[ "$line" == *"Failed to connect"* ]]; then
        echo "$timestamp CATEGORY:TECHNICAL_SYSTEMS PRIORITY:9 Google Drive connectivity FAILED - attempting repair" >> "$MEMORY_LOG"
        
    elif [[ "$line" == *"health check cycle completed"* ]]; then
        echo "$timestamp CATEGORY:TECHNICAL_SYSTEMS PRIORITY:6 Health check cycle completed successfully" >> "$MEMORY_LOG"
        
    elif [[ "$line" == *"Dropbox fallback activated"* ]]; then
        echo "$timestamp CATEGORY:TECHNICAL_SYSTEMS PRIORITY:9 Dropbox fallback activated due to Google Drive failure" >> "$MEMORY_LOG"
    fi
    
    # Mark as processed
    echo "$timestamp" >> "$PROCESSED_LOG"
}

# Process recent log entries (last 100 lines)
if [ -f "$LOGFILE" ]; then
    tail -n 100 "$LOGFILE" | while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" == *"["*"]"* ]]; then
            process_log_entry "$line"
        fi
    done
fi

# Clean up old processed entries (keep last 1000)
if [ -f "$PROCESSED_LOG" ]; then
    tail -n 1000 "$PROCESSED_LOG" > "${PROCESSED_LOG}.tmp"
    mv "${PROCESSED_LOG}.tmp" "$PROCESSED_LOG"
fi

# Generate summary stats
if [ -f "$MEMORY_LOG" ]; then
    RECENT_ENTRIES=$(tail -n 50 "$MEMORY_LOG" | wc -l)
    PRIORITY_10=$(tail -n 100 "$MEMORY_LOG" | grep -c "PRIORITY:10")
    PRIORITY_9=$(tail -n 100 "$MEMORY_LOG" | grep -c "PRIORITY:9")
    
    echo "[$(date)] 📊 MemoryPlugin Stats: $RECENT_ENTRIES recent entries, P10: $PRIORITY_10, P9: $PRIORITY_9" | tee -a "$MEMORY_LOG"
fi

echo "[$(date)] ✅ MemoryPlugin feed processing completed" | tee -a "$MEMORY_LOG"