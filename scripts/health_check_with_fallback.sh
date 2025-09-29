#!/bin/bash
# Health Check with Fallback Logic and Circuit Breaker
# Exponential backoff and intelligent Dropbox failover

LOGFILE="$(dirname "$0")/../logs/google_drive_mcp.log"
ENV_FILE="$(dirname "$0")/../config/.env"
CIRCUIT_BREAKER_FILE="$(dirname "$0")/../logs/circuit_breaker_state.json"

set -a
source "$ENV_FILE" 2>/dev/null || {
  echo "[$(date)] ERROR: Cannot load environment file" | tee -a "$LOGFILE"
  exit 1
}
set +a

# Circuit Breaker Configuration
FAILURE_THRESHOLD=5
TIMEOUT_THRESHOLD=3
RECOVERY_TIMEOUT=300

# Function: Load circuit breaker state
load_circuit_state() {
    if [ -f "$CIRCUIT_BREAKER_FILE" ]; then
        FAILURES=$(jq -r '.failures // 0' "$CIRCUIT_BREAKER_FILE")
        TIMEOUTS=$(jq -r '.timeouts // 0' "$CIRCUIT_BREAKER_FILE")
        LAST_FAILURE=$(jq -r '.last_failure // 0' "$CIRCUIT_BREAKER_FILE")
        STATE=$(jq -r '.state // "CLOSED"' "$CIRCUIT_BREAKER_FILE")
    else
        FAILURES=0
        TIMEOUTS=0
        LAST_FAILURE=0
        STATE="CLOSED"
    fi
}

# Function: Save circuit breaker state
save_circuit_state() {
    local state="$1"
    local failures="$2"
    local timeouts="$3"
    
    cat > "$CIRCUIT_BREAKER_FILE" << EOF
{
  "state": "$state",
  "failures": $failures,
  "timeouts": $timeouts,
  "last_failure": $(date +%s),
  "last_update": "$(date -Iseconds)"
}
EOF
}

# Function: Exponential backoff
exponential_backoff() {
    local attempt="$1"
    local base_delay=1
    local max_delay=60
    
    local delay=$((base_delay * (2 ** (attempt - 1))))
    [ $delay -gt $max_delay ] && delay=$max_delay
    
    echo "[$(date)] 🔄 Exponential backoff: waiting ${delay}s (attempt $attempt)" | tee -a "$LOGFILE"
    sleep $delay
}

# Function: Test Google Drive connection with retries
test_google_drive() {
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        echo "[$(date)] 🔍 Testing Google Drive (attempt $attempt/$max_attempts)" | tee -a "$LOGFILE"
        
        # Test with timeout
        RESPONSE=$(timeout 30 curl -s -w "%{http_code}" -H "Authorization: Bearer $GOOGLE_ACCESS_TOKEN" \\
            "https://www.googleapis.com/drive/v3/about?fields=user")
            
        HTTP_CODE="${RESPONSE: -3}"
        BODY="${RESPONSE%???}"
        
        case $HTTP_CODE in
            "200")
                if echo "$BODY" | jq -e '.user' > /dev/null 2>&1; then
                    USER=$(echo "$BODY" | jq -r '.user.displayName')
                    echo "[$(date)] ✅ Google Drive healthy - user: ${USER:0:3}***" | tee -a "$LOGFILE"
                    return 0
                fi
                ;;
            "401")
                echo "[$(date)] 🔑 401 Unauthorized - token refresh required" | tee -a "$LOGFILE"
                return 2  # Special code for token refresh needed
                ;;
            "403")
                echo "[$(date)] 🚫 403 Forbidden - scope or permission issue" | tee -a "$LOGFILE"
                return 3  # Special code for fallback needed
                ;;
            "")
                echo "[$(date)] ⏱️ Connection timeout (attempt $attempt)" | tee -a "$LOGFILE"
                TIMEOUTS=$((TIMEOUTS + 1))
                ;;
            *)
                echo "[$(date)] ❌ HTTP $HTTP_CODE error (attempt $attempt)" | tee -a "$LOGFILE"
                FAILURES=$((FAILURES + 1))
                ;;
        esac
        
        if [ $attempt -lt $max_attempts ]; then
            exponential_backoff $attempt
        fi
        
        attempt=$((attempt + 1))
    done
    
    return 1  # All attempts failed
}

# Function: Test Dropbox fallback
test_dropbox_fallback() {
    echo "[$(date)] 📦 Testing Dropbox fallback connectivity" | tee -a "$LOGFILE"
    
    if [ -z "$DROPBOX_ACCESS_TOKEN" ] || [ "$DROPBOX_ACCESS_TOKEN" == "your-dropbox-access-token" ]; then
        echo "[$(date)] ⚠️  Dropbox credentials not configured" | tee -a "$LOGFILE"
        return 1
    fi
    
    DROPBOX_RESPONSE=$(timeout 15 curl -s -X POST https://api.dropboxapi.com/2/users/get_current_account \\
        -H "Authorization: Bearer $DROPBOX_ACCESS_TOKEN")
        
    if echo "$DROPBOX_RESPONSE" | jq -e '.account_id' > /dev/null 2>&1; then
        ACCOUNT=$(echo "$DROPBOX_RESPONSE" | jq -r '.name.display_name')
        echo "[$(date)] ✅ Dropbox fallback ready - account: ${ACCOUNT:0:3}***" | tee -a "$LOGFILE"
        return 0
    else
        echo "[$(date)] ❌ Dropbox fallback test failed" | tee -a "$LOGFILE"
        return 1
    fi
}

# Function: Activate fallback mode
activate_fallback() {
    echo "[$(date)] 🎆 Activating Dropbox fallback mode" | tee -a "$LOGFILE"
    
    if test_dropbox_fallback; then
        # Update environment to use Dropbox as primary
        echo "STORAGE_PRIMARY=dropbox" >> "$ENV_FILE"
        echo "FALLBACK_ACTIVE=true" >> "$ENV_FILE"
        
        echo "[$(date)] ✅ Fallback activated - now using Dropbox as primary storage" | tee -a "$LOGFILE"
        return 0
    else
        echo "[$(date)] ❌ Fallback activation failed - both Google Drive and Dropbox unavailable" | tee -a "$LOGFILE"
        return 1
    fi
}

# Main health check execution
echo "[$(date)] 🏥 Google Drive MCP Health Check with Fallback" | tee -a "$LOGFILE"

# Load circuit breaker state
load_circuit_state

# Check if circuit breaker is open
NOW=$(date +%s)
if [ "$STATE" == "OPEN" ] && [ $((NOW - LAST_FAILURE)) -lt $RECOVERY_TIMEOUT ]; then
    echo "[$(date)] ⚠️  Circuit breaker OPEN - recovery timeout not expired" | tee -a "$LOGFILE"
    exit 1
fi

# Test Google Drive connectivity
test_google_drive
DRIVE_RESULT=$?

case $DRIVE_RESULT in
    0)
        echo "[$(date)] ✅ Google Drive healthy - resetting circuit breaker" | tee -a "$LOGFILE"
        save_circuit_state "CLOSED" 0 0
        ;;
    2)
        echo "[$(date)] 🔄 Token refresh needed - attempting refresh" | tee -a "$LOGFILE"
        if "$(dirname "$0")/google_drive_mcp.sh"; then
            echo "[$(date)] ✅ Token refreshed successfully" | tee -a "$LOGFILE"
        else
            echo "[$(date)] ❌ Token refresh failed - activating fallback" | tee -a "$LOGFILE"
            FAILURES=$((FAILURES + 1))
            activate_fallback
        fi
        ;;
    3)
        echo "[$(date)] 🚫 403 Forbidden - OAuth scope or permission issue, activating fallback" | tee -a "$LOGFILE"
        FAILURES=$((FAILURES + 1))
        activate_fallback
        ;;
    1)
        echo "[$(date)] ❌ Google Drive connectivity failed - incrementing failure count" | tee -a "$LOGFILE"
        FAILURES=$((FAILURES + 1))
        
        # Check if circuit breaker should open
        if [ $FAILURES -ge $FAILURE_THRESHOLD ] || [ $TIMEOUTS -ge $TIMEOUT_THRESHOLD ]; then
            echo "[$(date)] ⚠️  Circuit breaker threshold reached - opening circuit and activating fallback" | tee -a "$LOGFILE"
            save_circuit_state "OPEN" $FAILURES $TIMEOUTS
            activate_fallback
        else
            save_circuit_state "HALF_OPEN" $FAILURES $TIMEOUTS
        fi
        ;;
esac

echo "[$(date)] 🏥 Health check completed - Circuit: $STATE, Failures: $FAILURES" | tee -a "$LOGFILE"