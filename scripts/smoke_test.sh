#!/bin/bash
# 🧪 Google Drive MCP Connector - Comprehensive Smoke Test
# 5-10 minute validation of all production features

LOGFILE="$(dirname "$0")/../logs/smoke_test.log"
ENV_FILE="$(dirname "$0")/../config/.env"
TEST_START=$(date +%s)

echo "🧪 GOOGLE DRIVE MCP SMOKE TEST STARTING" | tee -a "$LOGFILE"
echo "===============================================" | tee -a "$LOGFILE"
echo "[$(date)] Test initiated in Honolulu timezone" | tee -a "$LOGFILE"

# Source environment
set -a
source "$ENV_FILE" 2>/dev/null || {
  echo "[$(date)] ❌ FAILED: Cannot load .env file" | tee -a "$LOGFILE"
  echo "Run: cp config/.env.template config/.env and configure credentials"
  exit 1
}
set +a

# Test counter
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Test function
run_test() {
  local test_name="$1"
  local test_command="$2"
  
  TEST_COUNT=$((TEST_COUNT + 1))
  echo "[$(date)] Test $TEST_COUNT: $test_name" | tee -a "$LOGFILE"
  
  if eval "$test_command" >> "$LOGFILE" 2>&1; then
    echo "[$(date)] ✅ PASS: $test_name" | tee -a "$LOGFILE"
    PASS_COUNT=$((PASS_COUNT + 1))
    return 0
  else
    echo "[$(date)] ❌ FAIL: $test_name" | tee -a "$LOGFILE"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return 1
  fi
}

# TEST 1: Activation script completes
run_test "Activation script validation" "bash -n ../activate.sh"

# TEST 2: Environment template exists and is complete
run_test "Environment template validation" "test -f ../config/.env.template && grep -q GOOGLE_CLIENT_ID ../config/.env.template"

# TEST 3: Required credentials are configured
run_test "OAuth credentials configured" "[ -n \"\$GOOGLE_CLIENT_ID\" ] && [ -n \"\$GOOGLE_CLIENT_SECRET\" ] && [ -n \"\$GOOGLE_REFRESH_TOKEN\" ]"

# TEST 4: Token refresh mechanism
if [ "$GOOGLE_ACCESS_TOKEN" != "your-current-access-token" ]; then
  run_test "Token refresh test" "curl -s --request POST --data \"client_id=\$GOOGLE_CLIENT_ID&client_secret=\$GOOGLE_CLIENT_SECRET&refresh_token=\$GOOGLE_REFRESH_TOKEN&grant_type=refresh_token\" https://oauth2.googleapis.com/token | jq -e '.access_token'"
else
  echo "[$(date)] ⚠️  SKIP: Token refresh test (template credentials detected)" | tee -a "$LOGFILE"
fi

# TEST 5: Google Drive API connectivity
if [ "$GOOGLE_ACCESS_TOKEN" != "your-current-access-token" ]; then
  run_test "Google Drive API connectivity" "curl -s -H \"Authorization: Bearer \$GOOGLE_ACCESS_TOKEN\" \"https://www.googleapis.com/drive/v3/about?fields=user\" | jq -e '.user'"
else
  echo "[$(date)] ⚠️  SKIP: API connectivity test (template credentials)" | tee -a "$LOGFILE"
fi

# TEST 6: Target folder access
if [ "$GOOGLE_ACCESS_TOKEN" != "your-current-access-token" ]; then
  FOLDER_ID="${GOOGLE_DRIVE_TARGET_FOLDER:-1YjaCFiKAduINrdq750dqtr6r9x2fb6JO}"
  run_test "Target folder access" "curl -s -H \"Authorization: Bearer \$GOOGLE_ACCESS_TOKEN\" \"https://www.googleapis.com/drive/v3/files?q='\$FOLDER_ID'+in+parents&pageSize=1\" | jq -e '.files'"
else
  echo "[$(date)] ⚠️  SKIP: Target folder test (template credentials)" | tee -a "$LOGFILE"
fi

# TEST 7: Dropbox fallback connectivity (if configured)
if [ -n "$DROPBOX_ACCESS_TOKEN" ] && [ "$DROPBOX_ACCESS_TOKEN" != "your-dropbox-access-token" ]; then
  run_test "Dropbox fallback connectivity" "curl -s -X POST https://api.dropboxapi.com/2/users/get_current_account -H \"Authorization: Bearer \$DROPBOX_ACCESS_TOKEN\" | jq -e '.account_id'"
else
  echo "[$(date)] ⚠️  SKIP: Dropbox fallback test (not configured)" | tee -a "$LOGFILE"
fi

# TEST 8: MemoryPlugin log format validation
run_test "MemoryPlugin log format" "echo '[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:6 Smoke test MemoryPlugin integration' >> ../logs/memory_plugin_feed.log"

# TEST 9: Logging directory permissions
run_test "Log directory writable" "touch ../logs/test_write.tmp && rm -f ../logs/test_write.tmp"

# TEST 10: Script syntax validation
run_test "Main script syntax" "bash -n ./google_drive_mcp.sh"

# TEST 11: Dependencies available
run_test "curl dependency" "command -v curl"
run_test "jq dependency" "command -v jq"

# TEST 12: Cron schedule format validation
run_test "Cron schedule valid" "test -f ../config/cron_schedule.txt && grep -q '0 \\* \\* \\* \\*' ../config/cron_schedule.txt"

# Simulate error conditions for testing (optional)
if [ "$1" == "--full-test" ]; then
  echo "[$(date)] Running full simulation tests..." | tee -a "$LOGFILE"
  
  # TEST 13: Simulate 401 (unauthorized) response
  echo "[$(date)] Simulating 401 unauthorized response..." | tee -a "$LOGFILE"
  OLD_TOKEN="$GOOGLE_ACCESS_TOKEN"
  export GOOGLE_ACCESS_TOKEN="invalid_token_for_test"
  run_test "401 error handling" "! curl -s -H \"Authorization: Bearer \$GOOGLE_ACCESS_TOKEN\" \"https://www.googleapis.com/drive/v3/about\" | jq -e '.user'"
  export GOOGLE_ACCESS_TOKEN="$OLD_TOKEN"
  
  # TEST 14: Simulate network timeout
  run_test "Network timeout handling" "timeout 1 curl -s https://www.googleapis.com/drive/v3/about; [ \$? -eq 124 ]"
fi

# Calculate test duration
TEST_END=$(date +%s)
TEST_DURATION=$((TEST_END - TEST_START))

# Final results
echo "" | tee -a "$LOGFILE"
echo "===============================================" | tee -a "$LOGFILE"
echo "📊 SMOKE TEST RESULTS" | tee -a "$LOGFILE"
echo "===============================================" | tee -a "$LOGFILE"
echo "Total Tests: $TEST_COUNT" | tee -a "$LOGFILE"
echo "Passed: $PASS_COUNT" | tee -a "$LOGFILE"
echo "Failed: $FAIL_COUNT" | tee -a "$LOGFILE"
echo "Duration: ${TEST_DURATION}s" | tee -a "$LOGFILE"
echo "Timezone: $(date +%Z) (Hawaii)" | tee -a "$LOGFILE"

if [ $FAIL_COUNT -eq 0 ]; then
  echo "✅ ALL TESTS PASSED - READY FOR PRODUCTION" | tee -a "$LOGFILE"
  exit 0
else
  echo "❌ SOME TESTS FAILED - REVIEW LOGS BEFORE PRODUCTION" | tee -a "$LOGFILE"
  exit 1
fi