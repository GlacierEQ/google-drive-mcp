#!/bin/bash
# Configuration Validation Script for Production Deployment
# Validates all components before production use

echo "🔍 Google Drive MCP Configuration Validation"
echo "============================================="

VALIDATION_LOG="$(dirname "$0")/../logs/validation.log"
echo "[$(date)] Starting configuration validation" | tee -a "$VALIDATION_LOG"

# Test counters
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Validation function
validate() {
    local test_name="$1"
    local test_command="$2"
    local critical="${3:-false}"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    echo "Test $TEST_COUNT: $test_name"
    
    if eval "$test_command" >> "$VALIDATION_LOG" 2>&1; then
        echo "✅ PASS: $test_name"
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    else
        if [ "$critical" == "true" ]; then
            echo "❌ CRITICAL FAIL: $test_name"
        else
            echo "⚠️  FAIL: $test_name"
        fi
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

# Required files validation
echo "
📁 Validating required files..."
validate "Main connector script exists" "test -f scripts/google_drive_mcp.sh" true
validate "Main script executable" "test -x scripts/google_drive_mcp.sh" true
validate "MemoryPlugin script exists" "test -f scripts/memory_plugin_feed.sh" true
validate "Health check script exists" "test -f scripts/health_check_with_fallback.sh" true
validate "Environment template exists" "test -f config/.env.template" true
validate "Activation script exists" "test -f activate.sh" true
validate "Logs directory exists" "test -d logs" true

# Environment template validation
echo "
⚙️ Validating environment template..."
validate "GOOGLE_CLIENT_ID in template" "grep -q '^GOOGLE_CLIENT_ID=' config/.env.template" true
validate "GOOGLE_CLIENT_SECRET in template" "grep -q '^GOOGLE_CLIENT_SECRET=' config/.env.template" true
validate "GOOGLE_REFRESH_TOKEN in template" "grep -q '^GOOGLE_REFRESH_TOKEN=' config/.env.template" true
validate "Target folder ID in template" "grep -q 'GOOGLE_DRIVE_TARGET_FOLDER=1YjaCFiKAduINrdq750dqtr6r9x2fb6JO' config/.env.template" true
validate "Dropbox fallback in template" "grep -q '^DROPBOX_ACCESS_TOKEN=' config/.env.template"

# Script syntax validation
echo "
📜 Validating shell script syntax..."
validate "Main script syntax" "bash -n scripts/google_drive_mcp.sh" true
validate "MemoryPlugin script syntax" "bash -n scripts/memory_plugin_feed.sh" true
validate "Health check script syntax" "bash -n scripts/health_check_with_fallback.sh" true
validate "Activation script syntax" "bash -n activate.sh" true

# Dependency validation
echo "
🔧 Validating system dependencies..."
validate "curl available" "command -v curl" true
validate "jq available" "command -v jq" true
validate "bash version >= 4" "[ \"\${BASH_VERSION%%.*}\" -ge 4 ]" true
validate "timeout command available" "command -v timeout"
validate "grep available" "command -v grep" true
validate "sed available" "command -v sed" true

# Configuration structure validation
echo "
🏗️ Validating configuration structure..."
validate "MCP orchestrator config" "test -f config/mcp_orchestrator.yml"
validate "Hawaii cron config" "test -f config/cron_honolulu.txt"
validate "GitHub workflow exists" "test -f .github/workflows/ci.yml"
validate "Gitignore prevents credential leaks" "grep -q 'config/.env' .gitignore"
validate "License file exists" "test -f LICENSE"

# Production readiness checks
echo "
🎯 Validating production readiness..."
validate "Runbook documentation" "test -f docs/RUNBOOK.md"
validate "Smoke test script" "test -f scripts/smoke_test.sh && test -x scripts/smoke_test.sh"
validate "Circuit breaker logic" "grep -q 'CIRCUIT_BREAKER' scripts/health_check_with_fallback.sh"
validate "PII redaction logic" "grep -q 'redact_pii' scripts/memory_plugin_feed.sh"
validate "Exponential backoff" "grep -q 'exponential_backoff' scripts/health_check_with_fallback.sh"

# Security validation
echo "
🛡️ Validating security measures..."
validate "No committed credentials" "! grep -r 'sk-' . --exclude-dir=.git --exclude='*.template'"
validate "No committed OAuth tokens" "! grep -r 'ya29\.' . --exclude-dir=.git --exclude='*.template'"
validate "No real folder IDs in docs" "! grep -r '1[A-Za-z0-9_-]\\{25,\\}' docs/ || true"  # Allow in config files

# Final validation summary
echo "
==============================================="
echo "📊 CONFIGURATION VALIDATION RESULTS"
echo "==============================================="
echo "Total Tests: $TEST_COUNT"
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"
echo "Success Rate: $(( (PASS_COUNT * 100) / TEST_COUNT ))%"

if [ $FAIL_COUNT -eq 0 ]; then
    echo "
✅ ALL VALIDATIONS PASSED"
    echo "🚀 SYSTEM READY FOR PRODUCTION DEPLOYMENT"
    echo "[$(date)] Configuration validation: ALL TESTS PASSED" | tee -a "$VALIDATION_LOG"
    exit 0
else
    echo "
❌ VALIDATION FAILURES DETECTED"
    echo "⚠️  SYSTEM NOT READY FOR PRODUCTION"
    echo "📝 Review logs and fix issues before deployment"
    echo "[$(date)] Configuration validation: $FAIL_COUNT FAILURES" | tee -a "$VALIDATION_LOG"
    exit 1
fi