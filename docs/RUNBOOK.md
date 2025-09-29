# 🛠️ Google Drive MCP Connector - Production Runbook

**Incident Response, Recovery Procedures, and Operational Guide**

## 🚑 Incident Response Modes

### 🔴 **CRITICAL: Complete Service Failure**
**Symptoms:** All connectivity tests fail, circuit breaker open, fallback unavailable

**Immediate Actions:**
```bash
# 1. Check system status
./scripts/smoke_test.sh --full-test

# 2. Review error logs
tail -n 100 logs/google_drive_mcp.log | grep -E "PRIORITY:(9|10)"

# 3. Force token refresh
export GOOGLE_TOKEN_EXPIRY=0
./scripts/google_drive_mcp.sh

# 4. Test fallback manually
./scripts/health_check_with_fallback.sh
```

**Escalation:** If still failing after 15 minutes, check:
- Google Drive API status: https://status.cloud.google.com/
- OAuth credential validity in Google Cloud Console
- Network connectivity and DNS resolution

---

### 🟡 **WARNING: Degraded Performance**
**Symptoms:** Intermittent failures, high latency, circuit breaker half-open

**Actions:**
```bash
# 1. Check circuit breaker state
cat logs/circuit_breaker_state.json

# 2. Monitor for recovery
watch -n 30 './scripts/health_check_with_fallback.sh'

# 3. Verify API quotas not exceeded
curl -s -H "Authorization: Bearer $GOOGLE_ACCESS_TOKEN" \\
  "https://www.googleapis.com/drive/v3/about?fields=quotaBytesUsed,quotaBytesTotal"
```

---

### 🟢 **INFO: Routine Maintenance**
**Symptoms:** Scheduled maintenance windows, planned token rotation

**Preparation:**
```bash
# 1. Backup current state
cp config/.env config/.env.backup.$(date +%Y%m%d)

# 2. Test fallback before maintenance
./scripts/health_check_with_fallback.sh

# 3. Schedule maintenance notification
echo "[$(date)] CATEGORY:TECHNICAL_SYSTEMS PRIORITY:7 Maintenance window starting" >> logs/memory_plugin_feed.log
```

---

## 🔧 Recovery Procedures

### **OAuth Token Recovery**
```bash
# If refresh token is invalid:
# 1. Re-authenticate with Google OAuth
# 2. Update GOOGLE_REFRESH_TOKEN in .env
# 3. Reset circuit breaker
rm -f logs/circuit_breaker_state.json
./scripts/google_drive_mcp.sh
```

### **Circuit Breaker Reset**
```bash
# Force circuit breaker to closed state
echo '{"state":"CLOSED","failures":0,"timeouts":0}' > logs/circuit_breaker_state.json
./scripts/health_check_with_fallback.sh
```

### **Fallback Recovery**
```bash
# Switch back from Dropbox to Google Drive
sed -i '/STORAGE_PRIMARY=dropbox/d' config/.env
sed -i '/FALLBACK_ACTIVE=true/d' config/.env
./scripts/google_drive_mcp.sh
```

---

## 📊 Operational Monitoring

### **Key Metrics to Monitor:**
- **Token Refresh Frequency**: Should be < 1/hour
- **API Response Time**: Should be < 5 seconds
- **Circuit Breaker State**: Should remain CLOSED
- **Fallback Activations**: Should be rare (< 1/day)
- **Memory Plugin Feed Rate**: 30-minute intervals

### **Log Monitoring Commands:**
```bash
# Monitor real-time health
tail -f logs/google_drive_mcp.log

# Check for critical errors
grep "PRIORITY:10" logs/memory_plugin_feed.log

# View circuit breaker history
jq '.' logs/circuit_breaker_state.json

# Monitor file sync activity
jq '.files | length' logs/target_folder_files.json
```

### **Performance Thresholds:**
| Metric | Good | Warning | Critical |
|--------|------|---------|----------|
| Response Time | < 2s | 2-5s | > 5s |
| Failure Rate | < 1% | 1-5% | > 5% |
| Token Refresh | < 1/hour | 1-2/hour | > 2/hour |
| Circuit State | CLOSED | HALF_OPEN | OPEN |

---

## 🔄 Automated Recovery Workflows

### **Self-Healing Capabilities:**
1. **Token Expiration**: Auto-refresh before expiry
2. **API Failures**: Exponential backoff and retry
3. **Service Outage**: Automatic Dropbox fallback
4. **Network Issues**: Circuit breaker protection
5. **Memory Overflow**: Automatic log rotation

### **Manual Recovery Triggers:**
```bash
# Force complete system reset
./scripts/smoke_test.sh --full-test
if [ $? -ne 0 ]; then
    echo "System requires manual intervention"
    # Follow incident response procedures above
fi
```

---

## 📱 Emergency Contacts & Escalation

### **Escalation Matrix:**
1. **Priority 6-7**: Routine operations - No action needed
2. **Priority 8**: Token events - Monitor for patterns
3. **Priority 9**: Service degradation - Investigate within 30 minutes
4. **Priority 10**: Critical failure - Immediate response required

### **Emergency Procedures:**
```bash
# Complete system diagnostic
./scripts/smoke_test.sh --full-test > emergency_diagnostic.log 2>&1

# Capture system state
ps aux | grep google-drive-mcp > system_state.log
df -h >> system_state.log
free -m >> system_state.log

# Create incident report
echo "Incident: $(date)" > incident_report.txt
echo "Symptoms: [DESCRIBE]" >> incident_report.txt
echo "Actions Taken: [LIST]" >> incident_report.txt
echo "Current Status: [STATUS]" >> incident_report.txt
```

---

## ⚙️ Maintenance Windows

### **Scheduled Maintenance (Monthly)**
**Hawaii Time: First Sunday, 3:00 AM - 4:00 AM HST**

**Maintenance Checklist:**
- [ ] Backup all configuration files
- [ ] Rotate and compress old logs
- [ ] Update OAuth tokens if needed
- [ ] Test fallback connectivity
- [ ] Validate MemoryPlugin integration
- [ ] Update dependencies and security patches
- [ ] Run comprehensive smoke test
- [ ] Document any issues or improvements

**Post-Maintenance Validation:**
```bash
# Complete system validation after maintenance
./scripts/smoke_test.sh --full-test
./scripts/memory_plugin_feed.sh
tail -f logs/google_drive_mcp.log
```

---

## 📌 Quick Reference Commands

### **Daily Operations:**
```bash
# Check system health
./scripts/health_check_with_fallback.sh

# View recent activity
tail -n 20 logs/google_drive_mcp.log

# Check MemoryPlugin feed
tail -n 10 logs/memory_plugin_feed.log
```

### **Troubleshooting:**
```bash
# Debug mode (verbose logging)
DEBUG=true ./scripts/google_drive_mcp.sh

# Test specific folder access
curl -H "Authorization: Bearer $GOOGLE_ACCESS_TOKEN" \\
  "https://www.googleapis.com/drive/v3/files?q='1YjaCFiKAduINrdq750dqtr6r9x2fb6JO'+in+parents"

# Validate cron schedule
crontab -l | grep google-drive-mcp
```

### **Emergency Reset:**
```bash
# Nuclear option - complete reset
rm -f logs/circuit_breaker_state.json
rm -f logs/memory_processed.log
sed -i '/STORAGE_PRIMARY/d; /FALLBACK_ACTIVE/d' config/.env
./scripts/google_drive_mcp.sh
```

---

**📞 Emergency Hotline: Check GitHub Issues or your MCP Gateway page**  
**🔗 Repository: https://github.com/GlacierEQ/google-drive-mcp**  
**🏥 Health Dashboard: ./scripts/smoke_test.sh**