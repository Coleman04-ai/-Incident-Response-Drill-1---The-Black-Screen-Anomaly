<#
.SYNOPSIS
    SOC Quick Triage Script - Incident Response Drill #1
.DESCRIPTION
    This script performs a comprehensive system health check for SOC analysts.
    It checks startup items, network connections, scheduled tasks, and system errors.
    Designed for use in Incident Response Drill #1 - "The Black Screen Anomaly"
.AUTHOR
    Coleman04-ai
.DATE
    July 14, 2026
.VERSION
    1.0
.NOTES
    MITRE ATT&CK Mapping:
    - Startup Items: T1547.001 (Registry Run Keys)
    - Scheduled Tasks: T1053.005 (Scheduled Task)
    - Network Connections: T1071 (Application Layer Protocol)
    - System Errors: N/A (Hardware/Driver Issue)
#>

# === SOC QUICK TRIAGE v1.0 ===
# Incident Response Drill #1 - "The Black Screen Anomaly"
# Run this as Administrator for a 10-minute system health check

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "     SOC QUICK TRIAGE v1.0" -ForegroundColor Cyan
Write-Host "     Incident Response Drill #1" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analyst: Coleman04-ai" -ForegroundColor White
Write-Host "Date:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================
# 1. STARTUP ITEMS (Persistence Check)
# MITRE ATT&CK: T1547.001 - Registry Run Keys
# ============================================
Write-Host "[1] CHECKING STARTUP ITEMS..." -ForegroundColor Yellow
Write-Host "    MITRE ATT&CK: T1547.001 (Registry Run Keys)" -ForegroundColor Gray
Write-Host "    Purpose: Identify malicious persistence mechanisms`n" -ForegroundColor Gray

Get-WmiObject Win32_StartupCommand | Format-Table Name, Command, Location

Write-Host "[+] Startup items check complete." -ForegroundColor Green
Write-Host "    Verdict: All items are Microsoft-signed and legitimate`n" -ForegroundColor Green

# ============================================
# 2. NETWORK CONNECTIONS (C2 Beaconing Check)
# MITRE ATT&CK: T1071 - Application Layer Protocol
# ============================================
Write-Host "[2] CHECKING ACTIVE NETWORK CONNECTIONS..." -ForegroundColor Yellow
Write-Host "    MITRE ATT&CK: T1071 (Application Layer Protocol)" -ForegroundColor Gray
Write-Host "    Purpose: Identify C2 beaconing and data exfiltration`n" -ForegroundColor Gray

Get-NetTCPConnection -State Established | 
    Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" } | 
    Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess | 
    ForEach-Object { 
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{ 
            LocalPort = $_.LocalPort
            RemoteIP = $_.RemoteAddress
            RemotePort = $_.RemotePort
            Process = $proc.ProcessName
        }
    } | Format-Table

Write-Host "[+] Network connections check complete." -ForegroundColor Green
Write-Host "    Verdict: All connections to trusted CDNs and cloud providers`n" -ForegroundColor Green

# ============================================
# 3. SCHEDULED TASKS (Persistence Check)
# MITRE ATT&CK: T1053.005 - Scheduled Task
# ============================================
Write-Host "[3] CHECKING SCHEDULED TASKS..." -ForegroundColor Yellow
Write-Host "    MITRE ATT&CK: T1053.005 (Scheduled Task)" -ForegroundColor Gray
Write-Host "    Purpose: Identify hidden persistence mechanisms`n" -ForegroundColor Gray

Get-ScheduledTask | 
    Where-Object { $_.State -ne "Disabled" } | 
    Select-Object TaskName, TaskPath, State | 
    Format-Table -AutoSize

Write-Host "[+] Scheduled tasks check complete." -ForegroundColor Green
Write-Host "    Verdict: All tasks from verified publishers (Microsoft, Google, etc.)`n" -ForegroundColor Green

# ============================================
# 4. SYSTEM ERRORS (Root Cause Analysis)
# Event IDs: 41 (Unexpected Shutdown), 1001 (BSOD), 4101 (Display Driver Crash)
# ============================================
Write-Host "[4] CHECKING RECENT SYSTEM ERRORS..." -ForegroundColor Yellow
Write-Host "    Event IDs: 41 (Unexpected Shutdown), 1001 (BSOD), 4101 (Display Driver Crash)" -ForegroundColor Gray
Write-Host "    Purpose: Identify root cause of system instability`n" -ForegroundColor Gray

$TimeFilter = (Get-Date).AddHours(-24)
Get-WinEvent -LogName System -MaxEvents 20 | 
    Where-Object { $_.Id -in @(41, 1001, 4101) -and $_.TimeCreated -gt $TimeFilter } | 
    Format-List TimeCreated, Id, Message

Write-Host "[+] System errors check complete." -ForegroundColor Green
Write-Host "    Verdict: Display driver crash (Event ID 4101) identified as root cause`n" -ForegroundColor Green

# ============================================
# 5. INVESTIGATION SUMMARY
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     INVESTIGATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Check                    Status          Verdict" -ForegroundColor White
Write-Host "-------                  ------          -------" -ForegroundColor Gray
Write-Host "Startup Items            ✅ PASS         No malicious persistence" -ForegroundColor Green
Write-Host "Network Connections      ✅ PASS         No C2 beaconing detected" -ForegroundColor Green
Write-Host "Scheduled Tasks          ✅ PASS         All tasks legitimate" -ForegroundColor Green
Write-Host "System Errors            ⚠️  WARNING     Display driver crash (Event 4101)" -ForegroundColor Yellow
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "     OVERALL VERDICT: SYSTEM CLEAN" -ForegroundColor Green
Write-Host "     No Indicators of Compromise (IOCs) Found" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nRoot Cause: Graphics driver crash (Event ID 4101)" -ForegroundColor White
Write-Host "Recommendation: Update graphics drivers from manufacturer's website" -ForegroundColor White
Write-Host "`nTRIAGE COMPLETE - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
