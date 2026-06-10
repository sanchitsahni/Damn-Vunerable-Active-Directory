Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

# WinRM
winrm quickconfig -q 2>$null
winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>$null
winrm set winrm/config/service/auth '@{Basic="true"}' 2>$null
winrm set winrm/config/client '@{TrustedHosts="*"}' 2>$null
winrm set winrm/config '@{MaxTimeoutms="7200000"}' 2>$null
Set-Service WinRM -StartupType Automatic
Start-Service WinRM -ErrorAction SilentlyContinue

# Firewall — off entirely (lab)
netsh advfirewall set allprofiles state off | Out-Null
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985 | Out-Null
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986 | Out-Null

# Defender — off
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
        -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true -ErrorAction SilentlyContinue
} catch {}
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f | Out-Null

# UAC — off
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f | Out-Null

# Windows Update — disabled
sc.exe config wuauserv start= disabled | Out-Null
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue

# Power — no sleep during build
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null

# Network discovery + file sharing (needed for SMB vulns later)
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes | Out-Null
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes | Out-Null

# Install virtio-win drivers if ISO is present (E: or D: drive)
foreach ($drive in @("E:", "D:", "F:")) {
    $inf = "$drive\vioscsi\2k22\amd64\vioscsi.inf"
    if (Test-Path $inf) {
        pnputil /add-driver "$drive\vioscsi\2k22\amd64\vioscsi.inf" /install 2>$null
        pnputil /add-driver "$drive\NetKVM\2k22\amd64\netkvm.inf" /install 2>$null
        pnputil /add-driver "$drive\Balloon\2k22\amd64\balloon.inf" /install 2>$null
        break
    }
    $inf19 = "$drive\vioscsi\2k19\amd64\vioscsi.inf"
    if (Test-Path $inf19) {
        pnputil /add-driver "$drive\vioscsi\2k19\amd64\vioscsi.inf" /install 2>$null
        pnputil /add-driver "$drive\NetKVM\2k19\amd64\netkvm.inf" /install 2>$null
        pnputil /add-driver "$drive\Balloon\2k19\amd64\balloon.inf" /install 2>$null
        break
    }
    $inf10 = "$drive\vioscsi\w10\amd64\vioscsi.inf"
    if (Test-Path $inf10) {
        pnputil /add-driver "$drive\vioscsi\w10\amd64\vioscsi.inf" /install 2>$null
        pnputil /add-driver "$drive\NetKVM\w10\amd64\netkvm.inf" /install 2>$null
        break
    }
}

Write-Host "[+] setup-winrm.ps1 complete"
