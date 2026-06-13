<#
.SYNOPSIS
    Galactic Empire victim traffic simulator.
    Runs as a domain user, generates periodic SMB/HTTP auth traffic every ~30 s.

    Attack surface produced:
      - NTLMv2 hashes capturable via Responder (LLMNR/NBNS poisoning)
      - Relay targets reachable via ntlmrelayx (real hosts, SMB signing disabled)
      - WPAD HTTP auth (WPAD/proxy spoofing)

    Run via Task Scheduler — do not launch directly.
#>
param(
    [string]$Identity = "generic",
    [int]   $IntervalSeconds = 30
)

$ErrorActionPreference = "SilentlyContinue"

# ── Targets ───────────────────────────────────────────────────────────────────
#
# Real shares  → auth sent to actual host → ntlmrelayx relay target
# Fake names   → DNS fails → LLMNR/NBNS fallback → Responder captures NTLMv2
# IP paths     → no LLMNR (DNS skip), but auth still sent → relay by IP
#
$RealTargets = @(
    "\\scarif.empire.local\Accounting",
    "\\scarif.empire.local\HR",
    "\\scarif.empire.local\Sales",
    "\\kamino.empire.local\Reports",
    "\\coruscant.empire.local\NETLOGON",
    "\\coruscant.empire.local\SYSVOL",
    "\\10.10.0.13\Accounting",        # IP → bypasses DNS, forces auth directly
    "\\10.10.0.14\Reports"
)

$FakeTargets = @(
    "\\EMPIRE-PRINT\Printers",        # plausible printer server typo → LLMNR
    "\\EMPIRESHARE\Documents",        # plausible share name → LLMNR
    "\\TATOOINE-FS\ImperialOrders",      # Imperial file server → LLMNR
    "\\EMPIRE-BACKUP\Archives",       # backup server → LLMNR
    "\\EMPIRE-FILE\Reports",          # file server variant → LLMNR
    "\\PALPATINE-PC\Docs",             # Palpatine's computer → LLMNR
    "\\CANTINA\Scheduling"          # reception workstation → LLMNR
)

$WpadUrls = @(
    "http://wpad/wpad.dat",
    "http://wpad.empire.local/wpad.dat",
    "http://proxy/wpad.dat"
)

# ── Helpers ───────────────────────────────────────────────────────────────────

function Invoke-ShareAccess([string]$Path) {
    # Multiple access patterns to maximise auth events
    $null = [System.IO.Directory]::Exists($Path)
    $null = Get-ChildItem -Path $Path -Force -Depth 0 -ErrorAction SilentlyContinue
    $null = Test-Path -Path $Path
}

function Invoke-NetUse([string]$Path) {
    # net use generates a full SMB auth exchange
    $null = & net.exe use $Path /savecred 2>$null
    Start-Sleep -Milliseconds 500
    $null = & net.exe use $Path /delete 2>$null
}

function Invoke-WpadProbe([string]$Url) {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Proxy = [System.Net.WebProxy]::GetDefaultProxy()
        $null = $wc.DownloadString($Url)
    } catch {}
}

function Invoke-DnsProbe([string]$Hostname) {
    try { $null = [System.Net.Dns]::GetHostEntry($Hostname) } catch {}
}

# ── Identity-specific activity sets ───────────────────────────────────────────

$ActivitySets = @{
    "leia.organa" = @{
        ShareComment = "Pam checking Accounting & HR shares"
        Real  = @("\\scarif.empire.local\Accounting", "\\scarif.empire.local\HR", "\\10.10.0.13\Accounting")
        Fake  = @("\\EMPIRE-BACKUP\Archives", "\\TATOOINE-FS\Payroll", "\\CANTINA\Scheduling")
        UseNet = $true
    }
    "luke.skywalker" = @{
        ShareComment = "Jim accessing Sales materials"
        Real  = @("\\scarif.empire.local\Sales", "\\10.10.0.13\Sales", "\\coruscant.empire.local\NETLOGON")
        Fake  = @("\\PALPATINE-PC\Docs", "\\EMPIRE-FILE\Reports", "\\EMPIRESHARE\CustomerData")
        UseNet = $true
    }
    "darth.maul" = @{
        ShareComment = "Vader doing security audit of shares"
        Real  = @("\\scarif.empire.local\Sales", "\\kamino.empire.local\Reports", "\\coruscant.empire.local\SYSVOL")
        Fake  = @("\\EMPIRE-PRINT\Printers", "\\TATOOINE-FS\ImperialOrders", "\\EMPIRE-FILE\DeathStarReports")
        UseNet = $false
    }
    "sheev.palpatine" = @{
        ShareComment = "Palpatine looking for party planning docs"
        Real  = @("\\scarif.empire.local\HR", "\\coruscant.empire.local\NETLOGON")
        Fake  = @("\\PALPATINE-PC\Docs", "\\EMPIRESHARE\Documents", "\\EMPIRE-PRINT\Printers")
        UseNet = $true
    }
    "generic" = @{
        ShareComment = "Generic workstation traffic"
        Real  = $RealTargets | Get-Random -Count 3
        Fake  = $FakeTargets | Get-Random -Count 3
        UseNet = $true
    }
}

$ActivitySet = if ($ActivitySets.ContainsKey($Identity)) {
    $ActivitySets[$Identity]
} else {
    $ActivitySets["generic"]
}

# ── Main loop — runs forever, 30 s between rounds ─────────────────────────────

$LogFile = "C:\EmpireLab\traffic-sim.log"
$null = New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force

function Write-TrafficLog([string]$Msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$ts] [$Identity] $Msg" -ErrorAction SilentlyContinue
}

Write-TrafficLog "Traffic simulator started (interval=${IntervalSeconds}s)"

while ($true) {
    try {
        # 1. Pick one real share (relay target)
        $realPath = $ActivitySet.Real | Get-Random
        Write-TrafficLog "SMB real: $realPath"
        Invoke-ShareAccess $realPath
        if ($ActivitySet.UseNet) { Invoke-NetUse $realPath }

        Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 2000)

        # 2. Pick one fake share (LLMNR trigger)
        $fakePath = $ActivitySet.Fake | Get-Random
        Write-TrafficLog "SMB fake (LLMNR): $fakePath"
        Invoke-ShareAccess $fakePath

        Start-Sleep -Milliseconds (Get-Random -Minimum 300 -Maximum 1000)

        # 3. Every other round: WPAD probe (triggers proxy auth abuse)
        if ((Get-Random -Maximum 2) -eq 0) {
            $wpad = $WpadUrls | Get-Random
            Write-TrafficLog "WPAD probe: $wpad"
            Invoke-WpadProbe $wpad
        }

        # 4. DNS lookup for non-existent host (fuels LLMNR on next round)
        $fakeHost = ($ActivitySet.Fake | Get-Random).Split('\')[2]
        Invoke-DnsProbe $fakeHost

    } catch {
        Write-TrafficLog "Error: $_"
    }

    Start-Sleep -Seconds $IntervalSeconds
}
