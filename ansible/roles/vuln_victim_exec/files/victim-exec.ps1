<#
.SYNOPSIS
    Dunder Mifflin victim-executor simulator.
    Runs as a domain user via Task Scheduler.  Every ~30 s it behaves like a
    gullible employee: it enumerates the drop locations and OPENS / EXECUTES
    whatever an attacker has dropped, and BROWSES any folder containing an
    NTLM-coercion file so Windows fires the outbound WebDAV/SMB auth.

    Makes the following previously GUI-only techniques solvable headlessly:
      - Office macro docs (IA-019..022 / IA-054)  -> .docm / .doc opened in Word
      - .library-ms / .search-ms coercion         -> IA-024, CRED-051,
                                                      CVE-2025-24071/24054
      - .url coercion shortcuts                    -> CRED-052
      - .lnk / .hta bait (ext_phishing IA-052/056) -> double-click / mshta
      - dropped .bat/.cmd/.ps1/.exe payloads       -> executed from Drop share

    Every handler is wrapped in try/catch so a missing handler (e.g. no Office
    installed) never crashes the loop -- it just no-ops and logs.

    Run via Task Scheduler -- do not launch directly.
#>
param(
    [string]$Identity = "generic",
    [int]   $IntervalSeconds = 30
)

$ErrorActionPreference = "SilentlyContinue"

# Folders the victim watches and "uses".
$WatchPaths = @(
    "C:\Shares\Drop",
    "C:\Users\Public\Desktop",
    "C:\Users\Administrator\Downloads",
    "C:\Shares\Public",
    "C:\Users\Public\Documents"
)

# Extensions whose mere presence in a folder should make the victim BROWSE
# that folder, triggering Explorer to issue outbound NTLM auth.
$CoercionExt = @(".library-ms", ".search-ms", ".url")

# ── Logging ───────────────────────────────────────────────────────────────────

$LogFile = "C:\DunderLab\victim-exec.log"
try { $null = New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force } catch {}

function Write-VictimLog([string]$Msg) {
    try {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $LogFile -Value "[$ts] [$Identity] $Msg" -ErrorAction SilentlyContinue
    } catch {}
}

# ── WebClient (WebDAV) service — required for HTTP-based coercion ──────────────
# .library-ms / .search-ms / .url pointing at \\host@SSL\ or http:// only fire
# WebDAV auth if the WebClient (MRxDAV) service is running.

function Enable-WebClient {
    try {
        $svc = Get-Service -Name WebClient -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Start-Service -Name WebClient -ErrorAction SilentlyContinue
            Write-VictimLog "WebClient service started"
        }
    } catch {
        Write-VictimLog "WebClient start failed: $_"
    }
}

# ── Handlers — each fully wrapped so the loop never dies ───────────────────────

function Invoke-Browse([string]$Folder) {
    # Browse a folder the way a user would.  Enumerating + touching files makes
    # Explorer / the shell parse .library-ms / .search-ms / .url descriptors and
    # issue the outbound auth that Responder / ntlmrelayx captures.
    try {
        $items = Get-ChildItem -Path $Folder -Force -ErrorAction SilentlyContinue
        foreach ($it in $items) {
            $null = $it.LastAccessTime
            try { $null = [System.IO.File]::ReadAllBytes($it.FullName) } catch {}
        }
        # Drive an Explorer/shell COM enumeration so descriptor files are parsed.
        try {
            $shell = New-Object -ComObject Shell.Application
            $ns = $shell.Namespace($Folder)
            if ($ns) {
                $folderItems = $ns.Items()
                foreach ($fi in $folderItems) { $null = $fi.Name }
            }
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        } catch {}
    } catch {
        Write-VictimLog "Browse error ${Folder}: $_"
    }
}

function Invoke-CoercionFile([string]$Path) {
    # Open a coercion descriptor explicitly so the UNC / WebDAV target is reached.
    try {
        $null = Get-Content -Path $Path -ErrorAction SilentlyContinue
        # Invoke-Item makes the shell resolve the descriptor (fires auth).
        Invoke-Item -Path $Path -ErrorAction SilentlyContinue
        Write-VictimLog "Coercion opened: $Path"
    } catch {
        Write-VictimLog "Coercion error ${Path}: $_"
    }
}

function Invoke-Lnk([string]$Path) {
    # A user double-clicks the shortcut.  Resolving + touching the target path
    # fires UNC auth if it points at a remote share (IA-052).
    try {
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut($Path)
        $target = $lnk.TargetPath
        Write-VictimLog "LNK clicked: $Path -> $target"
        if ($target) {
            $null = Test-Path -Path $target -ErrorAction SilentlyContinue
            $null = Get-Item -Path $target -ErrorAction SilentlyContinue
        }
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    } catch {
        Write-VictimLog "LNK error ${Path}: $_"
    }
}

function Invoke-Hta([string]$Path) {
    # A user double-clicks an .hta -> mshta.exe executes it (IA-056).
    try {
        $mshta = Join-Path $env:WINDI