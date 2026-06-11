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

# Extensions whose presence in a folder makes the victim BROWSE that folder,
# triggering Explorer to issue outbound NTLM auth.
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
# WebDAV auth when the WebClient (MRxDAV) service is running.

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
        # Drive a shell COM enumeration so descriptor files are parsed.
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
    # fires UNC auth when it points at a remote share (IA-052).
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
        $mshta = Join-Path $env:WINDIR "System32\mshta.exe"
        if (Test-Path $mshta) {
            Write-VictimLog "HTA via mshta: $Path"
            $p = Start-Process -FilePath $mshta -ArgumentList "`"$Path`"" -PassThru -ErrorAction SilentlyContinue
            if ($p) {
                Start-Sleep -Seconds 5
                if (-not $p.HasExited) { $p.Kill() }
            }
        } else {
            $null = Get-Content -Path $Path -ErrorAction SilentlyContinue
            Write-VictimLog "HTA (no mshta, read only): $Path"
        }
    } catch {
        Write-VictimLog "HTA error ${Path}: $_"
    }
}

function Invoke-OfficeDoc([string]$Path) {
    # A user opens a macro doc.  Drive Word via COM with macros enabled so an
    # AutoOpen / Document_Open VBA payload runs (IA-019..022 / IA-054).
    # Office may not be installed -> guard, fall back to read-only, never crash.
    $word = $null
    try {
        if (-not [Type]::GetTypeFromProgID("Word.Application")) {
            $null = Get-Content -Path $Path -ErrorAction SilentlyContinue
            Write-VictimLog "DOC (no Word, read only): $Path"
            return
        }
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $word.DisplayAlerts = 0
        try { $word.AutomationSecurity = 1 } catch {}   # msoAutomationSecurityLow = macros enabled
        Write-VictimLog "DOC opened in Word (macros on): $Path"
        $doc = $word.Documents.Open($Path, $false, $true)
        try { $doc.RunAutoMacros(2) } catch {}          # wdAutoOpen
        Start-Sleep -Seconds 3
        try { $doc.Close($false) } catch {}
    } catch {
        try { $null = Get-Content -Path $Path -ErrorAction SilentlyContinue } catch {}
        Write-VictimLog "DOC error (fell back to read) ${Path}: $_"
    } finally {
        try { if ($word) { $word.Quit() } } catch {}
        try { if ($word) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null } } catch {}
    }
}

function Invoke-Script([string]$Path) {
    # A user runs a dropped executable / script.  Simulate execution; cap the
    # runtime so a hung or interactive payload cannot wedge the loop.
    try {
        $ext = [System.IO.Path]::GetExtension($Path).ToLower()
        $exe = $null
        $args = $null
        switch ($ext) {
            ".bat" { $exe = Join-Path $env:WINDIR "System32\cmd.exe"; $args = "/c `"$Path`"" }
            ".cmd" { $exe = Join-Path $env:WINDIR "System32\cmd.exe"; $args = "/c `"$Path`"" }
            ".ps1" {
                $exe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
                $args = "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Path`""
            }
            ".exe" { $exe = $Path; $args = $null }
            default { return }
        }
        if ($exe -and (Test-Path $exe)) {
            Write-VictimLog "Executing dropped payload: $Path"
            if ($args) {
                $p = Start-Process -FilePath $exe -ArgumentList $args -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            } else {
                $p = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            }
            if ($p) {
                Start-Sleep -Seconds 5
                if (-not $p.HasExited) { $p.Kill() }
            }
        }
    } catch {
        Write-VictimLog "Exec error ${Path}: $_"
    }
}

# ── Per-folder processing ─────────────────────────────────────────────────────

function Invoke-WatchPath([string]$Folder) {
    try {
        if (-not (Test-Path -Path $Folder -ErrorAction SilentlyContinue)) { return }

        # 1. Always browse the folder first (fires coercion descriptors).
        Invoke-Browse $Folder

        $files = Get-ChildItem -Path $Folder -File -Force -ErrorAction SilentlyContinue
        if (-not $files) { return }

        # 2. If any coercion descriptor is present, open it explicitly too.
        $hasCoercion = $false
        foreach ($f in $files) {
            if ($CoercionExt -contains $f.Extension.ToLower()) { $hasCoercion = $true; break }
        }
        if ($hasCoercion) { Enable-WebClient }

        # 3. Act on each artifact the way a gullible user would.
        foreach ($f in $files) {
            $ext = $f.Extension.ToLower()
            switch ($ext) {
                ".library-ms" { Invoke-CoercionFile $f.FullName }
                ".search-ms"  { Invoke-CoercionFile $f.FullName }
                ".url"        { Invoke-CoercionFile $f.FullName }
                ".lnk"        { Invoke-Lnk          $f.FullName }
                ".hta"        { Invoke-Hta          $f.FullName }
                ".docm"       { Invoke-OfficeDoc    $f.FullName }
                ".doc"        { Invoke-OfficeDoc    $f.FullName }
                ".docx"       { Invoke-OfficeDoc    $f.FullName }
                ".rtf"        { Invoke-OfficeDoc    $f.FullName }
                ".bat"        { Invoke-Script       $f.FullName }
                ".cmd"        { Invoke-Script       $f.FullName }
                ".ps1"        { Invoke-Script       $f.FullName }
                ".exe"        { Invoke-Script       $f.FullName }
                default       { $null = $f.Name }
            }
        }
    } catch {
        Write-VictimLog "WatchPath error ${Folder}: $_"
    }
}

# ── Main loop — runs forever, ~30 s between rounds ────────────────────────────

Write-VictimLog "Victim-executor started (interval=${IntervalSeconds}s)"
Enable-WebClient

while ($true) {
    foreach ($path in $WatchPaths) {
        Invoke-WatchPath $path
        Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 800)
    }
    Start-Sleep -Seconds $IntervalSeconds
}
