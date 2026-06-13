#!/usr/bin/env python3
"""EMPIRE — empire Mifflin Vulnerable AD Lab — interactive menu."""
import sys
assert sys.version_info >= (3, 8), "Python 3.8+ required"

import os
import re
import cmd as _cmd
import argparse
import fcntl
import shutil
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

EMPIRE_HOME = Path(__file__).parent.resolve()
LOCK_FILE   = Path("/tmp/empire-deploy.lock")

IS_TTY = sys.stdin.isatty() and sys.stdout.isatty()

# Cron / non-login shells often have a stripped PATH.
# Prepend common tool locations so packer, ansible, qemu binaries are found.
_EXTRA_PATHS = [
    "/usr/local/bin", "/usr/bin", "/bin",
    "/usr/local/sbin", "/usr/sbin", "/sbin",
    "/opt/homebrew/bin",          # macOS Homebrew
    "/snap/bin",                  # Ubuntu snap
]
os.environ["PATH"] = ":".join(
    _EXTRA_PATHS + [p for p in os.environ.get("PATH", "").split(":") if p not in _EXTRA_PATHS]
)

VIRTIO_WIN_URL = (
    "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/"
    "stable-virtio/virtio-win.iso"
)

# Ubuntu 22.04 LTS (jammy) cloud image — prebuilt, NOT a packer build.
# The Linux member (mandalore) boots this directly via a qcow2 backing clone +
# a cloud-init NoCloud seed ISO. See providers/qemu/vm-create.sh launch branch.
UBUNTU_CLOUD_IMG = {
    "filename": "ubuntu-22.04-cloud.img",
    "url": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
    "size_hint": "~700 MB",
    "min_mb": 200,
}

# Evaluation ISOs — no key required, 180-day eval
# Using -4 (IPv4 only) + --tries=5 to avoid IPv6 CDN resets (same approach as GOAD)
WINDOWS_ISOS = [
    {
        "filename": "windows-server-2022.iso",
        "url": "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso",
        "size_hint": "~4.7 GB",
    },
    {
        "filename": "windows-server-2019.iso",
        "url": "https://software-static.download.prss.microsoft.com/dbazure/988969d5-f34g-4e03-ac9d-1f9786c66749/17763.3650.221105-1748.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso",
        "size_hint": "~5.3 GB",
    },
    # windows-10.iso dropped — tatooine is now Server Core (server2022 base).
]

PROFILES = {
    "full":      {"vms": 9, "forests": 3, "ram_gb": 12.25, "label": "9 VMs (incl. mandalore) · 3 forests · ~12.25 GB alloc (~15 GB real)"},
    "minimal":   {"vms": 7, "forests": 1, "ram_gb": 9.75,  "label": "7 VMs · empire.local + mandalore · ~9.75 GB alloc (rock-solid)"},
    "single-dc": {"vms": 1, "forests": 1, "ram_gb": 1.5,  "label": "1 VM · smoke test · ~1.5 GB RAM"},
}

PACKER_TEMPLATES = [
    "windows-server-2022.pkr.hcl",
    "windows-server-2019.pkr.hcl",
    # windows-10.pkr.hcl dropped — tatooine now uses the Server Core (server2022)
    # base so the whole lab is headless. No Win10 image/ISO needed.
]

# ANSI colours
R   = "\033[0;31m"
G   = "\033[0;32m"
Y   = "\033[1;33m"
B   = "\033[0;34m"
C   = "\033[0;36m"
M   = "\033[0;35m"
BLD = "\033[1m"
DIM = "\033[2m"
NC  = "\033[0m"

# readline (used by cmd.Cmd) counts every byte of the prompt as a visible
# column unless non-printing runs are bracketed by \001 (RL_PROMPT_START_IGNORE)
# and \002 (RL_PROMPT_END_IGNORE). Without these guards the cursor wraps back to
# column 0 after a few keystrokes. Wrap each ANSI escape before using a coloured
# string as an interactive prompt.
_ANSI_RE = re.compile(r"(\033\[[0-9;]*m)")
def rl_safe(prompt: str) -> str:
    return _ANSI_RE.sub("\001\\1\002", prompt)

def log(msg):  print(f"{G}[+]{NC} {msg}")
def warn(msg): print(f"{Y}[!]{NC} {msg}")
def err(msg):  print(f"{R}[x]{NC} {msg}")
def info(msg): print(f"{B}[*]{NC} {msg}")
def step(msg): print(f"\n{C}{BLD}[>>]{NC} {msg}")


def _human_size(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024:
            return f"{num_bytes:.0f}{unit}" if unit in ("B", "KB") else f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}PB"


def _human_time(secs: float) -> str:
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s   = divmod(rem, 60)
    if h: return f"{h}h{m:02d}m"
    if m: return f"{m}m{s:02d}s"
    return f"{s}s"


# ─────────────────────────────────────────────────────────────────────────────
# System helpers
# ─────────────────────────────────────────────────────────────────────────────

def detect_ram_gb() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    return int(line.split()[1]) // 1024 // 1024
    except Exception:
        pass
    return 0


def detect_free_disk_gb(path: str) -> int:
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        st = os.statvfs(path)
        return (st.f_bavail * st.f_frsize) // (1024 ** 3)
    except Exception:
        return 0


def cmd_in_path(name: str) -> bool:
    return shutil.which(name) is not None


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess helpers
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(label: str, cmd: list, cwd: Path = EMPIRE_HOME, env: dict = None) -> bool:
    info(f"Running: {' '.join(str(c) for c in cmd)}")
    merged_env = {**os.environ}
    if env:
        merged_env.update(env)
    result = subprocess.run(
        cmd, cwd=str(cwd), env=merged_env,
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        log(f"{label} — PASS")
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines()[-20:]:
                print(f"    {line}")
        return True
    err(f"{label} — FAIL (exit {result.returncode})")
    err(f"Command: {' '.join(str(c) for c in cmd)}")
    err("--- stdout ---")
    for line in (result.stdout or "").strip().splitlines():
        print(f"  {line}")
    err("--- stderr (last 40 lines) ---")
    for line in (result.stderr or "").strip().splitlines()[-40:]:
        print(f"  {line}")
    err("--------------")
    return False


def run_streaming(label: str, cmd: list, cwd: Path = EMPIRE_HOME, env: dict = None) -> bool:
    """Run cmd with live stdout/stderr — for long downloads or Ansible."""
    info(f"Running: {' '.join(str(c) for c in cmd)}")
    merged_env = {**os.environ}
    if env:
        merged_env.update(env)
    result = subprocess.run(cmd, cwd=str(cwd), env=merged_env)
    if result.returncode == 0:
        log(f"{label} — PASS")
        return True
    err(f"{label} — FAIL (exit {result.returncode})")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Prompt helpers
# ─────────────────────────────────────────────────────────────────────────────

def prompt_choice(question: str, choices: list, default: int = 1) -> str:
    print(f"\n  {BLD}{question}{NC}")
    for i, (val, desc) in enumerate(choices, 1):
        marker = f"{G}*{NC}" if i == default else " "
        print(f"    {marker}{i}) {val:<14} {DIM}{desc}{NC}")
    while True:
        raw = input(f"    Choice [1-{len(choices)}] (default {default}): ").strip()
        if raw == "":
            return choices[default - 1][0]
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1][0]
        warn(f"Enter a number 1–{len(choices)}.")


def prompt_input(question: str, default: str) -> str:
    print(f"\n  {BLD}{question}{NC} [{DIM}{default}{NC}]: ", end="")
    raw = input().strip()
    return raw if raw else default


def prompt_confirm(question: str, default: bool = True) -> bool:
    hint = f"{G}Y{NC}/n" if default else f"y/{R}N{NC}"
    print(f"\n  {BLD}{question}{NC} [{hint}]: ", end="")
    raw = input().strip().lower()
    if raw == "":
        return default
    return raw in ("y", "yes")


def pause():
    if IS_TTY:
        input(f"\n  {DIM}Press Enter to continue...{NC}")


# ─────────────────────────────────────────────────────────────────────────────
# Banner + status bar
# ─────────────────────────────────────────────────────────────────────────────

_BANNER_W = 62

def _box_line(text: str) -> str:
    pad = _BANNER_W - len(text)
    return "║" + text + " " * max(0, pad) + "║"

def print_banner():
    print(f"\n{C}{BLD}")
    print("╔" + "═" * _BANNER_W + "╗")
    print(_box_line("   EMPIRE  ·  empire Mifflin Vulnerable Active Directory"))
    print(_box_line("   CTF / Red-Team Lab  ·  deploy.py"))
    print("╚" + "═" * _BANNER_W + "╝")
    print(NC, end="")


def cfg_summary_line(cfg: dict) -> str:
    p    = cfg["profile"]
    meta = PROFILES[p]
    return (
        f"{DIM}profile:{NC}{BLD}{p}{NC}  "
        f"{DIM}provider:{NC}{BLD}{cfg['provider']}{NC}  "
        f"{DIM}VMs:{NC}{BLD}{meta['vms']}{NC}  "
        f"{DIM}RAM budget:{NC}{BLD}{cfg['ram_budget']} GB{NC}  "
        f"{DIM}flags:{NC}{BLD}{cfg['flag_mode']}{NC}  "
        f"{DIM}attacker:{NC}{BLD}{cfg['attacker_ip']}{NC}"
    )


def vm_status_quick(cfg: dict) -> str:
    """One-liner: how many .installed markers exist under vms/."""
    try:
        vms_dir = Path(cfg["disk_path"])
        installed = list(vms_dir.glob("*.installed"))
        running   = list(vms_dir.glob("*.pid"))
        return f"{G}{len(installed)} installed{NC}  {G}{len(running)} running{NC}"
    except Exception:
        return f"{DIM}(vms dir not found){NC}"


# ─────────────────────────────────────────────────────────────────────────────
# Phase functions
# ─────────────────────────────────────────────────────────────────────────────

_MIN_ISO_MB = 200  # anything under 200 MB is a corrupt/partial download

def _download_file(label: str, url: str, dest: Path, min_mb: int = _MIN_ISO_MB) -> bool:
    """Download url → dest. IPv4-only, 5 retries, resume support. wget preferred."""
    if dest.exists():
        size_mb = dest.stat().st_size // (1024 ** 2)
        if size_mb >= min_mb:
            log(f"{dest.name} already present ({size_mb} MB) — skipping")
            return True
        warn(f"{dest.name} exists but only {size_mb} MB (need ≥{min_mb} MB) — re-downloading")

    info(f"Downloading {label} → {dest}")

    if cmd_in_path("wget"):
        return run_streaming(
            f"Download {label}",
            [
                "wget",
                "-4",                  # IPv4 only — avoids IPv6 CDN resets
                "--tries=5",           # retry up to 5 times
                "--retry-connrefused",
                "--continue",          # resume partial download
                "--show-progress",
                "-q",
                "-O", str(dest),
                url,
            ],
        )

    if cmd_in_path("curl"):
        return run_streaming(
            f"Download {label}",
            [
                "curl",
                "-4",                  # IPv4 only
                "--retry", "5",
                "--retry-connrefused",
                "-L",
                "--continue-at", "-",  # resume partial download
                "--progress-bar",
                "-o", str(dest),
                url,
            ],
        )

    err("Neither wget nor curl found.")
    err(f"Download manually: {url}")
    err(f"Place at: {dest}")
    return False


def phase_download_media(cfg: dict) -> bool:
    step("Phase 0: Download required media")
    media_dir = EMPIRE_HOME / "media"
    media_dir.mkdir(parents=True, exist_ok=True)

    ok = True

    # virtio-win drivers (always needed for QEMU)
    ok = _download_file("virtio-win.iso", VIRTIO_WIN_URL,
                        media_dir / "virtio-win.iso") and ok

    # Windows ISOs — packer reads local file:// paths, never hits network during build
    for iso in WINDOWS_ISOS:
        ok = _download_file(iso["filename"], iso["url"],
                            media_dir / iso["filename"]) and ok

    # Ubuntu cloud image for the Linux member (mandalore). Prebuilt — no packer.
    # ~700 MB; resumable; skipped if already present and ≥ min_mb.
    ok = _download_file(
        UBUNTU_CLOUD_IMG["filename"], UBUNTU_CLOUD_IMG["url"],
        media_dir / UBUNTU_CLOUD_IMG["filename"],
        min_mb=UBUNTU_CLOUD_IMG["min_mb"],
    ) and ok

    return ok


# Output subdirectory produced by each template, keyed by (template, provider)
PACKER_OUTPUT_DIRS = {
    ("windows-server-2022.pkr.hcl", "qemu"):        "server2022-qemu",
    ("windows-server-2022.pkr.hcl", "virtualbox"):  "server2022-virtualbox",
    ("windows-server-2019.pkr.hcl", "qemu"):        "server2019-qemu",
    ("windows-server-2019.pkr.hcl", "virtualbox"):  "server2019-virtualbox",
    ("windows-10.pkr.hcl",          "qemu"):        "win10-qemu",
    ("windows-10.pkr.hcl",          "virtualbox"):  "win10-virtualbox",
}


# A real Windows base image is multi-GB. Anything smaller is a partial/aborted
# build (qemu pre-allocates a ~200 KB qcow2 shell before the OS installs).
_MIN_IMAGE_MB = 1000


def _packer_output_dir(tpl: str, provider: str):
    subdir = PACKER_OUTPUT_DIRS.get((tpl, provider))
    if not subdir:
        return None
    return EMPIRE_HOME / "packer-output" / subdir


def _packer_output_built(tpl: str, provider: str) -> bool:
    """True only if a fully-built image (≥ _MIN_IMAGE_MB) is present."""
    out_dir = _packer_output_dir(tpl, provider)
    if not out_dir or not out_dir.exists():
        return False
    ext = "*.qcow2" if provider == "qemu" else "*.ova"
    for f in out_dir.glob(ext):
        if f.stat().st_size >= _MIN_IMAGE_MB * 1024 * 1024:
            return True
    return False


# Ordered packer-output substrings → human-readable build stage.
_BUILD_STAGES = [
    ("Retrieving ISO",        "preparing install media"),
    ("Starting VM",           "booting Windows installer"),
    ("Typing the boot",       "booting Windows installer"),
    ("Waiting for WinRM",     "installing Windows (long step — wait for WinRM)"),
    ("Connected to WinRM",    "WinRM up — connecting"),
    ("Provisioning with",     "running provisioners"),
    ("Gracefully halting",    "shutting down VM"),
    ("Converting hard drive", "finalizing qcow2 image"),
    ("Converting",            "finalizing image"),
]


class BuildMonitor:
    """Runs one packer build via Popen, tees output to a log file, and prints a
    live status line: elapsed · stage · disk size (proof-of-life) · VNC port."""

    def __init__(self, tpl: str, out_dir: Path, log_path: Path, inline: bool = True):
        self.tpl      = tpl
        self.name     = tpl.replace(".pkr.hcl", "")
        self.vm_hint  = self.name + "-base"          # qemu -name <hint>.qcow2
        self.out_dir  = out_dir
        self.log_path = log_path
        self.inline   = inline                       # False in parallel mode
        self.stage    = "starting"
        self.vnc      = None
        self.start    = time.time()
        self._lock    = threading.Lock()
        self._done    = threading.Event()

    def _reader(self, proc, log_fh):
        import re
        vnc_re = re.compile(r"VNC[^\d]*(127\.0\.0\.1:\d+)")
        for raw in iter(proc.stdout.readline, ""):
            log_fh.write(raw)
            log_fh.flush()
            line = raw.rstrip("\n")
            for key, label in _BUILD_STAGES:
                if key in line:
                    with self._lock:
                        self.stage = label
                    break
            m = vnc_re.search(line)
            if m:
                with self._lock:
                    self.vnc = m.group(1)
        self._done.set()

    def _qcow_size(self) -> int:
        try:
            sizes = [f.stat().st_size for f in self.out_dir.glob("*.qcow2")]
            return max(sizes) if sizes else 0
        except Exception:
            return 0

    def _find_vnc_via_ps(self):
        """Fallback: scan the qemu child process for its -vnc display."""
        try:
            out = subprocess.check_output(["ps", "-eo", "args"], text=True)
        except Exception:
            return None
        for ln in out.splitlines():
            if "qemu-system" in ln and self.vm_hint in ln and "-vnc" in ln:
                parts = ln.split()
                try:
                    disp = parts[parts.index("-vnc") + 1]      # e.g. 127.0.0.1:52
                    host, _, d = disp.rpartition(":")
                    return f"{host or '127.0.0.1'}:{5900 + int(d)}"
                except (ValueError, IndexError):
                    return None
        return None

    def run(self, cmd, cwd, env) -> bool:
        log_fh = open(self.log_path, "w", buffering=1)
        proc = subprocess.Popen(
            cmd, cwd=str(cwd), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        rt = threading.Thread(target=self._reader, args=(proc, log_fh), daemon=True)
        rt.start()

        last_size = 0
        flat_ticks = 0
        hb = 0
        while not self._done.wait(timeout=6):
            with self._lock:
                stage, vnc = self.stage, self.vnc
            if not vnc:
                vnc = self._find_vnc_via_ps()
                if vnc:
                    with self._lock:
                        self.vnc = vnc
            size    = self._qcow_size()
            elapsed = _human_time(time.time() - self.start)
            grow    = f"{G}▲{NC}" if size > last_size else f"{DIM}·{NC}"
            # Stuck detection: disk flat for >10 min while supposedly installing
            if size == last_size and size > 0:
                flat_ticks += 1
            else:
                flat_ticks = 0
            stuck = f"  {Y}(disk flat {_human_time(flat_ticks*6)} — check VNC){NC}" if flat_ticks >= 100 else ""
            vnc_s = f" · {C}VNC {vnc}{NC}" if vnc else ""
            line  = (f"  {C}{BLD}[{self.name}]{NC} {elapsed} · {stage} · "
                     f"disk {_human_size(size)} {grow}{vnc_s}{stuck}")
            if IS_TTY and self.inline:
                print("\r\033[K" + line, end="", flush=True)
            else:
                hb += 1
                if hb % 5 == 0:   # ~every 30s in non-TTY / parallel mode
                    print(line)
            last_size = size

        proc.wait()
        rt.join(timeout=2)
        log_fh.close()
        if IS_TTY and self.inline:
            print()  # close off the \r status line
        return proc.returncode == 0


def phase_packer_build(cfg: dict) -> bool:
    step("Phase 1: Packer — building base images")
    # All-fresh model (qemu): each Windows VM installs from the ISO directly in
    # phase 3, so every VM gets a unique machine SID and no shared base image is
    # needed. Skip the packer build entirely. (virtualbox still uses base images.)
    if cfg["provider"] == "qemu":
        log("Skipped — all-fresh: Windows VMs install from ISO in phase 3 (unique SID, no base image).")
        return True
    packer_dir = EMPIRE_HOME / "packer"
    only_flag  = "*.qemu.*" if cfg["provider"] == "qemu" else "*.virtualbox-iso.*"
    log_dir    = EMPIRE_HOME / "packer-output" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    results    = {}

    info(f"Live build logs: {log_dir}/<template>.log  (tail -f to watch full output)")

    # Install required plugins (qemu / virtualbox) before building — otherwise
    # `packer build` fails with "Missing plugins / Did you run packer init?".
    # Use `packer plugins install` (NOT `packer init`): init parses the whole
    # template dir and collides on the 3 templates' shared variables/locals,
    # and it installs into the running user's home (matters under sudo).
    info("Installing packer plugins (qemu, virtualbox)...")
    for _plugin in ("github.com/hashicorp/qemu", "github.com/hashicorp/virtualbox"):
        _r = subprocess.run(["packer", "plugins", "install", _plugin],
                            cwd=str(packer_dir), capture_output=True, text=True)
        if _r.returncode == 0:
            log(f"plugin ready: {_plugin.split('/')[-1]}")
        else:
            warn(f"plugin install {_plugin} exit {_r.returncode}: {(_r.stderr or _r.stdout).strip()[:200]}")

    def build_template(tpl: str):
        provider = cfg["provider"]
        out_dir  = _packer_output_dir(tpl, provider)

        # Skip only if a fully-built image already exists (idempotent re-runs).
        if _packer_output_built(tpl, provider):
            log(f"packer build {tpl} — skipped ({out_dir.name} already built)")
            results[tpl] = True
            return

        # Remove any partial/aborted output dir — packer refuses to build if the
        # output directory already exists, even when empty/incomplete.
        if out_dir and out_dir.exists():
            warn(f"packer {tpl} — removing partial output {out_dir.name} before rebuild")
            shutil.rmtree(out_dir, ignore_errors=True)

        tpl_path = packer_dir / tpl
        cmd      = ["packer", "build", f"-only={only_flag}", str(tpl_path)]
        log_path = log_dir / f"{tpl.replace('.pkr.hcl', '')}.log"
        info(f"Starting packer build {tpl}  ({log_path.name})")
        merged_env = {**os.environ, "PACKER_LOG": "0"}

        mon = BuildMonitor(tpl, out_dir, log_path, inline=not _PARALLEL_BUILD)
        ok  = mon.run(cmd, cwd=packer_dir, env=merged_env)
        results[tpl] = ok
        if ok:
            log(f"packer build {tpl} — PASS ({_human_time(time.time() - mon.start)})")
        else:
            err(f"packer build {tpl} — FAIL — see {log_path}")
            try:
                tail = log_path.read_text().strip().splitlines()[-30:]
                err(f"--- {tpl} last 30 log lines ---")
                for line in tail:
                    print(f"  {line}")
            except Exception:
                pass

    # Use physical core count (not HT threads) to decide parallel vs sequential.
    # Parallel only if host has ≥ (num_templates × packer_cpus) physical cores.
    try:
        phys_cores = int(subprocess.check_output(
            ["grep", "-c", "^core id", "/proc/cpuinfo"], text=True
        ).strip()) or 1
        # De-duplicate: /proc/cpuinfo lists each core once per package
        phys_cores = max(
            len(set(
                line.split(":")[1].strip()
                for line in open("/proc/cpuinfo")
                if line.startswith("core id")
            )),
            1,
        )
    except Exception:
        import multiprocessing
        phys_cores = multiprocessing.cpu_count() // 2 or 1

    needed = len(PACKER_TEMPLATES) * 2  # 2 vCPUs per template
    # Require host headroom (+2 cores) so the host stays responsive — building
    # N templates in parallel pins N*2 vCPUs; on a 4-core host that's 100% and
    # the machine hangs. Parallel only when cores comfortably exceed the load.
    _PARALLEL_BUILD = phys_cores >= needed + 2
    if _PARALLEL_BUILD:
        info(f"Host has {phys_cores} physical cores — building {len(PACKER_TEMPLATES)} templates in parallel")
        threads = [threading.Thread(target=build_template, args=(tpl,)) for tpl in PACKER_TEMPLATES]
        for t in threads: t.start()
        for t in threads: t.join()
    else:
        info(f"Host has {phys_cores} physical cores (need {needed}) — building sequentially to avoid vCPU thrash")
        for tpl in PACKER_TEMPLATES:
            build_template(tpl)

    all_ok = all(results.values())
    if not all_ok:
        failed = [tpl for tpl, ok in results.items() if not ok]
        err(f"Packer build failed for: {', '.join(failed)}")
    return all_ok


def phase_network_setup(cfg: dict) -> bool:
    step("Phase 2: Network setup")
    if cfg["provider"] != "qemu":
        info("Skipping network setup (not QEMU provider).")
        return True
    net_script = EMPIRE_HOME / "providers" / "qemu" / "network-setup.sh"
    if not net_script.exists():
        err(f"Network setup script not found: {net_script}")
        return False
    return run_cmd("Network setup", ["bash", str(net_script), "setup"])


def phase_vm_create(cfg: dict) -> bool:
    step("Phase 3: VM creation")
    vm_script = EMPIRE_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM create script not found: {vm_script}")
        return False
    return run_cmd(
        "VM create",
        ["bash", str(vm_script), "create", "--profile", cfg["profile"]],
        env={"CFG_DEPLOY_MODE": cfg["profile"], "CFG_DISK_PATH": cfg["disk_path"]},
    )


# ── All-fresh VM readiness map ────────────────────────────────────────────────
# vm name (matches vms/<name>.qcow2) -> (static IP, readiness port, VNC port).
# Windows VMs come up on WinRM 5985; the Linux member on SSH 22.
_VM_READY = {
    "coruscant":     ("10.10.0.10",  5985, 5901),
    "deathstar":   ("10.10.0.11",  5985, 5902),
    "endor":     ("10.10.0.12",  5985, 5903),
    "scarif":   ("10.10.0.13",  5985, 5904),
    "kamino":    ("10.10.0.14",  5985, 5905),
    "tatooine":     ("10.10.0.100", 5985, 5906),
    "yavin4":  ("10.10.20.10", 5985, 5907),
    "neimoidia": ("10.10.30.10", 5985, 5908),
    "mandalore":  ("10.10.0.15",  22,   5909),
}
_PROFILE_VMS = {
    "full":      ["coruscant", "deathstar", "endor", "scarif", "kamino", "tatooine", "yavin4", "neimoidia", "mandalore"],
    "minimal":   ["coruscant", "deathstar", "endor", "scarif", "kamino", "tatooine", "mandalore"],
    "single-dc": ["coruscant"],
}


def _port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def phase_wait_winrm(cfg: dict) -> bool:
    step("Phase 4: Installing VMs — live progress until WinRM/SSH answers")
    profile  = cfg["profile"]
    vms      = _PROFILE_VMS.get(profile, _PROFILE_VMS["full"])
    disk_dir = Path(cfg.get("disk_path") or (EMPIRE_HOME / "vms"))
    max_min  = int(os.environ.get("MAX_WAIT_MINUTES", "60"))
    deadline = time.time() + max_min * 60
    start    = time.time()
    poll     = 15

    info(f"All-fresh: each Windows VM installs from ISO (~15-20 min, parallel); "
         f"mandalore boots cloud-init. Max wait {max_min} min.")

    ready: set = set()
    last_size: dict = {}
    flat: dict = {v: 0 for v in vms}
    drawn = 0

    while True:
        rows = []
        for vm in vms:
            ip, port, vnc = _VM_READY.get(vm, ("?", 5985, 0))
            disk = disk_dir / f"{vm}.qcow2"
            try:
                size = disk.stat().st_size if disk.exists() else 0
            except OSError:
                size = 0

            if vm not in ready and ip != "?" and _port_open(ip, port):
                ready.add(vm)
                try:
                    (disk_dir / f"{vm}.installed").touch()
                except OSError:
                    pass

            if vm in ready:
                svc = "SSH" if port == 22 else "WinRM"
                rows.append(f"  {G}{vm:<9}{NC} {G}● UP ({svc}){NC}  {DIM}{ip}{NC}")
            else:
                # disk growth = install proof-of-life; flag if flat too long
                if size == last_size.get(vm, -1):
                    flat[vm] += 1
                else:
                    flat[vm] = 0
                last_size[vm] = size
                gb   = size / 1e9
                note = f" {Y}(disk flat — check VNC :{vnc}){NC}" if flat[vm] >= 8 else ""
                rows.append(f"  {vm:<9} {C}○ installing{NC} {gb:5.1f} GB  "
                            f"{DIM}{ip} · VNC :{vnc}{NC}{note}")

        elapsed = _human_time(time.time() - start)
        header  = f"{B}[*]{NC} {BLD}{len(ready)}/{len(vms)}{NC} ready · elapsed {elapsed}"
        block   = "\n".join([header] + rows)

        if drawn:
            sys.stdout.write(f"\033[{drawn}A")
        sys.stdout.write("\033[J" + block + "\n")
        sys.stdout.flush()
        drawn = len(rows) + 1

        if len(ready) >= len(vms):
            log(f"All {len(vms)} VM(s) reachable in {_human_time(time.time() - start)}.")
            return True
        if time.time() >= deadline:
            warn(f"Timeout after {max_min} min — {len(ready)}/{len(vms)} ready. "
                 f"Stamping markers so Ansible can still attempt the rest.")
            for vm in vms:
                try:
                    (disk_dir / f"{vm}.installed").touch()
                except OSError:
                    pass
            return True
        time.sleep(poll)


def phase_ansible(cfg: dict) -> bool:
    step("Phase 5: Ansible provisioning")
    ansible_dir = EMPIRE_HOME / "ansible"
    inventory   = ansible_dir / "inventory.yml"
    playbook    = ansible_dir / "playbooks" / "site.yml"

    if not inventory.exists():
        err(f"Ansible inventory not found: {inventory}")
        return False

    cmd = [
        "ansible-playbook",
        "-i", str(inventory),
        str(playbook),
        "-e", (
            f"attacker_ip={cfg['attacker_ip']} "
            f"flag_mode={cfg['flag_mode']} "
            f"deploy_profile={cfg['profile']}"
        ),
    ]
    return run_streaming("Ansible provisioning", cmd, cwd=ansible_dir)


def phase_verify(cfg: dict) -> bool:
    step("Phase 6: Vulnerability verification")
    verify_script = EMPIRE_HOME / "scripts" / "verify_vulns.py"
    if not verify_script.exists():
        warn(f"Verify script not found at {verify_script} — skipping.")
        return True
    return run_cmd(
        "Verify vulns",
        [sys.executable, str(verify_script), "--profile", cfg["profile"]],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline definition
# ─────────────────────────────────────────────────────────────────────────────

PHASES = [
    (0, "Download media", phase_download_media, lambda cfg: cfg["base_action"] == "build" and cfg["provider"] == "qemu"),
    (1, "Packer build",   phase_packer_build,   lambda cfg: cfg["base_action"] == "build"),
    (2, "Network setup",  phase_network_setup,  lambda cfg: cfg["provider"] == "qemu"),
    (3, "VM create",      phase_vm_create,      lambda cfg: True),
    (4, "Wait WinRM",     phase_wait_winrm,     lambda cfg: True),
    (5, "Ansible",        phase_ansible,        lambda cfg: True),
    (6, "Verify vulns",   phase_verify,         lambda cfg: True),
]


def run_pipeline(cfg: dict, start_phase: int = 0) -> dict:
    results = {}
    for num, name, fn, condition in PHASES:
        if num < start_phase:
            info(f"Skipping phase {num} ({name}) — before start phase {start_phase}.")
            continue
        if not condition(cfg):
            info(f"Skipping phase {num} ({name}) — not applicable for this config.")
            continue
        ok = fn(cfg)
        results[f"Phase {num}: {name}"] = ok
        if not ok:
            err(f"Pipeline aborted at phase {num} ({name}).")
            for rnum, rname, _, _ in PHASES:
                if rnum > num:
                    results[f"Phase {rnum}: {rname}"] = False
            break
    return results


def print_pipeline_report(cfg: dict, phase_results: dict):
    print(f"\n{G}{BLD}{'─' * 62}{NC}")
    print(f"{G}{BLD}   Deployment Report{NC}")
    print(f"{G}{BLD}{'─' * 62}{NC}")
    for phase_name, passed in phase_results.items():
        mark = f"{G}PASS{NC}" if passed else f"{R}FAIL{NC}"
        print(f"  {phase_name:<40} {mark}")
    print()
    all_ok = all(phase_results.values())
    if all_ok:
        print(f"  {G}{BLD}All phases completed successfully.{NC}")
        print()
        print("  Next steps:")
        print("    1. Check PLAN.md for topology and attack paths.")
        print(f"    2. python3 {EMPIRE_HOME}/chains/validator.py \\")
        print(f"         --dc-ip 10.10.0.10 --domain empire.local \\")
        print(f"         --attacker-ip {cfg['attacker_ip']}")
        if cfg["flag_mode"] == "ctf":
            print("    3. Flags require exploitation — see PLAN.md.")
        else:
            print("    3. Flags visible at C:\\Flags\\ on each target (training mode).")
    else:
        failed = [n for n, ok in phase_results.items() if not ok]
        print(f"  {R}{BLD}Incomplete — failed: {', '.join(failed)}{NC}")
        print()
        print("  Tip: use --phase <n> to restart from a specific phase.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Preflight checks
# ─────────────────────────────────────────────────────────────────────────────

def preflight_checks(cfg: dict) -> bool:
    ok           = True
    p            = cfg["profile"]
    profile_meta = PROFILES[p]

    step("Preflight checks")

    required_ram = profile_meta["ram_gb"]
    if cfg["ram_budget"] < required_ram:
        warn(f"RAM budget ({cfg['ram_budget']} GB) < profile requirement ({required_ram} GB). OOM possible.")
    else:
        log(f"RAM OK ({cfg['ram_budget']} GB >= {required_ram} GB required)")

    free_disk = detect_free_disk_gb(cfg["disk_path"])
    if free_disk < 130:
        warn(f"Only {free_disk} GB free at {cfg['disk_path']} — recommend ≥ 130 GB.")
    else:
        log(f"Disk OK ({free_disk} GB free at {cfg['disk_path']})")

    if cfg["provider"] == "qemu":
        if not os.path.exists("/dev/kvm"):
            warn("/dev/kvm not found — QEMU will run in software emulation (very slow).")
        else:
            log("KVM available (/dev/kvm)")
    elif cfg["provider"] == "virtualbox":
        if not cmd_in_path("VBoxManage"):
            err("VBoxManage not in PATH — install VirtualBox first.")
            ok = False
        else:
            log("VBoxManage found")

    if cfg["base_action"] == "build":
        if not cmd_in_path("packer"):
            err("packer not in PATH — required for base image build.")
            ok = False
        else:
            log("packer found")

    if not cmd_in_path("ansible-playbook"):
        err("ansible-playbook not in PATH — required for provisioning.")
        ok = False
    else:
        log("ansible-playbook found")
        # pywinrm must be importable by the SAME python ansible-playbook uses,
        # or every Windows task fails with "No module named 'winrm'".
        ap = shutil.which("ansible-playbook")
        ansible_py = None
        try:
            with open(ap) as fh:
                shebang = fh.readline().strip()
            if shebang.startswith("#!"):
                ansible_py = shebang[2:].split()[0]
        except Exception:
            pass
        ansible_py = ansible_py or sys.executable
        rc = subprocess.run([ansible_py, "-c", "import winrm"],
                            capture_output=True).returncode
        if rc != 0:
            err(f"pywinrm not importable by {ansible_py} — Windows WinRM tasks will fail.")
            err("  Arch:   sudo pacman -S --needed python-pywinrm")
            err("  Debian: sudo apt install python3-winrm   (or pipx/pip pywinrm)")
            err("  pip:    pip install pywinrm   (use --break-system-packages if needed)")
            ok = False
        else:
            log("pywinrm available (WinRM ready)")

    py_ver = sys.version_info
    log(f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro}")

    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Menu actions
# ─────────────────────────────────────────────────────────────────────────────

def action_deploy(cfg: dict, start_phase: int = 0):
    """Full pipeline from start_phase."""
    print(f"\n  {BLD}Deploy{NC}  {DIM}(profile: {cfg['profile']}, provider: {cfg['provider']}){NC}")
    checks_ok = preflight_checks(cfg)
    if not checks_ok:
        warn("Preflight issues detected.")
    if not prompt_confirm("Proceed with deployment?", default=True):
        info("Aborted.")
        return
    Path(cfg["disk_path"]).mkdir(parents=True, exist_ok=True)
    results = run_pipeline(cfg, start_phase=start_phase)
    print_pipeline_report(cfg, results)


def action_build(cfg: dict):
    """Packer build only (phases 0–1)."""
    print(f"\n  {BLD}Build base images{NC}  {DIM}(phases 0–1){NC}")
    if not cmd_in_path("packer"):
        err("packer not in PATH.")
        return
    if not prompt_confirm("Run packer build? (~45–70 min first time)", default=True):
        info("Aborted.")
        return
    ok0 = phase_download_media(cfg) if cfg["provider"] == "qemu" else True
    if ok0:
        phase_packer_build(cfg)


def action_provision(cfg: dict):
    """Ansible only (phase 5)."""
    print(f"\n  {BLD}Provision (Ansible){NC}  {DIM}(VMs must already be up and WinRM-ready){NC}")
    if not prompt_confirm("Run Ansible provisioning?", default=True):
        info("Aborted.")
        return
    phase_ansible(cfg)


def action_start(cfg: dict):
    """Start existing VMs."""
    step("Start VMs")
    vm_script = EMPIRE_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return
    run_cmd("Start VMs", ["bash", str(vm_script), "start", "--profile", cfg["profile"]],
            env={"CFG_DEPLOY_MODE": cfg["profile"], "CFG_DISK_PATH": cfg["disk_path"]})


def action_stop(cfg: dict):
    """Stop all running VMs."""
    step("Stop VMs")
    vm_script = EMPIRE_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return
    if not prompt_confirm("Stop all running VMs?", default=False):
        info("Aborted.")
        return
    run_cmd("Stop VMs", ["bash", str(vm_script), "stop"],
            env={"CFG_DISK_PATH": cfg["disk_path"]})


def action_destroy(cfg: dict):
    """Destroy VMs + networks."""
    step("Destroy")
    vm_script = EMPIRE_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return
    print(f"  {R}{BLD}This will delete all VMs and networks.{NC}")
    if not prompt_confirm("Are you sure?", default=False):
        info("Aborted.")
        return
    vm_ok = run_cmd("VM destroy", ["bash", str(vm_script), "destroy"])
    if cfg["provider"] == "qemu":
        net_script = EMPIRE_HOME / "providers" / "qemu" / "network-setup.sh"
        if net_script.exists():
            run_cmd("Network destroy", ["bash", str(net_script), "destroy"])
    if vm_ok:
        log("Destroy complete.")


def action_status(cfg: dict):
    """Show VM and network status."""
    step("Status")
    vms_dir = Path(cfg["disk_path"])

    print(f"\n  {BLD}Lab config:{NC}")
    print(f"    {cfg_summary_line(cfg)}")

    print(f"\n  {BLD}Media:{NC}")
    virtio = EMPIRE_HOME / "media" / "virtio-win.iso"
    if virtio.exists():
        sz = virtio.stat().st_size // (1024 ** 2)
        log(f"virtio-win.iso present ({sz} MB)")
    else:
        warn("virtio-win.iso missing — run Deploy or Build to download.")

    print(f"\n  {BLD}VMs ({vms_dir}):{NC}")
    if not vms_dir.exists():
        info("  vms/ directory does not exist yet.")
    else:
        installed = sorted(vms_dir.glob("*.installed"))
        pids      = {p.stem.replace(".pid","").replace(".installed","") for p in vms_dir.glob("*.pid")}
        if not installed:
            info("  No installed VMs found.")
        # Map running VM name → VNC port by scanning qemu processes once.
        vnc_map = {}
        try:
            ps_out = subprocess.check_output(["ps", "-eo", "args"], text=True)
            for ln in ps_out.splitlines():
                if "qemu-system" not in ln or "-vnc" not in ln:
                    continue
                parts = ln.split()
                try:
                    nm   = parts[parts.index("-name") + 1] if "-name" in parts else ""
                    disp = parts[parts.index("-vnc") + 1]
                    host, _, d = disp.rpartition(":")
                    vnc_map[nm.replace(".qcow2", "")] = f"{host or '127.0.0.1'}:{5900 + int(d)}"
                except (ValueError, IndexError):
                    pass
        except Exception:
            pass
        for marker in installed:
            name  = marker.stem.replace(".installed", "")
            run   = name in pids
            state = f"{G}running{NC}" if run else f"{Y}stopped{NC}"
            vnc   = vnc_map.get(name) or vnc_map.get(f"{name}-base")
            vnc_s = f"  {C}VNC {vnc}{NC}" if (run and vnc) else ""
            log(f"  {name:<30} {state}{vnc_s}")

    if cfg["provider"] == "qemu":
        print(f"\n  {BLD}Networks:{NC}")
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        bridges = [l.split(":")[1].strip() for l in result.stdout.splitlines()
                   if "empire" in l and ":" in l]
        if bridges:
            for b in bridges:
                log(f"  bridge: {b}")
        else:
            warn("  No empire-* bridges found — network not set up.")

    print(f"\n  {BLD}Packer outputs:{NC}")
    packer_out = EMPIRE_HOME / "packer-output"
    if packer_out.exists():
        outputs = [d for d in packer_out.iterdir() if d.is_dir() and d.name != "logs"]
        if outputs:
            for d in sorted(outputs, key=lambda x: x.name):
                imgs = list(d.glob("*.qcow2")) + list(d.glob("*.ova"))
                if imgs:
                    biggest = max(imgs, key=lambda f: f.stat().st_size)
                    sz = biggest.stat().st_size
                    if sz >= _MIN_IMAGE_MB * 1024 * 1024:
                        log(f"  {d.name:<26} {G}built{NC}  {_human_size(sz)}")
                    else:
                        warn(f"  {d.name:<26} partial  {_human_size(sz)} (will rebuild)")
                else:
                    warn(f"  {d.name:<26} empty (will rebuild)")
        else:
            info("  packer-output/ has no images — not built yet.")
        log_dir = packer_out / "logs"
        if log_dir.exists() and any(log_dir.iterdir()):
            print(f"    {DIM}build logs: {log_dir}/*.log  (tail -f to watch){NC}")
    else:
        info("  packer-output/ does not exist — images not built yet.")


def action_verify(cfg: dict):
    """Run vulnerability verification."""
    phase_verify(cfg)


def action_settings(cfg: dict):
    """Interactively change lab settings."""
    print(f"\n  {BLD}Settings{NC}  {DIM}(current config shown in brackets){NC}")

    cfg["profile"] = prompt_choice(
        "Lab profile:",
        [
            ("full",      PROFILES["full"]["label"]),
            ("minimal",   PROFILES["minimal"]["label"]),
            ("single-dc", PROFILES["single-dc"]["label"]),
        ],
        default=list(PROFILES.keys()).index(cfg["profile"]) + 1,
    )

    cfg["provider"] = prompt_choice(
        "Provider:",
        [
            ("qemu",       "QEMU/KVM (Linux host)"),
            ("virtualbox", "VirtualBox (any host)"),
        ],
        default=1 if cfg["provider"] == "qemu" else 2,
    )

    host_ram = detect_ram_gb()
    ram_raw  = prompt_input(
        f"RAM budget (GB) [host has {host_ram} GB]",
        default=str(cfg["ram_budget"]),
    )
    try:
        cfg["ram_budget"] = float(ram_raw)
    except ValueError:
        warn(f"Could not parse '{ram_raw}' — keeping {cfg['ram_budget']} GB.")

    cfg["disk_path"] = prompt_input("Disk path for VMs", default=cfg["disk_path"])

    cfg["attacker_ip"] = prompt_input(
        "Attacker IP (your Kali/BlackArch box)",
        default=cfg["attacker_ip"],
    )

    cfg["base_action"] = prompt_choice(
        "Packer action:",
        [
            ("build", "run Packer now (~45–70 min first time)"),
            ("skip",  "images already built — skip packer"),
        ],
        default=1 if cfg["base_action"] == "build" else 2,
    )

    cfg["flag_mode"] = prompt_choice(
        "Flag mode:",
        [
            ("ctf",      "flags hidden — require exploitation"),
            ("training", "flags visible at C:\\Flags\\ (walkthrough mode)"),
        ],
        default=1 if cfg["flag_mode"] == "ctf" else 2,
    )

    print(f"\n  {G}Settings saved.{NC}")
    print(f"  {cfg_summary_line(cfg)}")


def action_ansible_tags(cfg: dict, preset: str = None):
    """Run Ansible with specific tags. `preset` skips the prompt (GOAD-style)."""
    print(f"\n  {BLD}Run Ansible with tags{NC}")
    if preset:
        tag_input = preset
    else:
        tag_input = prompt_input("Ansible tag(s) (comma-separated, e.g. kerberos,adcs)", default="all")
        if not prompt_confirm(f"Run ansible-playbook --tags '{tag_input}'?", default=True):
            info("Aborted.")
            return

    ansible_dir = EMPIRE_HOME / "ansible"
    inventory   = ansible_dir / "inventory.yml"
    playbook    = ansible_dir / "playbooks" / "site.yml"

    if not inventory.exists():
        err(f"Ansible inventory not found: {inventory}")
        return

    cmd = [
        "ansible-playbook",
        "-i", str(inventory),
        str(playbook),
        "--tags", tag_input,
        "-e", (
            f"attacker_ip={cfg['attacker_ip']} "
            f"flag_mode={cfg['flag_mode']} "
            f"deploy_profile={cfg['profile']}"
        ),
    ]
    run_streaming("Ansible (tagged)", cmd, cwd=ansible_dir)


def action_resume_phase(cfg: dict):
    """Restart pipeline from a specific phase."""
    print(f"\n  {BLD}Resume from phase{NC}")
    print(f"    0 = download media")
    print(f"    1 = packer build")
    print(f"    2 = network setup")
    print(f"    3 = VM create")
    print(f"    4 = wait WinRM")
    print(f"    5 = Ansible")
    print(f"    6 = verify")
    raw = prompt_input("Start from phase", default="5")
    try:
        phase_num = int(raw)
    except ValueError:
        warn(f"Invalid phase number '{raw}'.")
        return
    if phase_num not in range(7):
        warn("Phase must be 0–6.")
        return
    action_deploy(cfg, start_phase=phase_num)


# ─────────────────────────────────────────────────────────────────────────────
# Main menu
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# GOAD-style menu rendering (dotted-leader entries, grouped sections)
# ─────────────────────────────────────────────────────────────────────────────

def print_logo():
    print(f"\n{C}{BLD}")
    print(r"   ____  _    _ _   _ _____  ______ _____  ")
    print(r"  |  _ \| |  | | \ | |  __ \|  ____|  __ \ ")
    print(r"  | |  | | |  | |  \| | |  | | |__  | |__) |")
    print(r"  | |  | | |  | | . ` | |  | |  __| |  _  / ")
    print(r"  | |__| | |__| | |\  | |__| | |____| | \ \ ")
    print(r"  |_____/ \____/|_| \_|_____/|______|_|  \_\\")
    print(f"     {NC}{BLD}empire Mifflin Vulnerable Active Directory{NC}")
    print(f"{C}{BLD}       {Y}pwning is the best policy{NC}")
    print(f"\n{DIM}  management console — type {NC}{BLD}help{NC}{DIM} or {NC}{BLD}?{NC}{DIM} to list commands{NC}")


# Two-column grid menu. Each band is (left_panel, right_panel); a panel is
# (title, ncols, [commands]); commands fill top-to-bottom within their columns.
_SIDEW = 36  # printable width of one panel (half the grid)

_MENU_BANDS = [
    (("LAB", 2, ["check", "build", "vms", "resume <n>",
                 "install", "network", "provision"]),
     ("VMS", 2, ["status", "destroy", "reset",
                 "start", "stop", "snapshot", "vnc"])),
    (("PROVISION", 1, ["provision_tags <t>", "verify"]),
     ("CONFIG", 2, ["settings", "set_profile <p>", "set_provider <p>", "set_disk <path>",
                    "set_ram <gb>", "set_attacker <ip>", "set_flag_mode <m>"])),
]


def _seg(title: str, width: int) -> str:
    """A box-rule segment: ' TITLE ' then ─ fill to width."""
    head = f" {C}{BLD}{title}{NC} "
    pad = width - (len(title) + 2)  # visible length, colour codes are zero-width
    return f"{DIM}{head}{'─' * max(pad, 0)}{NC}"


def _panel_body(cmds, ncols) -> list:
    """Lay cmds into ncols columns (column-major); return SIDEW-wide body lines."""
    if not cmds:
        return []
    rows = -(-len(cmds) // ncols)          # ceil
    cellw = _SIDEW // ncols
    lines = []
    for r in range(rows):
        cells = []
        for col in range(ncols):
            idx = col * rows + r
            cmd = cmds[idx] if idx < len(cmds) else ""
            cells.append(f"{BLD}{cmd}{NC}".ljust(cellw + len(BLD) + len(NC)))
        lines.append("".join(cells))
    return lines


def _menu_title(title):  # retained for callers outside print_menu
    print(f"\n{C}{BLD}*** {title} ***{NC}")


def print_menu():
    corners = [("┌", "┬", "┐"), ("├", "┼", "┤")]
    print()
    for i, ((lt, ln, lc), (rt, rn, rc)) in enumerate(_MENU_BANDS):
        lead, mid, end = corners[i]
        print(f"  {lead}{_seg(lt, _SIDEW)}{mid}{_seg(rt, _SIDEW)}{end}")
        lbody, rbody = _panel_body(lc, ln), _panel_body(rc, rn)
        for r in range(max(len(lbody), len(rbody))):
            left = lbody[r] if r < len(lbody) else " " * _SIDEW
            right = rbody[r] if r < len(rbody) else ""
            print(f"    {left}  {right}".rstrip())
    print(f"  {DIM}└{'─' * _SIDEW}┴{'─' * _SIDEW}┘{NC}")
    print(f"    {DIM}help · ?{NC}  show this menu     "
          f"{DIM}settings{NC}  edit all     {DIM}exit · quit{NC}  leave")


# ─────────────────────────────────────────────────────────────────────────────
# GOAD-style interactive shell (cmd.Cmd REPL with settings-aware prompt)
# ─────────────────────────────────────────────────────────────────────────────

class DunderShell(_cmd.Cmd):
    def __init__(self, cfg: dict, start_phase: int = 0):
        super().__init__()
        self.cfg = cfg
        self.start_phase = start_phase
        self._refresh_prompt()

    # ---- prompt + intro ----
    def _refresh_prompt(self):
        c = self.cfg
        self.prompt = rl_safe(
            f"\n{C}empire{NC} "
            f"[{BLD}{c['profile']}{NC}·{BLD}{c['provider']}{NC}·{BLD}{c['flag_mode']}{NC}] "
            f"{DIM}{vm_status_quick(c)}{NC} > "
        )

    def preloop(self):
        print_logo()
        print(f"\n  {cfg_summary_line(self.cfg)}")
        print_menu()

    # ---- help ----
    def do_help(self, arg):
        """Show the command menu."""
        print_menu()
    do_menu = do_help

    def emptyline(self):
        pass

    def default(self, line):
        warn(f"Unknown command: {line.strip()} — type 'help'.")

    # ---- lifecycle ----
    def do_check(self, arg):
        "Preflight — verify host dependencies."
        preflight_checks(self.cfg)

    def do_install(self, arg):
        "Full pipeline (media → packer → net → VMs → ansible → verify)."
        action_deploy(self.cfg, start_phase=self.start_phase)
    do_deploy = do_install

    def do_build(self, arg):
        "Packer base images only."
        action_build(self.cfg)

    def do_network(self, arg):
        "Create bridges + dnsmasq (phase 2)."
        phase_network_setup(self.cfg)

    def do_vms(self, arg):
        "Create + boot all VMs (phase 3)."
        phase_vm_create(self.cfg)
    do_create = do_vms

    def do_provision(self, arg):
        "Run all Ansible (phase 5)."
        action_provision(self.cfg)

    def do_resume(self, arg):
        "resume <n> — run the full pipeline from phase n (0–6)."
        try:
            n = int(arg.strip())
            assert 0 <= n <= 6
        except (ValueError, AssertionError):
            warn("usage: resume <0-6>"); return
        action_deploy(self.cfg, start_phase=n)

    # ---- VM control ----
    def do_status(self, arg):
        "Show VM / network / media state."
        action_status(self.cfg)
        self._refresh_prompt()

    def do_start(self, arg):
        "Start existing stopped VMs."
        action_start(self.cfg); self._refresh_prompt()

    def do_stop(self, arg):
        "Gracefully stop all running VMs."
        action_stop(self.cfg); self._refresh_prompt()

    def do_destroy(self, arg):
        "Delete VMs + tear down networks."
        action_destroy(self.cfg); self._refresh_prompt()

    def do_snapshot(self, arg):
        "Snapshot all VM disks (run after a good provision — stops VMs first)."
        vm_script = EMPIRE_HOME / "providers" / self.cfg["provider"] / "vm-create.sh"
        if vm_script.exists():
            run_cmd("Snapshot VMs",
                    ["bash", str(vm_script), "snapshot", self.cfg["profile"]],
                    env={"CFG_DISK_PATH": self.cfg["disk_path"]})
        self._refresh_prompt()

    def do_reset(self, arg):
        "Restore all VMs to the last snapshot in seconds, then start them."
        vm_script = EMPIRE_HOME / "providers" / self.cfg["provider"] / "vm-create.sh"
        if vm_script.exists():
            run_cmd("Reset VMs",
                    ["bash", str(vm_script), "reset", self.cfg["profile"]],
                    env={"CFG_DISK_PATH": self.cfg["disk_path"]})
        self._refresh_prompt()

    def do_vnc(self, arg):
        "Show the VNC endpoint for each running VM."
        vm_script = EMPIRE_HOME / "providers" / self.cfg["provider"] / "vm-create.sh"
        if vm_script.exists():
            run_cmd("VNC endpoints", ["bash", str(vm_script), "status"],
                    env={"CFG_DISK_PATH": self.cfg["disk_path"]})

    # ---- provisioning / validation ----
    def do_provision_tags(self, arg):
        "provision_tags <tags> — run Ansible with specific tag(s)."
        action_ansible_tags(self.cfg, preset=arg.strip() or None)

    def do_verify(self, arg):
        "Run vulnerability reachability checks."
        action_verify(self.cfg)

    # ---- configuration ----
    def do_settings(self, arg):
        "Interactive — change all settings."
        action_settings(self.cfg); self._refresh_prompt()

    def do_set_profile(self, arg):
        "set_profile <full|minimal|single-dc>"
        v = arg.strip()
        if v not in PROFILES:
            warn(f"profile must be one of: {', '.join(PROFILES)}"); return
        self.cfg["profile"] = v; log(f"profile = {v}"); self._refresh_prompt()

    def complete_set_profile(self, text, *_):
        return [p for p in PROFILES if p.startswith(text)]

    def do_set_provider(self, arg):
        "set_provider <qemu|virtualbox>"
        v = arg.strip()
        if v not in ("qemu", "virtualbox"):
            warn("provider must be qemu or virtualbox"); return
        self.cfg["provider"] = v; log(f"provider = {v}"); self._refresh_prompt()

    def complete_set_provider(self, text, *_):
        return [p for p in ("qemu", "virtualbox") if p.startswith(text)]

    def do_set_ram(self, arg):
        "set_ram <gb>"
        try:
            self.cfg["ram_budget"] = float(arg.strip()); log(f"ram_budget = {self.cfg['ram_budget']} GB")
        except ValueError:
            warn("usage: set_ram <number>")

    def do_set_attacker(self, arg):
        "set_attacker <ip>"
        if arg.strip():
            self.cfg["attacker_ip"] = arg.strip(); log(f"attacker_ip = {arg.strip()}")

    def do_set_flag_mode(self, arg):
        "set_flag_mode <ctf|training>"
        v = arg.strip()
        if v not in ("ctf", "training"):
            warn("flag_mode must be ctf or training"); return
        self.cfg["flag_mode"] = v; log(f"flag_mode = {v}"); self._refresh_prompt()

    def complete_set_flag_mode(self, text, *_):
        return [m for m in ("ctf", "training") if m.startswith(text)]

    def do_set_disk(self, arg):
        "set_disk <path>"
        if arg.strip():
            self.cfg["disk_path"] = arg.strip(); log(f"disk_path = {arg.strip()}")

    # ---- exit ----
    def do_exit(self, arg):
        "Leave the console."
        info("Goodbye.")
        return True
    do_quit = do_exit

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)


def main_menu(cfg: dict, start_phase: int = 0):
    DunderShell(cfg, start_phase).cmdloop()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deploy.py",
        description="EMPIRE — empire Mifflin Vulnerable AD Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Interactive mode (default):
  python3 deploy.py

Non-interactive / CI / cron (--yes):
  python3 deploy.py --profile minimal --provider qemu --yes
  python3 deploy.py --profile full --flag-mode ctf --attacker-ip 10.10.0.1 --yes
  python3 deploy.py --phase 5 --yes                   # restart from Ansible
  python3 deploy.py --destroy --yes                   # tear down everything
  python3 deploy.py --log-file /var/log/empire.log --yes

Cron setup:
  python3 deploy.py --install-cron                    # write crontab entry + sudoers
        """,
    )
    p.add_argument("--yes",          "-y", action="store_true",  help="Skip all prompts (CI/cron mode)")
    p.add_argument("--phase",        "-p", type=int, default=0, metavar="N",
                   help="Start from phase N (0=media,1=packer,2=network,3=VMs,4=WinRM,5=ansible,6=verify)")
    p.add_argument("--destroy",            action="store_true",  help="Destroy all VMs and networks")
    p.add_argument("--profile",            choices=list(PROFILES.keys()), help="Lab profile")
    p.add_argument("--provider",           choices=["qemu", "virtualbox"], help="Hypervisor provider")
    p.add_argument("--ram",                type=float, metavar="GB",  help="RAM budget in GB")
    p.add_argument("--disk-path",          metavar="PATH",             help="VM disk path")
    p.add_argument("--attacker-ip",        metavar="IP",               help="Attacker/listener IP")
    p.add_argument("--base-action",        choices=["build", "skip"],  help="build=run packer, skip=images exist")
    p.add_argument("--flag-mode",          choices=["ctf", "training"], help="Flag visibility")
    p.add_argument("--log-file",           metavar="PATH",             help="Append all output to this file")
    p.add_argument("--install-cron",       action="store_true",        help="Write crontab + sudoers and exit")
    p.add_argument("--from-phase",         metavar="PHASE",
                   help="Run Ansible from this phase to the end and exit. "
                        "Phases: 1 2 5 6 7 8 8b 9 10 11 13 14 16 17 18 19 20")
    p.add_argument("--only-phase",         metavar="PHASE", help="Run only this Ansible phase and exit")
    p.add_argument("--limit",              metavar="HOST",  help="Ansible --limit (restrict to host/group), e.g. endor.empire.local")
    return p


def apply_cli_overrides(cfg: dict, args: argparse.Namespace) -> dict:
    if args.profile:      cfg["profile"]     = args.profile
    if args.provider:     cfg["provider"]    = args.provider
    if args.ram:          cfg["ram_budget"]  = args.ram
    if args.disk_path:    cfg["disk_path"]   = args.disk_path
    if args.attacker_ip:  cfg["attacker_ip"] = args.attacker_ip
    if args.base_action:  cfg["base_action"] = args.base_action
    if args.flag_mode:    cfg["flag_mode"]   = args.flag_mode
    return cfg


def build_default_config() -> dict:
    host_ram = detect_ram_gb()
    return {
        "profile":     "full",
        "provider":    "qemu",
        "ram_budget":  float(host_ram) if host_ram else 32.0,
        "disk_path":   str(EMPIRE_HOME / "vms"),
        "attacker_ip": "10.10.0.1",
        "base_action": "build",
        "flag_mode":   "ctf",
        "host_ram":    host_ram,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Lock file — prevent concurrent runs
# ─────────────────────────────────────────────────────────────────────────────

class DeployLock:
    def __init__(self):
        self._fh = None

    def acquire(self) -> bool:
        try:
            self._fh = open(LOCK_FILE, "w")
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fh.write(str(os.getpid()))
            self._fh.flush()
            return True
        except OSError:
            if self._fh:
                self._fh.close()
                self._fh = None
            return False

    def release(self):
        if self._fh:
            try:
                fcntl.flock(self._fh, fcntl.LOCK_UN)
                self._fh.close()
                LOCK_FILE.unlink(missing_ok=True)
            except Exception:
                pass
            self._fh = None


# ─────────────────────────────────────────────────────────────────────────────
# Cron install
# ─────────────────────────────────────────────────────────────────────────────

def install_cron(cfg: dict):
    """Write a crontab entry and a sudoers drop-in, then exit."""
    import getpass, grp as grp_mod

    user    = getpass.getuser()
    py_bin  = sys.executable
    script  = str(EMPIRE_HOME / "deploy.py")
    log_f   = str(EMPIRE_HOME / "logs" / "empire-cron.log")
    profile = cfg["profile"]
    provider = cfg["provider"]

    # ── sudoers drop-in ────────────────────────────────────────────────────
    sudoers_content = f"""\
# EMPIRE lab — NOPASSWD for network/VM operations
# Generated by: python3 deploy.py --install-cron
# Remove this file to revoke: sudo rm /etc/sudoers.d/empire-lab

Cmnd_Alias EMPIRE_NET = \\
    /usr/sbin/ip, /sbin/ip, /usr/bin/ip, \\
    /usr/sbin/nft, /sbin/nft, \\
    /usr/sbin/iptables, /sbin/iptables, \\
    /usr/sbin/sysctl, /sbin/sysctl, \\
    /usr/bin/tee, /bin/tee, \\
    /usr/bin/grep, /bin/grep, \\
    /usr/bin/mkdir, /bin/mkdir, \\
    /usr/sbin/dnsmasq, /usr/bin/dnsmasq, /usr/local/sbin/dnsmasq, \\
    /usr/bin/kill, /bin/kill

{user} ALL=(root) NOPASSWD: EMPIRE_NET
"""

    sudoers_path = Path("/etc/sudoers.d/empire-lab")

    # Validate with visudo -cf before writing
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sudoers", delete=False) as tmp:
        tmp.write(sudoers_content)
        tmp_path = tmp.name

    result = subprocess.run(["sudo", "visudo", "-cf", tmp_path], capture_output=True, text=True)
    if result.returncode != 0:
        err(f"sudoers validation failed: {result.stderr.strip()}")
        Path(tmp_path).unlink(missing_ok=True)
    else:
        subprocess.run(["sudo", "cp", tmp_path, str(sudoers_path)], check=True)
        subprocess.run(["sudo", "chmod", "440", str(sudoers_path)], check=True)
        Path(tmp_path).unlink(missing_ok=True)
        log(f"Sudoers written: {sudoers_path}")

    # ── crontab entry ──────────────────────────────────────────────────────
    (EMPIRE_HOME / "logs").mkdir(parents=True, exist_ok=True)

    path_env = ":".join(_EXTRA_PATHS)
    cron_line = (
        f"# EMPIRE lab — nightly re-provision (Ansible only, VMs already up)\n"
        f"0 2 * * * {user} "
        f"PATH={path_env} "
        f"EMPIRE_HOME={EMPIRE_HOME} "
        f"{py_bin} {script} "
        f"--phase 5 --profile {profile} --provider {provider} --yes "
        f"--log-file {log_f} "
        f">> {log_f} 2>&1\n"
    )

    cron_path = Path("/etc/cron.d/empire-lab")
    cron_tmp  = Path(f"/tmp/empire-cron-{os.getpid()}")
    cron_tmp.write_text(cron_line)
    result2 = subprocess.run(["sudo", "cp", str(cron_tmp), str(cron_path)], capture_output=True, text=True)
    cron_tmp.unlink(missing_ok=True)
    if result2.returncode == 0:
        subprocess.run(["sudo", "chmod", "644", str(cron_path)], check=False)
        log(f"Cron job written: {cron_path}")
        info(f"Runs at 02:00 daily — phase 5 (Ansible re-provision)")
        info(f"Log: {log_f}")
    else:
        err(f"Could not write {cron_path}: {result2.stderr.strip()}")
        warn("Add this line to your crontab manually (crontab -e):")
        print(f"\n  {cron_line}")

    info("To run immediately without cron:  python3 deploy.py --phase 5 --yes")
    sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# Log file tee
# ─────────────────────────────────────────────────────────────────────────────

def setup_log_file(path: str):
    """Tee all stdout/stderr to a log file (append mode)."""
    import io
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "a", buffering=1)

    class Tee(io.TextIOWrapper):
        def __init__(self, stream, file_handle):
            self._stream = stream
            self._fh     = file_handle

        def write(self, data):
            self._stream.write(data)
            self._stream.flush()
            self._fh.write(data)
            self._fh.flush()
            return len(data)

        def flush(self):
            self._stream.flush()
            self._fh.flush()

        def isatty(self):
            return self._stream.isatty()

        def fileno(self):
            return self._stream.fileno()

    sys.stdout = Tee(sys.stdout, log_fh)
    sys.stderr = Tee(sys.stderr, log_fh)
    log(f"Logging to: {log_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

# ── Ansible phase shortcuts (ordered as in playbooks/site.yml) ────────────────
# Lets you re-run from / only a single phase instead of the whole pipeline.
_ANSIBLE_PHASES = [
    ("1", "phase1"), ("2", "phase2"), ("5", "phase5"), ("6", "phase6"), ("7", "phase7"),
    ("8", "phase8"), ("8b", "vuln_adcs"), ("9", "phase9"), ("10", "phase10"), ("11", "phase11"),
    ("13", "phase13"), ("14", "phase14"), ("16", "phase16"), ("17", "phase17"),
    ("18", "phase18"), ("19", "phase19"), ("20", "phase20"),
]


def run_ansible_phase(cfg: dict, phase: str, only: bool = False, limit: str = None) -> int:
    """Run site.yml from `phase` to the end (or only that phase). Returns exit code."""
    ansible_dir = EMPIRE_HOME / "ansible"
    inventory   = ansible_dir / "inventory.yml"
    playbook    = ansible_dir / "playbooks" / "site.yml"
    ids = [p for p, _ in _ANSIBLE_PHASES]
    if phase not in ids:
        err(f"Unknown phase '{phase}'. Valid: {', '.join(ids)}")
        return 2
    i = ids.index(phase)
    if only:
        tags = _ANSIBLE_PHASES[i][1]
        step(f"Ansible — ONLY phase {phase} (tag: {tags})" + (f" · limit {limit}" if limit else ""))
    else:
        tags = ",".join(t for _, t in _ANSIBLE_PHASES[i:])
        step(f"Ansible — phases {phase} → end" + (f" · limit {limit}" if limit else ""))
        info(f"tags: {tags}")
    cmd = [
        "ansible-playbook", "-i", str(inventory), str(playbook),
        "--tags", tags,
        "-e", (f"attacker_ip={cfg['attacker_ip']} flag_mode={cfg['flag_mode']} "
               f"deploy_profile={cfg['profile']}"),
    ]
    if limit:
        cmd += ["--limit", limit]
    return 0 if run_streaming("Ansible (phase run)", cmd, cwd=ansible_dir) else 1


def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    if args.log_file:
        setup_log_file(args.log_file)

    cfg = build_default_config()
    cfg = apply_cli_overrides(cfg, args)

    # ── Cron install ───────────────────────────────────────────────────────
    if args.install_cron:
        print_banner()
        install_cron(cfg)  # exits

    # ── Lock file ─────────────────────────────────────────────────────────
    lock = DeployLock()
    if not lock.acquire():
        err(f"Another deploy is running (lock: {LOCK_FILE}). Aborting.")
        sys.exit(1)

    def _release_on_signal(sig, frame):
        lock.release()
        sys.exit(1)

    signal.signal(signal.SIGTERM, _release_on_signal)
    signal.signal(signal.SIGHUP,  _release_on_signal)

    try:
        _run(args, cfg, lock)
    finally:
        lock.release()


def _run(args, cfg, lock):
    # ── Phase shortcut: run Ansible from/only a phase, then exit ───────────
    if args.from_phase or args.only_phase:
        print_banner()
        sys.exit(run_ansible_phase(
            cfg,
            args.from_phase or args.only_phase,
            only=bool(args.only_phase),
            limit=args.limit,
        ))

    # ── Non-interactive / CI / cron path ──────────────────────────────────
    if args.yes:
        print_banner()
        info(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        if args.destroy:
            ok = False
            vm_script = EMPIRE_HOME / "providers" / cfg["provider"] / "vm-create.sh"
            if vm_script.exists():
                ok = run_cmd("VM destroy", ["bash", str(vm_script), "destroy"])
                if cfg["provider"] == "qemu":
                    net_script = EMPIRE_HOME / "providers" / "qemu" / "network-setup.sh"
                    if net_script.exists():
                        ok = run_cmd("Network destroy", ["bash", str(net_script), "destroy"]) and ok
            sys.exit(0 if ok else 1)

        Path(cfg["disk_path"]).mkdir(parents=True, exist_ok=True)
        results = run_pipeline(cfg, start_phase=args.phase)
        print_pipeline_report(cfg, results)
        info(f"Finished: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        sys.exit(0 if all(results.values()) else 1)

    # ── Interactive menu ───────────────────────────────────────────────────
    if args.destroy:
        print_banner()
        action_destroy(cfg)
        sys.exit(0)

    main_menu(cfg, start_phase=args.phase)


if __name__ == "__main__":
    main()
