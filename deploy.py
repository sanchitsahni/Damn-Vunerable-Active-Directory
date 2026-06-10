#!/usr/bin/env python3
"""DUNDER — Dunder Mifflin Vulnerable AD Lab — interactive menu."""
import sys
assert sys.version_info >= (3, 8), "Python 3.8+ required"

import os
import argparse
import fcntl
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DUNDER_HOME = Path(__file__).parent.resolve()
LOCK_FILE   = Path("/tmp/dunder-deploy.lock")

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

# Evaluation ISOs — no key required, 180-day eval
# Using -4 (IPv4 only) + --tries=5 to avoid IPv6 CDN resets (same approach as GOAD)
WINDOWS_ISOS = [
    {
        "filename": "windows-server-2022.iso",
        "url": "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US",
        "size_hint": "~5.4 GB",
    },
    {
        "filename": "windows-server-2019.iso",
        "url": "https://go.microsoft.com/fwlink/p/?LinkID=2195167&clcid=0x409&culture=en-us&country=US",
        "size_hint": "~5.0 GB",
    },
    {
        "filename": "windows-10.iso",
        "url": "https://go.microsoft.com/fwlink/?LinkId=821363",
        "size_hint": "~5.8 GB",
    },
]

PROFILES = {
    "full":      {"vms": 8, "forests": 3, "ram_gb": 13.5, "label": "8 VMs · 3 forests · ~13.5 GB RAM"},
    "minimal":   {"vms": 5, "forests": 1, "ram_gb": 8.5,  "label": "5 VMs · corp.local only · ~8.5 GB RAM"},
    "single-dc": {"vms": 1, "forests": 1, "ram_gb": 2.0,  "label": "1 VM · smoke test · ~2 GB RAM"},
}

PACKER_TEMPLATES = [
    "windows-server-2022.pkr.hcl",
    "windows-server-2019.pkr.hcl",
    "windows-10.pkr.hcl",
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

def log(msg):  print(f"{G}[+]{NC} {msg}")
def warn(msg): print(f"{Y}[!]{NC} {msg}")
def err(msg):  print(f"{R}[x]{NC} {msg}")
def info(msg): print(f"{B}[*]{NC} {msg}")
def step(msg): print(f"\n{C}{BLD}[>>]{NC} {msg}")


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

def run_cmd(label: str, cmd: list, cwd: Path = DUNDER_HOME, env: dict = None) -> bool:
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


def run_streaming(label: str, cmd: list, cwd: Path = DUNDER_HOME, env: dict = None) -> bool:
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

def print_banner():
    print(f"\n{C}{BLD}", end="")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║      DUNDER  ·  Dunder Mifflin Vulnerable Active Directory   ║")
    print("║      CTF / Red-Team Lab  ·  deploy.py                        ║")
    print("╚══════════════════════════════════════════════════════════════╝")
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

def _download_file(label: str, url: str, dest: Path) -> bool:
    """Download url → dest. IPv4-only, 5 retries, resume support. wget preferred."""
    if dest.exists() and dest.stat().st_size > 0:
        size_mb = dest.stat().st_size // (1024 ** 2)
        log(f"{dest.name} already present ({size_mb} MB) — skipping")
        return True
    if dest.exists():
        warn(f"{dest.name} exists but is empty — re-downloading")

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
    media_dir = DUNDER_HOME / "media"
    media_dir.mkdir(parents=True, exist_ok=True)

    ok = True

    # virtio-win drivers (always needed for QEMU)
    ok = _download_file("virtio-win.iso", VIRTIO_WIN_URL,
                        media_dir / "virtio-win.iso") and ok

    # Windows ISOs — packer reads local file:// paths, never hits network during build
    for iso in WINDOWS_ISOS:
        ok = _download_file(iso["filename"], iso["url"],
                            media_dir / iso["filename"]) and ok

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


def _packer_output_exists(tpl: str, provider: str) -> bool:
    """True if this template's output dir is non-empty — already built."""
    subdir = PACKER_OUTPUT_DIRS.get((tpl, provider))
    if not subdir:
        return False
    out_dir = DUNDER_HOME / "packer-output" / subdir
    if not out_dir.exists():
        return False
    files = list(out_dir.iterdir())
    return len(files) > 0


def phase_packer_build(cfg: dict) -> bool:
    step("Phase 1: Packer — building base images (parallel)")
    packer_dir = DUNDER_HOME / "packer"
    only_flag  = "*.qemu.*" if cfg["provider"] == "qemu" else "*.virtualbox-iso.*"
    results    = {}

    def build_template(tpl: str):
        # Skip if output already exists (idempotent re-runs)
        if _packer_output_exists(tpl, cfg["provider"]):
            out_dir = PACKER_OUTPUT_DIRS.get((tpl, cfg["provider"]), "?")
            log(f"packer build {tpl} — skipped (packer-output/{out_dir} already present)")
            results[tpl] = True
            return

        tpl_path = packer_dir / tpl
        cmd      = ["packer", "build", f"-only={only_flag}", str(tpl_path)]
        info(f"[thread] Starting packer build {tpl}")
        merged_env = {**os.environ, "PACKER_LOG": "1"}
        result = subprocess.run(
            cmd, cwd=str(packer_dir), env=merged_env,
            capture_output=True, text=True,
        )
        results[tpl] = result.returncode == 0
        fn = log if results[tpl] else err
        fn(f"packer build {tpl} — {'PASS' if results[tpl] else 'FAIL'}")
        if not results[tpl]:
            err(f"--- {tpl} stderr (last 30 lines) ---")
            for line in result.stderr.strip().splitlines()[-30:]:
                print(f"  {line}")

    # Sequential on low-core hosts avoids vCPU contention; parallel only helps if
    # host has ≥ (num_templates × packer_cpus) physical cores.
    import multiprocessing
    parallel = multiprocessing.cpu_count() >= len(PACKER_TEMPLATES) * 2
    if parallel:
        threads = [threading.Thread(target=build_template, args=(tpl,)) for tpl in PACKER_TEMPLATES]
        for t in threads: t.start()
        for t in threads: t.join()
    else:
        info(f"Host has {multiprocessing.cpu_count()} cores — building sequentially to avoid vCPU thrash")
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
    net_script = DUNDER_HOME / "providers" / "qemu" / "network-setup.sh"
    if not net_script.exists():
        err(f"Network setup script not found: {net_script}")
        return False
    return run_cmd("Network setup", ["bash", str(net_script), "setup"])


def phase_vm_create(cfg: dict) -> bool:
    step("Phase 3: VM creation")
    vm_script = DUNDER_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM create script not found: {vm_script}")
        return False
    return run_cmd(
        "VM create",
        ["bash", str(vm_script), "create", "--profile", cfg["profile"]],
        env={"CFG_DEPLOY_MODE": cfg["profile"], "CFG_DISK_PATH": cfg["disk_path"]},
    )


def phase_wait_winrm(cfg: dict) -> bool:
    step("Phase 4: Wait for WinRM on all VMs")
    vm_script = DUNDER_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return False
    return run_cmd(
        "Wait WinRM",
        ["bash", str(vm_script), "wait-winrm", "--profile", cfg["profile"]],
        env={"CFG_DEPLOY_MODE": cfg["profile"]},
    )


def phase_ansible(cfg: dict) -> bool:
    step("Phase 5: Ansible provisioning")
    ansible_dir = DUNDER_HOME / "ansible"
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
    verify_script = DUNDER_HOME / "scripts" / "verify_vulns.py"
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
        print("    1. Check AGENTS.md for topology and attack paths.")
        print(f"    2. python3 {DUNDER_HOME}/chains/validator.py \\")
        print(f"         --dc-ip 10.10.0.10 --domain corp.local \\")
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
    vm_script = DUNDER_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return
    run_cmd("Start VMs", ["bash", str(vm_script), "start", "--profile", cfg["profile"]],
            env={"CFG_DEPLOY_MODE": cfg["profile"], "CFG_DISK_PATH": cfg["disk_path"]})


def action_stop(cfg: dict):
    """Stop all running VMs."""
    step("Stop VMs")
    vm_script = DUNDER_HOME / "providers" / cfg["provider"] / "vm-create.sh"
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
    vm_script = DUNDER_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return
    print(f"  {R}{BLD}This will delete all VMs and networks.{NC}")
    if not prompt_confirm("Are you sure?", default=False):
        info("Aborted.")
        return
    vm_ok = run_cmd("VM destroy", ["bash", str(vm_script), "destroy"])
    if cfg["provider"] == "qemu":
        net_script = DUNDER_HOME / "providers" / "qemu" / "network-setup.sh"
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
    virtio = DUNDER_HOME / "media" / "virtio-win.iso"
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
        for marker in installed:
            name   = marker.stem.replace(".installed", "")
            state  = f"{G}running{NC}" if name in pids else f"{Y}stopped{NC}"
            log_f  = vms_dir / f"{name}.log"
            log(f"  {name:<30} {state}")

    if cfg["provider"] == "qemu":
        print(f"\n  {BLD}Networks:{NC}")
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        bridges = [l.split(":")[1].strip() for l in result.stdout.splitlines()
                   if "dvad" in l and ":" in l]
        if bridges:
            for b in bridges:
                log(f"  bridge: {b}")
        else:
            warn("  No dvad-* bridges found — network not set up.")

    print(f"\n  {BLD}Packer outputs:{NC}")
    packer_out = DUNDER_HOME / "packer-output"
    if packer_out.exists():
        outputs = [d.name for d in packer_out.iterdir() if d.is_dir()]
        if outputs:
            for o in sorted(outputs): log(f"  {o}")
        else:
            info("  packer-output/ is empty — images not built yet.")
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


def action_ansible_tags(cfg: dict):
    """Run Ansible with specific tags."""
    print(f"\n  {BLD}Run Ansible with tags{NC}")
    tag_input = prompt_input("Ansible tag(s) (comma-separated, e.g. kerberos,adcs)", default="all")
    if not prompt_confirm(f"Run ansible-playbook --tags '{tag_input}'?", default=True):
        info("Aborted.")
        return

    ansible_dir = DUNDER_HOME / "ansible"
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

def main_menu(cfg: dict, start_phase: int = 0):
    while True:
        print_banner()
        print(f"  {cfg_summary_line(cfg)}")
        print(f"  {DIM}VMs: {vm_status_quick(cfg)}{NC}")
        print()
        print(f"  {BLD}[1]{NC} Deploy         {DIM}full pipeline (phases 0–6){NC}")
        print(f"  {BLD}[2]{NC} Build          {DIM}packer base images only{NC}")
        print(f"  {BLD}[3]{NC} Provision      {DIM}Ansible only (VMs must be up){NC}")
        print(f"  {BLD}[4]{NC} Ansible tags   {DIM}run specific playbook tags{NC}")
        print(f"  {BLD}[5]{NC} Resume phase   {DIM}restart pipeline from a specific phase{NC}")
        print(f"  {BLD}[6]{NC} Start VMs      {DIM}start existing stopped VMs{NC}")
        print(f"  {BLD}[7]{NC} Stop VMs       {DIM}gracefully stop all running VMs{NC}")
        print(f"  {BLD}[8]{NC} Destroy        {DIM}delete VMs + tear down networks{NC}")
        print(f"  {BLD}[9]{NC} Status         {DIM}show VM, network, and media state{NC}")
        print(f"  {BLD}[v]{NC} Verify         {DIM}run vulnerability checks{NC}")
        print(f"  {BLD}[s]{NC} Settings       {DIM}change profile, provider, paths, flags{NC}")
        print(f"  {BLD}[0]{NC} Exit")
        print()

        choice = input(f"  > ").strip().lower()

        if choice == "0" or choice == "q":
            info("Goodbye.")
            break
        elif choice == "1":
            action_deploy(cfg, start_phase=start_phase)
            pause()
        elif choice == "2":
            action_build(cfg)
            pause()
        elif choice == "3":
            action_provision(cfg)
            pause()
        elif choice == "4":
            action_ansible_tags(cfg)
            pause()
        elif choice == "5":
            action_resume_phase(cfg)
            pause()
        elif choice == "6":
            action_start(cfg)
            pause()
        elif choice == "7":
            action_stop(cfg)
            pause()
        elif choice == "8":
            action_destroy(cfg)
            pause()
        elif choice == "9":
            action_status(cfg)
            pause()
        elif choice == "v":
            action_verify(cfg)
            pause()
        elif choice == "s":
            action_settings(cfg)
            pause()
        else:
            warn("Invalid choice — enter a number 0–9 or v/s.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deploy.py",
        description="DUNDER — Dunder Mifflin Vulnerable AD Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Interactive mode (default):
  python3 deploy.py

Non-interactive / CI / cron (--yes):
  python3 deploy.py --profile minimal --provider qemu --yes
  python3 deploy.py --profile full --flag-mode ctf --attacker-ip 10.10.0.1 --yes
  python3 deploy.py --phase 5 --yes                   # restart from Ansible
  python3 deploy.py --destroy --yes                   # tear down everything
  python3 deploy.py --log-file /var/log/dunder.log --yes

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
        "disk_path":   str(DUNDER_HOME / "vms"),
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
    script  = str(DUNDER_HOME / "deploy.py")
    log_f   = str(DUNDER_HOME / "logs" / "dunder-cron.log")
    profile = cfg["profile"]
    provider = cfg["provider"]

    # ── sudoers drop-in ────────────────────────────────────────────────────
    sudoers_content = f"""\
# DUNDER lab — NOPASSWD for network/VM operations
# Generated by: python3 deploy.py --install-cron
# Remove this file to revoke: sudo rm /etc/sudoers.d/dunder-lab

Cmnd_Alias DUNDER_NET = \\
    /usr/sbin/ip, /sbin/ip, /usr/bin/ip, \\
    /usr/sbin/nft, /sbin/nft, \\
    /usr/sbin/iptables, /sbin/iptables, \\
    /usr/sbin/sysctl, /sbin/sysctl, \\
    /usr/bin/tee, /bin/tee, \\
    /usr/bin/grep, /bin/grep, \\
    /usr/bin/mkdir, /bin/mkdir, \\
    /usr/sbin/dnsmasq, /usr/bin/dnsmasq, /usr/local/sbin/dnsmasq, \\
    /usr/bin/kill, /bin/kill

{user} ALL=(root) NOPASSWD: DUNDER_NET
"""

    sudoers_path = Path("/etc/sudoers.d/dunder-lab")

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
    (DUNDER_HOME / "logs").mkdir(parents=True, exist_ok=True)

    path_env = ":".join(_EXTRA_PATHS)
    cron_line = (
        f"# DUNDER lab — nightly re-provision (Ansible only, VMs already up)\n"
        f"0 2 * * * {user} "
        f"PATH={path_env} "
        f"DUNDER_HOME={DUNDER_HOME} "
        f"{py_bin} {script} "
        f"--phase 5 --profile {profile} --provider {provider} --yes "
        f"--log-file {log_f} "
        f">> {log_f} 2>&1\n"
    )

    cron_path = Path("/etc/cron.d/dunder-lab")
    cron_tmp  = Path(f"/tmp/dunder-cron-{os.getpid()}")
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
    # ── Non-interactive / CI / cron path ──────────────────────────────────
    if args.yes:
        print_banner()
        info(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        if args.destroy:
            ok = False
            vm_script = DUNDER_HOME / "providers" / cfg["provider"] / "vm-create.sh"
            if vm_script.exists():
                ok = run_cmd("VM destroy", ["bash", str(vm_script), "destroy"])
                if cfg["provider"] == "qemu":
                    net_script = DUNDER_HOME / "providers" / "qemu" / "network-setup.sh"
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
