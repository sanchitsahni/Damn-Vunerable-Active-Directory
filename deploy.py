#!/usr/bin/env python3
"""DUNDER — Dunder Mifflin Vulnerable AD Lab — interactive deploy wizard."""
import sys
assert sys.version_info >= (3, 8), "Python 3.8+ required"

import os
import argparse
import shutil
import subprocess
import threading
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DVAD_HOME = Path(__file__).parent.resolve()

VIRTIO_WIN_URL = (
    "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/"
    "stable-virtio/virtio-win.iso"
)

PROFILES = {
    "full":      {"vms": 8, "forests": 3, "ram_gb": 13.5, "label": "8 VMs, 3 forests, ~13.5 GB RAM"},
    "minimal":   {"vms": 5, "forests": 1, "ram_gb": 8.5,  "label": "5 VMs, corp.local only, ~8.5 GB RAM"},
    "single-dc": {"vms": 1, "forests": 1, "ram_gb": 2.0,  "label": "1 VM, smoke test, ~2 GB RAM"},
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
BLD = "\033[1m"
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
        st = os.statvfs(path)
        return (st.f_bavail * st.f_frsize) // (1024 ** 3)
    except Exception:
        return 0


def cmd_in_path(name: str) -> bool:
    return shutil.which(name) is not None


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess helpers
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(label: str, cmd: list, cwd: Path = DVAD_HOME, env: dict = None) -> bool:
    """Run cmd, capture output, print status. Returns True on success."""
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


def run_streaming(label: str, cmd: list, cwd: Path = DVAD_HOME, env: dict = None) -> bool:
    """Run cmd with live stdout/stderr — for long downloads or interactive output."""
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
# Wizard prompts
# ─────────────────────────────────────────────────────────────────────────────

def prompt_choice(question: str, choices: list, default: int = 1) -> str:
    print(f"\n{BLD}[?]{NC} {question}")
    for i, (val, desc) in enumerate(choices, 1):
        marker = "*" if i == default else " "
        print(f"    {marker}{i}) {val:<12} — {desc}")
    while True:
        raw = input(f"    Choice [1-{len(choices)}] (default {default}): ").strip()
        if raw == "":
            return choices[default - 1][0]
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1][0]
        warn(f"Please enter a number between 1 and {len(choices)}.")


def prompt_input(question: str, default: str) -> str:
    print(f"\n{BLD}[?]{NC} {question} [{default}]: ", end="")
    raw = input().strip()
    return raw if raw else default


def prompt_confirm(question: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    print(f"\n{BLD}[?]{NC} {question} [{hint}]: ", end="")
    raw = input().strip().lower()
    if raw == "":
        return default
    return raw in ("y", "yes")


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    print(f"\n{C}{BLD}", end="")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   DUNDER — Dunder Mifflin Vulnerable Active Directory    ║")
    print("║   CTF / Red-Team Lab  ·  deploy.py                       ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{NC}")


# ─────────────────────────────────────────────────────────────────────────────
# Wizard
# ─────────────────────────────────────────────────────────────────────────────

def run_wizard() -> dict:
    print_banner()

    profile = prompt_choice(
        "Lab profile:",
        [
            ("full",      PROFILES["full"]["label"]),
            ("minimal",   PROFILES["minimal"]["label"]),
            ("single-dc", PROFILES["single-dc"]["label"]),
        ],
        default=1,
    )

    provider = prompt_choice(
        "Provider:",
        [
            ("qemu",       "QEMU/KVM (Linux host)"),
            ("virtualbox", "VirtualBox (any host)"),
        ],
        default=1,
    )

    host_ram    = detect_ram_gb()
    ram_default = str(host_ram) if host_ram else "32"
    ram_raw = prompt_input(
        f"RAM budget (GB) [auto-detected: {ram_default}]",
        default=ram_default,
    )
    try:
        ram_budget = float(ram_raw)
    except ValueError:
        warn(f"Could not parse '{ram_raw}' as a number, using {ram_default} GB.")
        ram_budget = float(ram_default)

    disk_path = prompt_input("Disk path", default=str(DVAD_HOME / "vms"))

    attacker_ip = prompt_input(
        "Attacker IP (your Kali/BlackArch box)\n"
        "    (used by coercion roles to configure listener targets)",
        default="10.10.0.1",
    )

    base_action = prompt_choice(
        "Base image action:",
        [
            ("build", "run Packer now (~45–70 min first time)"),
            ("skip",  "images already built, go straight to VM create"),
        ],
        default=1,
    )

    flag_mode = prompt_choice(
        "Flag mode:",
        [
            ("ctf",      "flags hidden, require exploitation to read"),
            ("training", "flags visible in C:\\Flags\\ (walkthrough mode)"),
        ],
        default=1,
    )

    return {
        "profile":     profile,
        "provider":    provider,
        "ram_budget":  ram_budget,
        "disk_path":   disk_path,
        "attacker_ip": attacker_ip,
        "base_action": base_action,
        "flag_mode":   flag_mode,
        "host_ram":    host_ram,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Preflight summary + checks
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(cfg: dict):
    p            = cfg["profile"]
    profile_meta = PROFILES[p]
    free_disk    = detect_free_disk_gb(cfg["disk_path"])

    print(f"\n{BLD}[*] Preflight summary:{NC}")
    print(f"    Profile:    {p} ({profile_meta['vms']} VMs)")
    print(f"    Provider:   {cfg['provider']}")
    print(f"    RAM:        {profile_meta['ram_gb']} GB required / {cfg['ram_budget']} GB budget")
    print(f"    Disk:       {cfg['disk_path']} ({free_disk} GB free)")
    print(f"    Attacker:   {cfg['attacker_ip']}")
    print(f"    Packer:     {cfg['base_action']}")
    print(f"    Flags:      {cfg['flag_mode']}")


def preflight_checks(cfg: dict) -> bool:
    ok           = True
    p            = cfg["profile"]
    profile_meta = PROFILES[p]

    step("Running preflight checks")

    required_ram = profile_meta["ram_gb"]
    if cfg["ram_budget"] < required_ram:
        warn(f"RAM budget ({cfg['ram_budget']} GB) < profile requirement ({required_ram} GB). OOM-killer may strike.")
    else:
        log(f"RAM budget OK ({cfg['ram_budget']} GB >= {required_ram} GB required)")

    free_disk = detect_free_disk_gb(cfg["disk_path"])
    if free_disk < 130:
        warn(f"Only {free_disk} GB free on {cfg['disk_path']} — recommend ≥ 130 GB.")
    else:
        log(f"Disk space OK ({free_disk} GB free at {cfg['disk_path']})")

    if cfg["provider"] == "qemu":
        if not os.path.exists("/dev/kvm"):
            warn("/dev/kvm not found — QEMU will run in software emulation (very slow).")
        else:
            log("KVM available (/dev/kvm present)")
    elif cfg["provider"] == "virtualbox":
        if not cmd_in_path("VBoxManage"):
            err("VBoxManage not found in PATH — VirtualBox requires VirtualBox to be installed.")
            ok = False
        else:
            log("VBoxManage found in PATH")

    if cfg["base_action"] == "build":
        if not cmd_in_path("packer"):
            err("packer not found in PATH — required for base image build.")
            ok = False
        else:
            log("packer found in PATH")

    if not cmd_in_path("ansible-playbook"):
        err("ansible-playbook not found in PATH — required for provisioning.")
        ok = False
    else:
        log("ansible-playbook found in PATH")

    py_ver = sys.version_info
    if py_ver < (3, 8):
        err(f"Python 3.8+ required, got {py_ver.major}.{py_ver.minor}")
        ok = False
    else:
        log(f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} OK")

    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline phases
# ─────────────────────────────────────────────────────────────────────────────

def phase_download_media(cfg: dict) -> bool:
    """Download virtio-win.iso to media/ before packer runs."""
    step("Phase 0: Download required media")
    media_dir  = DVAD_HOME / "media"
    media_dir.mkdir(parents=True, exist_ok=True)
    virtio_iso = media_dir / "virtio-win.iso"

    if virtio_iso.exists():
        size_mb = virtio_iso.stat().st_size // (1024 ** 2)
        log(f"virtio-win.iso already present ({size_mb} MB) — skipping download")
        return True

    info(f"Downloading virtio-win.iso (~600 MB) → {virtio_iso}")
    info(f"Source: {VIRTIO_WIN_URL}")

    if cmd_in_path("wget"):
        return run_streaming(
            "Download virtio-win.iso",
            ["wget", "--show-progress", "-q", "-O", str(virtio_iso), VIRTIO_WIN_URL],
        )
    if cmd_in_path("curl"):
        return run_streaming(
            "Download virtio-win.iso",
            ["curl", "-L", "--progress-bar", "-o", str(virtio_iso), VIRTIO_WIN_URL],
        )

    err("Neither wget nor curl found — cannot download virtio-win.iso.")
    err(f"Download manually:  {VIRTIO_WIN_URL}")
    err(f"Place the file at:  {virtio_iso}")
    return False


def phase_packer_build(cfg: dict) -> bool:
    """Build all 3 Packer templates in parallel using threads."""
    step("Phase 1: Packer — building base images (parallel)")
    packer_dir = DVAD_HOME / "packer"
    only_flag  = "*.qemu.*" if cfg["provider"] == "qemu" else "*.virtualbox-iso.*"
    results    = {}
    errors     = {}

    def build_template(tpl: str):
        tpl_path = packer_dir / tpl
        label    = f"packer build {tpl}"
        cmd      = ["packer", "build", f"-only={only_flag}", str(tpl_path)]
        info(f"[thread] Starting {label}")
        merged_env = {**os.environ, "PACKER_LOG": "1"}
        result = subprocess.run(
            cmd, cwd=str(packer_dir), env=merged_env,
            capture_output=True, text=True,
        )
        results[tpl] = result.returncode == 0
        errors[tpl]  = result.stderr if result.returncode != 0 else ""
        status = "PASS" if results[tpl] else "FAIL"
        fn = log if results[tpl] else err
        fn(f"packer build {tpl} — {status}")
        if not results[tpl]:
            err(f"--- {tpl} stderr (last 30 lines) ---")
            for line in result.stderr.strip().splitlines()[-30:]:
                print(f"  {line}")

    threads = [threading.Thread(target=build_template, args=(tpl,)) for tpl in PACKER_TEMPLATES]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    all_ok = all(results.values())
    if not all_ok:
        failed = [tpl for tpl, ok in results.items() if not ok]
        err(f"Packer build failed for: {', '.join(failed)}")
    return all_ok


def phase_network_setup(cfg: dict) -> bool:
    """Set up virtual networks (QEMU only)."""
    step("Phase 2: Network setup")
    if cfg["provider"] != "qemu":
        info("Skipping network setup (not QEMU provider).")
        return True
    net_script = DVAD_HOME / "providers" / "qemu" / "network-setup.sh"
    if not net_script.exists():
        err(f"Network setup script not found: {net_script}")
        return False
    return run_cmd("Network setup", ["bash", str(net_script), "setup"])


def phase_vm_create(cfg: dict) -> bool:
    """Create VMs for the chosen profile."""
    step("Phase 3: VM creation")
    vm_script = DVAD_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM create script not found: {vm_script}")
        return False
    return run_cmd(
        "VM create",
        ["bash", str(vm_script), "create", "--profile", cfg["profile"]],
        env={"CFG_DEPLOY_MODE": cfg["profile"], "CFG_DISK_PATH": cfg["disk_path"]},
    )


def phase_wait_winrm(cfg: dict) -> bool:
    """Wait for WinRM readiness on all VMs."""
    step("Phase 4: Wait for WinRM on all VMs")
    vm_script = DVAD_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return False
    return run_cmd(
        "Wait WinRM",
        ["bash", str(vm_script), "wait-winrm", "--profile", cfg["profile"]],
        env={"CFG_DEPLOY_MODE": cfg["profile"]},
    )


def phase_ansible(cfg: dict) -> bool:
    """Run Ansible provisioning."""
    step("Phase 5: Ansible provisioning")
    ansible_dir = DVAD_HOME / "ansible"
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
    return run_cmd("Ansible provisioning", cmd, cwd=ansible_dir)


def phase_verify(cfg: dict) -> bool:
    """Run vulnerability verification."""
    step("Phase 6: Vulnerability verification")
    verify_script = DVAD_HOME / "scripts" / "verify_vulns.py"
    if not verify_script.exists():
        warn(f"Verify script not found at {verify_script} — skipping.")
        return True
    return run_cmd(
        "Verify vulns",
        [sys.executable, str(verify_script), "--profile", cfg["profile"]],
    )


def phase_destroy(cfg: dict) -> bool:
    """Destroy VMs and networks."""
    step("Destroy: tearing down VMs and networks")
    vm_script = DVAD_HOME / "providers" / cfg["provider"] / "vm-create.sh"
    if not vm_script.exists():
        err(f"VM script not found: {vm_script}")
        return False

    vm_ok = run_cmd("VM destroy", ["bash", str(vm_script), "destroy"])

    net_ok = True
    if cfg["provider"] == "qemu":
        net_script = DVAD_HOME / "providers" / "qemu" / "network-setup.sh"
        if net_script.exists():
            net_ok = run_cmd("Network destroy", ["bash", str(net_script), "destroy"])

    return vm_ok and net_ok


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline definition
# ─────────────────────────────────────────────────────────────────────────────

PHASES = [
    # num  name                  fn                      condition (lambda cfg → bool)
    (0, "Download media",    phase_download_media,  lambda cfg: cfg["base_action"] == "build" and cfg["provider"] == "qemu"),
    (1, "Packer build",      phase_packer_build,    lambda cfg: cfg["base_action"] == "build"),
    (2, "Network setup",     phase_network_setup,   lambda cfg: cfg["provider"] == "qemu"),
    (3, "VM create",         phase_vm_create,       lambda cfg: True),
    (4, "Wait WinRM",        phase_wait_winrm,      lambda cfg: True),
    (5, "Ansible",           phase_ansible,         lambda cfg: True),
    (6, "Verify vulns",      phase_verify,          lambda cfg: True),
]


def run_pipeline(cfg: dict, start_phase: int = 0) -> dict:
    results = {}
    for num, name, fn, condition in PHASES:
        if num < start_phase:
            info(f"Skipping phase {num} ({name}) — before --phase {start_phase}.")
            continue
        if not condition(cfg):
            info(f"Skipping phase {num} ({name}) — not applicable.")
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


def print_final_report(cfg: dict, phase_results: dict):
    print(f"\n{G}{BLD}{'=' * 60}{NC}")
    print(f"{G}{BLD}   DUNDER Lab — Final Deployment Report{NC}")
    print(f"{G}{BLD}{'=' * 60}{NC}")
    for phase_name, passed in phase_results.items():
        mark = f"{G}PASS{NC}" if passed else f"{R}FAIL{NC}"
        print(f"  {phase_name:<40} {mark}")
    print()
    all_ok = all(phase_results.values())
    if all_ok:
        print(f"  {G}{BLD}All phases completed successfully.{NC}")
        print()
        print("  Next steps:")
        print("    1. Check AGENTS.md for lab topology and attack paths.")
        print("    2. Run the chain validator:")
        print(f"         python3 {DVAD_HOME}/chains/validator.py \\")
        print(f"           --dc-ip 10.10.0.10 --domain corp.local \\")
        print(f"           --attacker-ip {cfg['attacker_ip']}")
        if cfg["flag_mode"] == "ctf":
            print("    3. Flags require exploitation — see PLAN.md for attack vectors.")
        else:
            print("    3. Flags visible at C:\\Flags\\ on each target (training mode).")
    else:
        failed = [n for n, ok in phase_results.items() if not ok]
        print(f"  {R}{BLD}Deployment incomplete — failed phases: {', '.join(failed)}{NC}")
        print()
        print("  Tip: use --phase <n> to restart from a specific phase.")
        print("       Phase 0 = download media, 1 = packer, 2 = network, 3 = VMs,")
        print("       4 = wait WinRM, 5 = ansible, 6 = verify")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deploy.py",
        description="DUNDER — Dunder Mifflin Vulnerable AD Lab — interactive deploy wizard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 deploy.py                                        # interactive wizard
  python3 deploy.py --yes                                  # skip confirmation (CI)
  python3 deploy.py --phase 5                              # restart from Ansible phase
  python3 deploy.py --destroy                              # tear down everything
  python3 deploy.py --profile minimal --provider qemu --yes
        """,
    )
    p.add_argument("--yes",        "-y",  action="store_true",   help="Skip confirmation prompt (CI)")
    p.add_argument("--phase",      "-p",  type=int, default=0, metavar="N",
                   help="Start from phase N (0=media, 1=packer, 2=network, 3=VMs, 4=WinRM, 5=ansible, 6=verify)")
    p.add_argument("--destroy",           action="store_true",   help="Destroy all VMs and networks")
    p.add_argument("--profile",           choices=list(PROFILES.keys()),
                   help="Lab profile (overrides wizard)")
    p.add_argument("--provider",          choices=["qemu", "virtualbox"],
                   help="Hypervisor provider (overrides wizard)")
    p.add_argument("--ram",               type=float, metavar="GB",
                   help="RAM budget in GB (overrides wizard)")
    p.add_argument("--disk-path",         metavar="PATH",
                   help="VM disk path (overrides wizard)")
    p.add_argument("--attacker-ip",       metavar="IP",
                   help="Attacker/listener IP (overrides wizard)")
    p.add_argument("--base-action",       choices=["build", "skip"],
                   help="Packer action: build=run packer, skip=images already exist")
    p.add_argument("--flag-mode",         choices=["ctf", "training"],
                   help="Flag visibility mode (overrides wizard)")
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
        "disk_path":   str(DVAD_HOME / "vms"),
        "attacker_ip": "10.10.0.1",
        "base_action": "build",
        "flag_mode":   "ctf",
        "host_ram":    host_ram,
    }


def all_required_supplied(args: argparse.Namespace) -> bool:
    return all([
        args.profile,
        args.provider,
        args.ram is not None,
        args.disk_path,
        args.attacker_ip,
        args.base_action,
        args.flag_mode,
    ])


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    if args.destroy:
        print_banner()
        cfg = build_default_config()
        cfg = apply_cli_overrides(cfg, args)
        ok  = phase_destroy(cfg)
        sys.exit(0 if ok else 1)

    if all_required_supplied(args) and args.yes:
        cfg = build_default_config()
        cfg = apply_cli_overrides(cfg, args)
        print_banner()
    else:
        print_banner()
        if all_required_supplied(args):
            cfg = build_default_config()
            cfg = apply_cli_overrides(cfg, args)
        else:
            cfg = run_wizard()
            cfg = apply_cli_overrides(cfg, args)

    print_summary(cfg)
    checks_ok = preflight_checks(cfg)

    if not args.yes:
        if not prompt_confirm("Proceed?", default=True):
            info("Aborted by user.")
            sys.exit(0)

    if not checks_ok:
        warn("One or more preflight checks failed — proceeding anyway.")

    Path(cfg["disk_path"]).mkdir(parents=True, exist_ok=True)

    results = run_pipeline(cfg, start_phase=args.phase)
    print_final_report(cfg, results)

    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
