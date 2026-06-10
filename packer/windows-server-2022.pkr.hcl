packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
    virtualbox = {
      source  = "github.com/hashicorp/virtualbox"
      version = "~> 1"
    }
  }
}

# ==============================================================================
# Variables
# ==============================================================================
variable "iso_url" {
  type        = string
  description = "Windows Server 2022 eval ISO — deploy.py phase 0 downloads to media/ first"
  # Uses local file pre-downloaded by phase_download_media (IPv4 + retry).
  # Override with the go.microsoft.com URL only if you want packer to download directly.
  default = "../media/windows-server-2022.iso"
}

variable "iso_checksum" {
  type    = string
  default = "none"
}

variable "virtio_iso" {
  type        = string
  description = "Path to virtio-win ISO (used by QEMU builder for driver injection)"
  default     = "../media/virtio-win.iso"
}

variable "output_dir" {
  type    = string
  default = "../packer-output"
}

variable "disk_size" {
  type    = number
  default = 40960
}

variable "memory" {
  type    = number
  default = 4096
}

variable "cpus" {
  type    = number
  default = 2
}

locals {
  winrm_user     = "Administrator"
  winrm_password = "DVADlab2024!"
  vm_name        = "windows-server-2022-base"
}

# ==============================================================================
# QEMU builder — outputs windows-server-2022-base.qcow2
# ==============================================================================
source "qemu" "server2022" {
  vm_name          = "${local.vm_name}.qcow2"
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "${var.output_dir}/server2022-qemu"

  disk_size        = var.disk_size
  disk_interface   = "ide"   # IDE during install; virtio drivers injected post-install by setup-winrm.ps1
  format           = "qcow2"
  accelerator      = "kvm"
  machine_type     = "q35"
  memory           = var.memory
  cpus             = var.cpus
  headless         = true
  net_device       = "e1000"

  # autounattend.xml served from floppy image (A:\) — Windows setup picks it up automatically
  floppy_content = {
    "Autounattend.xml" = file("${path.root}/http/autounattend-server-2022.xml")
    "setup-winrm.ps1"  = file("${path.root}/scripts/setup-winrm.ps1")
  }
  floppy_label = "UNATTEND"

  # NOTE: do NOT add a qemuargs "-drive" override here. Packer keys qemuargs
  # overrides by switch name, so a single "-drive" entry REPLACES packer's
  # auto-generated disk + bootable install-ISO drives, leaving the VM with no
  # boot media ("boot failed code 0004"). The runtime (providers/qemu/vm-create.sh)
  # uses ide-hd + e1000e — both in-box Windows drivers — so virtio-win is not
  # needed during the build. Let packer attach disk + ISO natively.

  communicator   = "winrm"
  winrm_username = local.winrm_user
  winrm_password = local.winrm_password
  winrm_port     = 5985
  winrm_timeout  = "2h"
  winrm_use_ssl  = false
  winrm_insecure = true

  boot_wait      = "3s"
  boot_command   = ["<spacebar>"]

  shutdown_command = "shutdown /s /t 10 /f"
  shutdown_timeout = "15m"
}

# ==============================================================================
# VirtualBox builder — outputs windows-server-2022-base.ova
# ==============================================================================
source "virtualbox-iso" "server2022" {
  vm_name          = local.vm_name
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "${var.output_dir}/server2022-virtualbox"
  format           = "ova"

  disk_size        = var.disk_size
  memory           = var.memory
  cpus             = var.cpus
  headless         = true

  # autounattend.xml on floppy (A:\)
  floppy_content = {
    "Autounattend.xml" = file("${path.root}/http/autounattend-server-2022.xml")
    "setup-winrm.ps1"  = file("${path.root}/scripts/setup-winrm.ps1")
  }

  gfx_controller        = "vmsvga"
  gfx_vram_size         = 16
  guest_os_type         = "Windows2022_64"
  guest_additions_mode  = "upload"
  guest_additions_path  = "C:/Setup/VBoxGuestAdditions.iso"

  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nat-localhostreachable1", "on"],
    ["modifyvm", "{{.Name}}", "--clipboard-mode", "disabled"],
    ["modifyvm", "{{.Name}}", "--draganddrop", "disabled"],
  ]

  communicator   = "winrm"
  winrm_username = local.winrm_user
  winrm_password = local.winrm_password
  winrm_port     = 5985
  winrm_timeout  = "2h"
  winrm_use_ssl  = false
  winrm_insecure = true

  boot_wait      = "5s"
  boot_command   = ["<spacebar>"]

  shutdown_command = "shutdown /s /t 10 /f"
  shutdown_timeout = "15m"
}

# ==============================================================================
# Build
# ==============================================================================
build {
  name = "server2022"

  sources = [
    "source.qemu.server2022",
    "source.virtualbox-iso.server2022",
  ]

  # Ensure setup-winrm.ps1 ran and WinRM is fully up
  provisioner "windows-shell" {
    inline = ["echo WinRM OK"]
  }

  # Sysprep-friendly cleanup — remove event logs, temp files
  provisioner "windows-shell" {
    inline = [
      "wevtutil cl System",
      "wevtutil cl Application",
      "wevtutil cl Security",
      // NOTE: do NOT 'del C:\Windows\Temp\*' or '...\AppData\Local\Temp\*' here —
      // packer runs this provisioner from %TEMP%, so it deletes its own running
      // script -> "The batch file cannot be found" -> build fails. Leave temp be.
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_dir}/server2022-manifest.json"
    strip_path = true
  }
}
