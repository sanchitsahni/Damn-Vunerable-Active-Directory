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
  description = "Windows 10 ISO — deploy.py phase 0 downloads to media/ first. Must be Desktop Experience (full GUI)."
  default     = "../media/windows-10.iso"
}

variable "iso_checksum" {
  type    = string
  default = "none"
}

variable "virtio_iso" {
  type    = string
  default = "../media/virtio-win.iso"
}

variable "output_dir" {
  type    = string
  default = "../packer-output"
}

variable "disk_size" {
  type    = number
  # ws01 needs more room: Desktop Experience + tools + phishing payloads
  default = 61440
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
  vm_name        = "windows-10-base"
}

# ==============================================================================
# QEMU builder
# ws01 — victim workstation; needs full Desktop Experience for:
#   CVE-2025-24071 (.library-ms Explorer preview NTLM leak)
#   CVE-2023-21716 (WordPad RTF RCE)
#   CVE-2024-30051 (DWM Core Library LPE — graphical session required)
# ==============================================================================
source "qemu" "win10" {
  vm_name          = "${local.vm_name}.qcow2"
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "${var.output_dir}/win10-qemu"

  disk_size      = var.disk_size
  disk_interface = "ide"
  format         = "qcow2"
  accelerator    = "kvm"
  machine_type   = "q35"
  memory         = var.memory
  cpus           = var.cpus
  headless       = true
  net_device     = "e1000"

  floppy_files = [
    "${path.root}/http/autounattend-win10.xml",
    "${path.root}/scripts/setup-winrm.ps1",
  ]
  floppy_label = "UNATTEND"

  qemuargs = [
    ["-drive", "file=${var.virtio_iso},media=cdrom,if=ide,index=2"],
  ]

  communicator   = "winrm"
  winrm_username = local.winrm_user
  winrm_password = local.winrm_password
  winrm_port     = 5985
  winrm_timeout  = "2h"
  winrm_use_ssl  = false
  winrm_insecure = true

  boot_wait        = "3s"
  boot_command     = ["<spacebar>"]
  shutdown_command = "shutdown /s /t 10 /f"
  shutdown_timeout = "20m"
}

# ==============================================================================
# VirtualBox builder
# ==============================================================================
source "virtualbox-iso" "win10" {
  vm_name          = local.vm_name
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "${var.output_dir}/win10-virtualbox"
  format           = "ova"

  disk_size = var.disk_size
  memory    = var.memory
  cpus      = var.cpus
  headless  = true

  floppy_files = [
    "${path.root}/http/autounattend-win10.xml",
    "${path.root}/scripts/setup-winrm.ps1",
  ]

  gfx_controller       = "vmsvga"
  gfx_vram_size        = 128
  guest_os_type        = "Windows10_64"
  guest_additions_mode = "upload"
  guest_additions_path = "C:/Setup/VBoxGuestAdditions.iso"

  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nat-localhostreachable1", "on"],
    ["modifyvm", "{{.Name}}", "--clipboard-mode", "disabled"],
    # Enable 3D acceleration needed for DWM CVEs
    ["modifyvm", "{{.Name}}", "--accelerate3d", "off"],
  ]

  communicator   = "winrm"
  winrm_username = local.winrm_user
  winrm_password = local.winrm_password
  winrm_port     = 5985
  winrm_timeout  = "2h"
  winrm_use_ssl  = false
  winrm_insecure = true

  boot_wait        = "5s"
  boot_command     = ["<spacebar>"]
  shutdown_command = "shutdown /s /t 10 /f"
  shutdown_timeout = "20m"
}

# ==============================================================================
# Build
# ==============================================================================
build {
  name = "win10"

  sources = [
    "source.qemu.win10",
    "source.virtualbox-iso.win10",
  ]

  provisioner "windows-shell" {
    inline = ["echo WinRM OK"]
  }

  # Install WordPad (needed for CVE-2023-21716 surface)
  provisioner "windows-shell" {
    inline = [
      "DISM /Online /Add-Capability /CapabilityName:Microsoft.Windows.WordPad~~~~0.0.1.0 /NoRestart 2>nul || echo WordPad already present",
    ]
  }

  provisioner "windows-shell" {
    inline = [
      "wevtutil cl System",
      "wevtutil cl Application",
      "wevtutil cl Security",
      "del /f /q C:\\Windows\\Temp\\* 2>nul",
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_dir}/win10-manifest.json"
    strip_path = true
  }
}
