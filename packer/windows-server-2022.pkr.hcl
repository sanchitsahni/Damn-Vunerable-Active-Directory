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
  description = "Windows Server 2022 eval ISO URL or local path"
  # Microsoft eval ISO (direct download — no key required for eval)
  default = "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US"
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
  floppy_files = [
    "${path.root}/http/autounattend-server-2022.xml",
    "${path.root}/scripts/setup-winrm.ps1",
  ]
  floppy_label = "UNATTEND"

  # virtio-win ISO mounted as second CD for driver installation
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
  floppy_files = [
    "${path.root}/http/autounattend-server-2022.xml",
    "${path.root}/scripts/setup-winrm.ps1",
  ]

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
      "del /f /q C:\\Windows\\Temp\\* 2>nul",
      "del /f /q C:\\Users\\Administrator\\AppData\\Local\\Temp\\* 2>nul",
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_dir}/server2022-manifest.json"
    strip_path = true
  }
}
