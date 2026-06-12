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
  description = "Windows Server 2019 eval ISO — deploy.py phase 0 downloads to media/ first"
  default     = "../media/windows-server-2019.iso"
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
  winrm_password = "SithLord123!"
  vm_name        = "windows-server-2019-base"
}

# ==============================================================================
# QEMU builder
# scarif uses 2019 specifically for EternalBlue (MS17-010) + SMBv1 surface
# ==============================================================================
source "qemu" "server2019" {
  vm_name          = "${local.vm_name}.qcow2"
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "${var.output_dir}/server2019-qemu"

  disk_size      = var.disk_size
  disk_interface = "ide"
  format         = "qcow2"
  accelerator    = "kvm"
  machine_type   = "q35"
  memory         = var.memory
  cpus           = var.cpus
  headless       = true
  net_device     = "e1000"

  floppy_content = {
    "Autounattend.xml" = file("${path.root}/http/autounattend-server-2019.xml")
    "setup-winrm.ps1"  = file("${path.root}/scripts/setup-winrm.ps1")
  }
  floppy_label = "UNATTEND"

  # NOTE: no qemuargs "-drive" override — it would wipe packer's auto-generated
  # disk + bootable install-ISO drives (causes "boot failed code 0004").
  # Runtime uses ide-hd + e1000e (in-box drivers), so virtio-win is unneeded here.

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
  shutdown_timeout = "15m"
}

# ==============================================================================
# VirtualBox builder
# ==============================================================================
source "virtualbox-iso" "server2019" {
  vm_name          = local.vm_name
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "${var.output_dir}/server2019-virtualbox"
  format           = "ova"

  disk_size = var.disk_size
  memory    = var.memory
  cpus      = var.cpus
  headless  = true

  floppy_content = {
    "Autounattend.xml" = file("${path.root}/http/autounattend-server-2019.xml")
    "setup-winrm.ps1"  = file("${path.root}/scripts/setup-winrm.ps1")
  }

  gfx_controller       = "vmsvga"
  gfx_vram_size        = 16
  guest_os_type        = "Windows2019_64"
  guest_additions_mode = "upload"
  guest_additions_path = "C:/Setup/VBoxGuestAdditions.iso"

  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nat-localhostreachable1", "on"],
    ["modifyvm", "{{.Name}}", "--clipboard-mode", "disabled"],
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
  shutdown_timeout = "15m"
}

# ==============================================================================
# Build
# ==============================================================================
build {
  name = "server2019"

  sources = [
    "source.qemu.server2019",
    "source.virtualbox-iso.server2019",
  ]

  provisioner "windows-shell" {
    inline = ["echo WinRM OK"]
  }

  # Pre-bake scarif's IIS/WebDAV/file-server features so Ansible skips the
  # per-deploy feature installs + their reboot. Tolerant 'exit 0'.
  provisioner "windows-shell" {
    inline = [
      "powershell -NoProfile -Command \"Install-WindowsFeature -Name Web-Server,Web-DAV-Publishing,Web-Dir-Browsing,Web-CGI,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Asp-Net45,Web-Http-Logging,Web-Mgmt-Console,FS-FileServer -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null; exit 0\"",
    ]
  }

  provisioner "windows-shell" {
    inline = [
      "wevtutil cl System",
      "wevtutil cl Application",
      "wevtutil cl Security",
      // Do NOT del %TEMP% here — packer runs this script from there (self-delete -> build fail).
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_dir}/server2019-manifest.json"
    strip_path = true
  }
}
