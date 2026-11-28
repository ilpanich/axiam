# The sizing and exposure rules of claude_dev/bench-vm-runbook.md §0.3, as plain
# inputs, so `tofu test` can exercise them without a cloud: the flavor data
# source's vcpus/disk are not mockable (they are filter arguments that the
# provider fills in on read).

variable "flavor_name" {
  type = string
}

variable "vcpus" {
  type = number
}

variable "root_disk_gb" {
  type = number
}

variable "min_vcpus" {
  type = number
}

variable "min_disk_gb" {
  type = number
}

variable "ssh_allowed_cidrs" {
  type = list(string)
}

variable "allow_ssh_from_anywhere" {
  type = bool
}

locals {
  open_cidrs = [for c in var.ssh_allowed_cidrs : c if c == "0.0.0.0/0" || c == "::/0"]
}

resource "terraform_data" "gate" {
  input = {
    vcpus        = var.vcpus
    root_disk_gb = var.root_disk_gb
  }

  lifecycle {
    precondition {
      condition     = var.vcpus >= var.min_vcpus
      error_message = "Flavor ${var.flavor_name} has ${var.vcpus} vCPUs; at least ${var.min_vcpus} are required. k6 runs beside the stacks and used ~5 cores on AXIAM's fastest cells in run 5 (bench-vm-runbook.md §0.3)."
    }
    precondition {
      condition     = var.root_disk_gb >= var.min_disk_gb
      error_message = "The root disk would be ${var.root_disk_gb} GB; at least ${var.min_disk_gb} GB is required. Pick a flavor with a larger local disk, or set boot_volume_size (a -disk0 flavor needs it)."
    }
    precondition {
      condition     = length(local.open_cidrs) == 0 || var.allow_ssh_from_anywhere
      error_message = "ssh_allowed_cidrs contains ${join(", ", local.open_cidrs)}. Use your own address, or set allow_ssh_from_anywhere = true if you mean it."
    }
  }
}
