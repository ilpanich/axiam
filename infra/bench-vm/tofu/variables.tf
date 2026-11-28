variable "name" {
  description = "Name of the instance, and the prefix of the key pair and security group."
  type        = string
  default     = "axiam-bench"
}

variable "flavor_name" {
  description = <<-EOT
    The flavor. 16 vCPU is recommended, 12 the minimum (claude_dev/bench-vm-runbook.md
    §0.3: k6 runs beside the stacks, and run 5 measured it at about 5 cores on
    AXIAM's fastest cells). List them with `openstack flavor list --sort-column VCPUs`.
  EOT
  type        = string
}

variable "min_vcpus" {
  description = <<-EOT
    The apply refuses a flavor with fewer vCPUs than this. Lower it only for a
    deliberate smoke test: a smaller box flags AXIAM's fastest cells as
    generator_saturated and understates whichever target is fastest.
  EOT
  type        = number
  default     = 12
}

variable "min_disk_gb" {
  description = "The apply refuses less root disk than this (the flavor's local disk, or boot_volume_size). The eleven SDK toolchains alone take 20-25 GB."
  type        = number
  default     = 60
}

variable "boot_volume_size" {
  description = <<-EOT
    0: boot from the flavor's local disk. N > 0: boot from a new N GB volume
    instead (required for a `-disk0` flavor). Volumes are network storage, so
    database fsync latency differs from a local disk; it is fair either way,
    because every target shares it, but write down which one the run used.
  EOT
  type        = number
  default     = 0

  validation {
    condition     = var.boot_volume_size == 0 || var.boot_volume_size >= 20
    error_message = "boot_volume_size is 0 (local disk) or at least 20."
  }
}

variable "boot_volume_type" {
  description = "Volume type for the boot volume (`openstack volume type list`). null: the cloud's default."
  type        = string
  default     = null
}

variable "image_name" {
  description = <<-EOT
    Exact image name. null: the newest public image matching image_name_regex.
    Set it to the name of a snapshot taken with `run.sh snapshot` to boot an
    already provisioned VM.
  EOT
  type        = string
  default     = null
}

variable "image_name_regex" {
  description = "Used when image_name is null. Must match an Ubuntu 24.04 LTS image: the scripts are written for it."
  type        = string
  default     = "^Ubuntu 24\\.04"
}

variable "network_name" {
  description = "The public network (`openstack network list`). On Infomaniak it is usually ext-net1."
  type        = string
  default     = "ext-net1"
}

variable "ssh_public_key_path" {
  description = "Public key installed for the image's default user (ubuntu)."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "ssh_allowed_cidrs" {
  description = <<-EOT
    Where SSH may come from: your own address, e.g. ["203.0.113.7/32"]
    (`curl -fsS https://ifconfig.me`). Port 22 is the only inbound port; the
    benchmark stacks bind loopback and must stay unreachable.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.ssh_allowed_cidrs) > 0 && alltrue([for c in var.ssh_allowed_cidrs : can(cidrhost(c, 0))])
    error_message = "ssh_allowed_cidrs needs at least one valid CIDR, e.g. \"203.0.113.7/32\"."
  }
}

variable "allow_ssh_from_anywhere" {
  description = "Must be true to accept 0.0.0.0/0 or ::/0 in ssh_allowed_cidrs. Key-only SSH survives it, but nothing needs it."
  type        = bool
  default     = false
}
