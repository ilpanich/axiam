# One instance, one key pair, one security group.
#
# The sizing rules of claude_dev/bench-vm-runbook.md §0.3 are checked by
# modules/sizing at plan time, so an undersized flavor fails before anything is
# created rather than twenty hours into a matrix whose fastest cells were
# measuring k6.

data "openstack_compute_flavor_v2" "this" {
  name = var.flavor_name
}

data "openstack_images_image_v2" "this" {
  name        = var.image_name
  name_regex  = var.image_name == null ? var.image_name_regex : null
  most_recent = true
}

data "openstack_networking_network_v2" "public" {
  name = var.network_name
}

locals {
  boot_from_volume = var.boot_volume_size > 0
  root_disk_gb     = local.boot_from_volume ? var.boot_volume_size : data.openstack_compute_flavor_v2.this.disk
}

module "sizing" {
  source = "./modules/sizing"

  flavor_name             = var.flavor_name
  vcpus                   = data.openstack_compute_flavor_v2.this.vcpus
  root_disk_gb            = local.root_disk_gb
  min_vcpus               = var.min_vcpus
  min_disk_gb             = var.min_disk_gb
  ssh_allowed_cidrs       = var.ssh_allowed_cidrs
  allow_ssh_from_anywhere = var.allow_ssh_from_anywhere
}

resource "openstack_compute_keypair_v2" "this" {
  name       = var.name
  public_key = trimspace(file(pathexpand(var.ssh_public_key_path)))
}

# The default rules (egress anywhere, IPv4 and IPv6) are kept: the VM pulls
# images, toolchains and the checkouts. Inbound is port 22 and nothing else.
resource "openstack_networking_secgroup_v2" "ssh" {
  name        = "${var.name}-ssh"
  description = "SSH only, from the operator. The benchmark stacks bind 127.0.0.1."
}

resource "openstack_networking_secgroup_rule_v2" "ssh" {
  for_each = toset(var.ssh_allowed_cidrs)

  security_group_id = openstack_networking_secgroup_v2.ssh.id
  direction         = "ingress"
  ethertype         = strcontains(each.value, ":") ? "IPv6" : "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
}

resource "openstack_compute_instance_v2" "bench" {
  name            = var.name
  flavor_id       = data.openstack_compute_flavor_v2.this.id
  key_pair        = openstack_compute_keypair_v2.this.name
  security_groups = [openstack_networking_secgroup_v2.ssh.name]

  # Booting from a volume takes the image through block_device instead.
  image_id = local.boot_from_volume ? null : data.openstack_images_image_v2.this.id

  dynamic "block_device" {
    for_each = local.boot_from_volume ? [1] : []
    content {
      source_type           = "image"
      uuid                  = data.openstack_images_image_v2.this.id
      destination_type      = "volume"
      volume_size           = var.boot_volume_size
      volume_type           = var.boot_volume_type
      boot_index            = 0
      delete_on_termination = true
    }
  }

  network {
    uuid = data.openstack_networking_network_v2.public.id
  }

  metadata = {
    purpose = "axiam-benchmarks"
  }
}
