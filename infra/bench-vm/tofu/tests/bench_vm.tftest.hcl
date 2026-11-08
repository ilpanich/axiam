# Offline tests: `tofu test` (or `terraform test`, 1.7+). No cloud and no
# credentials; the provider is mocked, so these check this module's own logic,
# not the cloud's answers.
#
# The sizing gate is tested on its own in sizing.tftest.hcl: the flavor data
# source's vcpus/disk cannot be mocked, so here the gate is overridden.

mock_provider "openstack" {
  mock_data "openstack_compute_flavor_v2" {
    defaults = { id = "flavor-id" }
  }
  mock_data "openstack_images_image_v2" {
    defaults = { id = "image-id" }
  }
  mock_data "openstack_networking_network_v2" {
    defaults = { id = "network-id" }
  }
}

override_module {
  target = module.sizing
}

variables {
  flavor_name         = "a16-ram64-disk0"
  boot_volume_size    = 100
  ssh_allowed_cidrs   = ["203.0.113.7/32"]
  ssh_public_key_path = "tests/fixture.pub"
}

run "boot_from_volume_uses_block_device_only" {
  command = plan

  # image_id is left unset (the provider computes it), so the image travels
  # only through the block device.
  assert {
    condition     = one(openstack_compute_instance_v2.bench.block_device).source_type == "image" && one(openstack_compute_instance_v2.bench.block_device).uuid == "image-id"
    error_message = "The boot volume is created from the selected image."
  }
  assert {
    condition     = one(openstack_compute_instance_v2.bench.block_device).volume_size == 100 && one(openstack_compute_instance_v2.bench.block_device).boot_index == 0 && one(openstack_compute_instance_v2.bench.block_device).delete_on_termination
    error_message = "The boot volume has the requested size, is the boot disk, and goes with the instance."
  }
}

run "local_disk_boot_uses_the_image_directly" {
  command = plan

  variables {
    boot_volume_size = 0
  }

  assert {
    condition     = openstack_compute_instance_v2.bench.image_id == "image-id"
    error_message = "A local-disk boot takes the image directly."
  }
  assert {
    condition     = length(openstack_compute_instance_v2.bench.block_device) == 0
    error_message = "A local-disk boot has no block_device."
  }
}

run "inbound_is_ssh_from_the_operator_only" {
  command = plan

  variables {
    ssh_allowed_cidrs = ["203.0.113.7/32", "2001:db8::/64"]
  }

  assert {
    condition     = length(openstack_networking_secgroup_rule_v2.ssh) == 2
    error_message = "One rule per allowed CIDR, nothing else."
  }
  assert {
    condition     = alltrue([for r in openstack_networking_secgroup_rule_v2.ssh : r.direction == "ingress" && r.protocol == "tcp" && r.port_range_min == 22 && r.port_range_max == 22])
    error_message = "Every inbound rule is TCP 22."
  }
  assert {
    condition     = openstack_networking_secgroup_rule_v2.ssh["2001:db8::/64"].ethertype == "IPv6" && openstack_networking_secgroup_rule_v2.ssh["203.0.113.7/32"].ethertype == "IPv4"
    error_message = "Each CIDR gets the rule of its address family."
  }
  assert {
    condition     = openstack_compute_instance_v2.bench.security_groups == toset(["axiam-bench-ssh"])
    error_message = "The instance carries only the SSH group."
  }
}

run "rejects_a_malformed_cidr" {
  command = plan

  variables {
    ssh_allowed_cidrs = ["203.0.113.7"]
  }
  expect_failures = [var.ssh_allowed_cidrs]
}

run "rejects_a_tiny_boot_volume" {
  command = plan

  variables {
    boot_volume_size = 10
  }
  expect_failures = [var.boot_volume_size]
}
