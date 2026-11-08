output "ipv4" {
  description = "The instance's public IPv4 address."
  value       = openstack_compute_instance_v2.bench.access_ip_v4
}

output "ssh" {
  description = "How to reach it. The Ubuntu images' default user is ubuntu."
  value       = "ssh ubuntu@${openstack_compute_instance_v2.bench.access_ip_v4}"
}

output "instance_id" {
  value = openstack_compute_instance_v2.bench.id
}

# For the run notes (bench-vm-runbook.md §9.7): the host is part of the result.
output "host_for_run_notes" {
  value = {
    flavor       = var.flavor_name
    vcpus        = data.openstack_compute_flavor_v2.this.vcpus
    ram_mib      = data.openstack_compute_flavor_v2.this.ram
    root_disk    = local.boot_from_volume ? "volume" : "local"
    root_disk_gb = local.root_disk_gb
    image        = coalesce(var.image_name, "newest match of ${var.image_name_regex}")
    image_id     = data.openstack_images_image_v2.this.id
    network      = var.network_name
  }
}
