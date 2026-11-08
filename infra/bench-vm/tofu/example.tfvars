# Copy to bench-vm.auto.tfvars in this directory (gitignored):
#
#     cp example.tfvars bench-vm.auto.tfvars
#
# NO SECRETS HERE. The OpenStack credentials come from your openrc, in the
# environment of the command (run.sh refuses to start without OS_AUTH_URL or
# OS_CLOUD). Nothing in this file is sensitive, and the state holds only the
# public key, the instance's id and its address.

# REQUIRED. A 16-vCPU flavor (12 minimum). Pick one from
# `openstack flavor list --sort-column VCPUs`.
flavor_name = "a16-ram64-disk0"

# A -disk0 flavor boots from a volume; give it one (GB). With a flavor that has
# a large local disk (…-disk80-perf1 or similar), set 0.
boot_volume_size = 100

# REQUIRED. Your own address: curl -fsS https://ifconfig.me
ssh_allowed_cidrs = ["203.0.113.7/32"]

# Optional; the defaults are shown.
# name                = "axiam-bench"
# network_name        = "ext-net1"
# ssh_public_key_path = "~/.ssh/id_ed25519.pub"
# image_name_regex    = "^Ubuntu 24\\.04"

# To boot the snapshot of an already provisioned VM (run.sh snapshot):
# image_name = "axiam-bench-provisioned"
