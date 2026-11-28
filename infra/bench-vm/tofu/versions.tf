# The benchmark VM on an OpenStack cloud (Infomaniak Public Cloud).
#
# One root module: the provider needs nothing this module creates, so there is
# no reason to stage it the way infra/rpi5-k3s/ is staged.
terraform {
  # Same floor as infra/rpi5-k3s/: both OpenTofu and Terraform have everything
  # used here, and nothing in this tree is OpenTofu-only.
  required_version = ">= 1.6"

  # Local state, at the path run.sh passes with -backend-config (outside the
  # repository: ~/axiam-infra/state/bench-vm/). Declared so that path is applied
  # without the "missing backend configuration" warning.
  backend "local" {}

  required_providers {
    openstack = {
      # EXACT pin, as in infra/rpi5-k3s/. Bump deliberately. 3.4.0 was the
      # newest release published on 2026-11-08.
      source  = "terraform-provider-openstack/openstack"
      version = "3.4.0"
    }
  }
}

# No arguments on purpose. The provider reads the OS_* variables your cloud's
# `openrc` exports (OS_AUTH_URL, OS_PROJECT_ID, OS_USERNAME, OS_PASSWORD,
# OS_REGION_NAME, the domain variables), or OS_CLOUD with a clouds.yaml. A
# credential in HCL or in a tfvars file would end up in the state; in the
# environment it does not.
provider "openstack" {}
