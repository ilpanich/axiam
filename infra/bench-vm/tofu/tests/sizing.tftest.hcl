# The sizing and exposure gate (modules/sizing), with the flavor's figures as
# plain inputs. `tofu test` from the tofu/ directory.

variables {
  flavor_name             = "a16-ram64-disk0"
  vcpus                   = 16
  root_disk_gb            = 100
  min_vcpus               = 12
  min_disk_gb             = 60
  ssh_allowed_cidrs       = ["203.0.113.7/32"]
  allow_ssh_from_anywhere = false
}

run "accepts_the_recommended_size" {
  command = plan
  module {
    source = "./modules/sizing"
  }
}

run "accepts_the_minimum" {
  command = plan
  module {
    source = "./modules/sizing"
  }
  variables {
    vcpus        = 12
    root_disk_gb = 60
  }
}

run "rejects_the_a8_flavor" {
  command = plan
  module {
    source = "./modules/sizing"
  }
  variables {
    flavor_name  = "a8-ram32-disk20-perf1"
    vcpus        = 8
    root_disk_gb = 100
  }
  expect_failures = [terraform_data.gate]
}

run "rejects_the_20_gb_disk" {
  command = plan
  module {
    source = "./modules/sizing"
  }
  variables {
    root_disk_gb = 20
  }
  expect_failures = [terraform_data.gate]
}

run "rejects_ssh_from_anywhere" {
  command = plan
  module {
    source = "./modules/sizing"
  }
  variables {
    ssh_allowed_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [terraform_data.gate]
}

run "accepts_ssh_from_anywhere_only_when_explicit" {
  command = plan
  module {
    source = "./modules/sizing"
  }
  variables {
    ssh_allowed_cidrs       = ["::/0"]
    allow_ssh_from_anywhere = true
  }
}
