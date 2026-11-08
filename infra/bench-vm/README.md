# The benchmark VM, with OpenTofu and five scripts

**The operator guide is [`claude_dev/bench-vm-runbook.md`](../../claude_dev/bench-vm-runbook.md).**
It says why the box is sized as it is, in what order things run, and how the comparison
round (its §9) uses the machine. This file is the map of what is in this directory.

```
infra/bench-vm/
├── run.sh                    from your PC: init/plan/apply/destroy/output/test, push, ssh, fetch, snapshot
├── tofu/                     the instance on OpenStack (Infomaniak Public Cloud)
│   ├── versions.tf           OpenTofu >= 1.6 / Terraform; provider pinned exactly; local state
│   ├── variables.tf          flavor, disk, image, network, SSH key and allowed CIDRs
│   ├── main.tf               key pair, SSH-only security group, the instance
│   ├── modules/sizing/       the sizing and exposure gate (>= 12 vCPU, >= 60 GB, no SSH from anywhere)
│   ├── outputs.tf            address, ssh command, the host facts for the run notes
│   ├── example.tfvars        copy to bench-vm.auto.tfvars (gitignored); NO SECRETS EVER
│   └── tests/                `tofu test`: offline, provider mocked
└── scripts/                  on the VM, in order; each idempotent and safe to re-run
    ├── versions.env          every pinned version, in one file
    ├── _lib.sh               the helpers, sourced by the rest
    ├── 00-host-prepare.sh    OS and size checks, upgrade, background noise off, base packages
    ├── 01-docker-k6.sh       Docker Engine >= 25, Compose >= 2.24, log rotation, pinned k6
    ├── 02-sdk-toolchains.sh  the eleven SDK toolchains
    ├── 03-checkouts.sh       axiam at the release tag, the eleven SDKs beside it
    ├── 04-verify.sh          read-only PASS/WARN/FAIL table; exit status = number of FAILs
    └── 05-qualify.sh         sysbench consistency and steal under load; go / watch / recreate
```

## The order

```
  your PC                              the VM
  ───────                              ──────
  source <project>-openrc.sh
  ./run.sh plan / apply
  ./run.sh push, ./run.sh ssh   ───▶   00-host-prepare.sh     (sudo reboot, if it says so)
                                       01-docker-k6.sh        (log out and in: docker group)
                                       docker login ghcr.io; docker login        ← a human
                                       02-sdk-toolchains.sh   (exec bash -l)
                                       03-checkouts.sh
                                       04-verify.sh           exit 0 = ready
                                       05-qualify.sh          exit 3 = recreate the VM
                                       … the round: bench-vm-runbook.md §9, in tmux
  ./run.sh fetch                ◀───   the packed results, ~/bench/logs
                                       docker logout; drop the GitHub token      ← a human
  ./run.sh snapshot, ./run.sh destroy
```

## What is not automated, on purpose

1. **Credentials.** The registry logins and the GitHub read token are typed on the VM. A
   value in cloud-init user-data is readable by every process on the VM through the
   metadata service, and a Tofu variable lands in the state.
2. **Judgement.** `05-qualify.sh` prints a verdict from operator heuristics; deciding to
   recreate the VM, and deciding the dry run is all-PASS before a 17-hour matrix, stay with
   the operator.
3. **The run.** `bench-matrix` and friends already orchestrate the cells; a wrapper around
   them would hide which step failed in a run that lasts a day.
4. **The snapshot as a resource.** OpenStack has no Tofu resource that images a running
   instance, so `run.sh snapshot` calls the OpenStack CLI.

## What was verified, and what was not

Verified on 2026-11-08 in an Ubuntu 24.04 sandbox: `tofu validate` and `tofu fmt`, the
eleven offline tests (`./run.sh test`), `shellcheck` on every script, every apt package
name resolving on Ubuntu 24.04, the PHP extensions (`sodium`, `sockets`) present in
`php8.3-cli`, `03-checkouts.sh` end to end against the real repositories (all twelve at
`v1.3.0`), `04-verify.sh`'s table, and `05-qualify.sh` end to end. Every pinned version
was confirmed to exist upstream (sources in `versions.env`).

**Not verified**: an apply against Infomaniak (no credentials in the sandbox — the first
`./run.sh apply` is yours), and the installs of scripts 01 and 02 (the sandbox has no
Docker daemon or systemd and blocks several of the download hosts). The first VM is
their test; each script stops at the first failing step, and re-running it after a fix
resumes where it stopped.

No `.terraform.lock.hcl` is committed, as in `infra/rpi5-k3s/`: the sandbox could not reach
the provider registry, and a lock file built from a local mirror records one platform's
checksum only. The provider is pinned exactly; commit the lock file your first `init` writes.
