# PR H — contract 1.50 (C-0): progress ledger

Temporary. Deleted in the PR's final commit. Branch `docs/contract-1.50`, cut
from `1cb1371` (the merge of #496, PR G2). Brief: `dogfooding-findings-fix-plan.md` §6 C-0.

Resume check-ins (send_later): `trig_01QoSznG8scYRczWhYxqJqv9` (fires
2026-09-24T01:40Z), `trig_01RS29Nv81YvNbFnrjT93QxF` (fires 2026-09-24T05:40Z).
Delete both once the PR is open and green.

- [x] 0. Resume check-ins armed, ledger written
- [x] 1. SAGE boot — MCP not connected, noted below
- [ ] 2. Citations re-validated against `1cb1371`; S-3/S-4/S-7/S-9/S-10 read in code; drift noted
- [ ] 3. Contract amendments 1–8 of §6 C-0 (incl. §27.5 decision, §27.10 tier gap)
- [ ] 4. Version bump to 1.50 + every gate that moves with it; drift check red only for SDK re-vendor
- [ ] 5. Records: CHANGELOG, roadmap T22.15, EXECUTED block in §6 C-0, §13 item 1, threat model verified
- [ ] 6. Gates run (doc links, docs lint, contract/spec checks); signed commits
- [ ] 7. PR opened, subscribed, green
- [ ] 8. Next-session prompt (I₁ = C-1, Rust SDK) printed

## Notes (half-done state, findings)

- Step 1: no SAGE MCP server is connected in this session (none of its tools
  exist); continued without it.
- **Version-number collision (found at step 2, blocks step 4).** Contract
  **1.50 already exists on main**: `d5a6811` (2026-09-18, "mark the DCR initial
  access token Sensitive — contract 1.50") is the top Breaking Changes Log entry,
  and all eleven SDK repositories' `main` vendor that exact `CONTRACT.md`
  (sha256 `d877a1a05e9a…`, identical to `1cb1371`'s). The plan (§3, §6 C-0) was
  written as if 1.50 were free. C-0 therefore cannot reuse 1.50; next free is
  **1.51** (and C-12 would become 1.52). Asked the user; steps 2–3 proceed
  number-agnostic meanwhile.
