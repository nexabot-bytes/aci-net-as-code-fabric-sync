# ACI Fabric Sync

**Bidirectional synchronization between a Cisco ACI fabric and YAML + Terraform**,
built on top of [Cisco Network-as-Code (NaC)](https://netascode.cisco.com/).

Cisco NaC pushes YAML to a fabric (greenfield). ACI Fabric Sync adds the missing
direction — **brownfield**: it reads any existing fabric, writes its complete
configuration as NaC YAML, brings it under Terraform management **without touching
it**, and keeps fabric, YAML and Terraform state identical from then on.

```
Existing fabric, never managed as code:

  nac.py bootstrap --adopt      one command, read-mostly
  nac.py plan                   -> "No changes."      your fabric is now code
```

## How it works

The tool contains **no hard-coded object catalog**. At runtime it parses the source
of the Terraform NaC modules (downloaded by `terraform init`) and derives the
APIC-class → YAML mapping from them. It therefore works on **any fabric** and follows
the NaC data model exactly. Four capture passes (flat lists, global singletons,
hierarchical tenants/access, plus ~60 dedicated handlers for special cases) produce a
complete photo of the fabric in `data/*.nac.yaml`.

## Commands

| Command | Description | Writes to fabric |
|---|---|---|
| `capture` | Photograph the fabric → write `data/*.nac.yaml` (full replacement — a photo, not a merge) | No (read-only) |
| `validate` | Validate the YAML against the official NaC schema (`nac-validate`) | No |
| `plan` | `terraform plan` — show every difference between fabric, YAML and state | No |
| `adopt` | **Write-free adoption**: bulk-generate `terraform import` blocks from the plan JSON, verify each object actually exists on the APIC (per-class), and import them into the state | Imports only (+ minor in-place alignments) |
| `sync` | `terraform apply` — make the fabric match the YAML. Creates, updates, rebuilds | Yes |
| `drift` | **Read-only 3-way audit**: fabric vs YAML vs Terraform state. Catches out-of-band creations that `terraform plan` cannot see (objects in neither YAML nor state). Exit code 2 on drift — cron/CI friendly | No |
| `bootstrap` | `capture` + `validate` + `plan`; add `--adopt` to chain the adoption | Only with `--adopt` |

Common options: `-y/--yes` (no prompt), `--force` (override the destroy guard),
`-v/--verbose`.

## Safety guarantees

- **Destroy guard** — `sync` and `adopt` refuse to run if the plan would destroy even
  a single object. Overriding requires an explicit `--force`.
- **Secret-overwrite guard** — `sync` refuses to *create* a secret-bearing object
  (RADIUS/TACACS/LDAP/user, remote location, keyring, MACsec keychain...) that
  already exists on the fabric: that would overwrite the real secret with a
  placeholder. Adopt existing ones with `adopt` (import — the secret is never
  touched); all other attributes are then fully managed. Provide real secrets
  only at intentional creation time.
- **`capture` and `plan` never write** to the fabric.
- **Secrets are never stored**: passwords/keys the APIC does not expose are written
  as documented placeholders (NaC modules `ignore_changes` them), and no credential
  is ever committed — `main.tf`, `data/` and the Terraform state are git-ignored.
- **Photo semantics**: every `capture` fully replaces the previous YAML, including
  sections that became empty — no stale objects can survive.

## Quick start

```bash
git clone https://github.com/nexabot-bytes/aci-net-as-code-fabric-sync
cd aci-net-as-code-fabric-sync
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

cp main.tf.example main.tf                    # or use environment variables:
export APIC_URL=https://<apic> APIC_USER=admin APIC_PWD=<password>       # nac.py
export ACI_URL=$APIC_URL ACI_USERNAME=$APIC_USER ACI_PASSWORD=$APIC_PWD # terraform

terraform init                                # downloads the NaC modules
.venv/bin/python tools/nac.py bootstrap --adopt   # capture + validate + plan + adopt
.venv/bin/python tools/nac.py plan                # -> "No changes."
```

## Typical workflows

**Day 0 — take over an existing fabric (brownfield)**
```
bootstrap --adopt        # photo + validation + write-free adoption
plan                     # "No changes." — done
```

**Daily operations (GitOps)**
```
edit data/*.nac.yaml  →  plan  →  sync        # YAML is the source of truth
```

**Someone changed something in the APIC GUI**
```
drift                    # 3-way audit — also catches NEW objects plan can't see
capture                  # accept the change: pull it into the YAML,  or
sync                     # reject the change: push the YAML back over it
```

**Disaster recovery — rebuild an empty fabric from the recipe**
```
# fabric is blank, data/ holds the last photo (keep it backed up!)
plan                     # everything "to add", 0 to destroy
sync                     # recreates the entire configuration in one apply
plan                     # "No changes."
```
> Never run `capture` against a blank fabric you intend to rebuild — a capture is a
> photo, and it would replace your recipe with emptiness.

## Golden rules

| `plan` says | Meaning | Do |
|---|---|---|
| `No changes` | Everything in sync | nothing ✓ |
| `to add` (objects exist on fabric) | Terraform doesn't know them yet | `adopt` |
| `to add` (objects don't exist) | To be created | `sync` |
| `to change` | Attribute drift | `sync` |
| `to destroy` | ⚠️ stop and understand first | `capture` to re-sync, `--force` only knowingly |

## Managing secrets

The APIC never returns passwords or keys (write-only attributes) — no tool can
read them back. ACI Fabric Sync therefore manages secret-bearing objects with a
simple doctrine: **everything is managed except the secret itself.**

| Object | Secret (never captured) | Managed attributes |
|---|---|---|
| RADIUS / TACACS / LDAP providers | key / monitoring password | host, port, timeouts, monitoring, mgmt EPG... |
| Local users (`aaaUser`) | password (constant placeholder `Placeholder123!`) | status, email, expiry, names, domains/roles |
| Remote locations (`fileRemotePath`) | password / SSH keys | host, protocol, path, port, username |
| Key rings (`pkiKeyRing`) | certificate + private key | name, CA reference, modulus |
| MACsec keychains | pre-shared keys (hex placeholder) | structure, key names, lifetimes |
| OSPF interface auth (`ospfIfP`) | `authKey` (placeholder `NacKey12`) | **auth type + key id are captured** — otherwise a sync would silently disable MD5 auth on a brownfield |
| BGP peers (`bgpPeerP`) | session password (omitted — the APIC preserves it) | all 20+ peer attributes |

How it works:

- **Existing objects (brownfield)** — adopt them with `adopt` (Terraform *import*:
  the object is read, never written — the real secret stays in place). The
  **secret-overwrite guard** enforces this: `sync` refuses to *create* a
  secret-bearing object whose DN already exists on the fabric.
- **New objects** — put the real secret in the YAML at creation time (it is
  posted once, thenignored via `ignore_changes`), and remove it from the file
  afterwards if you don't want it on disk.
- **Not manageable** — `mcp` and `smart-licensing` cannot even be created without
  their secret (kept disabled in `data/modules.nac.yaml`; enable them once you
  provide the secret). `snmp-trap` destinations re-post their community on every
  apply (no `ignore_changes` upstream) and are therefore not managed.
- EIGRP has no secret at all in the NaC data model.

APIC gotcha worth knowing: a MACsec pre-shared key's length must match the
cipher suite (64 hex chars = 256-bit ciphers), and OSPF *simple* auth keys are
limited to 8 characters.

## Both interface paradigms supported

ACI has two mutually exclusive (per workspace) interface configuration styles in
the NaC data model: the **classic** profiles/selectors model and the **per-port**
model (`new_interface_configuration`, ACI ≥ 5.2). `capture` reads both and
**auto-detects the paradigm**: on a pure per-port fabric it sets the flag
automatically; on a mixed fabric it warns and manages the classic style while
still capturing the per-port objects read-only. Node registration
(`fabricNodeIdentP`) is **disabled by default** (`data/modules.nac.yaml`) so node
entries can never re-register a switch — opt in explicitly for greenfield use.

## Validation status

Verified against APIC 6.0(7e): **181 / 195 NaC modules** proven by full round-trip
(fabric → YAML → fabric, attribute-by-attribute comparison, `plan = No changes`),
including an end-to-end factory-reset test: blank fabric → adopt → *No changes*,
full config restored → **701 objects imported (read-only), 0 destroyed** → *No
changes*, and a complete rebuild of 704 objects from YAML alone.

The 14 remaining modules are documented limitations (write-only secrets the APIC
never returns, classes absent from the 6.0 data model, VMM integrations requiring
vCenter, node registration). Details in `tools/MODULE_COVERAGE.md`.

## Known limitations

- Covers what the **NaC data model** models. APIC objects outside it are neither
  captured nor destroyed — they simply remain unmanaged.
- Secrets (RADIUS/TACACS keys, passwords, tokens) cannot round-trip: they are set
  at creation time and ignored afterwards.
- Objects whose DN contains `:` (e.g. MAC-tag policies) cannot be *imported*
  (ACI provider limitation) — `adopt` automatically falls back to creating them.

## Requirements

- Python ≥ 3.9 (PyYAML), Terraform ≥ 1.7
- Network reachability to the APIC (HTTPS)
- Read/write APIC account for `sync`/`adopt`; read-only is enough for
  `capture`/`plan`/`bootstrap`
