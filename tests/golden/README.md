# tests/golden — jeu de test persistant (méthode B)

Ce dossier contient le **jeu de test golden** décrit dans
[../../tools/TEST_PLAN.md](../../tools/TEST_PLAN.md) : pour chaque module NaC, **un
objet** écrit avec **TOUS ses paramètres** en **valeurs non-défaut**. Les objets
**s'accumulent** ici (1 fichier par section, même schéma que `data/*.nac.yaml`).

But : prouver, module par module, que `nac.py capture` fait l'aller-retour
`fabric → YAML` de **chaque attribut**. Un attribut manqué retombe au défaut → la
comparaison `test_nac.py test` le révèle.

## Conventions

- **Préfixe `GOLD-` / `GOLDEN`** sur tous les noms d'objets de test (isolation,
  cleanup facile, jamais de collision avec la vraie config).
- **Valeurs non-défaut** partout : si l'attribut a un défaut, on met autre chose,
  sinon un attribut manqué passerait inaperçu.
- **Additif et namespacé uniquement** : tenants (espacés par nom), objets access
  nommés. **JAMAIS de singletons** (DN `default`) ici — ils écraseraient la vraie
  config.
- Mêmes fichiers de section que `data/` : `tenants.nac.yaml`,
  `access_policies.nac.yaml`, etc.

## Cycle de test d'un module (méthode B — détaillé)

Vue d'ensemble :

```
[0] nac.py capture && nac.py plan            → "No changes" (état sain)
[1] écrire l'objet ici, tous attrs non-défaut (PERMANENT, il s'accumule)
[2] copier tests/golden/*.nac.yaml → data/   puis  nac.py sync  (garde-fou destroy)
[3] nac.py capture                            → relit la fabric
[4] test_nac.py test tests/golden data        → compare param-par-param
[5] nac.py plan                               → "No changes" (idempotence)
[6] corriger les gaps (handler/capture), re-tester, cocher dans MODULE_COVERAGE.md
```

### Étape 0 — BASELINE : partir d'un état sain

```bash
python tools/nac.py capture      # aspire la fabric → data/*.nac.yaml
python tools/nac.py plan          # terraform plan
```

- **But** : prouver que `data/` est synchrone avec la fabric **avant** de toucher à
  quoi que ce soit.
- **Attendu** : `No changes. Your infrastructure matches the configuration.`
- **Si ce n'est PAS le cas** : on **s'arrête**. Un plan qui montre `change`/`destroy`
  = `data/` et la fabric désynchronisés → appliquer maintenant pourrait écraser la
  vraie config. On recapture / on investigue d'abord.
- **Pourquoi** : filet n°1. Tout le reste suppose un état zéro-diff.

### Étape 1 — AJOUTER l'objet dans le golden (permanent)

Éditer `tests/golden/<section>.nac.yaml`.

- **But** : décrire l'objet avec **TOUS ses paramètres** en valeurs **non-défaut**.
- **Règle clé** : l'objet **reste** ici — il s'accumule. À terme `tests/golden/` =
  un environnement de test complet rejouable « d'une frappe ».
- **Pourquoi non-défaut** : si on oublie de capturer un attribut, il retombe à son
  défaut côté capture. Une valeur **non-défaut** rend ce gap **visible** à l'étape 4.
  Mettre la valeur défaut masquerait un attribut manqué (faux positif).

### Étape 2 — PUSH : pousser le golden sur la fabric

> ⚠️ **NE PAS** faire `cp tests/golden/tenants.nac.yaml data/tenants.nac.yaml` : ça
> **écrase** la vraie config (tous les vrais tenants passeraient en `to destroy`).
> Terraform lit *tous* les `*.nac.yaml` de `data/` et les **fusionne** → on dépose le
> golden dans un **fichier séparé** `data/_golden.nac.yaml`, qui s'ajoute sans clobber.

> ⚠️⚠️ **DÉFINITION UNIQUE du tenant golden** : à partir de la 2ᵉ itération, le tenant
> `GOLDEN` est **déjà** dans `data/tenants.nac.yaml` (réécrit par la capture). Si on
> dépose AUSSI le golden complet dans `data/_golden.nac.yaml`, le module NaC **fusionne
> et CONCATÈNE les listes** (nodes, loopbacks, static_routes…) → clés dupliquées →
> `Error: Duplicate object key`. **Avant le push**, retirer `GOLDEN` de
> `data/tenants.nac.yaml` pour qu'il ne soit défini **qu'une seule fois** (dans
> `_golden.nac.yaml`). La capture le réécrira ensuite dans `tenants.nac.yaml`.

```bash
cp tests/golden/tenants.nac.yaml data/_golden.nac.yaml   # fichier SÉPARÉ (merge additif)
# retirer GOLDEN de data/tenants.nac.yaml (source unique) :
python - <<'PY'
import yaml; p="data/tenants.nac.yaml"; d=yaml.safe_load(open(p))
d["apic"]["tenants"]=[t for t in d["apic"]["tenants"] if t.get("name")!="GOLDEN"]
open(p,"w").write("---\n"+yaml.safe_dump(d,sort_keys=False,allow_unicode=True))
PY
python tools/nac.py plan                                  # probe : doit dire "0 to destroy"
python tools/nac.py sync --yes                            # = terraform apply, AVEC garde-fou
```

- **But** : créer réellement l'objet sur la fabric.
- **Probe `plan` d'abord** : lecture seule, prouve que la fusion est additive
  (`X to add, 0 to change, 0 to destroy`). Si ce n'est pas le cas → **stop**.
- **Garde-fou anti-destruction** : `sync` relance un `plan`, compte les `to destroy`,
  et **refuse d'appliquer si destroy ≥ 1** (`--force` pour outrepasser — à ne PAS
  utiliser ici).
- **Si le plan montre du `destroy`** : `sync` abandonne seul → investiguer (golden mal
  écrit, dépendance manquante, mauvais nom de fichier…) avant de réessayer.
- **Sécurité** : on dépose dans `data/` car Terraform ne lit que
  `yaml_directories = ["data"]`. Snapshot APIC `Avec config` = filet n°2.

### Étape 3 — CAPTURE : relire la fabric

```bash
python tools/nac.py capture              # fabric (avec l'objet neuf) → data/
rm -f data/_golden.nac.yaml              # IMPORTANT : retirer le fichier séparé (doublon)
```

- **But** : refaire l'aller-retour `fabric → YAML`. C'est **ça** qu'on teste : la
  fabric contient l'objet, on vérifie que `capture` le ramène **fidèlement**.
- **Attendu** : `data/<section>.nac.yaml` contient l'objet `GOLD-…` avec ses
  attributs tels que la fabric les a stockés.
- **Doublon à retirer** : après capture, l'objet est dans `data/tenants.nac.yaml`
  (réécrit par la capture) **ET** dans `data/_golden.nac.yaml` → supprimer ce dernier,
  sinon le `plan` de l'étape 5 voit l'objet en double.

### Étape 4 — COMPARE : param-par-param

```bash
python tools/test_nac.py test tests/golden data
```

- **But** : comparer ce qu'on a **envoyé** (`tests/golden/`) à ce qui a été
  **recapturé** (`data/`), attribut par attribut, par nom/clé d'objet.
- **Sortie** : `identiques: N   differents: M   manquants: K` + la liste des écarts
  (`✗ …/qos_class: 'level1' != 'unspecified'` = attribut non capturé ;
  `✗ MANQUANT …/GOLD-ExtEPG` = objet entier non capturé).
- **Critère de réussite** : `differents: 0` et `manquants: 0` → **VERDICT 100% IDENTIQUE**.
- **Lecture des écarts** :
  - `!= 'default'` → attribut perdu par la capture (ou mapping var≠champ) → gap à
    corriger (étape 6).
  - `!= 'autre valeur'` → l'APIC a normalisé/transformé la valeur (casse, format) →
    corriger le handler, ou aligner le golden sur la forme canonique.

### Étape 5 — IDEMPOTENCE

```bash
python tools/nac.py plan                  # doit redire "No changes"
```

- **But** : prouver qu'après capture, rejouer Terraform ne produit **aucune** dérive.
- **Attendu** : `No changes`. Si le plan veut re-changer l'objet créé, c'est qu'un
  attribut fait un aller-retour instable → à corriger.

### Étape 6 — CORRIGER les gaps, re-tester, COCHER

- Pour chaque écart de l'étape 4 : ajuster le **handler d'attribut** ou la **logique
  de capture** dans `nac.py` (patterns `direct/bool/num0/float/list/flag/const`, ou un
  remap curaté `var≠champ`).
- Reboucler **4 → 5** jusqu'à `0 diff / 0 manquant / No changes`.
- Cocher le module dans [../../tools/MODULE_COVERAGE.md](../../tools/MODULE_COVERAGE.md)
  (`TODO`/`PARTIAL` → `DONE`) et noter dans [../../tools/avancement.md](../../tools/avancement.md).

### Nettoyage (entre deux modules / en fin de session)

L'objet golden **reste** dans `tests/golden/` (accumulation voulue). La copie de
travail dans `data/` doit, elle, refléter la vraie fabric :

- on **garde** l'objet sur la fabric pour le « test d'une frappe » final → rien à
  faire, il est déjà dans `data/` après capture ;
- on veut **retirer** l'objet de la fabric → l'enlever de `data/`, `nac.py sync`
  (destroy ciblé, sous confirmation), puis `capture` pour resynchroniser.

### Le « test d'une frappe » (final, plusieurs modules golden accumulés)

```
1. fabric → snapshot BLANK (configImportP, importType:replace, adminSt:triggered)
2. cp tests/golden/* data/  &&  terraform apply        # recrée TOUT le golden
3. python tools/nac.py capture
4. python tools/test_nac.py test tests/golden data     # verdict global, tous modules
5. fabric → snapshot "Avec config" (restaure la vraie config utilisateur)
```

> ⚠️ Sécurité : **toujours `capture` avant `sync`**, et le garde-fou abandonne si
> le plan détruit ≥1 objet. Snapshot APIC `Avec config` = filet.

## Dépendances externes des objets golden

Certains objets référencent des objets déjà présents sur la fabric (pour rester
légers). Notés ici :

| Objet golden | Dépend de (déjà sur la fabric) |
|---|---|
| `GOLDEN` tenant → L3Out | routed domain `Test_L3DOM_Standard` (access_policies) |

## Modules couverts par le golden

| # | Module | Classe | Fichier | Statut |
|---|---|---|---|---|
| 1 | external-endpoint-group | l3extInstP | tenants.nac.yaml | ✅ **VALIDÉ méthode B** — 31 attrs, 100% round-trip, plan No changes (2026-06-30) |
| 2 | l3out-node-profile | l3extLNodeP | tenants.nac.yaml | ✅ **VALIDÉ méthode B** — nodes/loopbacks/static_routes/next_hops, 45 attrs (2026-06-30) |
| 3 | l3out-interface-profile | l3extLIfP | tenants.nac.yaml | ✅ **interface SVI** — description/autostate/mac/mode/scope ajoutés, 60 attrs (2026-06-30). Reste : floating SVI, ospf/eigrp/pim/igmp/nd profiles |
| 4 | bgp-peer (l3out interface) | bgpPeerP | tenants.nac.yaml | ✅ **20 attrs** — flags ctrl/peerCtrl/privateASctrl/addrTCtrl reversés + bgpAsP/bgpLocalAsnP (2026-06-30). Gotcha ACI : remove-all exige remove-exclusive |
| 5 | ospf/bfd interface profile | ospfIfP/bfdIfP | tenants.nac.yaml | ✅ bloc `ospf:` (name+policy) + `bfd_policy` (2026-06-30). Auth OSPF = secret, omis. Réfs policies tenant GOLD-OSPF-IfPol/GOLD-BFD-IfPol |
| 6 | endpoint-security-group | fvESg | tenants.nac.yaml | ✅ attrs + vrf + tag_selectors + ip_subnet_selectors, 95 attrs (2026-06-30). Gotcha : instrImedcy KO en APIC 6.0(7e). Reste : epg/ip-external selectors, contrats |
| 7 | route-control-route-map | rtctrlProfile | tenants.nac.yaml (policies) | ✅ primaire + **contexts** (action/order/set_rule/match_rules), 102 attrs (2026-06-30). Réfs set_rules/match_rules tenant |
| 8 | set-rule / match-rule | rtctrlAttrP / rtctrlSubjP | tenants.nac.yaml (policies) | ✅ clauses set (community/tag/weight/next_hop/preference/metric/metric_type) + prefixes match, 115 attrs (2026-06-30). A adopté un prefix brownfield existant |
| 9 | access-leaf-interface-selector | infraHPortS | access_policies.nac.yaml | ✅ name/desc + policy_group(+type) + port_blocks, exclut profils system-*, 122 attrs (2026-06-30). A adopté 15 objets sélecteurs brownfield |
| 10 | imported-contract | vzCPIf | tenants.nac.yaml | ✅ name + tenant/contract (vzRsIf), 124 attrs (2026-06-30). Data model : clés `tenant`/`contract` |
| 11 | data-plane-policing-policy | qosDppPol | access_policies.nac.yaml | ✅ 22 attrs (retiré de PHASE2 ; fix _RE_BOOL implicite), 139 attrs (2026-06-30) |
| 12 | access-monitoring-policy | monInfraPol | access_policies.nac.yaml | ✅ name + fault_severity_policies (class->faults), 145 attrs (2026-06-30). Scope = classe infra |
| 13 | default-route-leak (l3out) | l3extDefaultRouteLeakP | tenants.nac.yaml | ✅ bloc default_route_leak_policy (always/criteria/context_scope/outside_scope), 149 attrs (2026-06-30) |
| 14 | monitoring-policy-custom | monFabricPol | fabric_policies.nac.yaml | ✅ fabric monitoring (fault_severity), capture généralisée access+fabric, 155 attrs (2026-06-30) |
| 15 | interface-type | infraRsPortDirection | interface_policies.nac.yaml | ✅ port uplink/downlink -> interface_policies.nodes ; fix SECTION_OUT, 159 attrs (2026-06-30) |
| 16 | interface-shutdown | fabricRsOosPath | interface_policies.nac.yaml | ✅ port shutdown (blacklist), fusion type+shutdown ; fix _keyof ; a adopté eth1/48 brownfield, 162 attrs (2026-06-30) |
| 17 | fabric-leaf-interface-selector | fabricLFPortS | fabric_policies.nac.yaml | ✅ sélecteur ports fabric (chaîne profil+PG+blocks), miroir de #9, 166 attrs (2026-06-30) |
| 18 | fabric-spine-interface-selector | fabricSFPortS | fabric_policies.nac.yaml | ✅ sélecteur ports spine fabric, capture généralisée leaf+spine, 170 attrs (2026-06-30). Pas de module NaC pour le PG spine |
| 19 | fabric-scheduler | trigSchedP | fabric_policies.nac.yaml | ✅ scheduler + recurring_windows ; filtre uid==0 (exclut système), 174 attrs (2026-06-30) |
| 20 | firmware + maintenance group | firmwareFwP/maintMaintP | node_policies.nac.yaml | ✅ update_groups + scheduler (réf #19), couvre les 2 modules, 175 attrs (2026-06-30). Node block non testé (node_registration) |
| 21 | bfd-policy | bfdIpv4InstPol | access_policies.nac.yaml | ✅ timers BFD globaux -> switch_policies, 182 attrs (2026-06-30). Piège : startupIntvl=défaut auto-APIC non capturé |
| 22 | psu-policy | psuInstPol | fabric_policies.nac.yaml | ✅ redondance alim (admin_state) -> fabric switch_policies, 183 attrs (2026-06-30) |
| 23 | config-export | configExportP | fabric_policies.nac.yaml | ✅ export config (snapshot local) + scheduler, exclut système/snapshot-mechanism, 187 attrs (2026-06-30) |
| 24 | macsec-parameters-policy | macsecParamPol | access_policies.nac.yaml | ✅ params macsec (cipher/offset/window/expiry/sec-policy), pas de secret, 194 attrs (2026-06-30) |
| 25 | oob-contract | vzOOBBrCP | tenants.nac.yaml (mgmt) | ✅ contrat OOB sous tenant système mgmt (strip mgmt+GOLDEN au push, managed:false préservé), 194 attrs (2026-06-30) |
| 26 | oob-endpoint-group | mgmtOoB | tenants.nac.yaml (mgmt) | ✅ EPG OOB + oob_contracts.providers (réf #25), bloc imbriqué, 194 attrs (2026-06-30). static_routes non testé |
| 27 | oob-external-management-instance | mgmtInstP | tenants.nac.yaml (mgmt) | ✅ instance mgmt externe (subnets + oob_contracts.consumers, réf #25), 194 attrs (2026-06-30) |
| 28 | inband-endpoint-group | mgmtInB | tenants.nac.yaml (mgmt) | ✅ EPG inband (vlan/BD/subnets/contracts), key inb_endpoint_groups, 194 attrs (2026-06-30) |
| 29 | redirect-health-group | vnsRedirectHealthGroup | tenants.nac.yaml (GOLDEN) | ✅ objet L4L7 standalone (services.redirect_health_groups), 195 attrs (2026-06-30) |
| 30 | redirect-policy (PBR) | vnsSvcRedirectPol | tenants.nac.yaml (GOLDEN) | ✅ PBR + l3_destinations + health group (réf #29), 205 attrs (2026-06-30). srcMacRewriteEnabled=auto-APIC |
| 91 | geolocation | geoSite | fabric_policies.nac.yaml | ✅ hiérarchie site/building/floor/room/row/rack + node 103, 653 attrs (2026-07-01). PIÈGE : chaîne default uid=0 auto-créée sous chaque site -> filtrée |
| 92 | mpls-custom-qos-policy | qosMplsCustomPol | tenants.nac.yaml (infra) | ✅ sous tenant système infra managed:false (patron #25) + ingress/egress rules, 653 attrs (2026-07-01). vxlan-custom-qos IMPOSSIBLE : classes absentes 6.0(7e) |
| 93 | mst-policy | stpMstRegionPol | access_policies.nac.yaml | ✅ RECLASSÉ (pas un singleton) : region/revision + instances + vlan_ranges, 662 attrs (2026-07-02) |
| 94 | vpc-group | fabricExplicitGEp | node_policies.nac.yaml | ✅ RECLASSÉ (groups additifs) : paire GOLD 103/104 + policy ; adoption brownfield vpc_pg_pod1_101_102 (2026-07-02) |
| 96 | radius | aaaRadiusProvider | fabric_policies.nac.yaml | ✅ PARTIEL : key/monitoring_password omis (ignore_changes), 8 attrs testés (2026-07-02) |
| 97 | tacacs | aaaTacacsPlusProvider | fabric_policies.nac.yaml | ✅ PARTIEL : miroir #96 (2026-07-02) |
| 98 | user | aaaUser | fabric_policies.nac.yaml | ✅ PARTIEL : pwd = placeholder write-only ; domains/roles ; PIÈGE userdomain common auto-créé uid=0 filtré (2026-07-02) |
| 99 | ca-certificate | pkiTP | fabric_policies.nac.yaml | ✅ COMPLET : certChain PUBLIC round-trippe (PEM openssl), reclassé depuis « secrets » (2026-07-02) |
| 100 | login-domain | aaaLoginDomain | fabric_policies.nac.yaml | ✅ COMPLET : aucun secret (reclassé) ; realm radius + refs providers ; name SANS tiret (2026-07-02) |
| 101 | ldap | aaaLdapProvider | fabric_policies.nac.yaml | ✅ PARTIEL : password omis ; group_map_rules + group_maps (rules = objets {name}) (2026-07-02) |
| 102-103 | fex-profile + selector | infraFexP | access_policies.nac.yaml | ✅ « pas de matériel » était faux ; descr hports fex jeté par l'APIC (2026-07-02) |
| 104-105 | oob/inband-node-address | mgmtRsOoBStNode | node_policies.nac.yaml | ✅ noeud fictif 103 role unspecified (dodge node_registration) ; node-1=APIC exclu ; v4+v6 (2026-07-02) |
| 106 | useg-endpoint-group | fvAEPg | tenants.nac.yaml (GOLDEN) | ✅ ip/mac statements ; match 'all'⊥statements (Error 105) ; DEFAUT use_epg_subnet=true (2026-07-02) |
| 107-109 | L4L7 PHYSICAL (device+SGT+selection) | vnsLDevVip/vnsAbsGraph/vnsLDevCtx | tenants.nac.yaml (GOLDEN) | ✅ chaîne complète 37 ressources, mode single-device, redirect → PBR #30 (2026-07-02) |
| 110-112 | nouveau paradigme interfaces (per-port + switch config) | infraPortConfig/fabricPortConfig/infraNodeConfig/fabricNodeConfig | interface_policies + node_policies | ✅ AUTO-DÉTECTION du paradigme (flag posé par capture) ; fabric mixte = warning ; node_registration DÉSACTIVÉ par défaut (2026-07-03) |
| 113 | remote-location | fileRemotePath | fabric_policies.nac.yaml | ✅ tout géré SAUF mdp/clés ssh ; brownfield « ubuntu » adopté par import, mdp intact ; garde-fou SECRET_CLASSES (2026-07-03) |
| 114 | keyring | pkiKeyRing | fabric_policies.nac.yaml | ✅ name/CA/modulus ; cert+key = ignore_changes (2026-07-03) |
| 115 | macsec-keychain-policies | macsecKeyChainPol | access_policies.nac.yaml | ✅ PSK = placeholder hex 64 ; PIÈGE : longueur PSK ⟷ cipher (2026-07-03) |
| 116 | macsec-interfaces-policy | macsecIfPol | access_policies.nac.yaml | ✅ AUCUN secret (mal classé) ; réfs keychain #115 + params #24 (2026-07-03) |
| #5+ | auth OSPF (complétion) | ospfIfP | tenants.nac.yaml (GOLDEN) | ✅ auth_type/auth_key_id capturés (trou brownfield fermé) + authKey placeholder 8 car. (2026-07-03) |

> **Garde-fou anti-écrasement de secret (2026-07-03)** : `sync` REFUSE de *créer* un
> objet d'une classe à secret (SECRET_CLASSES) dont le DN existe déjà sur la fabric —
> le POST écraserait le vrai secret avec un placeholder. Adoption de l'existant =
> `adopt` (import, secret jamais touché). Testé en réel sur le fileRemotePath « ubuntu ».

> **Méthode C (singletons, 2026-07-02)** : les singletons (DN `default`) ne peuvent PAS
> avoir de golden (ils écraseraient la vraie config). Ils sont testés par **mutation
> réversible** : `tools/methodec.py apply` (22 attrs non-défaut dans `data/`) → plan
> 0-destroy → sync → capture → `verify` (round-trip) → `revert` → plan No changes.
> Toujours prendre un snapshot APIC avant (configExportP adminSt=triggered).

### Correctifs du comparateur (`test_nac.py test`) issus du module #1

- `_keyof` reconnaît désormais la clé **`prefix`** (subnets l3extSubnet) — sinon les
  subnets tombaient tous sur la clé `None` et étaient comparés au mauvais objet.
- Comparaison **`golden ⊆ capture`** : on n'itère que sur les sections définies dans
  le golden (un golden partiel ne doit pas signaler les sections non couvertes comme
  des écarts).
