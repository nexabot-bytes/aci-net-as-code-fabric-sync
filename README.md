# ACI NaC Fabric Sync

**Synchronisation bidirectionnelle d'une fabric Cisco ACI avec YAML + Terraform**, en
complément de [Cisco Network-as-Code (NaC)](https://netascode.cisco.com/).

NaC sait pousser du YAML vers une fabric (greenfield). Cet outil ajoute le sens
inverse et le maintien en cohérence **brownfield** :

- **`capture`** — lit TOUTE la fabric via l'API REST APIC et écrit les fichiers
  `data/*.nac.yaml` au format du data model NaC. Le mapping APIC → YAML est **dérivé
  automatiquement du code source des modules Terraform NaC** (aucun mapping en dur) :
  l'outil fonctionne avec n'importe quelle fabric.
- **`plan`** — `terraform plan` : montre tout écart entre la fabric et le YAML
  (ex. une modification faite à la main dans le GUI APIC).
- **`sync`** — applique le YAML vers la fabric, avec **garde-fou anti-destruction**
  (refuse si le plan détruit ≥ 1 objet ; `--force` pour outrepasser sciemment).
- **`bootstrap`** — capture + validation + plan : l'adoption brownfield en une commande.

Résultat : fabric ↔ YAML ↔ state Terraform restent identiques (`plan` = *No changes*),
que les changements viennent du YAML (GitOps) ou du GUI (re-capture).

## Démarrage rapide

```bash
git clone https://github.com/nexabot-bytes/aci-net-as-code-fabric-sync
cd aci-net-as-code-fabric-sync
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

cp main.tf.example main.tf              # puis renseigner l'APIC (ou via env, cf. fichier)
export APIC_URL=https://<apic> APIC_USER=admin APIC_PWD=<mdp>
export ACI_URL=$APIC_URL ACI_USERNAME=$APIC_USER ACI_PASSWORD=$APIC_PWD

terraform init                          # télécharge le module NaC (requis par capture)
.venv/bin/python tools/nac.py bootstrap # capture (lecture seule) + validate + plan
.venv/bin/python tools/nac.py sync      # adoption : aligne le state (0 destroy garanti)
```

Ensuite, au quotidien : éditer `data/*.nac.yaml` → `plan` → `sync`, ou après une
modification GUI : `capture` (fabric → YAML) ou `plan`+`sync` (YAML → fabric, écrase
la dérive).

## Architecture

| Fichier | Rôle |
|---|---|
| `tools/nac.py` | Moteur de synchro : `capture · validate · plan · sync · bootstrap` |
| `tools/test_nac.py` | Harnais de test/dev : `audit · coverage · selftest · test` |
| `tools/methodec.py` | Test « méthode C » : mutation réversible des singletons |
| `tests/golden/` | Jeu de test persistant : 1 objet par module, tous attributs non-défaut |
| `tools/TEST_PLAN.md` | Méthodologie de test détaillée |
| `tools/MODULE_COVERAGE.md` | État de couverture des 195 modules NaC (source de vérité) |
| `tools/avancement.md` | Journal de la campagne de validation (pièges APIC documentés) |

Le moteur combine quatre passes de capture : classes plates (`for_each` listes),
singletons (`count`), passes hiérarchiques (access + tenants) et ~60 fonctions de
capture dédiées pour les cas que la dérivation automatique ne voit pas (relations,
listes dérivées, classes ambiguës).

## État de validation

**174 / 195 modules NaC prouvés** par round-trip complet (`fabric → YAML → fabric`,
comparaison attribut par attribut, idempotence `plan = No changes`) sur APIC 6.0(7e) :

- **764 attributs** validés via le jeu `tests/golden/` (méthode B : objet `GOLD-*`
  avec toutes les valeurs non-défaut, poussé, recapturé, comparé) ;
- **22 attributs** de 11 singletons globaux validés par mutation réversible
  (méthode C : `tools/methodec.py apply / verify / revert` sous snapshot APIC) ;
- test produit ultime : fabric → rollback usine → apply → re-capture → **100 % identique**.

Les **21 modules restants** sont des limites assumées, documentées une par une dans
`tools/MODULE_COVERAGE.md` : secrets non round-trippables (l'APIC ne renvoie jamais
mots de passe/clés), 3 classes absentes du data model 6.0(7e) (`vxlan*`),
incompatibilités (`interface-configuration` exige `new_interface_configuration`),
opérations risquées par nature (node-registration) et VMM (pas de vCenter).

## Limites et avertissements

- L'outil couvre ce que **NaC modélise**. Un objet APIC hors data model NaC n'est ni
  capturé ni détruit — il reste non géré.
- Les secrets (mots de passe RADIUS/TACACS, clés, tokens) sont écrits en
  placeholder documenté : ils se posent à la création mais ne se comparent jamais
  (`ignore_changes` dans les modules NaC).
- `sync` sur les **singletons fabric** (DN `default`) écrase la valeur globale :
  toujours `capture` avant `sync`, jamais d'apply avec un `data/` désynchronisé.
- ⚠️ Le **jeu de test golden** (`tests/golden/`) référence quelques objets de la
  fabric de lab d'origine (domaine `Test_L3DOM_Standard`, policies `CDP_Enabled`…,
  nœuds 101-104). L'outil est générique ; seul le REJEU du banc d'essai exige cet
  état de départ (snapshot de démo) ou une adaptation de ces références.

## Sécurité

Aucun identifiant dans le dépôt : `main.tf` (copie locale de `main.tf.example`),
`data/` (photo de votre fabric) et le state Terraform sont exclus par `.gitignore`.
