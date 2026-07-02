# Plan de test — couverture exhaustive des modules NaC ACI

But : valider que `nac.py` capture **chaque type d'objet** avec **chacun de ses
paramètres**, en construisant un jeu de test **persistant et rejouable**.

État & progression : [avancement.md](avancement.md) · Liste des modules : [MODULE_COVERAGE.md](MODULE_COVERAGE.md)

---

## Principe

Le mapping APIC↔YAML est dérivé des sous-modules Terraform → la capture est
correcte par construction pour ~94 % des attributs. **Le test sert à prouver,
objet par objet, que chaque paramètre fait l'aller-retour fabric → YAML.**

On ne fait pas confiance « sur parole » : pour chaque module on **crée** l'objet
avec des valeurs **non-défaut**, on **capture**, et on **compare param-par-param**.
Si un paramètre est manqué, sa valeur revient au défaut → visible dans la compa.

---

## Les 2 jeux de données

| Dossier | Contenu | Usage |
|---|---|---|
| `data/*.nac.yaml` | la **vraie** config brownfield (capture de la fabric) | synchro de production |
| `tests/golden/*.nac.yaml` | le **jeu de test** : 1 objet par type, **tous attributs**, valeurs connues | tests, **conservé et versionné** |

Les objets de test **s'accumulent** dans `tests/golden/` (dans leur bon fichier de
section). À la fin, `tests/golden/` décrit un environnement de test complet,
recréable « d'une frappe ».

---

## Méthode B — test d'un module (cycle unitaire)

```
[0] BASELINE
    nac.py capture && terraform plan   →  doit dire "No changes"

[1] AJOUTER l'objet (PERMANENT) dans tests/golden/<section>.nac.yaml
    avec TOUS ses paramètres, valeurs NON-DÉFAUT  (l'objet reste, il s'accumule)

[2] PUSH
    (copier/pointer tests/golden vers la fabric de test, puis)
    nac.py sync          →  garde-fou : refuse si "to destroy" > 0

[3] CAPTURE
    nac.py capture       →  relit la fabric

[4] COMPARE param-par-param
    test_nac.py test tests/golden data   →  X/N attributs round-trip + liste des gaps

[5] IDEMPOTENCE
    terraform plan       →  "No changes"

[6] CORRIGER les gaps (handler/capture), re-tester, COCHER le module
```

Critère de réussite : **tous** les params envoyés sont retrouvés avec la même
valeur, ET `plan = No changes`.

---

## Test final — « d'une frappe »

Rejoue tout le jeu de test sur une fabric vierge :

```
[1] fabric → snapshot BLANK
[2] apply tout tests/golden/        →  recrée tous les objets de test
[3] nac.py capture
[4] test_nac.py test tests/golden <capture>   →  verdict global tous modules
[5] (option) destroy → retour BLANK
```

> Snapshots APIC disponibles : `BLANK` (vierge) et `Avec config` (sauvegarde).
> Rollback = POST `configImportP` (snapshot:yes, importType:replace, adminSt:triggered).

---

## Outils

| Commande | Rôle |
|---|---|
| `nac.py capture` | aspire la fabric → `data/` (tous attributs) |
| `nac.py sync` | applique `data/` sur la fabric (garde-fou anti-destruction) |
| `test_nac.py coverage` | mesure objets/attributs couverts vs les 195 modules |
| `test_nac.py audit` | bindings présents sur la fabric vs couverts |
| `test_nac.py test A B` | compare deux jeux (golden vs capture) param-par-param |
| `test_nac.py selftest` | génère+pousse+capture+compare auto les policies tenant |

---

## Sécurité (leçon d'incident)

Un `apply` global avec `data/` désynchronisé **détruit** tout ce qui n'est pas
dans le YAML. Donc : **toujours `capture` avant `sync`**, et le garde-fou
**abandonne si le plan détruit ≥1 objet**. Snapshot `Avec config` = filet.
