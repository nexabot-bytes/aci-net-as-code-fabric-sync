#!/usr/bin/env python3
"""Méthode C — mutation réversible des singletons (vague 2).

Usage: methodec.py apply|verify|revert
  apply  : pose les valeurs MUTÉES (non-défaut) dans data/*.nac.yaml
  verify : vérifie que data/ (après sync+capture) contient les valeurs mutées
  revert : repose les valeurs ORIGINALES (celles d'avant mutation)
"""
import sys, yaml

DELETE = object()          # la clé n'existait pas à l'origine -> supprimer au revert

# (fichier, chemin sous apic.<section>, valeur_mutée, valeur_originale)
SPEC = [
    # banner (aaaPreLoginBanner) — 5 attrs mappés (guiMessage/isGuiMessageText = complexes non mappés)
    ("fabric_policies", "fabric_policies.banners.apic_gui_alias", "GOLD-GUI-Alias", DELETE),
    ("fabric_policies", "fabric_policies.banners.apic_cli_banner", "GOLD CLI banner methodeC",
     "Application Policy Infrastructure Controller"),
    ("fabric_policies", "fabric_policies.banners.apic_app_banner", "GOLD app banner methodeC", DELETE),
    ("fabric_policies", "fabric_policies.banners.apic_app_banner_severity", "critical", "info"),
    ("fabric_policies", "fabric_policies.banners.switch_cli_banner", "GOLD switch banner methodeC", DELETE),
    # atomic-counter
    ("fabric_policies", "fabric_policies.atomic_counter.admin_state", False, True),
    ("fabric_policies", "fabric_policies.atomic_counter.mode", "path", "trail"),
    # control-plane-mtu (APICMtuApply = complexe non mappé)
    ("fabric_policies", "fabric_policies.control_plane_mtu.mtu", 8000, 9000),
    # endpoint-loop-protection (action = forme chaîne, UN SEUL flag round-trippable)
    ("fabric_policies", "fabric_policies.ep_loop_protection.admin_state", True, False),
    ("fabric_policies", "fabric_policies.ep_loop_protection.action", "port-disable", "bd-learn-disable"),
    ("fabric_policies", "fabric_policies.ep_loop_protection.detection_interval", 90, 60),
    ("fabric_policies", "fabric_policies.ep_loop_protection.detection_multiplier", 6, 4),
    # error-disabled-recovery (enfants bpdu_guard/ep_move/mcp_loop = edrEventP non mappés)
    ("fabric_policies", "fabric_policies.err_disabled_recovery.interval", 600, 300),
    # health-score-evaluation-policy
    ("fabric_policies", "fabric_policies.ignore_acked_faults", True, False),
    # port-tracking (include_apic = complexe non mappé)
    ("fabric_policies", "fabric_policies.port_tracking.admin_state", True, False),
    ("fabric_policies", "fabric_policies.port_tracking.delay", 90, 120),
    ("fabric_policies", "fabric_policies.port_tracking.min_links", 2, 0),
    # sr-mpls-global-configuration
    ("fabric_policies", "fabric_policies.sr_mpls_global_configuration.sr_global_block_minimum", 17000, 16000),
    ("fabric_policies", "fabric_policies.sr_mpls_global_configuration.sr_global_block_maximum", 24999, 23999),
    # bgp-policy (asn du singleton fabric ; RRs non testés)
    ("fabric_policies", "fabric_policies.fabric_bgp_as", 65201, 65200),
    # aaa (defRolePolicy ; management_settings = enfants non mappés)
    ("fabric_policies", "fabric_policies.aaa.remote_user_login_policy", "assign-default-role", "no-login"),
    # qos global access (ctrl dot1p-preserve)
    ("access_policies", "access_policies.qos.preserve_cos", True, False),
]

def _walk(doc, dotted, create=False):
    node = doc["apic"]
    parts = dotted.split(".")
    for p in parts[:-1]:
        if p not in node:
            if not create:
                return None, None
            node[p] = {}
        node = node[p]
    return node, parts[-1]

def main(mode):
    files = sorted({f for f, *_ in SPEC})
    docs = {}
    for f in files:
        with open(f"data/{f}.nac.yaml") as fh:
            docs[f] = yaml.safe_load(fh)
    failures = []
    for f, path, mutated, original in SPEC:
        node, leaf = _walk(docs[f], path, create=(mode in ("apply", "revert")))
        if mode == "apply":
            node[leaf] = mutated
        elif mode == "revert":
            if original is DELETE:
                node.pop(leaf, None)
            else:
                node[leaf] = original
        elif mode == "verify":
            actual = None if node is None else node.get(leaf)
            ok = actual == mutated
            print(f"  {'OK ' if ok else 'FAIL'} {path} = {actual!r}"
                  + ("" if ok else f" (attendu {mutated!r})"))
            if not ok:
                failures.append(path)
    if mode == "verify":
        print(f"\n{len(SPEC) - len(failures)}/{len(SPEC)} attributs mutés round-trippés")
        sys.exit(1 if failures else 0)
    for f in files:
        with open(f"data/{f}.nac.yaml", "w") as fh:
            fh.write(f"# Capture {f} — MODIFIE PAR methodec.py ({mode}), "
                     "sera reecrit par nac.py capture.\n---\n")
            yaml.safe_dump(docs[f], fh, sort_keys=False, allow_unicode=True,
                           default_flow_style=False)
    print(f"{mode}: {len(SPEC)} champs, fichiers {files}")

if __name__ == "__main__":
    assert len(sys.argv) == 2 and sys.argv[1] in ("apply", "verify", "revert")
    main(sys.argv[1])
