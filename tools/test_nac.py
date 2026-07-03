#!/usr/bin/env python3
"""
test_nac.py — Outils de TEST / DEV pour le projet NaC ACI.

Séparé de nac.py : nac.py ne fait QUE la synchro (capture/validate/plan/sync/
bootstrap). Tout ce qui est analyse de couverture, audit de bindings, et tests
round-trip vit ici.

Sous-commandes :
  audit      bindings présents sur la fabric vs ce que nac.py capture
  coverage   couverture des 195 sous-modules (objets + attributs)
  selftest   crée chaque policy tenant avec tous ses attributs, capture, compare
  test       compare deux captures (round-trip) objet/attribut

Usage : python tools/test_nac.py <sous-commande> [options]
"""
import argparse, glob, os, re, sys, importlib.util

# ── importe nac.py (le moteur de capture/synchro) ──
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("nac", os.path.join(_here, "nac.py"))
nac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nac)

log = nac.log
Apic, load_creds = nac.Apic, nac.load_creds
ROOT, DATA_DIR, CHILDDIR = nac.ROOT, nac.DATA_DIR, nac.CHILDDIR

# ═══════════════════════════════════════════════════════ AUDIT
CAPTURED_RELATIONS = {
    "fvRsCtx", "fvRsBd", "fvRsDomP", "infraRsVlanNs", "vzRsSubjFiltAtt", "l3extRsEctx",
    "l3extRsL3DomAtt", "infraRsFuncToEpg", "fvRsCons", "fvRsProv", "fvRsDomAtt",
    "fvRsBDToOut", "infraRsAttEntP",
} | {c for c, _, _ in nac.PG_RELATIONS}

AUDIT_BINDINGS = [
    ("EPG -> BD", "fvRsBd"), ("EPG -> domaine", "fvRsDomAtt"),
    ("EPG -> contrat consomme", "fvRsCons"), ("EPG -> contrat fourni", "fvRsProv"),
    ("EPG -> contrat importe", "fvRsConsIf"), ("EPG -> static path", "fvRsPathAtt"),
    ("EPG -> master (inherit)", "fvRsSecInherited"),
    ("BD -> VRF", "fvRsCtx"), ("BD -> L3Out", "fvRsBDToOut"),
    ("AAEP -> EPG", "infraRsFuncToEpg"), ("AAEP -> domaine", "fvRsDomP"),
    ("Subject -> filtre", "vzRsSubjFiltAtt"),
    ("L3Out -> VRF", "l3extRsEctx"), ("L3Out -> domaine", "l3extRsL3DomAtt"),
    ("vzAny -> contrat consomme", "vzRsAnyToCons"), ("vzAny -> contrat fourni", "vzRsAnyToProv"),
    ("PolGrp -> CDP", "infraRsCdpIfPol"), ("PolGrp -> LLDP", "infraRsLldpIfPol"),
    ("PolGrp -> LACP", "infraRsLacpPol"), ("PolGrp -> AAEP", "infraRsAttEntP"),
    ("PolGrp -> link level", "infraRsHIfPol"), ("PolGrp -> STP", "infraRsStpIfPol"),
    ("Domaine -> VLAN pool", "infraRsVlanNs"),
    ("L3Out node profile", "l3extLNodeP"), ("L3Out interface profile", "l3extLIfP"),
    ("Interface selector (static port)", "infraHPortS"),
]

def cmd_audit(args):
    apic = Apic(*load_creds()); ver = apic.login()
    log.info("Audit des bindings — %s (v%s), LECTURE SEULE.\n", apic.url, ver)
    log.info("%-34s %-20s %6s  couvert ?", "Binding", "classe MO", "count")
    log.info("%s", "-" * 72)
    gaps = []
    for label, cls in AUDIT_BINDINGS:
        try:
            n = len([x for x in apic.get_class(cls)
                     if "/tn-infra" not in x.get("dn", "") and "/tn-mgmt" not in x.get("dn", "")])
        except Exception:
            n = -1
        covered = cls in CAPTURED_RELATIONS
        mark = "✅ oui" if covered else ("⚠️  NON COUVERT" if n > 0 else "—  (absent)")
        if n > 0 and not covered:
            gaps.append(label)
        log.info("%-34s %-20s %6s  %s", label, cls, n if n >= 0 else "?", mark)
    if gaps:
        log.warning("\n⚠️  %d binding(s) NON couvert(s) : %s", len(gaps), ", ".join(gaps))
    else:
        log.info("\n✅ Tous les bindings présents sont couverts.")
    return 1 if gaps else 0

# ═══════════════════════════════════════════════════════ COVERAGE
# classes capturées par nac.py via du code hiérarchique explicite
HIER_CLASSES = {
    "fvTenant", "fvCtx", "fvBD", "fvSubnet", "fvAp", "fvAEPg", "vzFilter", "vzEntry",
    "vzBrCP", "vzSubj", "l3extOut", "fvnsVlanInstP", "fvnsEncapBlk", "physDomP",
    "l3extDomP", "infraAttEntityP", "infraAccPortGrp", "infraAccBndlGrp",
    "l3extInstP", "l3extLNodeP", "l3extLIfP",
    "fvESg", "fvRsScope", "fvTagSelector", "fvEPSelector",
    "infraHPortS", "infraPortBlk", "infraRsAccBaseGrp",
    # classes capturées via fonctions/enrichissements dédiés (loop golden 2026-06-30)
    "monInfraPol", "monInfraTarget", "monFabricPol", "monFabricTarget", "faultSevAsnP",
    "vzCPIf", "vzRsIf", "l3extDefaultRouteLeakP",
    "bgpPeerP", "bgpAsP", "bgpLocalAsnP", "ospfIfP", "ospfRsIfPol", "bfdRsIfPol",
    "rtctrlCtxP", "rtctrlScope", "rtctrlRsScopeToAttrP", "rtctrlRsCtxPToSubjP",
    "rtctrlSetComm", "rtctrlSetTag", "rtctrlSetWeight", "rtctrlSetNh", "rtctrlSetPref",
    "rtctrlSetRtMetric", "rtctrlSetRtMetricType", "rtctrlMatchRtDest",
    "l3extLoopBackIfP", "ipRouteP", "ipNexthopP", "infraRsPortDirection", "fabricRsOosPath",
    "fabricLFPortS", "fabricPortBlk", "fabricRsLePortPGrp",
    "fabricSFPortS", "fabricRsSpPortPGrp", "trigSchedP", "trigRecurrWindowP",
    "firmwareFwGrp", "firmwareFwP", "maintMaintGrp", "maintMaintP", "maintRsPolScheduler",
    "bfdIpv4InstPol", "bfdIpv6InstPol", "psuInstPol", "configExportP", "macsecParamPol",
    "vzOOBBrCP", "mgmtOoB", "mgmtRsOoBProv", "mgmtStaticRoute",
    "mgmtInstP", "mgmtSubnet", "mgmtRsOoBCons", "mgmtInB", "mgmtRsMgmtBD",
    "vnsRedirectHealthGroup", "vnsSvcRedirectPol", "vnsRedirectDest", "vnsRsRedirectHealthGroup",
    "pimRouteMapPol", "pimRouteMapEntry",   # #67 multicast-route-map (entries = enrichissement dédié)
    # #68 tenant-netflow : relations capturées via enrichissement dédié
    "netflowRsExporterToCtx", "netflowRsExporterToEPg",
    "netflowRsMonitorToRecord", "netflowRsMonitorToExporter",
    # #75 snmp-policy fabric (capture dédiée) ; users=secrets omis
    "snmpPol", "snmpCommunityP", "snmpTrapFwdServerP",
    # #76 dns-policy fabric (capture dédiée)
    "dnsProfile", "dnsProv", "dnsDomain",
    # #77 date-time-policy fabric (capture dédiée) ; ntp_keys=secrets omis
    "datetimePol", "datetimeNtpProv",
    # #78 fabric-pod-policy-group (capture dédiée) + relations
    "fabricPodPGrp", "fabricRsSnmpPol", "fabricRsTimePol", "fabricRsCommPol",
    "fabricRsMacsecPol", "fabricRsPodPGrpBGPRRP",
    # #79 management-access-policy (capture dédiée) ; flags/keyring omis
    "commPol", "commTelnet", "commSsh", "commHttps", "commHttp",
    # #81 port-channel-policy ctrl flags + hash_key (enrichissement dédié)
    "lacpLagPol", "l2LoadBalancePol",
    # #83 qos-policy (qosCustomPol) enfants dscp/dot1p (enrichissement dédié)
    "qosCustomPol", "qosDscpClass", "qosDot1PClass",
    # #84 infra-dhcp-relay-policy (dhcpRelayP owner=infra, capture dédiée)
    "dhcpRelayP", "dhcpRsProv",
    # #85 tenant-monitoring-policy (monEPGPol + fault_severity, capture dédiée)
    "monEPGPol", "monEPGTarget",
    # #86 tenant-span dest/source groups (enrichissements dédiés)
    "spanDest", "spanRsDestEpg", "spanSpanLbl", "spanSrc", "spanRsSrcToEpg",
    # #87 monitoring-policy common (sources syslog sous moncommon)
    "syslogSrc", "syslogRsDestGroup",
    # #88 access-leaf-interface-policy-group relations DPP/PFC (PG_RELATIONS étendu)
    "infraRsQosEgressDppIfPol", "infraRsQosIngressDppIfPol", "infraRsQosPfcIfPol",
    # #89 access-spine (infraSpAccPortGrp) + fabric-leaf (fabricLePortPGrp) interface PG relations
    "infraSpAccPortGrp", "fabricLePortPGrp", "fabricRsFIfPol",
    # #91 geolocation (capture_geolocation dédiée, filtre uid=0)
    "geoSite", "geoBuilding", "geoFloor", "geoRoom", "geoRow", "geoRack",
    "geoRsNodeLocation",
    # #92 mpls-custom-qos (qosMplsCustomPol sous tn-infra, enrichissement tenant infra)
    "qosMplsCustomPol", "qosMplsIngressRule", "qosMplsEgressRule",
    # #93 mst-policy (capture_mst_policies dédiée)
    "stpMstRegionPol", "stpMstDomPol",
    # #94 vpc-group (capture_vpc_groups dédiée)
    "fabricExplicitGEp", "fabricNodePEp", "fabricRsVpcInstPol",
    # #96-#101 AAA (capture_aaa_security dédiée, secrets omis)
    "aaaRadiusProvider", "aaaTacacsPlusProvider", "aaaRsSecProvToEpg",
    "aaaUser", "aaaUserDomain", "aaaUserRole", "pkiTP",
    "aaaLoginDomain", "aaaDomainAuth", "aaaProviderRef",
    "aaaRadiusProviderGroup", "aaaTacacsPlusProviderGroup", "aaaLdapProviderGroup",
    "aaaLdapProvider", "aaaLdapGroupMapRule", "aaaLdapGroupMap", "aaaLdapGroupMapRuleRef",
    # #102-#103 fex (capture_fex_profiles dédiée)
    "infraFexP", "infraFexBndlGrp",
    # #104-#105 node addresses (capture_node_addresses dédiée)
    "mgmtRsOoBStNode", "mgmtRsInBStNode",
    # #106 useg-endpoint-group (enrichissement boucle AP)
    "fvCrtrn", "fvIpAttr", "fvMacAttr",
    # #107-#109 L4L7 PHYSICAL (capture dans capture_tenants)
    "vnsLDevVip", "vnsRsALDevToPhysDomP", "vnsCDev", "vnsCIf", "vnsRsCIfPathAtt",
    "vnsLIf", "vnsRsCIfAttN", "vnsAbsGraph", "vnsAbsNode", "vnsRsNodeToLDev",
    "vnsLDevCtx", "vnsLIfCtx", "vnsRsLIfCtxToLIf", "vnsRsLIfCtxToBD",
    "vnsRsLIfCtxToSvcRedirectPol",
    # #110-#112 nouveau paradigme d'interfaces (capture_port_configurations)
    "infraPortConfig", "fabricPortConfig", "infraNodeConfig", "fabricNodeConfig",
    # #113-#116 objets a secret write-only (capture_secretful_policies)
    "fileRemotePath", "fileRsARemoteHostToEpg", "pkiKeyRing",
    "macsecKeyChainPol", "macsecKeyPol", "macsecIfPol", "macsecFabIfPol",
    "macsecRsToKeyChainPol", "macsecRsToParamPol",
}

def _captured_classes():
    return ({c for _, c, _, _, _ in nac._flat_table()}
            | {c for _, c, _, _, _ in nac._singleton_table()}
            | {c for _, c, _, _ in nac._tenant_flat_table()}
            | HIER_CLASSES | CAPTURED_RELATIONS)

def _primary_class(txt):
    for m in re.finditer(r'resource\s+"aci_rest_managed"\s+"[^"]+"\s*\{(.*?)\n\}', txt, re.S):
        b = m.group(1)
        if "for_each" in b.split("content")[0] or "count" in b.split("content")[0]:
            continue
        c = re.search(r'class_name\s*=\s*"([^"]+)"', b)
        if c:
            return c.group(1)
    return None

def _is_derivable(e):
    is_flag = e.startswith("join(") and "concat(" in e and '== true ? ["' in e
    return bool(nac._RE_VAR.match(e) or nac._RE_BOOL.match(e) or nac._RE_NUM0.match(e)
                or nac._RE_FLOAT.match(e) or nac._RE_JOIN.match(e) or nac._RE_NUMNULL.match(e)
                or is_flag or re.match(r'^"[^"]*"$', e))

def cmd_coverage(args):
    captured = _captured_classes()
    rows, uncov, partial = [], [], []
    for d in sorted(glob.glob(os.path.join(CHILDDIR, "terraform-aci-*"))):
        mf = os.path.join(d, "main.tf")
        if not os.path.isfile(mf):
            continue
        txt = open(mf).read()
        cls = _primary_class(txt)
        m = re.search(r'resource\s+"aci_rest_managed".*?content\s*=\s*\{(.*?)\n\s*\}', txt, re.S)
        cplx = 0
        if m:
            for line in m.group(1).splitlines():
                mm = re.match(r'\s*"?[A-Za-z0-9_]+"?\s*=\s*(.+?)\s*$', line)
                if mm and not _is_derivable(mm.group(1).strip()):
                    cplx += 1
        cov = bool(cls) and cls in captured
        rows.append((os.path.basename(d), cls, cov, cplx))
        (uncov if not cov else partial if cplx else []).append(
            (os.path.basename(d), cls) if not cov else (os.path.basename(d), cls, cplx))
    cov_n = sum(1 for r in rows if r[2])
    log.info("=== COUVERTURE : %d/%d modules captures ===", cov_n, len(rows))
    log.info("\n%d modules NON captures :", len(uncov))
    for name, cls in uncov:
        log.info("  ✗ %-50s %s", name, cls)
    log.info("\n%d modules captures avec attributs COMPLEXES (non derives) :", len(partial))
    for name, cls, n in sorted(partial, key=lambda x: -x[2]):
        log.info("  ⚠️  %2d  %-46s %s", n, name, cls)
    return 1 if uncov else 0

# ═══════════════════════════════════════════════════════ TEST round-trip
def _load_dir(d):
    import yaml
    m = {}
    for f in sorted(glob.glob(os.path.join(d, "*.nac.yaml"))):
        for k, v in (yaml.safe_load(open(f)) or {}).get("apic", {}).items():
            if isinstance(v, dict):
                m.setdefault(k, {}).update(v)
            else:
                m[k] = v
    return m

def _keyof(o):
    if not isinstance(o, dict):
        return str(o)
    if "from" in o and "to" in o:
        return f"range-{o['from']}-{o['to']}"
    if "node_id" in o:
        return f"node-{o['node_id']}"
    if "id" in o:                                  # interface_policies node
        return f"id-{o['id']}"
    if "port" in o and "module" in o:              # interface entry (port-level)
        return f"port-{o['module']}/{o['port']}"
    return (o.get("name") or o.get("ip") or o.get("prefix") or o.get("filter")
            or o.get("mac") or o.get("key"))

def cmd_test(args):
    B, A = _load_dir(args.before), _load_dir(args.after)
    stats = {"ok": 0, "diff": 0, "missing": 0}

    def cmp_val(path, vb, va):
        if isinstance(vb, list):
            cmp_list(path, vb, va or [])
        elif isinstance(vb, dict):
            cmp_dict(path, vb, va or {})
        elif vb != va:
            log.info("  ✗ %s: %r != %r", path, vb, va); stats["diff"] += 1
        else:
            stats["ok"] += 1

    def cmp_dict(path, db, da):
        for k in db:
            cmp_val(f"{path}.{k}", db[k], da.get(k) if isinstance(da, dict) else None)

    def cmp_list(path, lb, la):
        lb, la = lb or [], la or []
        if lb and not isinstance(lb[0], dict):
            if set(map(str, lb)) == set(map(str, la)): stats["ok"] += 1
            else: log.info("  ✗ SET %s: %s", path, set(map(str, lb)) ^ set(map(str, la))); stats["diff"] += 1
            return
        da = {_keyof(o): o for o in la}
        for ob in lb:
            k = _keyof(ob); oa = da.get(k)
            if oa is None:
                log.info("  ✗ MANQUANT %s/%s", path, k); stats["missing"] += 1; continue
            cmp_dict(f"{path}/{k}", {x: v for x, v in ob.items() if x != "name"}, oa)

    for m in (B, A):
        if "tenants" in m:
            m["tenants"] = [t for t in m["tenants"] if t.get("managed") is not False]
    # Comparaison "golden ⊆ capture" : on ne teste que les sections DEFINIES dans
    # `before` (le golden est un sous-ensemble ; ne pas signaler les sections non
    # couvertes comme des écarts).
    for section in sorted(B):
        cmp_val(section, B.get(section), A.get(section))
    log.info("=== Comparaison par NOM/CLE -> ATTRIBUTS (toutes sections) ===")
    log.info("  identiques: %d   differents: %d   manquants: %d",
             stats["ok"], stats["diff"], stats["missing"])
    ok = stats["diff"] == 0 and stats["missing"] == 0
    log.info("  VERDICT: %s", "✅ 100%% IDENTIQUE" if ok else "⚠️ ecarts ci-dessus")
    return 0 if ok else 1

# ═══════════════════════════════════════════════════════ SELFTEST
SELFTEST_SKIP = {"endpoint_mac_tags", "endpoint_ip_tags", "netflow_exporters",
                 "netflow_monitors", "netflow_records"}

def _selftest_policies():
    import yaml
    defs = yaml.safe_load(open(os.path.join(ROOT, "defaults_effectifs.yaml")))
    defs = defs["defaults"]["apic"]["tenants"]["policies"]
    out = {}
    for sub, _, _, _ in nac._tenant_flat_table():
        key = sub.split(".", 1)[1] if "." in sub else sub
        if key in SELFTEST_SKIP:
            continue
        dd = defs.get(key)
        if not isinstance(dd, dict):
            continue
        sd = {k: v for k, v in dd.items() if k != "name_suffix" and not isinstance(v, (dict, list))}
        if sd:
            out[key] = [{"name": f"ST-{key[:12]}", **sd}]
    return out

def cmd_selftest(args):
    import yaml, subprocess
    if not args.yes:
        ans = input("selftest crée/détruit des objets SELFTEST sur la fabric. Continuer ? [y/N] ")
        if ans.strip().lower() not in ("y", "yes", "o", "oui"):
            return 1
    log.info("Capture de la fabric existante (sécurité avant apply)…")
    nac.cmd_capture(args)
    sent = _selftest_policies()
    testf = os.path.join(DATA_DIR, "_selftest.nac.yaml")
    with open(testf, "w") as f:
        f.write("---\n" + yaml.safe_dump({"apic": {"tenants": [{"name": "SELFTEST", "policies": sent}]}},
                                         sort_keys=False, allow_unicode=True))
    rc = 0
    try:
        plan = subprocess.run(["terraform", "plan", "-input=false", "-no-color"],
                              cwd=ROOT, capture_output=True, text=True)
        if "to destroy" in plan.stdout and not plan.stdout.count("0 to destroy"):
            log.error("ABANDON : le plan détruirait des objets existants."); return 1
        log.info("Création de %d types de policies (tous attributs)…", len(sent))
        if nac._run(["terraform", "apply", "-input=false", "-auto-approve"],
                    stdout=subprocess.DEVNULL).returncode:
            log.error("apply SELFTEST a échoué"); return 1
        os.remove(testf)
        nac.cmd_capture(args)
        cap = [t for t in _load_dir(DATA_DIR).get("tenants", []) if t.get("name") == "SELFTEST"]
        cap = cap[0].get("policies", {}) if cap else {}
        tot = ok = 0; gaps = []
        for ptype, plist in sent.items():
            c = (cap.get(ptype) or [{}])[0]
            for a in plist[0]:
                if a == "name":
                    continue
                tot += 1
                if a in c: ok += 1
                else: gaps.append(f"{ptype}.{a}")
        log.info("=== SELFTEST : %d/%d attributs recuperes (%d%%) ===", ok, tot, 100 * ok // max(tot, 1))
        for g in gaps:
            log.info("  ✗ NON recupere : %s", g)
        rc = 1 if gaps else 0
    finally:
        if os.path.isfile(testf):
            os.remove(testf)
        tp = os.path.join(DATA_DIR, "tenants.nac.yaml")
        if os.path.isfile(tp):
            d = yaml.safe_load(open(tp))
            d["apic"]["tenants"] = [t for t in d["apic"].get("tenants", []) if t.get("name") != "SELFTEST"]
            open(tp, "w").write("---\n" + yaml.safe_dump(d, sort_keys=False, allow_unicode=True))
        nac._run(["terraform", "apply", "-input=false", "-auto-approve"], stdout=subprocess.DEVNULL)
        log.info("Objets SELFTEST detruits.")
    return rc

# ═══════════════════════════════════════════════════════ CLI
def main(argv=None):
    p = argparse.ArgumentParser(prog="test_nac.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("audit", help="bindings fabric vs couverture")
    sub.add_parser("coverage", help="couverture modules/attributs")
    ss = sub.add_parser("selftest", help="crée chaque policy avec tous attrs, capture, vérifie")
    ss.add_argument("-y", "--yes", action="store_true", help="sans confirmation")
    st = sub.add_parser("test", help="compare deux captures (round-trip)")
    st.add_argument("before"); st.add_argument("after")
    args = p.parse_args(argv)
    nac._setup_log(args.verbose)
    return {"audit": cmd_audit, "coverage": cmd_coverage,
            "selftest": cmd_selftest, "test": cmd_test}[args.cmd](args)

if __name__ == "__main__":
    sys.exit(main())
