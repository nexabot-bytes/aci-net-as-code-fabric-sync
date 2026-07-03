#!/usr/bin/env python3
"""
nac.py — Brownfield Network-as-Code management tool for Cisco ACI.

Captures an EXISTING ACI fabric as NaC YAML (netascode/nac-aci module),
synchronizes it with Terraform, and validates everything — without ever
overwriting the fabric.

The APIC<->YAML mapping is DERIVED automatically from the `content {}` blocks
of the Terraform sub-modules (versioned source of truth): 100% of attributes,
zero hand-written mapping.

Pure SYNC tool: fabric <-> data/*.nac.yaml <-> Terraform.
Test/dev tooling (audit, coverage, selftest, comparison) lives in
test_nac.py (separate) — nac.py only does its sync job.

Subcommands
-----------
  capture     Read the fabric -> data/*.nac.yaml (READ-ONLY, ALL attributes)
  validate    nac-validate on the data/ directory
  plan        terraform plan (preview, changes nothing)
  sync        terraform apply (destroy guard included)
  adopt       write-free adoption (bulk terraform import)
  bootstrap   capture + validate + plan (+ adoption with --adopt)

Authentication: read from the `provider "aci"` block in main.tf
(overridable with the APIC_URL / APIC_USER / APIC_PWD environment variables).

Usage: python tools/nac.py <subcommand> [options]
"""
from __future__ import annotations
import argparse, datetime, glob, json, logging, os, re, ssl, sys, urllib.request
from collections import defaultdict

# ───────────────────────────────────────────────────────────── chemins & log
ROOT     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
MAIN_TF  = os.path.join(ROOT, "main.tf")
MODDIR   = os.path.join(ROOT, ".terraform", "modules", "aci")
CHILDDIR = os.path.join(MODDIR, "modules")
SYSTEM_TENANTS = {"infra", "mgmt", "common"}
SECTION_FILES = {
    "access_policies":    "aci_access_policies.tf",
    "fabric_policies":    "aci_fabric_policies.tf",
    "node_policies":      "aci_node_policies.tf",
    "pod_policies":       "aci_pod_policies.tf",
}
SECTION_OUT = {  # section -> fichier data
    "access_policies": "access_policies.nac.yaml", "fabric_policies": "fabric_policies.nac.yaml",
    "node_policies": "node_policies.nac.yaml", "pod_policies": "pod_policies.nac.yaml",
    "interface_policies": "interface_policies.nac.yaml",
}
# Modules a relation/secret : objets incomplets ou non capturables -> exclus de la passe plate
PHASE2_MODULES = {
    "aci_physical_domain", "aci_routed_domain", "aci_l2_domain", "aci_aaep",
    "aci_user", "aci_login_domain", "aci_radius", "aci_tacacs", "aci_ca_certificate",
    "aci_keyring", "aci_psu_policy", "aci_config_export", "aci_remote_location",
    "aci_fabric_scheduler", "aci_node_registration", "aci_inband_node_address",
    "aci_oob_node_address", "aci_rbac_node_rule", "aci_vmware_vmm_domain",
    "aci_nutanix_vmm_domain", "aci_vlan_pool",
    "aci_mcp",             # MCP global : requiert un mot de passe (secret non capturable)
    "aci_smart_licensing", # requiert un Token ID CSSM (secret non capturable)
    "aci_pod_setup",       # TEP pool (fondamental, indexe par 'id' != var) -> non gere
    # SPAN destination groups : classe spanDestGrp AMBIGUE (access uni/infra ET fabric uni/fabric).
    # Le moteur plat dédoublonne par classe et rangerait l'objet dans la mauvaise section ->
    # géré par capture_span_destination_groups (filtré par DN uni/infra). [#37]
    "aci_access_span_destination_group", "aci_fabric_span_destination_group",
    # idem spanSrcGrp ambiguë access/fabric -> capture_span_source_groups (filtre uni/infra). [#40]
    "aci_access_span_source_group", "aci_fabric_span_source_group",
}
# Singletons que le MODULE cree toujours (count sans garde de donnees) mais qui
# exigent un secret : on les DESACTIVE via la cle `modules:` du data model, sinon
# terraform tente de les creer avec des defauts incomplets et echoue.
DISABLE_MODULES = {
    "aci_mcp": False,             # mot de passe MCP requis
    "aci_smart_licensing": False, # Token ID CSSM requis
}

log = logging.getLogger("nac")

def _setup_log(verbose=False):
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(message)s", stream=sys.stderr)

# ───────────────────────────────────────────────────────────── credentials
def load_creds() -> tuple[str, str, str]:
    """URL/user/pwd depuis le provider "aci" de main.tf, surchargeable par l'env."""
    url = user = pwd = None
    if os.path.isfile(MAIN_TF):
        m = re.search(r'provider\s+"aci"\s*\{(.*?)\n\}', open(MAIN_TF).read(), re.S)
        if m:
            blk = m.group(1)
            def g(k):
                mm = re.search(rf'\b{k}\s*=\s*"([^"]*)"', blk)
                return mm.group(1) if mm else None
            url, user, pwd = g("url"), g("username"), g("password")
    url  = os.environ.get("APIC_URL",  url)
    user = os.environ.get("APIC_USER", user)
    pwd  = os.environ.get("APIC_PWD",  pwd)
    if not all((url, user, pwd)):
        sys.exit("ERROR: credentials not found (provider \"aci\" block in main.tf "
                 "or APIC_URL/APIC_USER/APIC_PWD environment variables).")
    return url, user, pwd

# ───────────────────────────────────────────────────────────── client APIC
class Apic:
    """Client REST APIC minimal, en lecture seule par defaut."""
    def __init__(self, url, user, pwd):
        self.url, self.user, self.pwd = url, user, pwd
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.token = None

    def _do(self, path, data=None, method=None):
        req = urllib.request.Request(
            self.url + path,
            data=json.dumps(data).encode() if data is not None else None,
            method=method or ("POST" if data is not None else "GET"))
        if self.token:
            req.add_header("Cookie", "APIC-cookie=" + self.token)
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            return json.loads(r.read())

    def login(self):
        d = self._do("/api/aaaLogin.json",
                     {"aaaUser": {"attributes": {"name": self.user, "pwd": self.pwd}}})
        a = d["imdata"][0]["aaaLogin"]["attributes"]
        self.token = a["token"]
        return a.get("version", "?")

    def get_class(self, cn):
        return [list(x.values())[0]["attributes"]
                for x in self._do(f"/api/class/{cn}.json")["imdata"]]

    def count(self, cn):
        return len(self.get_class(cn))

    def post_mo(self, path, body):
        return self._do(path, body, method="POST")

# ───────────────────────────────────────────────── mapping derive des modules
_RE_BOOL = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)(?:\s*==\s*true)?\s*\?\s*"([^"]*)"\s*:\s*"([^"]*)"$')
_RE_VAR  = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)$')
# nombre avec sentinelle pour 0 : var.x == 0 ? "infinite" : var.x  (endpoint retention, etc.)
_RE_NUM0 = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)\s*==\s*0\s*\?\s*"([^"]*)"\s*:\s*(?:var|each\.value)\.\1$')
_RE_FLOAT = re.compile(r'^format\("%\.\d+f",\s*(?:var|each\.value)\.([a-z0-9_]+)\)$')  # rate/burst
_RE_JOIN  = re.compile(r'^join\("[^"]*",\s*(?:var|each\.value)\.([a-z0-9_]+)\)$')      # liste -> csv
_RE_NUMNULL = re.compile(r'^(?:var|each\.value)\.([a-z0-9_]+)\s*!=\s*0\s*\?\s*(?:var|each\.value)\.\1\s*:\s*null$')
_MAP_CACHE: dict = {}

def attr_map(module, label):
    """[(apicAttr, champYAML, kind, extra)] du resource <label> du sous-module."""
    key = (module, label)
    if key in _MAP_CACHE:
        return _MAP_CACHE[key]
    out, path = [], os.path.join(CHILDDIR, module, "main.tf")
    if os.path.isfile(path):
        m = re.search(rf'resource\s+"aci_rest_managed"\s+"{re.escape(label)}"\s*\{{(.*?)\n\}}',
                      open(path).read(), re.S)
        if m:
            cm = re.search(r'content\s*=\s*\{(.*?)\n\s*\}', m.group(1), re.S)
            if cm:
                for line in cm.group(1).splitlines():
                    mm = re.match(r'\s*"?([A-Za-z0-9_]+)"?\s*=\s*(.+?)\s*$', line)
                    if not mm:
                        continue
                    apic, expr = mm.group(1), mm.group(2).strip()
                    # champ "ctrl" = join(",", concat(var.X==true?["flag"]:[], ...)) -> N bools
                    if expr.startswith("join(") and "concat(" in expr:
                        pairs = re.findall(
                            r'(?:var|each\.value)\.([a-z0-9_]+)(?:\s*==\s*true)?\s*\?\s*\["([^"]+)"\]', expr)
                        if pairs:
                            for var, flag in pairs:
                                out.append((apic, var, "flag", flag))
                            continue
                    b, v, n0 = _RE_BOOL.match(expr), _RE_VAR.match(expr), _RE_NUM0.match(expr)
                    fl, jn, nn = _RE_FLOAT.match(expr), _RE_JOIN.match(expr), _RE_NUMNULL.match(expr)
                    if b:    out.append((apic, b.group(1), "bool", (b.group(2), b.group(3))))
                    elif n0: out.append((apic, n0.group(1), "num0", n0.group(2)))
                    elif fl: out.append((apic, fl.group(1), "float", None))
                    elif jn: out.append((apic, jn.group(1), "list", None))
                    elif nn: out.append((apic, nn.group(1), "direct", None))
                    elif v:  out.append((apic, v.group(1), "direct", None))
    _MAP_CACHE[key] = out
    return out

def _num(v):
    return int(v) if isinstance(v, str) and re.fullmatch(r"-?\d+", v) else v

def reverse(amap, mo):
    """Construit l'objet YAML complet depuis le MO + mapping. Ignore null/vide."""
    o = {}
    for apic, field, kind, extra in amap:
        if apic not in mo:
            continue
        raw = mo[apic]
        if kind == "bool":
            o[field] = (raw == extra[0])
        elif kind == "num0":                       # sentinelle ("infinite"/"none") -> 0
            o[field] = 0 if raw == extra else _num(raw)
        elif kind == "float":                       # "100.000000" -> 100 ou 100.5
            try:
                f = float(raw); o[field] = int(f) if f == int(f) else f
            except (ValueError, TypeError):
                pass
        elif kind == "list":                        # "a,b,c" -> [a,b,c]
            o[field] = [s for s in raw.split(",") if s]
        elif kind == "flag":                        # bool = flag present dans ctrl "f1,f2"
            o[field] = extra in str(raw).split(",")
        elif raw not in ("", None):
            o[field] = _num(raw)
    return o

def obj(module, label, mo):
    o = reverse(attr_map(module, label), mo)
    if mo.get("name") and "name" not in o:        # certains modules n'echoent pas name
        o = {"name": mo["name"], **o}
    return o

def child_primary(module):
    """(label, class_name) du resource primaire (sans for_each/count) d'un sous-module."""
    path = os.path.join(CHILDDIR, module, "main.tf")
    if not os.path.isfile(path):
        return None
    txt = open(path).read()
    for m in re.finditer(r'resource\s+"aci_rest_managed"\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
        label, body = m.group(1), m.group(2)
        if "for_each" in body.split("content")[0] or "count" in body.split("content")[0]:
            continue
        c = re.search(r'class_name\s*=\s*"([^"]+)"', body)
        if c:
            return label, c.group(1)
    return None

# ─────────────────────────────────── moteur de classes PLATES (derive des sections)
def _flat_table():
    """[(section, class_name, module, label, yaml_path)] des list-classes simples."""
    table, seen = [], {}
    for section, fname in SECTION_FILES.items():
        txt = open(os.path.join(MODDIR, fname)).read()
        for m in re.finditer(r'module\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
            name, body = m.group(1), m.group(2)
            if name in PHASE2_MODULES:
                continue
            src = re.search(r'source\s*=\s*"\./modules/([^"]+)"', body)
            fe = re.search(r'for_each\s*=\s*\{\s*for\s+\w+\s+in\s+try\(\s*local\.([\w.]+)\s*,\s*\[\]\)', body)
            if not (src and fe):
                continue
            path = fe.group(1)
            if not path.startswith(section):
                continue
            prim = child_primary(src.group(1))
            if not prim:
                continue
            label, cls = prim
            if cls in seen:                       # une classe -> un seul chemin (sinon ambigu)
                continue
            seen[cls] = path
            table.append((section, cls, src.group(1), label, path))
    return table

def _place(tree, path, item):
    node = tree
    for p in path.split(".")[:-1]:
        node = node.setdefault(p, {})
    node.setdefault(path.split(".")[-1], []).append(item)

def _set_path(tree, path, field, value):
    node = tree
    for p in (path.split(".") if path else []):
        node = node.setdefault(p, {})
    node[field] = value

# ─────────────────────────────────── moteur de SINGLETONS (count-based, dict)
def _singleton_table():
    """[(section, class, module, label, {var:(path,field)})] des modules count-based."""
    out = []
    for section, fname in SECTION_FILES.items():
        txt = open(os.path.join(MODDIR, fname)).read()
        for m in re.finditer(r'module\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
            name, body = m.group(1), m.group(2)
            if name in PHASE2_MODULES or "for_each" in body or "\n  count" not in body:
                continue
            src = re.search(r'source\s*=\s*"\./modules/([^"]+)"', body)
            if not src:
                continue
            var2pf = {}
            for vm in re.finditer(r'^\s*([A-Za-z0-9_]+)\s*=\s*try\(\s*local\.([\w.]+)', body, re.M):
                full = vm.group(2)
                if "." not in full:
                    continue
                path, field = full.rsplit(".", 1)
                var2pf[vm.group(1)] = (path, field)
            prim = child_primary(src.group(1))
            if var2pf and prim:
                out.append((section, prim[1], src.group(1), prim[0], var2pf))
    return out

def capture_singletons(apic: Apic):
    """Capture les singletons (global_settings, coop, isis...) a leurs vraies valeurs."""
    trees = defaultdict(dict)
    for section, cls, module, label, var2pf in _singleton_table():
        try:
            mos = apic.get_class(cls)
        except Exception:
            continue
        if cls == "bgpAsP":
            # classe AMBIGUE : bgpAsP existe aussi sous les bgp peers tenant/l3out
            # -> ne garder que le singleton fabric (uni/fabric/bgpInstP-default/as)
            mos = [m for m in mos if m.get("dn", "").startswith("uni/fabric/bgpInstP")]
        if not mos:
            continue
        mo = mos[0]
        for apic_attr, var, kind, extra in attr_map(module, label):
            if var not in var2pf or apic_attr not in mo:
                continue
            path, field = var2pf[var]
            sub = path.split(".", 1)[1] if "." in path else ""      # "" = directement sous la section
            raw = mo[apic_attr]
            if kind == "bool":
                _set_path(trees[section], sub, field, raw == extra[0])
            elif raw not in ("", None):
                _set_path(trees[section], sub, field, _num(raw))
        if cls == "dbgOngoingAcMode" and mo.get("adminSt"):
            # admin_state cable SANS try() dans le parent -> absent de var2pf ; or
            # count = admin_state != null : sans ce champ le module n'est jamais
            # instancie (singleton non gere). [methode C]
            _set_path(trees[section], "atomic_counter", "admin_state",
                      mo["adminSt"] == "enabled")
    return trees

def capture_flat(apic: Apic):
    """Capture toutes les list-classes plates (full attrs) par section."""
    trees = defaultdict(dict)
    for section, cls, module, label, path in _flat_table():
        try:
            mos = apic.get_class(cls)
        except Exception:
            continue
        seen = set()
        for mo in mos:
            name = mo.get("name", "")
            if "/tn-" in mo.get("dn", ""):                       # tenant-scoped -> section tenants
                continue
            if name == "default" or name.startswith(("system-", "__")):
                continue
            if name in seen:
                continue
            seen.add(name)
            _place(trees[section], path.split(".", 1)[1], obj(module, label, mo))
    return trees

# ───────────────────────────────────────────────────────── helpers DN
def _seg(dn, key):
    m = re.search(rf"/{key}-([^/\[]+)", dn)
    return m.group(1) if m else None

def _parent(dn, depth=1):
    """Remonte de `depth` niveaux en ignorant les '/' dans les [crochets]."""
    for _ in range(depth):
        lvl = 0
        for i in range(len(dn) - 1, -1, -1):
            c = dn[i]
            if c == "]": lvl += 1
            elif c == "[": lvl -= 1
            elif c == "/" and lvl == 0:
                dn = dn[:i]; break
    return dn

def _ref(tdn):
    for pat in (r"uni/phys-([^/\]]+)", r"uni/l3dom-([^/\]]+)",
                r"uni/infra/vlanns-\[([^\]]+)\]", r"/ctx-([^/\]]+)", r"/BD-([^/\]]+)"):
        m = re.search(pat, tdn)
        if m:
            return m.group(1)
    return tdn

def _by_parent(rows, depth=1):
    d = defaultdict(list)
    for a in rows:
        d[_parent(a["dn"], depth)].append(a)
    return d

def _set(o, key, children):
    if children:
        o[key] = children

# ═══════════════════════════════════════════════════════ CAPTURE : access
def capture_access(apic: Apic, warnings: list):
    ap = {}
    # vlan pools (+ ranges)
    encaps = _by_parent(apic.get_class("fvnsEncapBlk"))
    pools = []
    for p in apic.get_class("fvnsVlanInstP"):
        o = obj("terraform-aci-vlan-pool", "fvnsVlanInstP", p)
        ranges = []
        for blk in encaps.get(p["dn"], []):
            r = obj("terraform-aci-vlan-pool", "fvnsEncapBlk", blk)
            r.pop("name", None)
            r["from"] = _num(blk["from"].replace("vlan-", ""))
            r["to"]   = _num(blk["to"].replace("vlan-", ""))
            ranges.append(r)
        _set(o, "ranges", ranges)
        pools.append(o)
    _set(ap, "vlan_pools", pools)
    # domains -> vlan_pool
    vlanns = {_parent(a["dn"]): _ref(a["tDn"]) for a in apic.get_class("infraRsVlanNs")}
    for cn, mod, key in (("physDomP", "terraform-aci-physical-domain", "physical_domains"),
                         ("l3extDomP", "terraform-aci-routed-domain", "routed_domains")):
        doms = []
        for d in apic.get_class(cn):
            if d["dn"] not in vlanns:
                continue
            o = obj(mod, cn, d); o["vlan_pool"] = vlanns[d["dn"]]
            doms.append(o)
        _set(ap, key, doms)
    # aaeps -> domains + bindings EPG (infraRsFuncToEpg sous gen-default)
    dom_by_aaep = _by_parent(apic.get_class("infraRsDomP"))
    epg_by_aaep = defaultdict(list)
    for rs in apic.get_class("infraRsFuncToEpg"):
        if "/gen-default/" not in rs["dn"]:                       # ignore le binding infra_vlan
            continue
        t = rs["tDn"]                                             # uni/tn-X/ap-Y/epg-Z
        b = {"tenant": _seg(t, "tn"), "application_profile": _seg(t, "ap"),
             "endpoint_group": _seg(t, "epg")}
        if rs.get("encap", "unknown") != "unknown":
            b["vlan"] = _num(rs["encap"].replace("vlan-", ""))
        if rs.get("primaryEncap", "unknown") != "unknown":
            b["primary_vlan"] = _num(rs["primaryEncap"].replace("vlan-", ""))
        if rs.get("mode"):
            b["mode"] = rs["mode"]
        epg_by_aaep[_parent(rs["dn"], 2)].append(b)               # parent: .../gen-default/rs.. -> attentp-X
    aaeps = []
    for a in apic.get_class("infraAttEntityP"):
        if a["name"] == "default":
            continue
        o = obj("terraform-aci-aaep", "infraAttEntityP", a)
        phys, rout = [], []
        for rs in dom_by_aaep.get(a["dn"], []):
            t = rs["tDn"]
            (phys if "/phys-" in t else rout if "/l3dom-" in t else []).append(_ref(t))
        _set(o, "physical_domains", phys); _set(o, "routed_domains", rout)
        _set(o, "endpoint_groups", epg_by_aaep.get(a["dn"], []))
        aaeps.append(o)
    _set(ap, "aaeps", aaeps)
    # interface policy groups (leaf access/bundle) + leurs references de policies
    _set(ap, "leaf_interface_policy_groups", _capture_pgs(apic))
    # (les interface_policies plates sont couvertes par capture_flat)
    return ap

# relation-class -> (attribut tn*Name, champ NaC) pour les interface policy groups
PG_RELATIONS = [
    ("infraRsHIfPol", "tnFabricHIfPolName", "link_level_policy"),
    ("infraRsCdpIfPol", "tnCdpIfPolName", "cdp_policy"),
    ("infraRsLldpIfPol", "tnLldpIfPolName", "lldp_policy"),
    ("infraRsStpIfPol", "tnStpIfPolName", "spanning_tree_policy"),
    ("infraRsMcpIfPol", "tnMcpIfPolName", "mcp_policy"),
    ("infraRsL2IfPol", "tnL2IfPolName", "l2_policy"),
    ("infraRsLacpPol", "tnLacpLagPolName", "port_channel_policy"),
    ("infraRsStormctrlIfPol", "tnStormctrlIfPolName", "storm_control_policy"),
    ("infraRsL2PortSecurityPol", "tnL2PortSecurityPolName", "port_security_policy"),
    ("infraRsQosEgressDppIfPol", "tnQosDppPolName", "egress_data_plane_policing_policy"),   # [#88]
    ("infraRsQosIngressDppIfPol", "tnQosDppPolName", "ingress_data_plane_policing_policy"),
    ("infraRsQosPfcIfPol", "tnQosPfcIfPolName", "priority_flow_control_policy"),
]

def _capture_pgs(apic: Apic):
    rels = defaultdict(dict)
    for cls_, attr, field in PG_RELATIONS:
        try:
            for r in apic.get_class(cls_):
                if r.get(attr):
                    rels[_parent(r["dn"])][field] = r[attr]
        except Exception:
            pass
    aaep_rel = {}
    try:
        for r in apic.get_class("infraRsAttEntP"):
            if r.get("tDn"):
                aaep_rel[_parent(r["dn"])] = _seg(r["tDn"], "attentp")
    except Exception:
        pass
    pgs = []
    for cls_, fixed_type in (("infraAccPortGrp", "access"), ("infraAccBndlGrp", None)):
        for pg in apic.get_class(cls_):
            if "/tn-" in pg["dn"] or pg["name"] == "default" or pg["name"].startswith("system-"):
                continue
            o = {"name": pg["name"],
                 "type": fixed_type or ("vpc" if pg.get("lagT") == "node" else "pc")}
            o.update(rels.get(pg["dn"], {}))
            if aaep_rel.get(pg["dn"]):
                o["aaep"] = aaep_rel[pg["dn"]]
            pgs.append(o)
    return pgs

# ─────────────────────────────────── moteur TENANT-POLICIES (flatten derive)
def _tenant_flat_table():
    """[(subpath, class, module, label)] des sous-objets tenant.policies.* (flatten)."""
    txt = open(os.path.join(MODDIR, "aci_tenants.tf")).read()
    local2sub = {}
    for m in re.finditer(r'^  ([a-z_]+)\s*=\s*flatten\(\[(.*?)\n  \]\)', txt, re.S | re.M):
        sm = re.search(r'for\s+\w+\s+in\s+try\(\s*tenant\.([\w.]+),', m.group(2))
        if sm:
            local2sub[m.group(1)] = sm.group(1)
    out, seen = [], set()
    for m in re.finditer(r'module\s+"([^"]+)"\s*\{(.*?)\n\}', txt, re.S):
        name, body = m.group(1), m.group(2)
        if name in PHASE2_MODULES:
            continue
        src = re.search(r'source\s*=\s*"\./modules/([^"]+)"', body)
        fe = re.search(r'for_each\s*=\s*\{\s*for\s+\w+\s+in\s+local\.([\w]+)\s*:', body)
        if not (src and fe):
            continue
        sub = local2sub.get(fe.group(1))
        if not sub or not sub.startswith("policies"):     # generique = uniquement policies.*
            continue
        prim = child_primary(src.group(1))
        if prim and prim[1] not in seen:                  # une classe -> un seul subpath
            seen.add(prim[1]); out.append((sub, prim[1], src.group(1), prim[0]))
    return out

# Cas connus var-module != champ-YAML (curated : un remap générique parse-les-sections
# s'est avéré non fiable -> on liste seulement les cas sûrs et vérifiés).
TENANT_FIELD_REMAP = {
    "igmpIfPol": {"version_": "version"},
}

def capture_tenant_policies(apic: Apic, keep):
    """tenant -> {subpath: [objets]} pour toutes les policies tenant.
    Dedup par nom en gardant le DN le plus court (la même classe peut exister à
    plusieurs scopes : ex rtctrlProfile au niveau tenant ET sous un L3Out)."""
    byname = defaultdict(lambda: defaultdict(dict))   # tenant -> sub -> {name: (dn, obj)}
    for sub, cls, module, label in _tenant_flat_table():
        try:
            mos = apic.get_class(cls)
        except Exception:
            continue
        rmap = TENANT_FIELD_REMAP.get(cls, {})
        for mo in mos:
            t = _seg(mo["dn"], "tn")
            if t not in keep:
                continue
            o = obj(module, label, mo)
            for lf, yf in rmap.items():
                if lf in o:
                    o[yf] = o.pop(lf)
            key = o.get("name", mo["dn"])
            prev = byname[t][sub].get(key)
            if prev is None or len(mo["dn"]) < len(prev[0]):   # garde le scope le plus haut
                byname[t][sub][key] = (mo["dn"], o)
    # enrichir les route maps (rtctrlProfile) avec leurs contexts (rtctrlCtxP)
    ctx_by_prof = _by_parent(apic.get_class("rtctrlCtxP"))            # contexts par route map DN
    scope_attr = {x["dn"]: x for x in apic.get_class("rtctrlRsScopeToAttrP")}  # set_rule
    ctx_subj = _by_parent(apic.get_class("rtctrlRsCtxPToSubjP"))      # match_rules par ctx DN
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.route_control_route_maps", {}).items():
            contexts = []
            for c in sorted(ctx_by_prof.get(dn, []), key=lambda x: int(x.get("order", "0") or 0)):
                cx = {"name": c["name"]}
                if c.get("descr"):
                    cx["description"] = c["descr"]
                if c.get("action") and c["action"] != "permit":     # defaut permit
                    cx["action"] = c["action"]
                if c.get("order") and c["order"] != "0":            # defaut 0
                    cx["order"] = int(c["order"])
                sc = scope_attr.get(c["dn"] + "/scp/rsScopeToAttrP")
                if sc and sc.get("tnRtctrlAttrPName"):
                    cx["set_rule"] = sc["tnRtctrlAttrPName"]
                mrs = [r["tnRtctrlSubjPName"] for r in ctx_subj.get(c["dn"], [])
                       if r.get("tnRtctrlSubjPName")]
                if mrs:
                    cx["match_rules"] = mrs
                contexts.append(cx)
            if contexts:
                o["contexts"] = contexts
    # enrichir les set_rules (rtctrlAttrP) avec leurs clauses set
    setcomm = {x["dn"]: x for x in apic.get_class("rtctrlSetComm")}
    settag = {x["dn"]: x for x in apic.get_class("rtctrlSetTag")}
    sweight = {x["dn"]: x for x in apic.get_class("rtctrlSetWeight")}
    snh = {x["dn"]: x for x in apic.get_class("rtctrlSetNh")}
    spref = {x["dn"]: x for x in apic.get_class("rtctrlSetPref")}
    smetric = {x["dn"]: x for x in apic.get_class("rtctrlSetRtMetric")}
    smetrict = {x["dn"]: x for x in apic.get_class("rtctrlSetRtMetricType")}
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.set_rules", {}).items():
            c = setcomm.get(dn + "/scomm")
            if c and c.get("community"):
                o["community"] = c["community"]
                if c.get("setCriteria") and c["setCriteria"] != "append":   # defaut append
                    o["community_mode"] = c["setCriteria"]
            for d, field, key, cast in (
                (settag, "tag", "tag", int), (sweight, "weight", "weight", int),
                (snh, "addr", "next_hop", str), (spref, "localPref", "preference", int),
                (smetric, "metric", "metric", int)):
                suffix = {"tag": "/srttag", "weight": "/sweight", "addr": "/nh",
                          "localPref": "/spref", "metric": "/smetric"}[field]
                mo = d.get(dn + suffix)
                if mo and mo.get(field) not in (None, ""):
                    o[key] = cast(mo[field])
            mt = smetrict.get(dn + "/smetrict")
            if mt and mt.get("metricType"):
                o["metric_type"] = mt["metricType"]
    # enrichir les match_rules (rtctrlSubjP) avec leurs prefixes (rtctrlMatchRtDest)
    matchdest = _by_parent(apic.get_class("rtctrlMatchRtDest"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.match_rules", {}).items():
            prefixes = []
            for p in matchdest.get(dn, []):
                px = {"ip": p["ip"], "aggregate": p.get("aggregate") == "yes"}
                if p.get("descr"):
                    px["description"] = p["descr"]
                if p.get("fromPfxLen") and p["fromPfxLen"] != "0":
                    px["from_length"] = int(p["fromPfxLen"])
                if p.get("toPfxLen") and p["toPfxLen"] != "0":
                    px["to_length"] = int(p["toPfxLen"])
                prefixes.append(px)
            if prefixes:
                o["prefixes"] = prefixes
    # enrichir les multicast route maps (pimRouteMapPol) avec leurs entries (pimRouteMapEntry)
    # for_each sur var.entries (liste derivee) -> non capture par le moteur generique
    mrm_entries = _by_parent(apic.get_class("pimRouteMapEntry"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.multicast_route_maps", {}).items():
            entries = []
            for e in sorted(mrm_entries.get(dn, []), key=lambda x: int(x.get("order", "0") or 0)):
                ex = {"order": int(e["order"])}
                if e.get("action") and e["action"] != "permit":       # defaut permit
                    ex["action"] = e["action"]
                if e.get("src") and e["src"] not in ("0.0.0.0", ""):   # defaut 0.0.0.0
                    ex["source_ip"] = e["src"]
                if e.get("grp") and e["grp"] not in ("0.0.0.0", ""):
                    ex["group_ip"] = e["grp"]
                if e.get("rp") and e["rp"] not in ("0.0.0.0", ""):
                    ex["rp_ip"] = e["rp"]
                entries.append(ex)
            if entries:
                o["entries"] = entries
    # tenant netflow : match_parameters (join+sort non parsé) + relations exporter/monitor
    nf_rec = {x["dn"]: x for x in apic.get_class("netflowRecordPol")}
    nf_exp_ctx = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToCtx")}
    nf_exp_epg = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToEPg")}
    nf_mon_rec = {_parent(x["dn"]): x for x in apic.get_class("netflowRsMonitorToRecord")}
    nf_mon_exp = _by_parent(apic.get_class("netflowRsMonitorToExporter"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.netflow_records", {}).items():
            mo = nf_rec.get(dn)
            if mo and mo.get("match"):
                o["match_parameters"] = sorted(mo["match"].split(","))
        for name, (dn, o) in subs.get("policies.netflow_exporters", {}).items():
            ctx = nf_exp_ctx.get(dn)
            if ctx and ctx.get("tDn"):                       # -> vrf
                o["vrf"] = _seg(ctx["tDn"], "ctx")
            epg = nf_exp_epg.get(dn)
            if epg and epg.get("tDn"):
                tdn = epg["tDn"]
                if "/ap-" in tdn:                            # binding EPG
                    o["epg_type"] = "epg"
                    o["application_profile"] = _seg(tdn, "ap")
                    o["endpoint_group"] = _seg(tdn, "epg")
                elif "/out-" in tdn:                         # binding L3Out ext-EPG
                    o["epg_type"] = "external_epg"
                    o["l3out"] = _seg(tdn, "out")
                    o["external_endpoint_group"] = _seg(tdn, "instP")
        for name, (dn, o) in subs.get("policies.netflow_monitors", {}).items():
            rec = nf_mon_rec.get(dn)
            if rec and rec.get("tnNetflowRecordPolName"):
                o["flow_record"] = rec["tnNetflowRecordPolName"]
            exps = sorted(x["tnNetflowExporterPolName"] for x in nf_mon_exp.get(dn, [])
                          if x.get("tnNetflowExporterPolName"))
            if exps:
                o["flow_exporters"] = exps
    # qos custom (qosCustomPol) : dscp_priority_maps (qosDscpClass) + dot1p_classifiers
    # (qosDot1PClass) = for_each dérivés -> non vus par le générique. [#83]
    qds = _by_parent(apic.get_class("qosDscpClass"))
    qd1 = _by_parent(apic.get_class("qosDot1PClass"))

    def _qos_map(c, fromk, tok):
        m = {fromk: _num(c["from"]), tok: _num(c["to"])}    # DSCP keyword reste str, dot1p -> int
        if c.get("prio") and c["prio"] != "level3":            # défaut level3
            m["priority"] = c["prio"]
        if c.get("target") and c["target"] != "unspecified":
            m["dscp_target"] = c["target"]
        if c.get("targetCos") and c["targetCos"] != "unspecified":
            m["cos_target"] = _num(c["targetCos"])
        return m
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.qos", {}).items():
            dm = [_qos_map(c, "dscp_from", "dscp_to") for c in qds.get(dn, [])]
            if dm:
                o["dscp_priority_maps"] = dm
            d1 = [_qos_map(c, "dot1p_from", "dot1p_to") for c in qd1.get(dn, [])]
            if d1:
                o["dot1p_classifiers"] = d1
    # tenant-monitoring-policy (monEPGPol, base captée par le générique subpath
    # policies.monitoring.policies) : ENRICHIR avec fault_severity_policies (monEPGTarget/
    # faultSevAsnP, même logique que #14). snmp/syslog sources = réfs fabric groups -> omis. [#85]
    mon_tgt = _by_parent(apic.get_class("monEPGTarget"))       # par monEPGPol DN
    mon_fsev = _by_parent(apic.get_class("faultSevAsnP"))      # par monEPGTarget DN
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.monitoring.policies", {}).items():
            fsp = []
            for tgt in mon_tgt.get(dn, []):
                faults = []
                for f in mon_fsev.get(tgt["dn"], []):
                    fx = {"fault_id": f["code"], "initial_severity": f["initial"],
                          "target_severity": f["target"]}
                    if f.get("descr"):
                        fx["description"] = f["descr"]
                    faults.append(fx)
                if faults:
                    fsp.append({"class": tgt["scope"], "faults": faults})
            if fsp:
                o["fault_severity_policies"] = fsp
    # tenant-span dest groups (spanDestGrp) : base générique + spanRsDestEpg (comme #37/#41) [#86]
    sp_dest = _by_parent(apic.get_class("spanDest"))
    sp_destepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsDestEpg")}
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.span.destination_groups", {}).items():
            for d in sp_dest.get(dn, []):
                e = sp_destepg.get(d["dn"])
                if not e:
                    continue
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                if mm:
                    o["tenant"], o["application_profile"], o["endpoint_group"] = mm.groups()
                if e.get("ip"):
                    o["ip"] = e["ip"]
                if e.get("srcIpPrefix"):
                    o["source_prefix"] = e["srcIpPrefix"]
                if e.get("dscp") and e["dscp"] != "unspecified":
                    o["dscp"] = e["dscp"]
                if e.get("flowId") and e["flowId"] != "1":
                    o["flow_id"] = int(e["flowId"])
                if e.get("mtu") and e["mtu"] != "1518":
                    o["mtu"] = int(e["mtu"])
                if e.get("ttl") and e["ttl"] != "64":
                    o["ttl"] = int(e["ttl"])
                vm = re.match(r"ver(\d+)", e.get("ver", ""))
                if vm and vm.group(1) != "2":
                    o["version"] = int(vm.group(1))
                if e.get("verEnforced") == "yes":
                    o["enforce_version"] = True
                break
    # tenant-span source groups (spanSrcGrp) : base + admin_state générique ; enrichir
    # destination (spanSpanLbl) + sources (spanSrc + spanRsSrcToEpg) (comme #40) [#86]
    sp_src = _by_parent(apic.get_class("spanSrc"))
    sp_srcepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToEpg")}
    sp_lbl = _by_parent(apic.get_class("spanSpanLbl"))
    for t, subs in byname.items():
        for name, (dn, o) in subs.get("policies.span.source_groups", {}).items():
            for l in sp_lbl.get(dn, []):
                o["destination"] = l["name"]            # tenant : destination = string (nom du dest group)
                break
            sl = []
            for s in sp_src.get(dn, []):
                so = {"name": s["name"]}
                if s.get("descr"):
                    so["description"] = s["descr"]
                if s.get("dir") and s["dir"] != "both":
                    so["direction"] = s["dir"]
                e = sp_srcepg.get(s["dn"])
                if e:
                    mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                    if mm:
                        so["tenant"], so["application_profile"], so["endpoint_group"] = mm.groups()
                sl.append(so)
            if sl:
                o["sources"] = sl
    res = defaultdict(lambda: defaultdict(list))
    for t, subs in byname.items():
        for sub, objs in subs.items():
            res[t][sub] = [o for _, o in objs.values()]
    return res

# ═══════════════════════════════════════════════════════ CAPTURE : tenants
def capture_tenants(apic: Apic, warnings: list):
    tn_rows = [t for t in apic.get_class("fvTenant") if t["name"] not in SYSTEM_TENANTS]
    tenants = {t["name"]: obj("terraform-aci-tenant", "fvTenant", t) for t in tn_rows}
    keep = set(tenants)
    system = [{"name": n, "managed": False} for n in SYSTEM_TENANTS]
    tn = lambda dn: _seg(dn, "tn")

    vrfs = defaultdict(list)
    for v in apic.get_class("fvCtx"):
        if tn(v["dn"]) in keep:
            vrfs[tn(v["dn"])].append(obj("terraform-aci-vrf", "fvCtx", v))

    bd_vrf = {_parent(a["dn"]): _seg(a["tDn"], "ctx") for a in apic.get_class("fvRsCtx")}
    subnets = _by_parent(apic.get_class("fvSubnet"))
    bd_out = _by_parent(apic.get_class("fvRsBDToOut"))            # BD -> L3Out
    bds = defaultdict(list)
    for b in apic.get_class("fvBD"):
        if tn(b["dn"]) not in keep:
            continue
        vrf = bd_vrf.get(b["dn"])
        if not vrf:
            warnings.append(f"BD '{tn(b['dn'])}/{b['name']}' has no VRF -> skipped")
            continue
        o = obj("terraform-aci-bridge-domain", "fvBD", b); o["vrf"] = vrf
        if b.get("mcastARPDrop") == "yes":          # conditionnel (!=null?...:null) non parsé par attr_map, défaut false [#56]
            o["multicast_arp_drop"] = True
        _set(o, "subnets", [obj("terraform-aci-bridge-domain", "fvSubnet", s)
                            for s in subnets.get(b["dn"], [])])
        _set(o, "l3outs", [rs["tnL3extOutName"] for rs in bd_out.get(b["dn"], [])])
        bds[tn(b["dn"])].append(o)

    epg_bd = {_parent(a["dn"]): _seg(a["tDn"], "BD") for a in apic.get_class("fvRsBd")}
    epg_cons = _by_parent(apic.get_class("fvRsCons"))           # EPG -> contrats consommes
    epg_prov = _by_parent(apic.get_class("fvRsProv"))           # EPG -> contrats fournis
    epg_dom = _by_parent(apic.get_class("fvRsDomAtt"))          # EPG -> domaines
    epgs = _by_parent(apic.get_class("fvAEPg"))
    esgs = _by_parent(apic.get_class("fvESg"))                  # ESG par AP DN
    esg_scope = {x["dn"]: x for x in apic.get_class("fvRsScope")}    # <esg>/rsscope -> vrf
    esg_tagsel = _by_parent(apic.get_class("fvTagSelector"))    # tag selectors par ESG
    esg_ipsel = _by_parent(apic.get_class("fvEPSelector"))      # ip subnet selectors par ESG
    crtrns = {_parent(c["dn"]): c for c in apic.get_class("fvCrtrn")}   # <epg>/crtrn [#106]
    ipattrs = _by_parent(apic.get_class("fvIpAttr"), 2)         # par EPG DN (sous crtrn)
    macattrs = _by_parent(apic.get_class("fvMacAttr"), 2)
    aps = defaultdict(list)
    for ap_mo in apic.get_class("fvAp"):
        if tn(ap_mo["dn"]) not in keep:
            continue
        eg, useg = [], []
        for e in epgs.get(ap_mo["dn"], []):
            attr_based = e.get("isAttrBasedEPg") == "yes"        # uSeg EPG [#106]
            mod = "terraform-aci-useg-endpoint-group" if attr_based else "terraform-aci-endpoint-group"
            eo = obj(mod, "fvAEPg", e)
            if epg_bd.get(e["dn"]):
                eo["bridge_domain"] = epg_bd[e["dn"]]
            # contrats (consommes / fournis) — cœur de la securite ACI
            cons = [rs["tnVzBrCPName"] for rs in epg_cons.get(e["dn"], [])]
            prov = [rs["tnVzBrCPName"] for rs in epg_prov.get(e["dn"], [])]
            if cons or prov:
                eo["contracts"] = {}
                if cons: eo["contracts"]["consumers"] = cons
                if prov: eo["contracts"]["providers"] = prov
            # domaines associes (physiques / vmm)
            phys, vmw = [], []
            for rs in epg_dom.get(e["dn"], []):
                t = rs["tDn"]
                if "/phys-" in t: phys.append(_ref(t))
                elif "/vmmp-VMware/dom-" in t: vmw.append(t.rsplit("/dom-", 1)[1])
            _set(eo, "physical_domains", phys); _set(eo, "vmware_vmm_domains", vmw)
            if attr_based:                                       # criteres uSeg [#106]
                cr = crtrns.get(e["dn"] + "/crtrn")
                ua = {}
                if cr and cr.get("match") and cr["match"] != "any":
                    ua["match_type"] = cr["match"]
                ips = []
                for x in ipattrs.get(e["dn"], []):
                    io = {"name": x["name"]}
                    if x.get("usefvSubnet") == "yes":            # DEFAUT NaC = true !
                        io["use_epg_subnet"] = True
                    else:
                        io["use_epg_subnet"] = False             # requis sinon defaut true
                        if x.get("ip") and x["ip"] != "0.0.0.0":
                            io["ip"] = x["ip"]
                    ips.append(io)
                _set(ua, "ip_statements", ips)
                macs = [{"name": x["name"], "mac": x["mac"]}
                        for x in macattrs.get(e["dn"], [])]
                _set(ua, "mac_statements", macs)
                # vm_statements (fvVmAttr) : VMM absent du simulateur -> non captures
                if ua:
                    eo["useg_attributes"] = ua
                useg.append(eo)
            else:
                eg.append(eo)
        # endpoint security groups (fvESg) sous l'AP : attrs + vrf + selecteurs
        esg_list = []
        for es in esgs.get(ap_mo["dn"], []):
            eso = obj("terraform-aci-endpoint-security-group", "fvESg", es)
            sc = esg_scope.get(es["dn"] + "/rsscope")
            if sc and sc.get("tnFvCtxName"):
                eso["vrf"] = sc["tnFvCtxName"]
            tags = []
            for ts in esg_tagsel.get(es["dn"], []):
                t = {"key": ts["matchKey"], "value": ts["matchValue"]}
                if ts.get("valueOperator") and ts["valueOperator"] != "equals":
                    t["operator"] = ts["valueOperator"]
                if ts.get("descr"):
                    t["description"] = ts["descr"]
                tags.append(t)
            _set(eso, "tag_selectors", tags)
            ips = []
            for s in esg_ipsel.get(es["dn"], []):
                mm = re.search(r"ip=='([^']+)'", s.get("matchExpression", ""))
                if not mm:
                    continue
                ip = {"value": mm.group(1)}
                if s.get("descr"):
                    ip["description"] = s["descr"]
                ips.append(ip)
            _set(eso, "ip_subnet_selectors", ips)
            esg_list.append(eso)
        ao = obj("terraform-aci-application-profile", "fvAp", ap_mo)
        _set(ao, "endpoint_groups", eg)
        _set(ao, "useg_endpoint_groups", useg)
        _set(ao, "endpoint_security_groups", esg_list)
        aps[tn(ap_mo["dn"])].append(ao)

    entries = _by_parent(apic.get_class("vzEntry"))
    filters = defaultdict(list)
    for f in apic.get_class("vzFilter"):
        if tn(f["dn"]) not in keep:
            continue
        fo = obj("terraform-aci-filter", "vzFilter", f)
        ents = []
        for e in entries.get(f["dn"], []):
            eo = obj("terraform-aci-filter", "vzEntry", e)
            # prot/ports = ternaires (numéro->mot-clé) non parsés par attr_map ; on capture la forme
            # mot-clé telle qu'APIC la stocke (DN basé sur le nom -> stable). [#58]
            if e.get("prot") and e["prot"] != "unspecified":
                eo["protocol"] = e["prot"]
            for fld, key in (("sFromPort", "source_from_port"), ("sToPort", "source_to_port"),
                             ("dFromPort", "destination_from_port"), ("dToPort", "destination_to_port")):
                if e.get(fld) and e[fld] != "unspecified":
                    eo[key] = e[fld]
            ents.append(eo)
        _set(fo, "entries", ents)
        filters[tn(f["dn"])].append(fo)

    subjf = _by_parent(apic.get_class("vzRsSubjFiltAtt"))
    subjs = _by_parent(apic.get_class("vzSubj"))
    contracts = defaultdict(list)
    for c in apic.get_class("vzBrCP"):
        if tn(c["dn"]) not in keep:
            continue
        co = obj("terraform-aci-contract", "vzBrCP", c)
        subs = []
        for s in subjs.get(c["dn"], []):
            so = obj("terraform-aci-contract", "vzSubj", s)
            _set(so, "filters", [{"filter": rs.get("tnVzFilterName") or _ref(rs["tDn"])}
                                 for rs in subjf.get(s["dn"], [])])
            subs.append(so)
        _set(co, "subjects", subs)
        contracts[tn(c["dn"])].append(co)

    l3_vrf = {_parent(a["dn"]): _seg(a["tDn"], "ctx") for a in apic.get_class("l3extRsEctx")}
    l3_dom = {_parent(a["dn"]): _ref(a["tDn"]) for a in apic.get_class("l3extRsL3DomAtt")}
    # external endpoint groups (l3extInstP) sous chaque L3Out : primaire + subnets + contrats
    ext_sub = _by_parent(apic.get_class("l3extSubnet"))
    extepg_by_l3out = defaultdict(list)
    for e in apic.get_class("l3extInstP"):
        if tn(e["dn"]) not in keep:
            continue
        eo = obj("terraform-aci-external-endpoint-group", "l3extInstP", e)
        _set(eo, "subnets", [obj("terraform-aci-external-endpoint-group", "l3extSubnet", s)
                             for s in ext_sub.get(e["dn"], [])])
        cons = [rs["tnVzBrCPName"] for rs in epg_cons.get(e["dn"], [])]
        prov = [rs["tnVzBrCPName"] for rs in epg_prov.get(e["dn"], [])]
        if cons or prov:
            eo["contracts"] = {}
            if cons: eo["contracts"]["consumers"] = cons
            if prov: eo["contracts"]["providers"] = prov
        extepg_by_l3out[_parent(e["dn"])].append(eo)
    # interface profiles (l3extLIfP) sous chaque node profile : name/qos + interfaces (paths)
    path_bind = _by_parent(apic.get_class("l3extRsPathL3OutAtt"))
    peer_bind = _by_parent(apic.get_class("bgpPeerP"))              # bgpPeerP par path DN
    asp_by_dn = {a["dn"]: a for a in apic.get_class("bgpAsP")}      # <peer>/as -> remote_as
    localasn_by_dn = {a["dn"]: a for a in apic.get_class("bgpLocalAsnP")}  # <peer>/localasn
    ospfifp_by_dn = {x["dn"]: x for x in apic.get_class("ospfIfP")}        # <lifp>/ospfIfP
    ospfrsifpol_by_dn = {x["dn"]: x for x in apic.get_class("ospfRsIfPol")}
    bfdrsifpol_by_dn = {x["dn"]: x for x in apic.get_class("bfdRsIfPol")}  # <lifp>/bfdIfP/rsIfPol
    ifp_by_np = defaultdict(list)
    for ifp in apic.get_class("l3extLIfP"):
        if tn(ifp["dn"]) not in keep:
            continue
        ifo = obj("terraform-aci-l3out-interface-profile", "l3extLIfP", ifp)
        ifaces = []
        for pb in path_bind.get(ifp["dn"], []):
            t = pb.get("tDn", "")
            mp = re.search(r"pod-(\d+)", t)
            mn = re.search(r"(?:protpaths|paths)-([\d-]+)", t)
            mport = re.search(r"pathep-\[([^\]]+)\]", t)
            if not (mp and mn and mport):
                continue
            ns = mn.group(1).split("-")
            ifc = {"node_id": int(ns[0]), "pod_id": int(mp.group(1))}
            if len(ns) > 1:
                ifc["node2_id"] = int(ns[1])
            # port physique eth<module>/<port>[/<sub>]  OU  port-channel/vPC (channel)
            pm = re.match(r"eth(\d+)/(\d+)(?:/(\d+))?$", mport.group(1))
            if pm:
                ifc["module"] = int(pm.group(1)); ifc["port"] = int(pm.group(2))
                if pm.group(3):
                    ifc["sub_port"] = int(pm.group(3))
            else:
                ifc["channel"] = mport.group(1)
            if pb.get("addr") and pb["addr"] != "0.0.0.0":
                ifc["ip"] = pb["addr"]
            if pb.get("encap", "").startswith("vlan-"):
                ifc["vlan"] = int(pb["encap"].replace("vlan-", ""))
            svi = pb.get("ifInstT") == "ext-svi"
            if svi:
                ifc["svi"] = True
            if pb.get("mtu") and pb["mtu"] != "inherit":
                ifc["mtu"] = _num(pb["mtu"])
            if pb.get("descr"):
                ifc["description"] = pb["descr"]
            if pb.get("autostate") == "enabled":          # defaut disabled (false)
                ifc["autostate"] = True
            if pb.get("mode") and pb["mode"] != "regular":  # defaut regular
                ifc["mode"] = pb["mode"]
            if pb.get("mac") and pb["mac"] != "00:22:BD:F8:19:FF":  # defaut module
                ifc["mac"] = pb["mac"]
            if svi and pb.get("encapScope") == "ctx":       # defaut local
                ifc["scope"] = "vrf"
            # bgp peers (bgpPeerP) sous le path : reverse des flags packes
            peers = []
            for bp in peer_bind.get(pb["dn"], []):
                pr = {"ip": bp["addr"]}
                asp = asp_by_dn.get(bp["dn"] + "/as")
                if asp and asp.get("asn"):
                    pr["remote_as"] = asp["asn"]
                if bp.get("descr"):
                    pr["description"] = bp["descr"]
                ctrl = set((bp.get("ctrl") or "").split(","))
                for fl, key in (("allow-self-as", "allow_self_as"), ("as-override", "as_override"),
                                ("dis-peer-as-check", "disable_peer_as_check"), ("nh-self", "next_hop_self"),
                                ("send-com", "send_community"), ("send-ext-com", "send_ext_community")):
                    if fl in ctrl:
                        pr[key] = True
                pctrl = set((bp.get("peerCtrl") or "").split(","))
                if "bfd" in pctrl:
                    pr["bfd"] = True
                if "dis-conn-check" in pctrl:
                    pr["disable_connected_check"] = True
                pas = set((bp.get("privateASctrl") or "").split(","))
                for fl, key in (("remove-all", "remove_all_private_as"), ("remove-exclusive", "remove_private_as"),
                                ("replace-as", "replace_private_as_with_local_as")):
                    if fl in pas:
                        pr[key] = True
                aft = set((bp.get("addrTCtrl") or "").split(","))
                pr["unicast_address_family"] = "af-ucast" in aft       # defaut true
                pr["multicast_address_family"] = "af-mcast" in aft     # defaut true
                if bp.get("adminSt") == "disabled":                    # defaut enabled (true)
                    pr["admin_state"] = False
                if bp.get("allowedSelfAsCnt") and bp["allowedSelfAsCnt"] != "3":
                    pr["allowed_self_as_count"] = int(bp["allowedSelfAsCnt"])
                if bp.get("ttl") and bp["ttl"] != "1":
                    pr["ttl"] = int(bp["ttl"])
                if bp.get("weight") and bp["weight"] != "0":
                    pr["weight"] = int(bp["weight"])
                la = localasn_by_dn.get(bp["dn"] + "/localasn")
                if la:
                    if la.get("localAsn"):
                        pr["local_as"] = int(la["localAsn"])
                    if la.get("asnPropagate") and la["asnPropagate"] != "none":
                        pr["as_propagate"] = la["asnPropagate"]
                peers.append(pr)
            if peers:
                ifc["bgp_peers"] = peers
            ifaces.append(ifc)
        _set(ifo, "interfaces", ifaces)
        # ospf interface profile (ospfIfP) + relation policy (ospfRsIfPol)
        oifp = ospfifp_by_dn.get(ifp["dn"] + "/ospfIfP")
        if oifp is not None:
            ospf = {}
            if oifp.get("name"):
                ospf["ospf_interface_profile_name"] = oifp["name"]
            rsp = ospfrsifpol_by_dn.get(oifp["dn"] + "/rsIfPol")
            if rsp and rsp.get("tnOspfIfPolName"):
                ospf["policy"] = rsp["tnOspfIfPolName"]
            if ospf:
                ifo["ospf"] = ospf
        # bfd interface profile (bfdIfP) -> bfd_policy (via bfdRsIfPol)
        brs = bfdrsifpol_by_dn.get(ifp["dn"] + "/bfdIfP/rsIfPol")
        if brs and brs.get("tnBfdIfPolName"):
            ifo["bfd_policy"] = brs["tnBfdIfPolName"]
        ifp_by_np[_parent(ifp["dn"])].append(ifo)
    # node profiles (l3extLNodeP) sous chaque L3Out : name/description + nodes + interface_profiles
    node_bind = _by_parent(apic.get_class("l3extRsNodeL3OutAtt"))
    loopback_bind = _by_parent(apic.get_class("l3extLoopBackIfP"))   # par node-binding DN
    route_bind = _by_parent(apic.get_class("ipRouteP"))              # par node-binding DN
    nh_bind = _by_parent(apic.get_class("ipNexthopP"))               # par route DN
    np_by_l3out = defaultdict(list)
    for np in apic.get_class("l3extLNodeP"):
        if tn(np["dn"]) not in keep:
            continue
        npo = obj("terraform-aci-l3out-node-profile", "l3extLNodeP", np)
        nodes = []
        for nb in node_bind.get(np["dn"], []):
            m = re.search(r"pod-(\d+)/node-(\d+)", nb.get("tDn", ""))
            if not m:
                continue
            nd = {"node_id": int(m.group(2)), "pod_id": int(m.group(1))}
            if nb.get("rtrId"):
                nd["router_id"] = nb["rtrId"]
            nd["router_id_as_loopback"] = nb.get("rtrIdLoopBack") == "yes"
            # loopbacks explicites (l3extLoopBackIfP enfants du node-binding)
            lbs = [lb["addr"] for lb in loopback_bind.get(nb["dn"], []) if lb.get("addr")]
            if lbs:
                nd["loopbacks"] = lbs
            # static routes (ipRouteP) + next hops (ipNexthopP)
            routes = []
            for rt in route_bind.get(nb["dn"], []):
                sr = {"prefix": rt["ip"]}
                if rt.get("descr"):
                    sr["description"] = rt["descr"]
                if rt.get("pref") is not None:
                    sr["preference"] = int(rt["pref"])
                sr["bfd"] = "bfd" in (rt.get("rtCtrl") or "")
                nhs = []
                for nh in nh_bind.get(rt["dn"], []):
                    h = {"ip": nh["nhAddr"]}
                    if nh.get("descr"):
                        h["description"] = nh["descr"]
                    if nh.get("pref") is not None:
                        h["preference"] = int(nh["pref"])
                    if nh.get("type"):
                        h["type"] = nh["type"]
                    nhs.append(h)
                if nhs:
                    sr["next_hops"] = nhs
                routes.append(sr)
            if routes:
                nd["static_routes"] = routes
            nodes.append(nd)
        _set(npo, "nodes", nodes)
        _set(npo, "interface_profiles", ifp_by_np.get(np["dn"], []))
        np_by_l3out[_parent(np["dn"])].append(npo)
    drl_by_l3out = {_parent(x["dn"]): x for x in apic.get_class("l3extDefaultRouteLeakP")}
    l3outs = defaultdict(list)
    for l in apic.get_class("l3extOut"):
        if tn(l["dn"]) not in keep:
            continue
        vrf, dom = l3_vrf.get(l["dn"]), l3_dom.get(l["dn"])
        if not (vrf and dom):
            warnings.append(f"L3Out '{tn(l['dn'])}/{l['name']}' has no VRF/domain -> skipped")
            continue
        lo = obj("terraform-aci-l3out", "l3extOut", l); lo["vrf"] = vrf; lo["domain"] = dom
        # content = merge(...) non parsé par attr_map -> enrich attrs propres l3extOut [#60]
        if l.get("descr"):
            lo["description"] = l["descr"]
        if l.get("nameAlias"):
            lo["alias"] = l["nameAlias"]
        if l.get("targetDscp") and l["targetDscp"] != "unspecified":
            lo["target_dscp"] = l["targetDscp"]
        rtc = (l.get("enforceRtctrl") or "").split(",")
        if "import" in rtc:                          # défaut false
            lo["import_route_control_enforcement"] = True
        if "export" not in rtc:                      # défaut true (export présent par défaut)
            lo["export_route_control_enforcement"] = False
        if l.get("mplsEnabled") == "yes":            # sr_mpls (défaut false)
            lo["sr_mpls"] = True
        # default route leak (l3extDefaultRouteLeakP) -> bloc default_route_leak_policy
        drl = drl_by_l3out.get(l["dn"])
        if drl:
            sc = (drl.get("scope") or "").split(",")
            lo["default_route_leak_policy"] = {
                "always": drl.get("always") == "yes",
                "criteria": drl.get("criteria"),
                "context_scope": "ctx" in sc,
                "outside_scope": "l3-out" in sc,
            }
        _set(lo, "external_endpoint_groups", extepg_by_l3out.get(l["dn"], []))
        _set(lo, "node_profiles", np_by_l3out.get(l["dn"], []))
        l3outs[tn(l["dn"])].append(lo)

    pols = capture_tenant_policies(apic, keep)                # policies.* (BGP/OSPF/HSRP...)
    # hsrp-interface-policy (hsrpIfPol) : ctrl = join(concat(var.bfd_enable?["bfd"], var.use_bia?["bia"]))
    # MULTI-LIGNE dans le module -> attr_map (parse ligne/ligne) tronque l'expr. Reverse dédié. [#54]
    hsrp_ctrl = {(_seg(x["dn"], "tn"), x["name"]): x.get("ctrl", "") for x in apic.get_class("hsrpIfPol")}
    for t2, subs in pols.items():
        for o in subs.get("policies.hsrp_interface_policies", []):
            flags = hsrp_ctrl.get((t2, o["name"]), "").split(",")
            if "bfd" in flags:                                # défaut false
                o["bfd_enable"] = True
            if "bia" in flags:
                o["use_bia"] = True
    # endpoint-mac-tag-policy (fvEpMacTag) : bdName/ctxName ternaires + tags (tagTag) ; for_each sur
    # liste dérivée -> capture dédiée. bdName '*' <-> bridge_domain 'all' (+ ctxName=vrf). [#55]
    epmt = defaultdict(list)
    tags_by = _by_parent(apic.get_class("tagTag"))            # par fvEpMacTag DN
    for m in apic.get_class("fvEpMacTag"):
        t2 = _seg(m["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"mac": m["mac"]}
        bd = m.get("bdName", "")
        if bd == "*":
            o["bridge_domain"] = "all"
            if m.get("ctxName"):
                o["vrf"] = m["ctxName"]
        elif bd:
            o["bridge_domain"] = bd
        tags = [{"key": tg["key"], "value": tg.get("value", "")}
                for tg in tags_by.get(m["dn"], []) if tg.get("key")]
        if tags:
            o["tags"] = tags
        epmt[t2].append(o)
    for t2, lst in epmt.items():
        pols.setdefault(t2, {})["policies.endpoint_mac_tags"] = lst
    # endpoint-ip-tag-policy (fvEpIpTag) : ip + vrf (ctxName) + tags. Miroir IP de #55. [#61]
    epit = defaultdict(list)
    for m in apic.get_class("fvEpIpTag"):
        t2 = _seg(m["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"ip": m["ip"]}
        if m.get("ctxName"):
            o["vrf"] = m["ctxName"]
        tags = [{"key": tg["key"], "value": tg.get("value", "")}
                for tg in tags_by.get(m["dn"], []) if tg.get("key")]
        if tags:
            o["tags"] = tags
        epit[t2].append(o)
    for t2, lst in epit.items():
        pols.setdefault(t2, {})["policies.endpoint_ip_tags"] = lst
    # dhcp-relay-policy (dhcpRelayP owner=tenant) + providers (dhcpRsProv tDn epg/l3out). for_each
    # liste dérivée -> capture dédiée. Filtre scope tenant (les owner=infra sont uni/infra). [#66]
    prov_by = _by_parent(apic.get_class("dhcpRsProv"))
    dhcpr = defaultdict(list)
    for p in apic.get_class("dhcpRelayP"):
        t2 = _seg(p["dn"], "tn")
        if not t2 or t2 not in keep:                          # exclut owner=infra (uni/infra)
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        provs = []
        for rs in prov_by.get(p["dn"], []):
            pr = {"ip": rs.get("addr")}
            tdn = rs.get("tDn", "")
            mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", tdn)
            if mm:
                pr["type"] = "epg"
                pr["tenant"], pr["application_profile"], pr["endpoint_group"] = mm.groups()
            else:
                mm = re.search(r"tn-([^/]+)/out-([^/]+)/instP-(.+)$", tdn)
                if mm:
                    pr["type"] = "l3out"
                    pr["tenant"], pr["l3out"], pr["external_endpoint_group"] = mm.groups()
            provs.append(pr)
        if provs:
            o["providers"] = provs
        dhcpr[t2].append(o)
    for t2, lst in dhcpr.items():
        pols.setdefault(t2, {})["policies.dhcp_relay_policies"] = lst
    # dhcp-option-policy (dhcpOptionPol) + options (dhcpOption id/data/name). [#66]
    opt_by = _by_parent(apic.get_class("dhcpOption"))
    dhcpo = defaultdict(list)
    for p in apic.get_class("dhcpOptionPol"):
        t2 = _seg(p["dn"], "tn")
        if not t2 or t2 not in keep:
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        opts = []
        for op in opt_by.get(p["dn"], []):
            oo = {"name": op["name"]}
            if op.get("id") and op["id"] != "0":
                oo["id"] = int(op["id"])
            if op.get("data"):
                oo["data"] = op["data"]
            opts.append(oo)
        if opts:
            o["options"] = opts
        dhcpo[t2].append(o)
    for t2, lst in dhcpo.items():
        pols.setdefault(t2, {})["policies.dhcp_option_policies"] = lst
    # ip-sla monitoring policy (fvIPSLAMonitoringPol) : le moteur générique ne mappe que `name`
    # (content = merge(...) non parsable par attr_map) -> capture dédiée, écrase l'entrée partielle.
    ipsla = defaultdict(list)
    for p in apic.get_class("fvIPSLAMonitoringPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("slaType") and p["slaType"] != "icmp":          # défaut icmp
            o["sla_type"] = p["slaType"]
        if p.get("slaDetectMultiplier") and p["slaDetectMultiplier"] != "3":   # défaut 3
            o["multiplier"] = int(p["slaDetectMultiplier"])
        if p.get("slaFrequency") and p["slaFrequency"] != "60":  # défaut 60
            o["frequency"] = int(p["slaFrequency"])
        if p.get("slaPort") and p["slaPort"] != "0":             # défaut 0
            o["port"] = int(p["slaPort"])
        if p.get("slaType") == "http":                            # champs http seulement si type http
            if p.get("httpMethod"):  o["http_method"] = p["httpMethod"]
            if p.get("httpVersion"): o["http_version"] = p["httpVersion"]
            if p.get("httpUri"):     o["http_uri"] = p["httpUri"]
        ipsla[t2].append(o)
    for t2, lst in ipsla.items():
        pols.setdefault(t2, {})["policies.ip_sla_policies"] = lst
    # track-member (fvTrackMember) + track-list (fvTrackList) -> tenant.policies.*  [modules #34/#33]
    # NON couverts par le moteur générique : leur module pointe local.track_lists (liste dérivée),
    # pas le flatten _raw -> _tenant_flat_table ne les associe pas. Capture dédiée + enfants/refs.
    ipsla_ref = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("fvRsIpslaMonPol")}
    for tm in apic.get_class("fvTrackMember"):
        t2 = _seg(tm["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": tm["name"]}
        if tm.get("descr"):
            o["description"] = tm["descr"]
        if tm.get("dstIpAddr"):
            o["destination_ip"] = tm["dstIpAddr"]
        sd = tm.get("scopeDn", "")
        mm = re.search(r"/out-(.+)$", sd)
        if mm:
            o["scope_type"] = "l3out"; o["scope"] = mm.group(1)
        else:
            mm = re.search(r"/BD-(.+)$", sd)
            if mm:
                o["scope_type"] = "bd"; o["scope"] = mm.group(1)
        mm = re.search(r"ipslaMonitoringPol-(.+)$", ipsla_ref.get(tm["dn"], ""))
        if mm:
            o["ip_sla_policy"] = mm.group(1)
        pols.setdefault(t2, {}).setdefault("policies.track_members", []).append(o)
    members_by_list = _by_parent(apic.get_class("fvRsOtmListMember"))   # track list DN -> relations
    for tl in apic.get_class("fvTrackList"):
        t2 = _seg(tl["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": tl["name"]}
        if tl.get("descr"):
            o["description"] = tl["descr"]
        if tl.get("type") and tl["type"] != "percentage":         # défaut percentage
            o["type"] = tl["type"]
        for fld, key, dflt in (("percentageUp", "percentage_up", "1"),
                               ("percentageDown", "percentage_down", "0"),
                               ("weightUp", "weight_up", "1"),
                               ("weightDown", "weight_down", "0")):
            if tl.get(fld) and tl[fld] != dflt:
                o[key] = int(tl[fld])
        mems = []
        for r in members_by_list.get(tl["dn"], []):
            mm = re.search(r"trackmember-(.+)$", r.get("tDn", ""))
            if mm:
                mems.append(mm.group(1))
        if mems:
            o["track_members"] = mems
        pols.setdefault(t2, {}).setdefault("policies.track_lists", []).append(o)
    out = list(system)
    # imported contracts (vzCPIf) : name + source (tenant/contract) via vzRsIf
    vzrsif = {_parent(x["dn"]): x for x in apic.get_class("vzRsIf")}   # cif DN -> rsif
    imported = defaultdict(list)
    for cif in apic.get_class("vzCPIf"):
        tnm = _seg(cif["dn"], "tn")
        if tnm not in keep:
            continue
        ic = {"name": cif["name"]}
        rs = vzrsif.get(cif["dn"])
        if rs and rs.get("tDn"):
            mm = re.search(r"tn-([^/]+)/brc-(.+)$", rs["tDn"])
            if mm:
                ic["tenant"] = mm.group(1); ic["contract"] = mm.group(2)
        imported[tnm].append(ic)
    # oob contracts (vzOOBBrCP sous tn-mgmt) -> enrichit le tenant systeme mgmt
    oob = []
    for c in apic.get_class("vzOOBBrCP"):
        if _seg(c["dn"], "tn") != "mgmt" or c.get("name") == "default":
            continue
        o = {"name": c["name"]}
        if c.get("nameAlias"):
            o["alias"] = c["nameAlias"]
        if c.get("descr"):
            o["description"] = c["descr"]
        if c.get("scope") and c["scope"] != "context":      # defaut context
            o["scope"] = c["scope"]
        oob.append(o)
    for s in system:
        if s["name"] == "mgmt" and oob:
            s["oob_contracts"] = oob
    # oob endpoint groups (mgmtOoB sous tn-mgmt) -> tenant mgmt.oob_endpoint_groups
    oob_prov = _by_parent(apic.get_class("mgmtRsOoBProv"))    # par mgmtOoB DN
    oob_sr = _by_parent(apic.get_class("mgmtStaticRoute"))    # par mgmtOoB DN
    ooepgs = []
    for e in apic.get_class("mgmtOoB"):
        if _seg(e["dn"], "tn") != "mgmt" or e.get("name") == "default":
            continue
        eo = {"name": e["name"]}
        prov = [r["tnVzOOBBrCPName"] for r in oob_prov.get(e["dn"], []) if r.get("tnVzOOBBrCPName")]
        if prov:
            eo["oob_contracts"] = {"providers": prov}     # bloc imbriqué (data model)
        sr = [r["prefix"] for r in oob_sr.get(e["dn"], []) if r.get("prefix")]
        if sr:
            eo["static_routes"] = sr
        ooepgs.append(eo)
    for s in system:
        if s["name"] == "mgmt" and ooepgs:
            s["oob_endpoint_groups"] = ooepgs
    # inband endpoint groups (mgmtInB sous tn-mgmt) -> tenant mgmt.inband_endpoint_groups
    inb_bd = {a["dn"].rsplit("/rsmgmtBD", 1)[0]: a.get("tnFvBDName")
              for a in apic.get_class("mgmtRsMgmtBD")}
    inb_sub = _by_parent(apic.get_class("fvSubnet"))
    inb_cons = _by_parent(apic.get_class("fvRsCons"))
    inb_prov = _by_parent(apic.get_class("fvRsProv"))
    inbepgs = []
    for e in apic.get_class("mgmtInB"):
        if _seg(e["dn"], "tn") != "mgmt":
            continue
        eo = {"name": e["name"]}
        if e.get("encap", "").startswith("vlan-"):
            eo["vlan"] = int(e["encap"].replace("vlan-", ""))
        if inb_bd.get(e["dn"]):
            eo["bridge_domain"] = inb_bd[e["dn"]]
        subs = []
        for s2 in inb_sub.get(e["dn"], []):
            su = {"ip": s2["ip"]}
            if s2.get("descr"):
                su["description"] = s2["descr"]
            subs.append(su)
        if subs:
            eo["subnets"] = subs
        cons = [r["tnVzBrCPName"] for r in inb_cons.get(e["dn"], []) if r.get("tnVzBrCPName")]
        prov = [r["tnVzBrCPName"] for r in inb_prov.get(e["dn"], []) if r.get("tnVzBrCPName")]
        if cons or prov:
            eo["contracts"] = {}
            if cons:
                eo["contracts"]["consumers"] = cons
            if prov:
                eo["contracts"]["providers"] = prov
        inbepgs.append(eo)
    for s in system:
        if s["name"] == "mgmt" and inbepgs:
            s["inb_endpoint_groups"] = inbepgs
    # external mgmt instances (mgmtInstP sous tn-mgmt) -> tenant mgmt.ext_mgmt_instances
    ext_sub = _by_parent(apic.get_class("mgmtSubnet"))       # par mgmtInstP DN
    ext_cons = _by_parent(apic.get_class("mgmtRsOoBCons"))   # par mgmtInstP DN
    extmgmt = []
    for e in apic.get_class("mgmtInstP"):
        if _seg(e["dn"], "tn") != "mgmt":
            continue
        eo = {"name": e["name"]}
        subs = [s2["ip"] for s2 in ext_sub.get(e["dn"], []) if s2.get("ip")]
        if subs:
            eo["subnets"] = subs
        cons = [c["tnVzOOBBrCPName"] for c in ext_cons.get(e["dn"], []) if c.get("tnVzOOBBrCPName")]
        if cons:
            eo["oob_contracts"] = {"consumers": cons}
        extmgmt.append(eo)
    for s in system:
        if s["name"] == "mgmt" and extmgmt:
            s["ext_mgmt_instances"] = extmgmt
    # mpls custom qos (qosMplsCustomPol sous tn-infra) -> enrichit le tenant systeme
    # infra (patron mgmt #25). NB vxlan custom qos : classes qosVxlan* absentes en
    # 6.0(7e) (unresolved class) -> pas de capture. [#92]
    mpls_ing = _by_parent(apic.get_class("qosMplsIngressRule"))
    mpls_eg = _by_parent(apic.get_class("qosMplsEgressRule"))
    mplspols = []
    for p in apic.get_class("qosMplsCustomPol"):
        if _seg(p["dn"], "tn") != "infra" or p.get("name") == "default":
            continue
        po = {"name": p["name"]}
        if p.get("nameAlias"):
            po["alias"] = p["nameAlias"]
        if p.get("descr"):
            po["description"] = p["descr"]
        ing = []
        for r in mpls_ing.get(p["dn"], []):
            ro = {"exp_from": _num(r["from"]), "exp_to": _num(r["to"])}
            if r.get("prio") not in ("", None, "unspecified"):
                ro["priority"] = r["prio"]
            if r.get("target") not in ("", None, "unspecified"):
                ro["dscp_target"] = _num(r["target"])
            if r.get("targetCos") not in ("", None, "unspecified"):
                ro["cos_target"] = _num(r["targetCos"])
            ing.append(ro)
        _set(po, "ingress_rules", ing)
        eg = []
        for r in mpls_eg.get(p["dn"], []):
            ro = {"dscp_from": _num(r["from"]), "dscp_to": _num(r["to"])}
            if r.get("targetExp") not in ("", None, "unspecified"):
                ro["exp_target"] = _num(r["targetExp"])
            if r.get("targetCos") not in ("", None, "unspecified"):
                ro["cos_target"] = _num(r["targetCos"])
            eg.append(ro)
        _set(po, "egress_rules", eg)
        mplspols.append(po)
    for s in system:
        if s["name"] == "infra" and mplspols:
            s.setdefault("policies", {})["mpls_custom_qos_policies"] = mplspols
    # service redirect health groups (vnsRedirectHealthGroup) -> tenant.services.redirect_health_groups
    hgs = defaultdict(list)
    for hg in apic.get_class("vnsRedirectHealthGroup"):
        t2 = _seg(hg["dn"], "tn")
        if t2 not in keep:
            continue
        ho = {"name": hg["name"]}
        if hg.get("descr"):
            ho["description"] = hg["descr"]
        hgs[t2].append(ho)
    # service redirect policies (vnsSvcRedirectPol, PBR) -> tenant.services.redirect_policies
    rdest = _by_parent(apic.get_class("vnsRedirectDest"))      # par vnsSvcRedirectPol DN
    rhg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("vnsRsRedirectHealthGroup")}  # par dest DN
    redir = defaultdict(list)
    for p in apic.get_class("vnsSvcRedirectPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        po = {"name": p["name"]}
        if p.get("descr"):
            po["description"] = p["descr"]
        if p.get("nameAlias"):
            po["alias"] = p["nameAlias"]
        if p.get("AnycastEnabled") == "yes":
            po["anycast"] = True
        if p.get("destType") and p["destType"] != "L3":
            po["type"] = p["destType"]
        if p.get("hashingAlgorithm") and p["hashingAlgorithm"] != "sip-dip-prototype":
            po["hashing"] = p["hashingAlgorithm"]
        if p.get("thresholdEnable") == "yes":
            po["threshold"] = True
        if p.get("maxThresholdPercent") and p["maxThresholdPercent"] != "0":
            po["max_threshold"] = int(p["maxThresholdPercent"])
        if p.get("minThresholdPercent") and p["minThresholdPercent"] != "0":
            po["min_threshold"] = int(p["minThresholdPercent"])
        if p.get("programLocalPodOnly") == "yes":
            po["pod_aware"] = True
        if p.get("resilientHashEnabled") == "yes":
            po["resilient_hashing"] = True
        if p.get("srcMacRewriteEnabled") == "yes":     # data model défaut null ; 'no'=auto-APIC -> ignoré
            po["rewrite_source_mac"] = True
        if p.get("thresholdDownAction") and p["thresholdDownAction"] != "permit":
            po["threshold_down_action"] = p["thresholdDownAction"]
        dests = []
        for d in rdest.get(p["dn"], []):
            de = {"ip": d["ip"]}
            if d.get("destName"):
                de["name"] = d["destName"]
            if d.get("descr"):
                de["description"] = d["descr"]
            if d.get("mac") and d["mac"] != "00:00:00:00:00:00":
                de["mac"] = d["mac"]
            if d.get("ip2") and d["ip2"] != "0.0.0.0":
                de["ip_2"] = d["ip2"]
            hgref = rhg.get(d["dn"])
            if hgref:
                mm = re.search(r"redirectHealthGroup-(.+)$", hgref)
                if mm:
                    de["redirect_health_group"] = mm.group(1)
            dests.append(de)
        if dests:
            po["l3_destinations"] = dests
        redir[t2].append(po)
    # service redirect BACKUP policies (vnsBackupPol) -> tenant.services.redirect_backup_policies  [module #31]
    # même structure que redirect_policies mais : objet plat (name/descr) + clé dest = destination_name
    bkp = defaultdict(list)
    for p in apic.get_class("vnsBackupPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        po = {"name": p["name"]}
        if p.get("descr"):
            po["description"] = p["descr"]
        dests = []
        for d in rdest.get(p["dn"], []):                       # rdest groupe vnsRedirectDest par parent DN
            de = {"ip": d["ip"]}
            if d.get("destName"):
                de["destination_name"] = d["destName"]         # clé destination_name (≠ redirect_policies)
            if d.get("descr"):
                de["description"] = d["descr"]
            if d.get("mac") and d["mac"] != "00:00:00:00:00:00":
                de["mac"] = d["mac"]
            if d.get("ip2") and d["ip2"] != "0.0.0.0":
                de["ip_2"] = d["ip2"]
            hgref = rhg.get(d["dn"])
            if hgref:
                mm = re.search(r"redirectHealthGroup-(.+)$", hgref)
                if mm:
                    de["redirect_health_group"] = mm.group(1)
            dests.append(de)
        if dests:
            po["l3_destinations"] = dests
        bkp[t2].append(po)
    # service EPG policies (vnsSvcEPgPol) -> tenant.services.service_epg_policies  [module #32]
    svcepg = defaultdict(list)
    for p in apic.get_class("vnsSvcEPgPol"):
        t2 = _seg(p["dn"], "tn")
        if t2 not in keep:
            continue
        po = {"name": p["name"]}
        if p.get("descr"):
            po["description"] = p["descr"]
        if p.get("prefGrMemb") == "include":          # défaut = exclude (preferred_group false)
            po["preferred_group"] = True
        svcepg[t2].append(po)
    # ── L4L7 PHYSICAL [#107-#109] : l4l7-device + service-graph-template (mode
    # single-device) + device-selection-policy. Objets logiques purs (aucun
    # deploiement requis). VIRTUAL/vmm + multi-device NON captures (hors sim).
    cdevs = _by_parent(apic.get_class("vnsCDev"))
    cifs = _by_parent(apic.get_class("vnsCIf"))
    cpaths = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsCIfPathAtt")}
    lifs = _by_parent(apic.get_class("vnsLIf"))
    liftgts = _by_parent(apic.get_class("vnsRsCIfAttN"))
    physdom = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsALDevToPhysDomP")}
    ldevs = defaultdict(list)
    for d in apic.get_class("vnsLDevVip"):
        t2 = _seg(d["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": d["name"]}
        if d.get("nameAlias"):
            o["alias"] = d["nameAlias"]
        if d.get("contextAware") and d["contextAware"] != "single-Context":
            o["context_aware"] = d["contextAware"]
        if d.get("devtype") and d["devtype"] != "PHYSICAL":
            o["type"] = d["devtype"]
        if d.get("funcType") and d["funcType"] != "GoTo":
            o["function"] = d["funcType"]
        if d.get("isCopy") == "yes":
            o["copy_device"] = True
        if d.get("managed") == "yes":
            o["managed"] = True
        if d.get("promMode") == "yes":
            o["promiscuous_mode"] = True
        if d.get("svcType") and d["svcType"] != "FW":
            o["service_type"] = d["svcType"]
        if d.get("trunking") == "yes":
            o["trunking"] = True
        if d.get("activeActive") == "yes":
            o["active_active"] = True
        if physdom.get(d["dn"]):
            o["physical_domain"] = physdom[d["dn"]].replace("uni/phys-", "")
        cl = []
        for c in cdevs.get(d["dn"], []):
            co = {"name": c["name"]}
            il = []
            for ci in cifs.get(c["dn"], []):
                io = {"name": ci["name"]}
                mm = re.search(r"pod-(\d+)/paths-(\d+)/pathep-\[eth(\d+)/(\d+)\]",
                               cpaths.get(ci["dn"], ""))
                if mm:
                    if mm.group(1) != "1":
                        io["pod_id"] = int(mm.group(1))
                    io["node_id"] = int(mm.group(2))
                    io["module"] = int(mm.group(3))
                    io["port"] = int(mm.group(4))
                il.append(io)
            _set(co, "interfaces", il)
            cl.append(co)
        _set(o, "concrete_devices", cl)
        ll = []
        for li in lifs.get(d["dn"], []):
            lo = {"name": li["name"]}
            if li.get("encap", "").startswith("vlan-"):
                lo["vlan"] = int(li["encap"].replace("vlan-", ""))
            cil = []
            for x in liftgts.get(li["dn"], []):
                mm = re.search(r"/cDev-([^/]+)/cIf-\[([^\]]+)\]", x.get("tDn", ""))
                if mm:
                    cil.append({"device": mm.group(1), "interface_name": mm.group(2)})
            _set(lo, "concrete_interfaces", cil)
            ll.append(lo)
        _set(o, "logical_interfaces", ll)
        ldevs[t2].append(o)
    absnodes = _by_parent(apic.get_class("vnsAbsNode"))
    node2dev = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsNodeToLDev")}
    sgts = defaultdict(list)
    for g in apic.get_class("vnsAbsGraph"):
        t2 = _seg(g["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("nameAlias"):
            o["alias"] = g["nameAlias"]
        nl = absnodes.get(g["dn"], [])
        if len(nl) == 1:                                     # mode single-device
            n = nl[0]
            if n.get("funcTemplateType") and n["funcTemplateType"] != "FW_ROUTED":
                o["template_type"] = n["funcTemplateType"]
            if n.get("routingMode") == "Redirect":
                o["redirect"] = True
            if n.get("shareEncap") == "yes":
                o["share_encapsulation"] = True
            dev = {}
            mm = re.search(r"tn-([^/]+)/lDevVip-(.+)$", node2dev.get(n["dn"], ""))
            if mm:
                dev["name"] = mm.group(2)
                if mm.group(1) != t2:
                    dev["tenant"] = mm.group(1)
            if n.get("name") and n["name"] != "N1":
                dev["node_name"] = n["name"]
            if dev:
                o["device"] = dev
        sgts[t2].append(o)
    lifctxs = _by_parent(apic.get_class("vnsLIfCtx"))
    ctx2lif = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsLIfCtxToLIf")}
    ctx2bd = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsLIfCtxToBD")}
    ctx2rp = {_parent(x["dn"]): x.get("tDn", "") for x in apic.get_class("vnsRsLIfCtxToSvcRedirectPol")}
    dsps = defaultdict(list)
    for c in apic.get_class("vnsLDevCtx"):
        t2 = _seg(c["dn"], "tn")
        if t2 not in keep:
            continue
        o = {"contract": c.get("ctrctNameOrLbl"),
             "service_graph_template": c.get("graphNameOrLbl")}
        if c.get("nodeNameOrLbl") and c["nodeNameOrLbl"] != "N1":
            o["node_name"] = c["nodeNameOrLbl"]
        for lc in lifctxs.get(c["dn"], []):
            side = lc.get("connNameOrLbl")
            if side not in ("consumer", "provider"):
                continue
            so = {}
            mm = re.search(r"/lIf-(.+)$", ctx2lif.get(lc["dn"], ""))
            if mm:
                so["logical_interface"] = mm.group(1)
            mm = re.search(r"tn-([^/]+)/BD-(.+)$", ctx2bd.get(lc["dn"], ""))
            if mm:
                so["bridge_domain"] = {"name": mm.group(2)}
                if mm.group(1) != t2:
                    so["bridge_domain"]["tenant"] = mm.group(1)
            mm = re.search(r"tn-([^/]+)/svcCont/svcRedirectPol-(.+)$", ctx2rp.get(lc["dn"], ""))
            if mm:
                so["redirect_policy"] = {"name": mm.group(2)}
                if mm.group(1) != t2:
                    so["redirect_policy"]["tenant"] = mm.group(1)
            if lc.get("l3Dest") == "no":                     # defaut true
                so["l3_destination"] = False
            if lc.get("permitLog") == "yes":                 # defaut false
                so["permit_logging"] = True
            if so:
                o[side] = so
        dsps[t2].append(o)
    for name, t in tenants.items():
        _set(t, "vrfs", vrfs[name]); _set(t, "bridge_domains", bds[name])
        _set(t, "application_profiles", aps[name]); _set(t, "filters", filters[name])
        _set(t, "contracts", contracts[name]); _set(t, "l3outs", l3outs[name])
        _set(t, "imported_contracts", imported[name])
        svc = {}
        if hgs[name]:
            svc["redirect_health_groups"] = hgs[name]
        if redir[name]:
            svc["redirect_policies"] = redir[name]
        if bkp[name]:
            svc["redirect_backup_policies"] = bkp[name]
        if svcepg[name]:
            svc["service_epg_policies"] = svcepg[name]
        if ldevs[name]:
            svc["l4l7_devices"] = ldevs[name]
        if sgts[name]:
            svc["service_graph_templates"] = sgts[name]
        if dsps[name]:
            svc["device_selection_policies"] = dsps[name]
        if svc:
            t["services"] = svc
        for sub, objs in pols.get(name, {}).items():          # place a tenant.<subpath>
            node = t
            for p in sub.split(".")[:-1]:
                node = node.setdefault(p, {})
            node[sub.split(".")[-1]] = objs
        out.append(t)
    return out

# ═══════════════════════════════════════════════════════ ecriture YAML
def _write_section(filename, top_key, payload, comment):
    import yaml
    path = os.path.join(DATA_DIR, filename)
    existing = {}
    if os.path.isfile(path):
        existing = yaml.safe_load(open(path)) or {}
    apic = existing.get("apic", {})
    # REMPLACEMENT COMPLET de la section (pas de merge) : la capture est une PHOTO
    # de la fabric. L'ancien merge superficiel laissait survivre des cles perimees
    # quand la fabric avait perdu des objets (ex : fabric remise a vide) -> data/
    # incoherent, erreurs d'evaluation terraform (Invalid index). [bug corrige 2026-07-02]
    apic[top_key] = payload
    head = (f"# {comment}\n# Generated by tools/nac.py on {datetime.date.today()} "
            f"(read-only). Check with `nac.py plan` before `sync`.\n")
    with open(path, "w") as f:
        f.write(head + "---\n" + yaml.safe_dump({"apic": apic}, sort_keys=False, allow_unicode=True))
    return os.path.relpath(path, ROOT)

# ═══════════════════════════════════════════════════════ sous-commandes
def _deep_merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        elif isinstance(v, list) and isinstance(dst.get(k), list):
            names = {o.get("name") for o in dst[k] if isinstance(o, dict)}
            dst[k].extend(o for o in v if not (isinstance(o, dict) and o.get("name") in names))
        else:
            dst[k] = v

def capture_leaf_selectors(apic: Apic):
    """Sélecteurs d'interface (infraHPortS) par leaf interface profile (nom).
    Exclut les profils système (system-port-profile-node-X, auto-générés)."""
    base = {x["dn"]: x for x in apic.get_class("infraRsAccBaseGrp")}    # <hps>/rsaccBaseGrp -> policy_group
    blks = _by_parent(apic.get_class("infraPortBlk"))                   # port blocks par infraHPortS DN
    out = defaultdict(list)
    for hp in apic.get_class("infraHPortS"):
        prof = _seg(hp["dn"], "accportprof")
        if not prof or prof.startswith("system-"):
            continue
        sel = {"name": hp["name"]}
        if hp.get("descr"):
            sel["description"] = hp["descr"]
        bg = base.get(hp["dn"] + "/rsaccBaseGrp")
        if bg and bg.get("tDn"):
            mm = re.search(r"funcprof/(accportgrp|accbundle|brkoutportgrp)-(.+)$", bg["tDn"])
            if mm:
                sel["policy_group_type"] = {"accportgrp": "access", "brkoutportgrp": "breakout"}.get(mm.group(1), "pc")
                sel["policy_group"] = mm.group(2)
        pblks = []
        for b in blks.get(hp["dn"], []):
            pb = {"name": b["name"], "from_port": int(b["fromPort"])}
            if b.get("descr"):
                pb["description"] = b["descr"]
            if b.get("fromCard") and b["fromCard"] != "1":            # defaut 1
                pb["from_module"] = int(b["fromCard"])
            if b.get("toCard") and b["toCard"] != b.get("fromCard", "1"):  # defaut = from_module
                pb["to_module"] = int(b["toCard"])
            if b.get("toPort") and b["toPort"] != b["fromPort"]:      # defaut = from_port
                pb["to_port"] = int(b["toPort"])
            pblks.append(pb)
        if pblks:
            sel["port_blocks"] = pblks
        out[prof].append(sel)
    return out

def capture_fex_profiles(apic: Apic):
    """fex interface profiles (infraFexP ; infraFexBndlGrp homonyme implicite) +
    selecteurs (infraHPortS sous fexprof-, miroir de capture_leaf_selectors) +
    port_blocks. Le type du policy_group vient de la definition du PG dans data
    (lookup cablage), pas du selecteur. -> access_policies.fex_interface_profiles.
    [#102-#103]"""
    base = {x["dn"]: x for x in apic.get_class("infraRsAccBaseGrp")}
    blks = _by_parent(apic.get_class("infraPortBlk"))
    sels = defaultdict(list)
    for hp in apic.get_class("infraHPortS"):
        prof = _seg(hp["dn"], "fexprof")
        if not prof:
            continue
        sel = {"name": hp["name"]}
        if hp.get("descr"):
            sel["description"] = hp["descr"]
        bg = base.get(hp["dn"] + "/rsaccBaseGrp")
        if bg and bg.get("tDn"):
            mm = re.search(r"funcprof/(?:accportgrp|accbundle)-(.+)$", bg["tDn"])
            if mm:
                sel["policy_group"] = mm.group(1)
        pblks = []
        for b in blks.get(hp["dn"], []):
            pb = {"name": b["name"], "from_port": int(b["fromPort"])}
            if b.get("descr"):
                pb["description"] = b["descr"]
            if b.get("fromCard") and b["fromCard"] != "1":
                pb["from_module"] = int(b["fromCard"])
            if b.get("toCard") and b["toCard"] != b.get("fromCard", "1"):
                pb["to_module"] = int(b["toCard"])
            if b.get("toPort") and b["toPort"] != b["fromPort"]:
                pb["to_port"] = int(b["toPort"])
            pblks.append(pb)
        _set(sel, "port_blocks", pblks)
        sels[prof].append(sel)
    out = []
    for f in apic.get_class("infraFexP"):
        o = {"name": f["name"]}
        if sels.get(f["name"]):
            o["selectors"] = sels[f["name"]]
        out.append(o)
    return out

def capture_node_addresses(apic: Apic, warnings: list):
    """adresses mgmt statiques (mgmtRsOoBStNode / mgmtRsInBStNode) -> node_policies
    {nodes: [{id, role: unspecified, oob_/inb_address...}], oob/inb_endpoint_group}.
    EXCLUT : node-1 (l'APIC lui-meme — son adresse OOB EST l'acces a la fabric) et
    tout noeud ENREGISTRE (fabricNode) : l'emettre exigerait role leaf/spine, ce qui
    declencherait node_registration + les profils switch auto. role: unspecified =
    sciemment HORS de tous les filtres for_each du cablage. [#104-#105]"""
    registered = set()
    for n in apic.get_class("fabricNode"):
        mm = re.search(r"node-(\d+)$", n.get("dn", ""))
        if mm:
            registered.add(int(mm.group(1)))
    nodes, epg = {}, {}
    for cls, key in (("mgmtRsOoBStNode", "oob"), ("mgmtRsInBStNode", "inb")):
        for r in apic.get_class(cls):
            mm = re.search(r"node-(\d+)\]", r.get("dn", ""))
            if not mm:
                continue
            nid = int(mm.group(1))
            if nid == 1:
                continue                                   # l'APIC : ne JAMAIS capturer
            if nid in registered:
                warnings.append(f"static mgmt address of REGISTERED node {nid} "
                                "not captured (would require leaf/spine role -> node_registration)")
                continue
            me = re.search(r"/(?:oob|inb)-([^/]+)/rs", r["dn"])
            if me:
                epg[key] = me.group(1)
            o = nodes.setdefault(nid, {"id": nid, "role": "unspecified"})
            if r.get("addr") and r["addr"] != "0.0.0.0":
                o[f"{key}_address"] = r["addr"]
            if r.get("gw") and r["gw"] != "0.0.0.0":
                o[f"{key}_gateway"] = r["gw"]
            if r.get("v6Addr") and r["v6Addr"] != "::":
                o[f"{key}_v6_address"] = r["v6Addr"]
            if r.get("v6Gw") and r["v6Gw"] != "::":
                o[f"{key}_v6_gateway"] = r["v6Gw"]
    out = {}
    for key, k2 in (("oob", "oob_endpoint_group"), ("inb", "inb_endpoint_group")):
        if epg.get(key) and epg[key] != "default":
            out[k2] = epg[key]
    if nodes:
        out["nodes"] = [nodes[k] for k in sorted(nodes)]
    return out

def capture_monitoring_policies(apic: Apic, pol_class="monInfraPol", target_class="monInfraTarget"):
    """monitoring policies (monInfraPol access / monFabricPol fabric) : name/descr +
    fault_severity_policies (<target> scope -> faultSevAsnP). Exclut 'default'/'common'."""
    targets = _by_parent(apic.get_class(target_class))       # par <pol> DN
    faults = _by_parent(apic.get_class("faultSevAsnP"))       # par <target> DN
    out = []
    for mp in apic.get_class(pol_class):
        if mp.get("name") in ("default", "common"):
            continue
        po = {"name": mp["name"]}
        if mp.get("descr"):
            po["description"] = mp["descr"]
        fsp = []
        for tg in targets.get(mp["dn"], []):
            flist = []
            for f in faults.get(tg["dn"], []):
                fd = {"fault_id": f["code"]}
                if f.get("initial") and f["initial"] != "inherit":
                    fd["initial_severity"] = f["initial"]
                if f.get("target") and f["target"] != "inherit":
                    fd["target_severity"] = f["target"]
                if f.get("descr"):
                    fd["description"] = f["descr"]
                flist.append(fd)
            if flist:
                fsp.append({"class": tg.get("scope"), "faults": flist})
        if fsp:
            po["fault_severity_policies"] = fsp
        out.append(po)
    return out

def capture_fabric_selectors(apic: Apic, sel_class, rs_class, rs_rn, prof_seg, pg_seg,
                             blk_class="fabricPortBlk"):
    """selecteurs d'interface FABRIC (leaf fabricLFPortS / spine fabricSFPortS) par
    profil. Miroir de capture_leaf_selectors, classes fabric. Exclut profils system-*.
    Réutilisé pour l'access spine (infraSHPortS) qui partage la structure mono-type-PG
    mais utilise infraPortBlk (passer blk_class)."""
    base = {x["dn"]: x for x in apic.get_class(rs_class)}   # -> policy_group
    blks = _by_parent(apic.get_class(blk_class))
    out = defaultdict(list)
    for hp in apic.get_class(sel_class):
        prof = _seg(hp["dn"], prof_seg)
        if not prof or prof.startswith("system-"):
            continue
        sel = {"name": hp["name"]}
        if hp.get("descr"):
            sel["description"] = hp["descr"]
        bg = base.get(hp["dn"] + "/" + rs_rn)
        if bg and bg.get("tDn"):
            mm = re.search(rf"{pg_seg}-(.+)$", bg["tDn"])
            if mm:
                sel["policy_group"] = mm.group(1)
        pblks = []
        for b in blks.get(hp["dn"], []):
            pb = {"name": b["name"], "from_port": int(b["fromPort"])}
            if b.get("descr"):
                pb["description"] = b["descr"]
            if b.get("fromCard") and b["fromCard"] != "1":
                pb["from_module"] = int(b["fromCard"])
            if b.get("toCard") and b["toCard"] != b.get("fromCard", "1"):
                pb["to_module"] = int(b["toCard"])
            if b.get("toPort") and b["toPort"] != b["fromPort"]:
                pb["to_port"] = int(b["toPort"])
            pblks.append(pb)
        if pblks:
            sel["port_blocks"] = pblks
        out[prof].append(sel)
    return out

def capture_span_filter_groups(apic: Apic):
    """span-filter-group (spanFilterGrp) + entries (spanFilterEntry) -> access_policies.span.filter_groups.
    PIÈGE : le module construit le DN de spanFilterEntry avec la valeur BRUTE (proto-${ip_protocol})
    mais le content avec le mot-clé (ipProto=tcp) ; APIC stocke le DN canonique en mots-clés
    (proto-tcp). Conséquence : la forme numérique ('6') est INSTABLE (le DN recalculé proto-6 ≠
    proto-tcp -> forces replacement). On capture donc la forme MOT-CLÉ telle que stockée par APIC
    (tcp/http/https…), qui round-trippe de façon stable (le data model l'accepte aussi)."""
    ents_by_grp = _by_parent(apic.get_class("spanFilterEntry"))
    out = []
    for g in apic.get_class("spanFilterGrp"):
        if not g["dn"].startswith("uni/infra/"):       # access only (uni/infra/filtergrp-)
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        ents = []
        for e in ents_by_grp.get(g["dn"], []):
            en = {}
            if e.get("name"):
                en["name"] = e["name"]
            if e.get("descr"):
                en["description"] = e["descr"]
            if e.get("srcAddr"):
                en["source_ip"] = e["srcAddr"]
            if e.get("dstAddr"):
                en["destination_ip"] = e["dstAddr"]
            if e.get("ipProto") and e["ipProto"] != "unspecified":
                en["ip_protocol"] = e["ipProto"]
            sfp, stp = e.get("srcPortFrom"), e.get("srcPortTo")
            if sfp and sfp != "unspecified":
                en["source_from_port"] = sfp
                if stp and stp != sfp:
                    en["source_to_port"] = stp
            dfp, dtp = e.get("dstPortFrom"), e.get("dstPortTo")
            if dfp and dfp != "unspecified":
                en["destination_from_port"] = dfp
                if dtp and dtp != dfp:
                    en["destination_to_port"] = dtp
            ents.append(en)
        if ents:
            o["entries"] = ents
        out.append(o)
    return out

def capture_span_destination_groups(apic: Apic, scope="uni/infra/"):
    """span-destination-group (spanDestGrp) -> {access|fabric}_policies.span.destination_groups.
    Variante ERSPAN-to-EPG (spanRsDestEpg) : tenant/ap/epg + ip/source_prefix + dscp/flow/mtu/ttl/ver.
    scope=uni/infra/ (access #37) ou uni/fabric/ (fabric #41) — la classe spanDestGrp est partagée."""
    dests = _by_parent(apic.get_class("spanDest"))                         # par spanDestGrp DN
    epg = {_parent(x["dn"]): x for x in apic.get_class("spanRsDestEpg")}   # par spanDest DN
    out = []
    for g in apic.get_class("spanDestGrp"):
        if not g["dn"].startswith(scope) or g.get("uid") == "0":         # scope + hors système
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        for d in dests.get(g["dn"], []):
            e = epg.get(d["dn"])
            if not e:
                continue
            mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
            if mm:
                o["tenant"], o["application_profile"], o["endpoint_group"] = mm.groups()
            if e.get("ip"):
                o["ip"] = e["ip"]
            if e.get("srcIpPrefix"):
                o["source_prefix"] = e["srcIpPrefix"]
            if e.get("dscp") and e["dscp"] != "unspecified":
                o["dscp"] = e["dscp"]
            if e.get("flowId") and e["flowId"] != "1":
                o["flow_id"] = int(e["flowId"])
            if e.get("mtu") and e["mtu"] != "1518":
                o["mtu"] = int(e["mtu"])
            if e.get("ttl") and e["ttl"] != "64":
                o["ttl"] = int(e["ttl"])
            vm = re.match(r"ver(\d+)", e.get("ver", ""))
            if vm and vm.group(1) != "2":                                  # défaut ver2
                o["version"] = int(vm.group(1))
            if e.get("verEnforced") == "yes":                              # défaut no
                o["enforce_version"] = True
            break                                                          # un seul spanDest par groupe
        out.append(o)
    return out

def capture_span_source_groups(apic: Apic):
    """access-span-source-group (spanSrcGrp) -> access_policies.span.source_groups. Classe AMBIGUË
    access(uni/infra)/fabric(uni/fabric) -> exclue du moteur plat, filtre uni/infra. name/desc +
    admin_state (adminSt enabled/disabled, défaut disabled) + filter_group (spanRsSrcGrpToFilterGrp,
    réf #36) + destination label (spanSpanLbl, réf dest group #37) + sources (spanSrc + EPG/L3Out)."""
    srcs = _by_parent(apic.get_class("spanSrc"))                              # par srcgrp DN
    srcepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToEpg")}  # par spanSrc DN
    srcl3 = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToL3extOut")}
    fgrp = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcGrpToFilterGrp")}  # par srcgrp DN
    lbl = _by_parent(apic.get_class("spanSpanLbl"))                           # par srcgrp DN
    out = []
    for g in apic.get_class("spanSrcGrp"):
        if not g["dn"].startswith("uni/infra/") or g.get("uid") == "0":      # access only, hors système
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("adminSt") == "enabled":                    # défaut disabled (admin_state false)
            o["admin_state"] = True
        fg = fgrp.get(g["dn"])                               # fgrp indexé par parent (srcgrp DN)
        if fg:
            mm = re.search(r"filtergrp-(.+)$", fg.get("tDn", ""))
            if mm:
                o["filter_group"] = mm.group(1)
        for l in lbl.get(g["dn"], []):
            dest = {"name": l["name"]}
            if l.get("descr"):
                dest["description"] = l["descr"]
            o["destination"] = dest
            break
        sl = []
        for s in srcs.get(g["dn"], []):
            so = {"name": s["name"]}
            if s.get("descr"):
                so["description"] = s["descr"]
            if s.get("dir") and s["dir"] != "both":          # défaut both
                so["direction"] = s["dir"]
            if s.get("spanOnDrop") == "yes":                 # défaut no
                so["span_drop"] = True
            e = srcepg.get(s["dn"])
            if e:
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                if mm:
                    so["tenant"], so["application_profile"], so["endpoint_group"] = mm.groups()
            l3 = srcl3.get(s["dn"])
            if l3:
                mm = re.search(r"tn-([^/]+)/out-(.+)$", l3.get("tDn", ""))
                if mm:
                    so["tenant"], so["l3out"] = mm.group(1), mm.group(2)
                vm = re.match(r"vlan-(\d+)", l3.get("encap", ""))
                if vm:
                    so["vlan"] = int(vm.group(1))
            sl.append(so)
        if sl:
            o["sources"] = sl
        out.append(o)
    return out

def capture_fabric_span_source_groups(apic: Apic):
    """fabric-span-source-group (spanSrcGrp uni/fabric) -> fabric_policies.span.source_groups.
    Diffère de l'access (#40) : pas de filter_group ; bindings source = VRF (spanRsSrcToCtx) /
    bridge_domain (spanRsSrcToBD) / fabric_paths (spanRsSrcToPathEp). admin_state défaut=enabled."""
    srcs = _by_parent(apic.get_class("spanSrc"))                             # par srcgrp DN
    ctx = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToCtx")}    # par spanSrc DN
    bd = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToBD")}
    lbl = _by_parent(apic.get_class("spanSpanLbl"))                          # par srcgrp DN
    out = []
    for g in apic.get_class("spanSrcGrp"):
        if not g["dn"].startswith("uni/fabric/") or g.get("uid") == "0":    # fabric only, hors système
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("adminSt") == "disabled":                   # défaut enabled (admin_state true)
            o["admin_state"] = False
        for l in lbl.get(g["dn"], []):
            dest = {"name": l["name"]}
            if l.get("descr"):
                dest["description"] = l["descr"]
            o["destination"] = dest
            break
        sl = []
        for s in srcs.get(g["dn"], []):
            so = {"name": s["name"]}
            if s.get("descr"):
                so["description"] = s["descr"]
            if s.get("dir") and s["dir"] != "both":
                so["direction"] = s["dir"]
            if s.get("spanOnDrop") == "yes":
                so["span_drop"] = True
            c = ctx.get(s["dn"])
            if c:
                mm = re.search(r"tn-([^/]+)/ctx-(.+)$", c.get("tDn", ""))
                if mm:
                    so["tenant"], so["vrf"] = mm.groups()
            b = bd.get(s["dn"])
            if b:
                mm = re.search(r"tn-([^/]+)/BD-(.+)$", b.get("tDn", ""))
                if mm:
                    so["tenant"], so["bridge_domain"] = mm.groups()
            sl.append(so)
        if sl:
            o["sources"] = sl
        out.append(o)
    return out

def capture_vspan_destination_groups(apic: Apic):
    """vspan-destination-group (spanVDestGrp) -> access_policies.vspan.destination_groups.
    destinations (spanVDest) + ERSPAN summary (spanVEpgSummary: ip/dscp/flow/mtu/ttl) +
    éventuel vport (spanRsDestToVPort: tenant/ap/epg/endpoint)."""
    vdest = _by_parent(apic.get_class("spanVDest"))                          # par vdestgrp DN
    summ = {_parent(x["dn"]): x for x in apic.get_class("spanVEpgSummary")}  # par vdest DN
    vport = {_parent(x["dn"]): x for x in apic.get_class("spanRsDestToVPort")}
    out = []
    for g in apic.get_class("spanVDestGrp"):
        if not g["dn"].startswith("uni/infra/") or g.get("uid") == "0":  # access only, exclut défauts système (3 scopes)
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        dl = []
        for d in vdest.get(g["dn"], []):
            de = {"name": d["name"]}
            if d.get("descr"):
                de["description"] = d["descr"]
            s = summ.get(d["dn"])
            if s:
                if s.get("dstIp") and s["dstIp"] != "0.0.0.0":
                    de["ip"] = s["dstIp"]
                if s.get("dscp") and s["dscp"] != "unspecified":
                    de["dscp"] = s["dscp"]
                if s.get("flowId") and s["flowId"] != "1":
                    de["flow_id"] = int(s["flowId"])
                if s.get("mtu") and s["mtu"] != "1518":
                    de["mtu"] = int(s["mtu"])
                if s.get("ttl") and s["ttl"] != "64":
                    de["ttl"] = int(s["ttl"])
            vp = vport.get(d["dn"])
            if vp:
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-([^/]+)/cep-(.+)$", vp.get("tDn", ""))
                if mm:
                    de["tenant"], de["application_profile"], de["endpoint_group"], de["endpoint"] = mm.groups()
            dl.append(de)
        if dl:
            o["destinations"] = dl
        out.append(o)
    return out

def capture_vspan_sessions(apic: Apic):
    """vspan-session (spanVSrcGrp) -> access_policies.vspan.sessions. NON capté par le moteur plat
    (for_each sur liste dérivée local.vspan_sessions). name/descr + admin_state (adminSt start/stop,
    défaut start) + destination label (spanSpanLbl) + sources (spanVSrc + spanRsSrcToEpg)."""
    lbl = _by_parent(apic.get_class("spanSpanLbl"))                           # par vsrcgrp DN
    vsrc = _by_parent(apic.get_class("spanVSrc"))                             # par vsrcgrp DN
    srcepg = {_parent(x["dn"]): x for x in apic.get_class("spanRsSrcToEpg")}  # par vsrc DN
    out = []
    for g in apic.get_class("spanVSrcGrp"):
        if not g["dn"].startswith("uni/infra/") or g.get("uid") == "0":  # access only, exclut défauts système (3 scopes)
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        if g.get("adminSt") == "stop":                       # défaut start (admin_state true)
            o["admin_state"] = False
        for l in lbl.get(g["dn"], []):
            dest = {"name": l["name"]}
            if l.get("descr"):
                dest["description"] = l["descr"]
            o["destination"] = dest
            break
        srcs = []
        for s in vsrc.get(g["dn"], []):
            so = {"name": s["name"]}
            if s.get("descr"):
                so["description"] = s["descr"]
            if s.get("dir") and s["dir"] != "both":          # défaut both
                so["direction"] = s["dir"]
            e = srcepg.get(s["dn"])
            if e:
                mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", e.get("tDn", ""))
                if mm:
                    so["tenant"], so["application_profile"], so["endpoint_group"] = mm.groups()
            srcs.append(so)
        if srcs:
            o["sources"] = srcs
        out.append(o)
    return out

def capture_leaf_switch_profiles(apic: Apic):
    """access-leaf-switch-profile (infraNodeP) -> access_policies.leaf_switch_profiles. name +
    selectors (infraLeafS : name + policy via infraRsAccNodePGrp + node_blocks infraNodeBlk from/to)
    + interface_profiles (infraRsAccPortP). Exclut profils/sélecteurs system-*. Adopte le brownfield. [#50]"""
    leafs = _by_parent(apic.get_class("infraLeafS"))             # par nprof DN
    blks = _by_parent(apic.get_class("infraNodeBlk"))            # par leafS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("infraRsAccNodePGrp")}  # par leafS DN
    ifp = defaultdict(list)
    for r in apic.get_class("infraRsAccPortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))           # par nprof DN
    out = []
    for p in apic.get_class("infraNodeP"):
        name = _seg(p["dn"], "nprof")
        if not name or name.startswith("system-") or name == "default":
            continue
        o = {"name": p["name"]}
        sels = []
        for s in leafs.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"accnodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:      # défaut = from
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"accportprof-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_leaf_switch_pgs(apic: Apic):
    """access-leaf-switch-policy-group (infraAccNodePGrp) -> access_policies.leaf_switch_policy_groups.
    name + refs policies (infraRs* -> tn*Name) : forwarding_scale/bfd_ipv4/bfd_ipv6/cdp/lldp. [#49]"""
    refs = [("infraRsTopoctrlFwdScaleProfPol", "tnTopoctrlFwdScaleProfilePolName", "forwarding_scale_policy"),
            ("infraRsBfdIpv4InstPol", "tnBfdIpv4InstPolName", "bfd_ipv4_policy"),
            ("infraRsBfdIpv6InstPol", "tnBfdIpv6InstPolName", "bfd_ipv6_policy"),
            ("infraRsLeafPGrpToCdpIfPol", "tnCdpIfPolName", "cdp_policy"),
            ("infraRsLeafPGrpToLldpIfPol", "tnLldpIfPolName", "lldp_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("infraAccNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:                                            # tn*Name vide = pas de réf
                o[field] = v
        out.append(o)
    return out

def capture_spine_switch_pgs(apic: Apic):
    """access-spine-switch-policy-group (infraSpineAccNodePGrp) -> access_policies.spine_switch_policy_groups.
    Miroir spine de #49 : refs bfd_ipv4/bfd_ipv6/cdp/lldp (pas de forwarding_scale). [#51]"""
    refs = [("infraRsSpineBfdIpv4InstPol", "tnBfdIpv4InstPolName", "bfd_ipv4_policy"),
            ("infraRsSpineBfdIpv6InstPol", "tnBfdIpv6InstPolName", "bfd_ipv6_policy"),
            ("infraRsSpinePGrpToCdpIfPol", "tnCdpIfPolName", "cdp_policy"),
            ("infraRsSpinePGrpToLldpIfPol", "tnLldpIfPolName", "lldp_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("infraSpineAccNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:
                o[field] = v
        out.append(o)
    return out

def capture_spine_switch_profiles(apic: Apic):
    """access-spine-switch-profile (infraSpineP) -> access_policies.spine_switch_profiles. Miroir spine
    de #50 : selectors (infraSpineS) + policy (infraRsSpineAccNodePGrp) + node_blocks (infraNodeBlk) +
    interface_profiles (infraRsSpAccPortP -> spaccportprof). Exclut profils/sélecteurs system-*. [#51]"""
    sels_by = _by_parent(apic.get_class("infraSpineS"))                     # par spprof DN
    blks = _by_parent(apic.get_class("infraNodeBlk"))                       # par spineS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("infraRsSpineAccNodePGrp")}
    ifp = defaultdict(list)
    for r in apic.get_class("infraRsSpAccPortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))                      # par spprof DN
    out = []
    for p in apic.get_class("infraSpineP"):
        name = _seg(p["dn"], "spprof")
        if not name or name.startswith("system-") or name == "default":   # spprof-default = système (uid=0)
            continue
        o = {"name": p["name"]}
        sels = []
        for s in sels_by.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"spaccnodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"spaccportprof-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_fabric_leaf_switch_pgs(apic: Apic):
    """fabric-leaf-switch-policy-group (fabricLeNodePGrp) -> fabric_policies.leaf_switch_policy_groups.
    refs psu_policy (fabricRsPsuInstPol) + node_control_policy (fabricRsNodeCtrl). [#52]"""
    refs = [("fabricRsPsuInstPol", "tnPsuInstPolName", "psu_policy"),
            ("fabricRsNodeCtrl", "tnFabricNodeControlName", "node_control_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("fabricLeNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:
                o[field] = v
        out.append(o)
    return out

def capture_fabric_leaf_switch_profiles(apic: Apic):
    """fabric-leaf-switch-profile (fabricLeafP) -> fabric_policies.leaf_switch_profiles. selectors
    (fabricLeafS) + policy (fabricRsLeNodePGrp) + node_blocks (fabricNodeBlk) + interface_profiles
    (fabricRsLePortP -> leportp). Exclut system-*/default. Miroir fabric de #50. [#52]"""
    sels_by = _by_parent(apic.get_class("fabricLeafS"))                     # par leprof DN
    blks = _by_parent(apic.get_class("fabricNodeBlk"))                      # par leafS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("fabricRsLeNodePGrp")}
    ifp = defaultdict(list)
    for r in apic.get_class("fabricRsLePortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))                      # par leprof DN
    out = []
    for p in apic.get_class("fabricLeafP"):
        name = _seg(p["dn"], "leprof")
        if not name or name.startswith("system-") or name == "default":
            continue
        o = {"name": p["name"]}
        sels = []
        for s in sels_by.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"lenodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"leportp-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_fabric_spine_switch_pgs(apic: Apic):
    """fabric-spine-switch-policy-group (fabricSpNodePGrp) -> fabric_policies.spine_switch_policy_groups.
    refs psu_policy/node_control_policy (miroir spine fabric de #52). [#53]"""
    refs = [("fabricRsPsuInstPol", "tnPsuInstPolName", "psu_policy"),
            ("fabricRsNodeCtrl", "tnFabricNodeControlName", "node_control_policy")]
    relmaps = [(field, {_parent(x["dn"]): x.get(attr) for x in apic.get_class(cls)})
               for cls, attr, field in refs]
    out = []
    for g in apic.get_class("fabricSpNodePGrp"):
        o = {"name": g["name"]}
        for field, m in relmaps:
            v = m.get(g["dn"])
            if v:
                o[field] = v
        out.append(o)
    return out

def capture_fabric_spine_switch_profiles(apic: Apic):
    """fabric-spine-switch-profile (fabricSpineP) -> fabric_policies.spine_switch_profiles. selectors
    (fabricSpineS) + policy (fabricRsSpNodePGrp) + node_blocks (fabricNodeBlk) + interface_profiles
    (fabricRsSpPortP -> spportp). Exclut system-*/default. Miroir spine fabric de #52. [#53]"""
    sels_by = _by_parent(apic.get_class("fabricSpineS"))                    # par spprof DN
    blks = _by_parent(apic.get_class("fabricNodeBlk"))                      # par spineS DN
    pg = {_parent(x["dn"]): x.get("tDn") for x in apic.get_class("fabricRsSpNodePGrp")}
    ifp = defaultdict(list)
    for r in apic.get_class("fabricRsSpPortP"):
        ifp[_parent(r["dn"])].append(r.get("tDn", ""))                      # par spprof DN
    out = []
    for p in apic.get_class("fabricSpineP"):
        name = _seg(p["dn"], "spprof")
        if not name or name.startswith("system-") or name == "default":
            continue
        o = {"name": p["name"]}
        sels = []
        for s in sels_by.get(p["dn"], []):
            if s["name"].startswith("system-"):
                continue
            so = {"name": s["name"]}
            tdn = pg.get(s["dn"])
            if tdn:
                mm = re.search(r"spnodepgrp-(.+)$", tdn)
                if mm:
                    so["policy"] = mm.group(1)
            nbs = []
            for b in blks.get(s["dn"], []):
                if b["name"].startswith("system-"):
                    continue
                nb = {"name": b["name"], "from": _num(b["from_"])}
                if b.get("to_") and b["to_"] != b["from_"]:
                    nb["to"] = _num(b["to_"])
                nbs.append(nb)
            if nbs:
                so["node_blocks"] = nbs
            sels.append(so)
        if sels:
            o["selectors"] = sels
        ifs = []
        for t in ifp.get(p["dn"], []):
            mm = re.search(r"spportp-(.+)$", t)
            if mm and not mm.group(1).startswith("system-"):
                ifs.append(mm.group(1))
        if ifs:
            o["interface_profiles"] = ifs
        out.append(o)
    return out

def capture_syslog_policies(apic: Apic):
    """syslog-policy (syslogGroup) -> fabric_policies.monitoring.syslogs. Group (format ternaire
    enhanced-log<->rfc5424-ts, show_milli/tz bools) + sous-singletons syslogProf(admin_state)/
    syslogFile(local_*)/syslogConsole(console_*) + destinations (syslogRemoteDest + mgmt_epg via
    fileRsARemoteHostToEpg). Plusieurs ternaires non parsés par attr_map -> capture dédiée."""
    prof = {_parent(x["dn"]): x for x in apic.get_class("syslogProf")}       # slgroup DN
    filo = {_parent(x["dn"]): x for x in apic.get_class("syslogFile")}
    cons = {_parent(x["dn"]): x for x in apic.get_class("syslogConsole")}
    dests = _by_parent(apic.get_class("syslogRemoteDest"))                   # slgroup DN
    epg = {_parent(x["dn"]): x for x in apic.get_class("fileRsARemoteHostToEpg")}  # rdst DN
    out = []
    for g in apic.get_class("syslogGroup"):
        if g.get("name") == "default":
            continue
        o = {"name": g["name"]}
        if g.get("descr"):
            o["description"] = g["descr"]
        fmt = "enhanced-log" if g.get("format") == "rfc5424-ts" else g.get("format")
        if fmt and fmt != "aci":                              # défaut aci
            o["format"] = fmt
        if g.get("includeMilliSeconds") == "yes":             # défaut no (false)
            o["show_millisecond"] = True
        if g.get("includeTimeZone") == "yes":
            o["show_timezone"] = True
        p = prof.get(g["dn"])
        if p and p.get("adminState") == "disabled":           # défaut enabled
            o["admin_state"] = False
        f = filo.get(g["dn"])
        if f:
            if f.get("adminState") == "disabled":
                o["local_admin_state"] = False
            if f.get("severity") and f["severity"] != "information":   # défaut information
                o["local_severity"] = f["severity"]
        c = cons.get(g["dn"])
        if c:
            if c.get("adminState") == "disabled":
                o["console_admin_state"] = False
            if c.get("severity") and c["severity"] != "alerts":        # défaut alerts
                o["console_severity"] = c["severity"]
        dl = []
        for d in dests.get(g["dn"], []):
            de = {"hostname_ip": d["host"]}
            if d.get("name"):
                de["name"] = d["name"]
            if d.get("protocol"):
                de["protocol"] = d["protocol"]
            if d.get("port"):
                de["port"] = _num(d["port"])
            if d.get("adminState") == "disabled":
                de["admin_state"] = False
            if d.get("forwardingFacility"):
                de["facility"] = d["forwardingFacility"]
            if d.get("severity"):
                de["severity"] = d["severity"]
            ref = epg.get(d["dn"])
            if ref and ref.get("tDn"):
                if "/oob-" in ref["tDn"]:
                    de["mgmt_epg"] = "oob"
                elif "/inb-" in ref["tDn"]:
                    de["mgmt_epg"] = "inb"
            dl.append(de)
        if dl:
            o["destinations"] = dl
        out.append(o)
    return out

def capture_macsec_param_policies(apic: Apic):
    """macsec parameters policies (macsecParamPol, type access) -> access_policies.
    interface_policies.macsec_parameters_policies. Pas de clé secrète. Exclut 'default'."""
    out = []
    for p in apic.get_class("macsecParamPol"):
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("cipherSuite") and p["cipherSuite"] != "gcm-aes-xpn-256":
            o["cipher_suite"] = p["cipherSuite"]
        if p.get("confOffset") and p["confOffset"] != "offset-0":
            o["confidentiality_offset"] = p["confOffset"]
        if p.get("keySvrPrio") and p["keySvrPrio"] != "16":
            o["key_server_priority"] = int(p["keySvrPrio"])
        if p.get("replayWindow") and p["replayWindow"] != "64":
            o["window_size"] = int(p["replayWindow"])
        if p.get("sakExpiryTime") and p["sakExpiryTime"] not in ("disabled", "0"):
            o["key_expiry_time"] = int(p["sakExpiryTime"])
        if p.get("secPolicy") and p["secPolicy"] != "should-secure":
            o["security_policy"] = p["secPolicy"]
        out.append(o)
    return out

def capture_snmp_policies(apic: Apic):
    """SNMP policies fabric (snmpPol uni/fabric-<name>) + communities + trap_forwarders.
    Users (snmpUserP) = SECRETS (authKey/privKey) -> omis. clients (snmpClientGrpP) =
    liés au mgmt_epg node_policies -> omis pour rester auto-suffisant. Exclut le pol
    système 'default'. -> fabric_policies.pod_policies.snmp_policies."""
    comms = _by_parent(apic.get_class("snmpCommunityP"))
    traps = _by_parent(apic.get_class("snmpTrapFwdServerP"))
    out = []
    for p in apic.get_class("snmpPol"):
        if not p.get("dn", "").startswith("uni/fabric/snmppol-"):
            continue
        if p.get("name") == "default":                       # pol système
            continue
        o = {"name": p["name"], "admin_state": p.get("adminSt") == "enabled"}
        if p.get("loc"):
            o["location"] = p["loc"]
        if p.get("contact"):
            o["contact"] = p["contact"]
        cs = sorted(c["name"] for c in comms.get(p["dn"], []) if c.get("name"))
        if cs:
            o["communities"] = cs
        tf = []
        for t in traps.get(p["dn"], []):
            tx = {"ip": t["addr"]}
            if t.get("port") and t["port"] != "162":         # defaut 162
                tx["port"] = int(t["port"])
            tf.append(tx)
        if tf:
            o["trap_forwarders"] = tf
        out.append(o)
    return out

def capture_infra_dhcp_relay_policies(apic: Apic):
    """infra dhcp relay (dhcpRelayP owner=infra, uni/infra/relayp-) + providers (dhcpRsProv).
    Miroir infra du dhcp-relay tenant #66. -> access_policies.dhcp_relay_policies."""
    prov_by = _by_parent(apic.get_class("dhcpRsProv"))
    out = []
    for p in apic.get_class("dhcpRelayP"):
        if "/infra/" not in p.get("dn", ""):
            continue
        if p.get("name") == "default":                        # relayp-default système
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        provs = []
        for rs in prov_by.get(p["dn"], []):
            pr = {"ip": rs.get("addr")}
            tdn = rs.get("tDn", "")
            mm = re.search(r"tn-([^/]+)/ap-([^/]+)/epg-(.+)$", tdn)
            if mm:
                pr["type"] = "epg"
                pr["tenant"], pr["application_profile"], pr["endpoint_group"] = mm.groups()
            else:
                mm = re.search(r"tn-([^/]+)/out-([^/]+)/instP-(.+)$", tdn)
                if mm:
                    pr["type"] = "l3out"
                    pr["tenant"], pr["l3out"], pr["external_endpoint_group"] = mm.groups()
            provs.append(pr)
        if provs:
            o["providers"] = provs
        out.append(o)
    return out

def capture_dns_policies(apic: Apic):
    """DNS policies fabric (dnsProfile uni/fabric/dnsp-) + providers (dnsProv) +
    domains (dnsDomain). mgmt_epg (rsProfileToEpg) = binding default inb -> omis
    (recréé par le défaut du module, idempotent). Exclut 'default'.
    -> fabric_policies.dns_policies."""
    provs = _by_parent(apic.get_class("dnsProv"))
    doms = _by_parent(apic.get_class("dnsDomain"))
    out = []
    for p in apic.get_class("dnsProfile"):
        if not p.get("dn", "").startswith("uni/fabric/dnsp-"):
            continue
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        pl = []
        for pr in provs.get(p["dn"], []):
            px = {"ip": pr["addr"]}
            if pr.get("preferred") == "yes":                 # defaut no
                px["preferred"] = True
            pl.append(px)
        if pl:
            o["providers"] = pl
        dl = []
        for d in doms.get(p["dn"], []):
            dx = {"name": d["name"]}
            if d.get("isDefault") == "no":                   # defaut yes
                dx["default"] = False
            dl.append(dx)
        if dl:
            o["domains"] = dl
        out.append(o)
    return out

def capture_geolocation(apic: Apic):
    """geolocation (geoSite uni/fabric/site- + hiérarchie building/floor/room/row/rack
    + geoRsNodeLocation -> node ids). Exclut le site 'default' (chaîne système uid 0).
    -> fabric_policies.geolocation.sites. [#91]"""
    def _rows(cn):
        # l'APIC auto-cree une chaine default (building/floor/room/rack) uid=0
        # sous chaque site -> exclue, comme le site-default systeme
        return [x for x in apic.get_class(cn) if x.get("uid") != "0"]
    bl = _by_parent(_rows("geoBuilding"))
    fl = _by_parent(_rows("geoFloor"))
    rm = _by_parent(_rows("geoRoom"))
    rw = _by_parent(_rows("geoRow"))
    rk = _by_parent(_rows("geoRack"))
    nd = _by_parent(apic.get_class("geoRsNodeLocation"))
    def _o(x):
        o = {"name": x["name"]}
        if x.get("descr"):
            o["description"] = x["descr"]
        return o
    sites = []
    for s in _rows("geoSite"):
        so = _o(s)
        buildings = []
        for b in bl.get(s["dn"], []):
            bo = _o(b)
            floors = []
            for f in fl.get(b["dn"], []):
                fo = _o(f)
                rooms = []
                for r in rm.get(f["dn"], []):
                    ro = _o(r)
                    rows = []
                    for w in rw.get(r["dn"], []):
                        wo = _o(w)
                        racks = []
                        for k in rk.get(w["dn"], []):
                            ko = _o(k)
                            nodes = [int(m.group(1)) for n in nd.get(k["dn"], [])
                                     if (m := re.search(r"node-(\d+)", n.get("tDn", "")))]
                            _set(ko, "nodes", nodes)
                            racks.append(ko)
                        _set(wo, "racks", racks)
                        rows.append(wo)
                    _set(ro, "rows", rows)
                    rooms.append(ro)
                _set(fo, "rooms", rooms)
                floors.append(fo)
            _set(bo, "floors", floors)
            buildings.append(bo)
        _set(so, "buildings", buildings)
        sites.append(so)
    return sites

AAA_PWD_PLACEHOLDER = "Placeholder123!"   # pwd aaaUser REQUIS par le cablage, write-only (ignore_changes)

def capture_aaa_security(apic: Apic):
    """objets AAA nommes -> fabric_policies.aaa.{radius_providers, tacacs_providers,
    users, ca_certificates, login_domains}. SECRETS non round-trippables : key /
    monitoringPassword omis (ignore_changes) ; pwd user = placeholder constant
    (requis par le cablage). certChain (pkiTP) est PUBLIC -> round-trip complet.
    Exclut uid==0 (admin, logindomain fallback). mgmt_epg des providers : capture
    'oob' seulement (inb = defaut recree par le module). [#96-#100]"""
    out = {}
    epgs = {_parent(r["dn"]): r.get("tDn", "") for r in apic.get_class("aaaRsSecProvToEpg")}
    def providers(cls, def_port):
        rows = []
        for p in apic.get_class(cls):
            o = {"hostname_ip": p["name"]}
            if p.get("descr"):
                o["description"] = p["descr"]
            if p.get("authProtocol") and p["authProtocol"] != "pap":
                o["protocol"] = p["authProtocol"]
            port = p.get("authPort") or p.get("port")
            if port and int(port) != def_port:
                o["port"] = int(port)
            if p.get("retries") not in (None, "", "1"):
                o["retries"] = _num(p["retries"])
            if p.get("timeout") not in (None, "", "5"):
                o["timeout"] = _num(p["timeout"])
            if p.get("monitorServer") == "enabled":
                o["monitoring"] = True
                if p.get("monitoringUser"):
                    o["monitoring_username"] = p["monitoringUser"]
            if "/oob-" in epgs.get(p["dn"], ""):
                o["mgmt_epg"] = "oob"
            rows.append(o)
        return rows
    rad = providers("aaaRadiusProvider", 1812)
    if rad:
        out["radius_providers"] = rad
    tac = providers("aaaTacacsPlusProvider", 49)
    if tac:
        out["tacacs_providers"] = tac
    # l'APIC auto-cree un userdomain 'common' + role 'read-all' uid=0 sous chaque
    # user -> exclus (meme piege que la chaine default geolocation #91)
    doms = _by_parent([d for d in apic.get_class("aaaUserDomain") if d.get("uid") != "0"])
    roles = _by_parent([r for r in apic.get_class("aaaUserRole") if r.get("uid") != "0"])
    users = []
    for u in apic.get_class("aaaUser"):
        if u.get("uid") == "0":
            continue
        o = {"username": u["name"], "password": AAA_PWD_PLACEHOLDER}
        if u.get("descr"):
            o["description"] = u["descr"]
        if u.get("accountStatus") and u["accountStatus"] != "active":
            o["status"] = u["accountStatus"]
        if u.get("email"):
            o["email"] = u["email"]
        if u.get("expires") == "yes":
            o["expires"] = True
        if u.get("expiration") and u["expiration"] != "never":
            o["expire_date"] = u["expiration"]
        if u.get("firstName"):
            o["first_name"] = u["firstName"]
        if u.get("lastName"):
            o["last_name"] = u["lastName"]
        if u.get("phone"):
            o["phone"] = u["phone"]
        if u.get("certAttribute"):
            o["certificate_name"] = u["certAttribute"]
        dl = []
        for d in doms.get(u["dn"], []):
            do = {"name": d["name"]}
            rl = []
            for r in roles.get(d["dn"], []):
                ro = {"name": r["name"]}
                if r.get("privType") == "readPriv":       # defaut write (writePriv)
                    ro["privilege_type"] = "read"
                rl.append(ro)
            _set(do, "roles", rl)
            dl.append(do)
        _set(o, "domains", dl)
        users.append(o)
    if users:
        out["users"] = users
    cas = []
    for c in apic.get_class("pkiTP"):
        o = {"name": c["name"]}
        if c.get("descr"):
            o["description"] = c["descr"]
        if c.get("certChain"):
            o["certificate_chain"] = c["certChain"].strip()
        cas.append(o)
    if cas:
        out["ca_certificates"] = cas
    # ldap (aaa.ldap : providers + group_map_rules + group_maps) [#101]
    # password (key/rootdn) + monitoring_password = SECRETS omis (ignore_changes)
    lprovs = []
    for p in apic.get_class("aaaLdapProvider"):
        o = {"hostname_ip": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("port") not in (None, "", "389"):
            o["port"] = _num(p["port"])
        if p.get("rootdn"):
            o["bind_dn"] = p["rootdn"]
        if p.get("basedn"):
            o["base_dn"] = p["basedn"]
        if p.get("timeout") not in (None, "", "30"):
            o["timeout"] = _num(p["timeout"])
        if p.get("retries") not in (None, "", "1"):
            o["retries"] = _num(p["retries"])
        if p.get("enableSSL") == "yes":
            o["enable_ssl"] = True
        if p.get("filter") and p["filter"] != "sAMAccountName=$userid":
            o["filter"] = p["filter"]
        if p.get("attribute") and p["attribute"] != "CiscoAVPair":
            o["attribute"] = p["attribute"]
        if p.get("SSLValidationLevel") and p["SSLValidationLevel"] != "strict":
            o["ssl_validation_level"] = p["SSLValidationLevel"]
        if p.get("monitorServer") == "enabled":
            o["server_monitoring"] = True
            if p.get("monitoringUser") and p["monitoringUser"] != "default":
                o["monitoring_username"] = p["monitoringUser"]
        if "/oob-" in epgs.get(p["dn"], ""):
            o["mgmt_epg"] = "oob"
        lprovs.append(o)
    lrules = []
    for r in apic.get_class("aaaLdapGroupMapRule"):
        o = {"name": r["name"]}
        if r.get("descr"):
            o["description"] = r["descr"]
        if r.get("groupdn"):
            o["group_dn"] = r["groupdn"]
        dl = []
        for d in doms.get(r["dn"], []):                   # meme filtre uid!=0 que users
            do = {"name": d["name"]}
            rl = []
            for x in roles.get(d["dn"], []):
                ro = {"name": x["name"]}
                if x.get("privType") == "readPriv":
                    ro["privilege_type"] = "read"
                rl.append(ro)
            _set(do, "roles", rl)
            dl.append(do)
        _set(o, "security_domains", dl)
        lrules.append(o)
    lrefs = _by_parent(apic.get_class("aaaLdapGroupMapRuleRef"))
    lmaps = []
    for g in apic.get_class("aaaLdapGroupMap"):
        o = {"name": g["name"]}
        rl = [{"name": x["name"]} for x in lrefs.get(g["dn"], [])]
        _set(o, "rules", rl)
        lmaps.append(o)
    ldap = {}
    if lprovs:
        ldap["providers"] = lprovs
    if lrules:
        ldap["group_map_rules"] = lrules
    if lmaps:
        ldap["group_maps"] = lmaps
    if ldap:
        out["ldap"] = ldap
    auth = {_parent(r["dn"]): r for r in apic.get_class("aaaDomainAuth")}
    refs = _by_parent(apic.get_class("aaaProviderRef"))
    grp_seg = {"radius": "radiusext/radiusprovidergroup-",
               "tacacs": "tacacsext/tacacsplusprovidergroup-",
               "ldap": "ldapext/ldapprovidergroup-"}
    lds = []
    for d in apic.get_class("aaaLoginDomain"):
        if d.get("uid") == "0":                           # logindomain 'fallback' systeme
            continue
        o = {"name": d["name"]}
        if d.get("descr"):
            o["description"] = d["descr"]
        au = auth.get(d["dn"])
        realm = au.get("realm") if au else None
        if realm and realm in grp_seg:
            o["realm"] = realm
            gdn = f"uni/userext/{grp_seg[realm]}{d['name']}"
            pl = []
            for r in refs.get(gdn, []):
                po = {"hostname_ip": r["name"]}
                if r.get("order") not in (None, "", "0"):
                    po["priority"] = _num(r["order"])
                pl.append(po)
            _set(o, f"{realm}_providers", pl)
        lds.append(o)
    if lds:
        out["login_domains"] = lds
    return out

def capture_vpc_groups(apic: Apic):
    """vpc protection groups (fabricExplicitGEp + fabricNodePEp + fabricRsVpcInstPol)
    -> node_policies.vpc_groups.groups (le mode fabricProtPol vient du moteur
    singleton). [#94]"""
    peps = _by_parent(apic.get_class("fabricNodePEp"))
    pols = {_parent(r["dn"]): r.get("tnVpcInstPolName")
            for r in apic.get_class("fabricRsVpcInstPol")}
    out = []
    for g in apic.get_class("fabricExplicitGEp"):
        o = {"name": g["name"], "id": _num(g["id"])}
        sw = sorted(int(p["id"]) for p in peps.get(g["dn"], []))
        if len(sw) == 2:
            o["switch_1"], o["switch_2"] = sw
        if pols.get(g["dn"]):
            o["policy"] = pols[g["dn"]]
        out.append(o)
    return out

def capture_mst_policies(apic: Apic):
    """mst region policies (stpMstRegionPol sous uni/infra/mstpInstPol-default/) +
    instances (stpMstDomPol) + vlan_ranges (fvnsEncapBlk, aussi utilisee sous les
    vlan pools -> indexee par parent, seuls les blocs sous stpMstDomPol matchent).
    -> access_policies.switch_policies.mst_policies. [#93]"""
    doms = _by_parent(apic.get_class("stpMstDomPol"))
    blks = _by_parent(apic.get_class("fvnsEncapBlk"))
    out = []
    for p in apic.get_class("stpMstRegionPol"):
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        if p.get("regName"):
            o["region"] = p["regName"]
        if p.get("rev"):
            o["revision"] = _num(p["rev"])
        insts = []
        for d in doms.get(p["dn"], []):
            io = {"name": d["name"], "id": _num(d["id"])}
            rngs = []
            for b in blks.get(d["dn"], []):
                fr = int(b["from"].replace("vlan-", ""))
                to = int(b["to"].replace("vlan-", ""))
                r = {"from": fr}
                if to != fr:
                    r["to"] = to
                rngs.append(r)
            _set(io, "vlan_ranges", rngs)
            insts.append(io)
        _set(o, "instances", insts)
        out.append(o)
    return out

def capture_date_time_policies(apic: Apic):
    """date-time policies fabric (datetimePol uni/fabric/time-) + ntp_servers
    (datetimeNtpProv). ntp_keys (datetimeNtpAuthKey) = SECRETS omis ; mgmt_epg
    (rsNtpProvToEpg) = binding default inb omis (recréé par défaut, idempotent).
    Exclut 'default'. -> fabric_policies.pod_policies.date_time_policies."""
    provs = _by_parent(apic.get_class("datetimeNtpProv"))
    out = []
    for p in apic.get_class("datetimePol"):
        if not p.get("dn", "").startswith("uni/fabric/time-"):
            continue
        if p.get("name") == "default":
            continue
        o = {"name": p["name"],
             "ntp_admin_state": p.get("adminSt") == "enabled",
             "ntp_auth_state": p.get("authSt") == "enabled",
             "apic_ntp_server_state": p.get("serverState") == "enabled",
             "apic_ntp_server_master_mode": p.get("masterMode") == "enabled"}
        if p.get("StratumValue"):
            o["apic_ntp_server_master_stratum"] = int(p["StratumValue"])
        srv = []
        for s in provs.get(p["dn"], []):
            srv.append({"hostname_ip": s["name"],
                        "preferred": s.get("preferred") == "yes"})
        if srv:
            o["ntp_servers"] = srv
        out.append(o)
    return out

def capture_fabric_pod_policy_groups(apic: Apic):
    """fabric pod policy groups (fabricPodPGrp uni/fabric/funcprof/podpgrp-) +
    relations snmp/time/comm/macsec/bgp-rr. -> fabric_policies.pod_policy_groups."""
    rels = {
        "fabricRsSnmpPol":        ("tnSnmpPolName", "snmp_policy"),
        "fabricRsTimePol":        ("tnDatetimePolName", "date_time_policy"),
        "fabricRsCommPol":        ("tnCommPolName", "management_access_policy"),
        "fabricRsMacsecPol":      ("tnMacsecFabIfPolName", "macsec_policy"),
        "fabricRsPodPGrpBGPRRP":  ("tnBgpInstPolName", "bgp_route_reflector_policy"),
    }
    relmap = {}
    for cls, (attr, key) in rels.items():
        for x in apic.get_class(cls):
            relmap.setdefault(_parent(x["dn"]), {})[key] = x.get(attr, "")
    out = []
    for p in apic.get_class("fabricPodPGrp"):
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        for key, val in relmap.get(p["dn"], {}).items():
            if val:                                          # ignore relations vides
                o[key] = val
        out.append(o)
    return out

def capture_management_access_policies(apic: Apic):
    """management access policies fabric (commPol uni/fabric/comm-) + sous-objets
    telnet/ssh/https/http (attrs cœur). Flags cipher/mac/kex/tls = défauts idempotents
    -> omis. keyring ref omis. Exclut 'default'.
    -> fabric_policies.pod_policies.management_access_policies."""
    tel = {_parent(x["dn"]): x for x in apic.get_class("commTelnet")}
    ssh = {_parent(x["dn"]): x for x in apic.get_class("commSsh")}
    htps = {_parent(x["dn"]): x for x in apic.get_class("commHttps")}
    htp = {_parent(x["dn"]): x for x in apic.get_class("commHttp")}
    out = []
    for p in apic.get_class("commPol"):
        if not p.get("dn", "").startswith("uni/fabric/comm-"):
            continue
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        t = tel.get(p["dn"])
        if t:
            o["telnet"] = {"admin_state": t.get("adminSt") == "enabled",
                           "port": int(t["port"])}
        s = ssh.get(p["dn"])
        if s:
            o["ssh"] = {"admin_state": s.get("adminSt") == "enabled",
                        "password_auth": s.get("passwordAuth") == "enabled",
                        "port": int(s["port"])}
        h = htps.get(p["dn"])
        if h:
            hd = {"admin_state": h.get("adminSt") == "enabled",
                  "client_cert_auth_state": h.get("clientCertAuthState") == "enabled",
                  "port": int(h["port"])}
            if h.get("dhParam") and h["dhParam"] != "none":
                hd["dh"] = int(h["dhParam"])
            o["https"] = hd
        hh = htp.get(p["dn"])
        if hh:
            o["http"] = {"admin_state": hh.get("adminSt") == "enabled",
                         "port": int(hh["port"])}
        out.append(o)
    return out

def capture_common_monitoring(apic: Apic):
    """common monitoring policy (uni/fabric/moncommon) : sources syslog (syslogSrc + incl
    flags + minSev + syslogRsDestGroup->slgroup). snmp_traps = réfs snmp-trap group (déféré)
    -> omis. -> entrée {name: common, syslogs:[...]} dans fabric_policies.monitoring.policies."""
    sl_dest = {_parent(x["dn"]): x for x in apic.get_class("syslogRsDestGroup")
               if "/moncommon/" in x.get("dn", "")}
    syslogs = []
    for s in apic.get_class("syslogSrc"):
        if "/moncommon/" not in s.get("dn", ""):
            continue
        o = {"name": s["name"]}
        incl = set(filter(None, s.get("incl", "").split(",")))
        allf = "all" in incl
        for flag in ("audit", "events", "faults", "session"):
            o[flag] = allf or flag in incl
        if s.get("minSev"):
            o["minimum_severity"] = s["minSev"]
        d = sl_dest.get(s["dn"])
        if d:
            mm = re.search(r"slgroup-(.+)$", d.get("tDn", ""))
            if mm:
                o["destination_group"] = mm.group(1)
        syslogs.append(o)
    return {"name": "common", "syslogs": syslogs} if syslogs else None

def capture_config_exports(apic: Apic):
    """config exports (configExportP) -> fabric_policies.config_exports. Exclut systeme
    (uid==0 ex DailyAutoBackup) et les default* (defaultOneTime = mécanisme snapshot)."""
    sched = {_parent(x["dn"]): x.get("tnTrigSchedPName") for x in apic.get_class("configRsExportScheduler")}
    rpath = {_parent(x["dn"]): x.get("tnFileRemotePathName") for x in apic.get_class("configRsRemotePath")}
    out = []
    for p in apic.get_class("configExportP"):
        if p.get("uid") == "0" or p.get("name", "").startswith("default"):
            continue
        o = {"name": p["name"]}
        if p.get("descr"):
            o["description"] = p["descr"]
        if p.get("format") and p["format"] != "json":      # defaut json
            o["format"] = p["format"]
        if p.get("snapshot") == "yes":                      # defaut no
            o["snapshot"] = True
        if sched.get(p["dn"]):
            o["scheduler"] = sched[p["dn"]]
        if rpath.get(p["dn"]):
            o["remote_location"] = rpath[p["dn"]]
        out.append(o)
    return out

def capture_psu_policies(apic: Apic):
    """psu policies (psuInstPol) -> fabric_policies.switch_policies.psu_policies.
    admin_state via adminRdnM (comb/rdn/ps-rdn). Exclut 'default'."""
    rmap = {"comb": "combined", "rdn": "nnred", "ps-rdn": "n1red"}
    out = []
    for p in apic.get_class("psuInstPol"):
        if p.get("name") == "default":
            continue
        o = {"name": p["name"]}
        a = rmap.get(p.get("adminRdnM"))
        if a and a != "combined":                  # defaut combined
            o["admin_state"] = a
        out.append(o)
    return out

def capture_bfd_policies(apic: Apic):
    """bfd switch policies globales (bfdIpv4InstPol/bfdIpv6InstPol) -> access_policies.
    switch_policies.bfd_ipv4_policies / bfd_ipv6_policies. Exclut 'default'."""
    fields = (("detectMult", "detection_multiplier", "3"),
              ("minTxIntvl", "min_transmit_interval", "50"),
              ("minRxIntvl", "min_receive_interval", "50"),
              ("slowIntvl", "slow_timer_interval", "2000"),
              # startupIntvl : défaut null côté data model, auto-rempli (10) par l'APIC -> NON capturé
              ("echoRxIntvl", "echo_receive_interval", "50"))
    res = {}
    for cls, key in (("bfdIpv4InstPol", "bfd_ipv4_policies"), ("bfdIpv6InstPol", "bfd_ipv6_policies")):
        lst = []
        for p in apic.get_class(cls):
            if p.get("name") == "default":
                continue
            o = {"name": p["name"]}
            if p.get("descr"):
                o["description"] = p["descr"]
            for af, yf, dflt in fields:
                if p.get(af) and p[af] != dflt:
                    o[yf] = int(p[af])
            if p.get("echoSrcAddr") and p["echoSrcAddr"] != "0.0.0.0":
                o["echo_frame_source_address"] = p["echoSrcAddr"]
            lst.append(o)
        if lst:
            res[key] = lst
    return res

def capture_update_groups(apic: Apic):
    """node_policies.update_groups : firmware+maintenance groups (firmwareFwGrp /
    maintMaintGrp, même nom) + scheduler (maintRsPolScheduler). Exclut 'default'."""
    sched = {}
    for rs in apic.get_class("maintRsPolScheduler"):
        name = _seg(rs["dn"], "maintpol")
        if name and rs.get("tnTrigSchedPName"):
            sched[name] = rs["tnTrigSchedPName"]
    out = []
    for g in apic.get_class("firmwareFwGrp"):
        name = g.get("name")
        if not name or name == "default":
            continue
        ug = {"name": name}
        if sched.get(name) and sched[name] != "default":     # defaut scheduler 'default'
            ug["scheduler"] = sched[name]
        out.append(ug)
    return out

def capture_schedulers(apic: Apic):
    """fabric schedulers (trigSchedP) : name/descr + recurring_windows (trigRecurrWindowP).
    Exclut les schedulers SYSTEME (uid=0 : ConstSchedP, EveryEightHours...)."""
    wins = _by_parent(apic.get_class("trigRecurrWindowP"))   # par trigSchedP DN
    out = []
    for s in apic.get_class("trigSchedP"):
        if s.get("uid") == "0":                              # systeme
            continue
        so = {"name": s["name"]}
        if s.get("descr"):
            so["description"] = s["descr"]
        rws = []
        for w in wins.get(s["dn"], []):
            rw = {"name": w["name"]}
            if w.get("day") and w["day"] != "every-day":     # defaut every-day
                rw["day"] = w["day"]
            if w.get("hour") and w["hour"] != "0":           # defaut 0
                rw["hour"] = int(w["hour"])
            if w.get("minute") and w["minute"] != "0":       # defaut 0
                rw["minute"] = int(w["minute"])
            rws.append(rw)
        if rws:
            so["recurring_windows"] = rws
        out.append(so)
    return out

def capture_interface_nodes(apic: Apic):
    """interface_policies.nodes[].interfaces[] : fusionne par (node,module,port) les
    attributs port-level — type (infraRsPortDirection) et shutdown (fabricRsOosPath)."""
    ifs = defaultdict(dict)   # (node,module,port) -> {attrs}
    for x in apic.get_class("infraRsPortDirection"):
        mm = re.search(r"paths-(\d+)/pathep-\[eth(\d+)/(\d+)\]", x.get("tDn", ""))
        if mm:
            k = (int(mm.group(1)), int(mm.group(2)), int(mm.group(3)))
            ifs[k]["type"] = "uplink" if x.get("direc") == "UpLink" else "downlink"
    for x in apic.get_class("fabricRsOosPath"):
        mm = re.search(r"paths-(\d+)/pathep-\[eth(\d+)/(\d+)\]", x.get("dn", ""))
        if mm:
            k = (int(mm.group(1)), int(mm.group(2)), int(mm.group(3)))
            ifs[k]["shutdown"] = True
    by_node = defaultdict(list)
    for (node, mod, port), attrs in sorted(ifs.items()):
        by_node[node].append({"module": mod, "port": port, **attrs})
    return [{"id": n, "interfaces": i} for n, i in sorted(by_node.items())]

def _capture_tree(apic):
    """Construit la PHOTO complete de la fabric EN MEMOIRE (aucune ecriture).
    Retourne (flat, tns, warnings). Utilisee par capture (qui ecrit data/) et
    par drift (qui compare sans rien toucher)."""
    warnings = []
    # 1. passe PLATE (list-classes : leaf/switch profiles, interface policies, vpc/mst...)
    flat = capture_flat(apic)
    # 1b. SINGLETONS (global_settings, coop, isis, control_plane_mtu... a leurs vraies valeurs)
    for section, tree in capture_singletons(apic).items():
        _deep_merge(flat[section], tree)
    # 2. passe HIERARCHIQUE : enrichit access (vlan pools+ranges, domaines, aaep) + tenants
    ap = capture_access(apic, warnings)
    _deep_merge(flat["access_policies"], ap)
    # 2b. selecteurs d'interface (infraHPortS) -> enrichit les leaf_interface_profiles par nom
    sels = capture_leaf_selectors(apic)
    for prof in flat["access_policies"].get("leaf_interface_profiles", []):
        if prof["name"] in sels:
            prof["selectors"] = sels[prof["name"]]
    # 2c. monitoring policies : access (monInfraPol) + fabric (monFabricPol)
    mon = capture_monitoring_policies(apic, "monInfraPol", "monInfraTarget")
    if mon:
        flat["access_policies"].setdefault("monitoring", {})["policies"] = mon
    monf = capture_monitoring_policies(apic, "monFabricPol", "monFabricTarget")
    if monf:
        flat["fabric_policies"].setdefault("monitoring", {})["policies"] = monf
    common_mon = capture_common_monitoring(apic)                            # [#87]
    if common_mon:
        flat["fabric_policies"].setdefault("monitoring", {}).setdefault("policies", []).append(common_mon)
    slg = capture_syslog_policies(apic)                                    # [#48]
    if slg:
        flat["fabric_policies"].setdefault("monitoring", {})["syslogs"] = slg
    flspg = capture_fabric_leaf_switch_pgs(apic)                            # [#52]
    if flspg:
        flat["fabric_policies"]["leaf_switch_policy_groups"] = flspg
    flsprof = capture_fabric_leaf_switch_profiles(apic)                    # [#52]
    if flsprof:
        flat["fabric_policies"]["leaf_switch_profiles"] = flsprof
    fsspg = capture_fabric_spine_switch_pgs(apic)                          # [#53]
    if fsspg:
        flat["fabric_policies"]["spine_switch_policy_groups"] = fsspg
    fssprof = capture_fabric_spine_switch_profiles(apic)                  # [#53]
    if fssprof:
        flat["fabric_policies"]["spine_switch_profiles"] = fssprof
    lspg = capture_leaf_switch_pgs(apic)                                    # [#49]
    if lspg:
        flat["access_policies"]["leaf_switch_policy_groups"] = lspg
    lsprof = capture_leaf_switch_profiles(apic)                            # [#50]
    if lsprof:
        flat["access_policies"]["leaf_switch_profiles"] = lsprof
    sspg = capture_spine_switch_pgs(apic)                                  # [#51]
    if sspg:
        flat["access_policies"]["spine_switch_policy_groups"] = sspg
    ssprof = capture_spine_switch_profiles(apic)                          # [#51]
    if ssprof:
        flat["access_policies"]["spine_switch_profiles"] = ssprof
    # selecteurs d'interface fabric (leaf + spine) -> enrichit les profils par nom
    fsels = capture_fabric_selectors(apic, "fabricLFPortS", "fabricRsLePortPGrp",
                                     "rslePortPGrp", "leportp", "leportgrp")
    for prof in flat["fabric_policies"].get("leaf_interface_profiles", []):
        if prof["name"] in fsels:
            prof["selectors"] = fsels[prof["name"]]
    ssels = capture_fabric_selectors(apic, "fabricSFPortS", "fabricRsSpPortPGrp",
                                     "rsspPortPGrp", "spportp", "spportgrp")
    for prof in flat["fabric_policies"].get("spine_interface_profiles", []):
        if prof["name"] in ssels:
            prof["selectors"] = ssels[prof["name"]]
    # access SPINE selectors (infraSHPortS) -> enrichit access_policies.spine_interface_profiles  [#35]
    asels = capture_fabric_selectors(apic, "infraSHPortS", "infraRsSpAccGrp",
                                     "rsspAccGrp", "spaccportprof", "spaccportgrp",
                                     blk_class="infraPortBlk")
    for prof in flat["access_policies"].get("spine_interface_profiles", []):
        if prof["name"] in asels:
            prof["selectors"] = asels[prof["name"]]
    # span filter groups (spanFilterGrp + entries) -> access_policies.span.filter_groups  [#36]
    sfg = capture_span_filter_groups(apic)
    if sfg:
        flat["access_policies"].setdefault("span", {})["filter_groups"] = sfg
    sdg = capture_span_destination_groups(apic)                            # [#37]
    if sdg:
        flat["access_policies"].setdefault("span", {})["destination_groups"] = sdg
    vdg = capture_vspan_destination_groups(apic)                           # [#38]
    if vdg:
        flat["access_policies"].setdefault("vspan", {})["destination_groups"] = vdg
    vss = capture_vspan_sessions(apic)                                     # [#39]
    if vss:
        flat["access_policies"].setdefault("vspan", {})["sessions"] = vss
    ssrcg = capture_span_source_groups(apic)                               # [#40]
    if ssrcg:
        flat["access_policies"].setdefault("span", {})["source_groups"] = ssrcg
    fdg = capture_span_destination_groups(apic, "uni/fabric/")             # [#41] fabric span dest
    if fdg:
        flat["fabric_policies"].setdefault("span", {})["destination_groups"] = fdg
    fsg = capture_fabric_span_source_groups(apic)                          # [#41] fabric span source
    if fsg:
        flat["fabric_policies"].setdefault("span", {})["source_groups"] = fsg
    # link-level policies (fabricHIfPol) : compléter autoNeg (ternaire) + portPhyMediaType
    # (conditionnel) que attr_map ne sait pas parser. Émission non-défaut. [#43]
    llp = {p["name"]: p for p in apic.get_class("fabricHIfPol")}
    for e in flat["access_policies"].get("interface_policies", {}).get("link_level_policies", []):
        p = llp.get(e["name"])
        if not p:
            continue
        if p.get("autoNeg") == "on-enforce":             # défaut 'on' (auto=true, auto_enforce=false)
            e["auto_enforce"] = True
        elif p.get("autoNeg") == "off":
            e["auto"] = False
        if p.get("portPhyMediaType") and p["portPhyMediaType"] != "auto":   # défaut auto
            e["physical_media_type"] = p["portPhyMediaType"]
    # priority-flow-control (qosPfcIfPol) : adminSt = auto_state?auto:(admin_state?on:off) [#44]
    # ternaire 3-états non parsé par attr_map. Défaut auto (auto_state=true). Émission non-défaut.
    pfc = {p["name"]: p for p in apic.get_class("qosPfcIfPol")}
    for e in flat["access_policies"].get("interface_policies", {}).get("priority_flow_control_policies", []):
        p = pfc.get(e["name"])
        if not p:
            continue
        if p.get("adminSt") == "on":                         # auto_state false, admin_state true (défaut)
            e["auto_state"] = False
        elif p.get("adminSt") == "off":                      # auto_state false ET admin_state false
            e["auto_state"] = False
            e["admin_state"] = False
    # netflow-record (netflowRecordPol) : match = join(",", sort(var.match_parameters)) — le sort()
    # empêche _RE_JOIN de matcher -> match_parameters non capturé. Enrichissement. [#45]
    nfr = {p["name"]: p for p in apic.get_class("netflowRecordPol") if "/infra/" in p["dn"]}
    for e in flat["access_policies"].get("interface_policies", {}).get("netflow_records", []):
        p = nfr.get(e["name"])
        if p and p.get("match"):
            e["match_parameters"] = sorted(p["match"].split(","))
    # netflow ACCESS exporters/monitors : relations (miroir #68 tenant, scope uni/infra) [#82]
    nfae_ctx = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToCtx") if "/infra/" in x["dn"]}
    nfae_epg = {_parent(x["dn"]): x for x in apic.get_class("netflowRsExporterToEPg") if "/infra/" in x["dn"]}
    nfae = {p["name"]: p for p in apic.get_class("netflowExporterPol") if "/infra/" in p["dn"]}
    for e in flat["access_policies"].get("interface_policies", {}).get("netflow_exporters", []):
        p = nfae.get(e["name"])
        if not p:
            continue
        ctx = nfae_ctx.get(p["dn"])
        if ctx and ctx.get("tDn"):
            e["tenant"] = _seg(ctx["tDn"], "tn"); e["vrf"] = _seg(ctx["tDn"], "ctx")
        epg = nfae_epg.get(p["dn"])
        if epg and epg.get("tDn"):
            tdn = epg["tDn"]; e["tenant"] = _seg(tdn, "tn")
            if "/ap-" in tdn:
                e["epg_type"] = "epg"; e["application_profile"] = _seg(tdn, "ap"); e["endpoint_group"] = _seg(tdn, "epg")
            elif "/out-" in tdn:
                e["epg_type"] = "external_epg"; e["l3out"] = _seg(tdn, "out"); e["external_endpoint_group"] = _seg(tdn, "instP")
    nfam = {p["name"]: p for p in apic.get_class("netflowMonitorPol") if "/infra/" in p["dn"]}
    nfam_rec = {_parent(x["dn"]): x for x in apic.get_class("netflowRsMonitorToRecord") if "/infra/" in x["dn"]}
    nfam_exp = _by_parent([x for x in apic.get_class("netflowRsMonitorToExporter") if "/infra/" in x["dn"]])
    for e in flat["access_policies"].get("interface_policies", {}).get("netflow_monitors", []):
        p = nfam.get(e["name"])
        if not p:
            continue
        rec = nfam_rec.get(p["dn"])
        if rec and rec.get("tnNetflowRecordPolName"):
            e["flow_record"] = rec["tnNetflowRecordPolName"]
        exps = sorted(x["tnNetflowExporterPolName"] for x in nfam_exp.get(p["dn"], [])
                      if x.get("tnNetflowExporterPolName"))
        if exps:
            e["flow_exporters"] = exps
    # port-channel (lacpLagPol) : ctrl = join(",", local.ctrl) — le concat est dans un LOCAL
    # (pas inline) -> non vu par le handler flag de attr_map. Reverse dédié + hash_key. [#81]
    lags = {p["name"]: p for p in apic.get_class("lacpLagPol")}
    lb = {_parent(x["dn"]): x.get("hashFields") for x in apic.get_class("l2LoadBalancePol")}
    PC_FLAGS = {"fast-sel-hot-stdby": "fast_select_standby", "graceful-conv": "graceful_convergence",
                "load-defer": "load_defer", "susp-individual": "suspend_individual",
                "symmetric-hash": "symmetric_hash"}
    for e in flat["access_policies"].get("interface_policies", {}).get("port_channel_policies", []):
        p = lags.get(e["name"])
        if not p:
            continue
        ctrl = set(filter(None, p.get("ctrl", "").split(",")))
        for flag, key in PC_FLAGS.items():
            e[key] = flag in ctrl
        if "symmetric-hash" in ctrl and lb.get(p["dn"]):
            e["hash_key"] = lb[p["dn"]]
    # access-spine + fabric-leaf interface policy groups : base captée par le générique
    # (name), enrichir les relations (infraSpAccPortGrp / fabricLePortPGrp). macsec omis. [#89]
    sp_ll = {_parent(x["dn"]): x.get("tnFabricHIfPolName") for x in apic.get_class("infraRsHIfPol") if "spaccportgrp-" in x.get("dn", "")}
    sp_cdp = {_parent(x["dn"]): x.get("tnCdpIfPolName") for x in apic.get_class("infraRsCdpIfPol") if "spaccportgrp-" in x.get("dn", "")}
    sp_aaep = {_parent(x["dn"]): _seg(x.get("tDn", ""), "attentp") for x in apic.get_class("infraRsAttEntP") if "spaccportgrp-" in x.get("dn", "")}
    for e in flat["access_policies"].get("spine_interface_policy_groups", []):
        dn = "uni/infra/funcprof/spaccportgrp-" + e["name"]
        if sp_ll.get(dn):
            e["link_level_policy"] = sp_ll[dn]
        if sp_cdp.get(dn):
            e["cdp_policy"] = sp_cdp[dn]
        if sp_aaep.get(dn):
            e["aaep"] = sp_aaep[dn]
    fl_ll = {_parent(x["dn"]): x.get("tnFabricFIfPolName") for x in apic.get_class("fabricRsFIfPol")}
    for e in flat["fabric_policies"].get("leaf_interface_policy_groups", []):
        dn = "uni/fabric/funcprof/leportgrp-" + e["name"]
        if fl_ll.get(dn):
            e["link_level_policy"] = fl_ll[dn]
    # storm-control (stormctrlIfPol) : isUcMcBcStormPktCfgValid = configuration_type=="separate"?Valid:Invalid
    # ternaire non parsé par attr_map. Défaut configuration_type=separate (Valid). Émission non-défaut. [#46]
    scp = {p["name"]: p for p in apic.get_class("stormctrlIfPol")}
    for e in flat["access_policies"].get("interface_policies", {}).get("storm_control_policies", []):
        p = scp.get(e["name"])
        if p and p.get("isUcMcBcStormPktCfgValid") == "Invalid":   # Valid=separate (défaut)
            e["configuration_type"] = "all"
    # ptp-profile (ptpProfile) : profileTemplate/ptpoeDstMacRxNoMatch/ptpoeDstMacType = ternaires
    # non parsés par attr_map (intervalles numériques OK en direct). Émission non-défaut. [#47]
    ptpp = {p["name"]: p for p in apic.get_class("ptpProfile")}
    for e in flat["access_policies"].get("ptp_profiles", []):
        p = ptpp.get(e["name"])
        if not p:
            continue
        tmpl = {"telecom_full_path": "telecom", "smpte": "smpte"}.get(p.get("profileTemplate"))  # aes67=défaut
        if tmpl:
            e["template"] = tmpl
        mh = {"replyWithRxMac": "received", "drop": "drop"}.get(p.get("ptpoeDstMacRxNoMatch"))  # replyWithCfgMac=configured(défaut)
        if mh:
            e["mismatch_handling"] = mh
        if p.get("ptpoeDstMacType") == "non-forwardable":          # défaut forwardable
            e["forwardable"] = False
    # 2d. interface_policies.nodes : type (infraRsPortDirection) + shutdown (fabricRsOosPath)
    inodes = capture_interface_nodes(apic)
    if inodes:
        flat["interface_policies"]["nodes"] = inodes
    # 2e. fabric schedulers (trigSchedP, hors systeme)
    scheds = capture_schedulers(apic)
    if scheds:
        flat["fabric_policies"]["schedulers"] = scheds
    # 2f. update groups (firmware/maintenance) -> node_policies.update_groups
    ugroups = capture_update_groups(apic)
    if ugroups:
        flat["node_policies"]["update_groups"] = ugroups
    # 2g. bfd switch policies -> access_policies.switch_policies
    bfd = capture_bfd_policies(apic)
    if bfd:
        flat["access_policies"].setdefault("switch_policies", {}).update(bfd)
    # 2h. psu policies -> fabric_policies.switch_policies
    psu = capture_psu_policies(apic)
    if psu:
        flat["fabric_policies"].setdefault("switch_policies", {})["psu_policies"] = psu
    # 2i. config exports -> fabric_policies.config_exports
    cexp = capture_config_exports(apic)
    if cexp:
        flat["fabric_policies"]["config_exports"] = cexp
    # 2i-bis. SNMP policies fabric -> fabric_policies.pod_policies.snmp_policies [#75]
    snmp = capture_snmp_policies(apic)
    if snmp:
        flat["fabric_policies"].setdefault("pod_policies", {})["snmp_policies"] = snmp
    # 2i-ter. DNS policies fabric -> fabric_policies.dns_policies [#76]
    dns = capture_dns_policies(apic)
    if dns:
        flat["fabric_policies"]["dns_policies"] = dns
    # 2i-duodecies. fex interface profiles + selecteurs [#102-#103]
    fex = capture_fex_profiles(apic)
    if fex:
        flat["access_policies"]["fex_interface_profiles"] = fex
    # 2i-undecies. objets AAA (radius/tacacs/users/ca-certs/login-domains) [#96-#100]
    aaa_sec = capture_aaa_security(apic)
    if aaa_sec:
        flat["fabric_policies"].setdefault("aaa", {}).update(aaa_sec)
    # 2i-nonies. mst policies -> access_policies.switch_policies.mst_policies [#93]
    mst = capture_mst_policies(apic)
    if mst:
        flat["access_policies"].setdefault("switch_policies", {})["mst_policies"] = mst
    # 2i-decies. vpc groups -> node_policies.vpc_groups.groups [#94]
    vg = capture_vpc_groups(apic)
    if vg:
        flat["node_policies"].setdefault("vpc_groups", {})["groups"] = vg
    # 2i-terdecies. adresses mgmt statiques (noeuds NON enregistres) [#104-#105]
    na = capture_node_addresses(apic, warnings)
    if na:
        flat["node_policies"].update(na)
    # 2i-octies. geolocation -> fabric_policies.geolocation.sites [#91]
    geo = capture_geolocation(apic)
    if geo:
        flat["fabric_policies"]["geolocation"] = {"sites": geo}
    # 2i-septies. infra dhcp relay -> access_policies.dhcp_relay_policies [#84]
    idr = capture_infra_dhcp_relay_policies(apic)
    if idr:
        flat["access_policies"]["dhcp_relay_policies"] = idr
    # 2i-quater. date-time policies fabric -> pod_policies.date_time_policies [#77]
    dtp = capture_date_time_policies(apic)
    if dtp:
        flat["fabric_policies"].setdefault("pod_policies", {})["date_time_policies"] = dtp
    # 2i-quinquies. fabric pod policy groups -> fabric_policies.pod_policy_groups [#78]
    podpg = capture_fabric_pod_policy_groups(apic)
    if podpg:
        flat["fabric_policies"]["pod_policy_groups"] = podpg
    # 2i-sexies. management access policies -> pod_policies.management_access_policies [#79]
    mgmta = capture_management_access_policies(apic)
    if mgmta:
        flat["fabric_policies"].setdefault("pod_policies", {})["management_access_policies"] = mgmta
    # 2j. macsec parameters policies -> access_policies.interface_policies
    macsec = capture_macsec_param_policies(apic)
    if macsec:
        flat["access_policies"].setdefault("interface_policies", {})["macsec_parameters_policies"] = macsec
    tns = capture_tenants(apic, warnings)
    return flat, tns, warnings

def cmd_capture(args):
    apic = Apic(*load_creds())
    ver = apic.login()
    log.info("Connected to APIC %s (v%s) — READ-ONLY.", apic.url, ver)
    flat, tns, warnings = _capture_tree(apic)
    # 3. ecriture par section — TOUTES les sections connues, TOUJOURS, meme vides :
    # la capture est une PHOTO complete. Sauter une section vide/absente laisserait
    # survivre l'ancien fichier (objets disparus de la fabric -> data/ perime).
    # [bug corrige 2026-07-02]
    for section, fname in SECTION_OUT.items():
        _write_section(fname, section, flat.get(section) or {},
                       f"Captured {section} (full attributes, derived from the NaC modules).")
    p2 = _write_section("tenants.nac.yaml", "tenants", tns,
                        "Captured tenants (full attributes).")
    # toggles : desactive les singletons a secret (sinon terraform echoue a les creer)
    import yaml
    with open(os.path.join(DATA_DIR, "modules.nac.yaml"), "w") as f:
        f.write("# Disabled modules: secret-bearing objects that cannot be captured (key required).\n"
                "# Generated by tools/nac.py.\n---\n"
                + yaml.safe_dump({"modules": DISABLE_MODULES}, sort_keys=False))
    log.info("  access_policies : %s", ", ".join(
        f"{k}={len(v) if isinstance(v, list) else 1}" for k, v in flat["access_policies"].items()))
    for section in ("fabric_policies", "node_policies", "pod_policies"):
        if flat.get(section):
            log.info("  %s : %s", section, ", ".join(
                f"{k}={len(v) if isinstance(v, list) else 1}" for k, v in flat[section].items()))
    napp = len([t for t in tns if t.get("managed") is not False])
    log.info("  %s : %d application tenant(s)", p2, napp)
    for t in tns:
        if t.get("managed") is False:
            continue
        log.info("     %s: %s", t["name"],
                 ", ".join(f"{k}={len(v)}" for k, v in t.items() if isinstance(v, list)))
    if warnings:
        log.warning("  ⚠️  %d incomplete object(s) skipped:", len(warnings))
        for w in warnings:
            log.warning("     - %s", w)
    return 0

def _run(cmd, **kw):
    import subprocess
    return subprocess.run(cmd, cwd=ROOT, **kw)

def cmd_validate(args):
    venv = os.path.join(ROOT, ".venv", "bin", "nac-validate")
    return _run([venv if os.path.exists(venv) else "nac-validate", "data/"]).returncode

def cmd_plan(args):
    return _run(["terraform", "plan", "-input=false"]).returncode

def cmd_sync(args):
    import subprocess
    plan = subprocess.run(["terraform", "plan", "-input=false", "-no-color"],
                          cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"Plan:.*?(\d+) to destroy", plan.stdout)
    ndes = int(m.group(1)) if m else 0
    if ndes and not args.force:
        log.error("ABORTED: the plan would DESTROY %d object(s). Make sure data/ reflects the "
                  "fabric (run `nac.py capture`). Use --force to override.", ndes)
        return 1
    if not args.yes:
        ans = input("terraform apply. Continue? [y/N] ")
        if ans.strip().lower() not in ("y", "yes", "o", "oui"):
            log.info("Cancelled."); return 1
    return _run(["terraform", "apply", "-input=false", "-auto-approve"]).returncode

_DRIFT_ID_KEYS = ("name", "id", "ip", "prefix", "hostname_ip", "mac", "username",
                  "vlan", "node_id", "class", "fault_id", "key", "contract",
                  "destination_name", "exp_from", "dscp_from", "from", "device",
                  "interface_name", "tenant", "module", "port")

def _drift_key(item):
    """Cle d'identite d'un element de liste (pour matcher YAML <-> fabric)."""
    if isinstance(item, dict):
        k = tuple((f, item[f]) for f in _DRIFT_ID_KEYS if f in item)
        return k if k else ("_raw", repr(sorted(item.items(), key=str)))
    return ("_val", repr(item))

def _drift_label(key):
    return key[0][1] if key and isinstance(key[0], tuple) else "?"

def _drift_diff(path, yaml_v, fab_v, only_fabric, only_yaml, changed):
    """Compare recursivement YAML declare vs photo fabric (insensible a l'ordre)."""
    if isinstance(fab_v, dict) or isinstance(yaml_v, dict):
        yd = yaml_v if isinstance(yaml_v, dict) else {}
        fd = fab_v if isinstance(fab_v, dict) else {}
        for k in sorted(set(yd) | set(fd)):
            _drift_diff(f"{path}.{k}", yd.get(k), fd.get(k), only_fabric, only_yaml, changed)
    elif isinstance(fab_v, list) or isinstance(yaml_v, list):
        yl = yaml_v if isinstance(yaml_v, list) else []
        fl = fab_v if isinstance(fab_v, list) else []
        ym = {_drift_key(x): x for x in yl}
        fm = {_drift_key(x): x for x in fl}
        for k in fm:
            if k not in ym:
                only_fabric.append(f"{path}[{_drift_label(k)}]")
        for k in ym:
            if k not in fm:
                only_yaml.append(f"{path}[{_drift_label(k)}]")
        for k in set(ym) & set(fm):
            _drift_diff(f"{path}[{_drift_label(k)}]", ym[k], fm[k],
                        only_fabric, only_yaml, changed)
    else:
        if yaml_v is None and fab_v is not None:
            only_fabric.append(f"{path} = {fab_v!r}")
        elif fab_v is None and yaml_v is not None:
            only_yaml.append(f"{path} = {yaml_v!r}")
        elif _num(yaml_v) != _num(fab_v):
            changed.append(f"{path}: YAML={yaml_v!r}  fabric={fab_v!r}")

def cmd_drift(args):
    """Read-only three-way alignment check: fabric vs YAML vs Terraform state.

    Detects out-of-band changes that `terraform plan` alone CANNOT see —
    in particular objects created directly in the APIC GUI, which exist in
    neither the YAML nor the Terraform state. Writes nothing anywhere.
    Exit code: 0 = in sync, 2 = drift detected."""
    import yaml, subprocess
    apic = Apic(*load_creds())
    ver = apic.login()
    log.info("Connected to APIC %s (v%s) — READ-ONLY.", apic.url, ver)
    log.info(">> Building in-memory photo of the fabric...")
    flat, tns, _ = _capture_tree(apic)
    fabric = {sec: (flat.get(sec) or {}) for sec in SECTION_OUT}
    fabric["tenants"] = tns
    declared = {}
    for sec, fname in list(SECTION_OUT.items()) + [("tenants", "tenants.nac.yaml")]:
        fpath = os.path.join(DATA_DIR, fname)
        doc = yaml.safe_load(open(fpath)) if os.path.isfile(fpath) else None
        declared[sec] = ((doc or {}).get("apic") or {}).get(sec)
    only_fabric, only_yaml, changed = [], [], []
    for sec in fabric:
        _drift_diff(sec, declared.get(sec), fabric[sec], only_fabric, only_yaml, changed)
    log.info(">> Checking Terraform state alignment (terraform plan)...")
    pl = subprocess.run(["terraform", "plan", "-input=false", "-no-color"],
                        cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"^(Plan:.*|No changes\..*)$", pl.stdout, re.M)
    state_line = m.group(0).strip() if m else "unavailable (terraform plan failed)"
    state_ok = state_line.startswith("No changes")
    log.info("=" * 64)
    log.info(" DRIFT REPORT")
    log.info("=" * 64)
    for title, items, sign in (
            ("[1] On the fabric but NOT in the YAML (created out-of-band)", only_fabric, "+"),
            ("[2] In the YAML but NOT on the fabric (deleted out-of-band)", only_yaml, "-"),
            ("[3] Attribute differences (modified out-of-band)", changed, "~")):
        log.info("%s: %d", title, len(items))
        for x in items[:20]:
            log.info("     %s %s", sign, x)
        if len(items) > 20:
            log.info("     ... and %d more", len(items) - 20)
    log.info("[4] Terraform state alignment: %s", state_line)
    drift = bool(only_fabric or only_yaml or changed) or not state_ok
    log.info("=" * 64)
    if drift:
        log.info(" VERDICT: DRIFT DETECTED — accept it with `capture` (+ `sync`/`adopt`), "
                 "or overwrite it with `sync`.")
        return 2
    log.info(" VERDICT: IN SYNC — fabric, YAML and Terraform state are aligned.")
    return 0

def cmd_adopt(args):
    """Adoption SANS ECRITURE fabric (terraform import, TF >= 1.5).

    1. terraform plan -out + show -json -> pour chaque objet 'to add', recupere
       son adresse Terraform et son DN APIC (connus au moment du plan).
    2. Genere des blocs `import { to=<adresse> id=<dn> }` dans imports_adopt.tf.
    3. Re-plan (garde-fou destroy) puis apply : une IMPORTATION lit l'objet sur
       la fabric et l'inscrit dans le state — AUCUN POST n'est envoye.
    Les objets sans DN connu au plan (ex: aci_rest 'workaround') sont laisses au
    circuit normal de creation. Le fichier imports_adopt.tf est supprime apres."""
    import subprocess, json
    imports_tf = os.path.join(ROOT, "imports_adopt.tf")
    planfile = os.path.join(ROOT, ".adopt.tfplan")
    if os.path.exists(imports_tf):
        os.remove(imports_tf)
    log.info(">> Analyzing plan (JSON) to discover addresses + DNs...")
    r = subprocess.run(["terraform", "plan", "-input=false", f"-out={planfile}"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        return r.returncode
    show = subprocess.run(["terraform", "show", "-json", planfile],
                          cwd=ROOT, capture_output=True, text=True)
    os.remove(planfile)
    candidates, skipped = [], []
    for rc in json.loads(show.stdout).get("resource_changes", []):
        if rc.get("change", {}).get("actions") != ["create"]:
            continue
        dn = (rc["change"].get("after") or {}).get("dn")
        if rc.get("type") != "aci_rest_managed" or not dn:
            skipped.append(rc["address"])
            continue
        if ":" in dn:
            # le parseur d'import du provider ACI utilise ':' comme separateur
            # (ex: DN de mac tags) -> non importable, creation normale
            skipped.append(rc["address"])
            continue
        cls = (rc["change"].get("after") or {}).get("class_name")
        candidates.append((rc["address"], dn, cls))
    if not candidates:
        log.info("Nothing to adopt: no importable 'to add' object in the plan.")
        return 0
    # ne generer un bloc import QUE si l'objet existe reellement sur la fabric
    # (sinon 'Cannot import non-existent remote object' fait echouer TOUT le lot).
    # Verification PAR CLASSE (les DN a crochets imbriques passent mal en URL /mo/).
    classes = sorted({c for _, _, c in candidates if c})
    log.info(">> Verifying existence on the APIC (%d DNs, %d classes)...",
             len(candidates), len(classes))
    apic = Apic(*load_creds())
    apic.login()
    fabric_dns = set()
    for cls in classes:
        try:
            fabric_dns.update(x.get("dn", "") for x in apic.get_class(cls))
        except Exception:
            pass                                           # classe illisible -> DNs absents
    blocks = []
    for addr, dn, cls in candidates:
        if dn in fabric_dns:
            blocks.append(f'import {{\n  to = {addr}\n  id = "{dn}"\n}}\n')
        else:
            skipped.append(addr)
    if not blocks:
        log.info("None of the 'to add' objects exist on the fabric: nothing to import, "
                 "use `nac.py sync` to create them.")
        return 0
    with open(imports_tf, "w") as f:
        f.write("# Generated by `nac.py adopt` (write-free adoption) — removed after apply.\n\n"
                + "\n".join(blocks))
    log.info("%d object(s) to IMPORT (read-only).", len(blocks))
    if skipped:
        log.info("%d object(s) not importable (absent from the fabric, DN unknown at plan "
                 "time, or DN containing ':') -> normal creation: %s",
                 len(skipped), ", ".join(skipped[:5]) + ("..." if len(skipped) > 5 else ""))
    try:
        plan2 = subprocess.run(["terraform", "plan", "-input=false", "-no-color"],
                               cwd=ROOT, capture_output=True, text=True)
        if plan2.returncode:
            sys.stderr.write(plan2.stdout + plan2.stderr)
            return plan2.returncode
        m = re.search(r"^Plan:.*$", plan2.stdout, re.M)
        log.info(m.group(0) if m else "Plan unavailable")
        md = re.search(r"(\d+) to destroy", plan2.stdout)
        ndes = int(md.group(1)) if md else 0
        if ndes and not args.force:
            log.error("ABORTED: the plan would DESTROY %d object(s). Run `nac.py capture` "
                      "first, or use --force knowingly.", ndes)
            return 1
        if not args.yes:
            ans = input("terraform apply (imports = read-only). Continue? [y/N] ")
            if ans.strip().lower() not in ("y", "yes", "o", "oui"):
                log.info("Cancelled.")
                return 1
        rc = _run(["terraform", "apply", "-input=false", "-auto-approve"]).returncode
        if rc == 0:
            log.info("Adoption complete. Verify with `nac.py plan` (expected: No changes).")
        return rc
    finally:
        if os.path.exists(imports_tf):
            os.remove(imports_tf)

def cmd_bootstrap(args):
    log.info("=" * 60)
    log.info(" NaC brownfield collection (READ-ONLY)")
    log.info("=" * 60)
    rc = cmd_capture(args)
    if rc: return rc
    log.info(">> Validation (nac-validate)...")
    cmd_validate(args)
    log.info(">> Preview (terraform plan, changes nothing)...")
    cmd_plan(args)
    if getattr(args, "adopt", False):
        log.info(">> Adoption (--adopt)...")
        return cmd_adopt(args)
    log.info("Collection complete. YAML written to data/. Adopt with `nac.py adopt` "
             "(write-free) or `nac.py sync`.")
    return 0

# ═══════════════════════════════════════════════════════ CLI
def main(argv=None):
    p = argparse.ArgumentParser(prog="nac.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("capture", help="read the fabric -> data/ (read-only)")
    sub.add_parser("validate", help="nac-validate on data/")
    sub.add_parser("plan", help="terraform plan (preview)")
    sp = sub.add_parser("sync", help="terraform apply (destroy guard included)")
    sp.add_argument("-y", "--yes", action="store_true", help="no confirmation prompt")
    sp.add_argument("--force", action="store_true", help="allow even if the plan destroys objects")
    sa = sub.add_parser("adopt", help="write-free adoption (bulk terraform import)")
    sa.add_argument("-y", "--yes", action="store_true", help="no confirmation prompt")
    sa.add_argument("--force", action="store_true", help="allow even if the plan destroys objects")
    sub.add_parser("drift", help="read-only 3-way check: fabric vs YAML vs state (exit 2 on drift)")
    sb = sub.add_parser("bootstrap", help="capture + validate + plan (+ adoption with --adopt)")
    sb.add_argument("--adopt", action="store_true", help="chain the adoption (bulk import)")
    sb.add_argument("-y", "--yes", action="store_true", help="no confirmation prompt")
    sb.add_argument("--force", action="store_true", help="allow even if the plan destroys objects")
    args = p.parse_args(argv)
    _setup_log(args.verbose)
    return {
        "capture": cmd_capture, "validate": cmd_validate, "plan": cmd_plan,
        "sync": cmd_sync, "adopt": cmd_adopt, "drift": cmd_drift,
        "bootstrap": cmd_bootstrap,
    }[args.cmd](args)

if __name__ == "__main__":
    sys.exit(main())
