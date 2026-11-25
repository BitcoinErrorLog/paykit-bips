#!/usr/bin/env python3
"""Assemble the series' three vector files from the pinned upstream vector sets.

Usage:
  assemble_vectors.py --paykit-rs PATH --pubky-switch PATH [--out BIPDIR] [--check]

PATH is a checkout of pubky/paykit-rs at aba097fa015e98f7b2926fce662d68b34ad56280
and of pubky/pubky-switch at 5f3209aae28d1b538a31c8ce43506b39df828b61. Every
upstream file read is checked against its SHA-256 below, so a checkout at
another commit is refused instead of producing different vectors.

The output keeps a Bitcoin-only subset: no case whose content names another
asset, the test payment method, or a conversion from another asset. Each
case keeps its upstream name and carries `source`, the upstream file and the
JSON path of the case. Cases written for these documents carry
`hand_written: true` and `basis`, the rule they follow.

--out defaults to the bip/ directory beside this script. --check writes
nothing and exits non-zero unless the files in --out equal the output byte
for byte.
"""

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

PAYKIT_COMMIT = "aba097fa015e98f7b2926fce662d68b34ad56280"
SWITCH_COMMIT = "5f3209aae28d1b538a31c8ce43506b39df828b61"

PAYKIT_DIR = "specs/v0.2/vectors"
SWITCH_DIR = "spec/vectors"

PINNED = {
    ("paykit-rs", "keys.json"): "9c8afb7dd787015218295bec1ca464887833b59631b9caf3637bb163ca366d4b",
    ("paykit-rs", "encoding.json"): "9312806fb11645ab23def9f8c90e1dfbe269f290ef5a732afffec9cf6e008dd6",
    ("paykit-rs", "identifiers.json"): "38cfb96bc0d16effd7ae4f42beffde43ded37d961c08ddb8f83e475d0494fa06",
    ("paykit-rs", "documents.json"): "3cc87d2a93511fb57fcab0ee256894c557c749a22fbec5bc19fa49f0d891319a",
    ("paykit-rs", "signatures.json"): "674b6f86c9ef5bffc73c3eac62731a60922ea6e41eac313413e29568840aced0",
    ("paykit-rs", "messages.json"): "028f01ff9b1d881c04863fdcc2f02f50c1f95bae95f8b2c9dcfad589d6be02ef",
    ("paykit-rs", "periods.json"): "4ca957911c8185a22a01ece14fc83ae6b972ef33e42181d70275c077ffcd4097",
    ("paykit-rs", "allowance_usage.json"): "5c8a0f7ebab933477d2d38ba86664dbee2489a037736a5cf6cb2eb23f9ecb420",
    ("paykit-rs", "sealed.json"): "f1b023667bfc176fb7241ee7c0b2f9e5b110f17fb9516b88b67f1e17cc039c57",
    ("pubky-switch", "keys.json"): "5fb02658d022e91a0f6251dad655e8b85ce1a5b5c037b670c7fd0bd7b81a73d1",
    ("pubky-switch", "encoding.json"): "987402379ce4942a12a1bbd96033313634d47e4603ce2ce29cf210f9fc62e9c0",
    ("pubky-switch", "identifiers.json"): "e5b35b452eeed324bb058ad1180a461b5d94d28675df4169137de4f59a070477",
    ("pubky-switch", "signatures.json"): "c7c810cec25bc81df0cacab4abe42f80636813fc97bd950862412a955ab663e5",
    ("pubky-switch", "documents.json"): "65a684a09c2451e9ef743f66942ada0496da04f27d06a6b33ccc9f6e5d1d0236",
}

# The PKARR record of the series' earlier vector set (pkarr 8.1.0): an
# identity with secret 0x61 * 32 pointing `_pubky` at a homeserver.
PKARR_RECORD = {
    "dns_packet_hex": "000080000000000100000000065f7075626b79346968646b3861336a6e686b716a6834736167716a736671706466653661357567636b693878786f386b74393174726864676f716f000041000100000e1000380000346b3161706f38657877396579683175376379673969717578666374796773336e3961336968663970367a68347773376f6b62347900",
    "homeserver_public": "k1apo8exw9eyh1u7cyg9iquxfctygs3n9a3ihf9p6zh4ws7okb4y",
    "identity": {
        "public": "ihdk8a3jnhkqjh4sagqjsfqpdfe6a5ugcki8xxo8kt91trhdgoqo",
        "public_hex": "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d",
        "secret_hex": "6161616161616161616161616161616161616161616161616161616161616161",
    },
    "signable_hex": "333a736571693137393030303030303030303030303065313a763133393a000080000000000100000000065f7075626b79346968646b3861336a6e686b716a6834736167716a736671706466653661357567636b693878786f386b74393174726864676f716f000041000100000e1000380000346b3161706f38657877396579683175376379673969717578666374796773336e3961336968663970367a68347773376f6b62347900",
    "signed_packet_hex": "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d03c0fbc9a9b34ee1fa960fe1902076c84600c610d447a4967234e0fb8fce57f31e8e3e4db95057158c5346644e4f4c04796091732483486ff64fbee92532be0900065bfeda25e000000080000000000100000000065f7075626b79346968646b3861336a6e686b716a6834736167716a736671706466653661357567636b693878786f386b74393174726864676f716f000041000100000e1000380000346b3161706f38657877396579683175376379673969717578666374796773336e3961336968663970367a68347773376f6b62347900",
    "source": {"file": "earlier series vector set (pkarr 8.1.0)", "path": "$.pkarr_record"},
    "timestamp_micros": 1790000000000000,
}

ENDPOINT_MEMBERS = {"payment_endpoints", "public_endpoints"}
IDENTIFIER_LISTS = {
    "endpoint_identifiers",
    "accepted_payment_endpoint_identifiers",
    "allowed_payment_endpoint_identifiers",
}
FOREIGN_TEXT = re.compile(r"\b(usdt|usd|eur|eth|erc-?20|polygon|tron)\b", re.I)


class Inputs:
    def __init__(self, paykit_root, switch_root):
        self.roots = {"paykit-rs": (Path(paykit_root), PAYKIT_DIR), "pubky-switch": (Path(switch_root), SWITCH_DIR)}
        self.cache = {}

    def load(self, repo, name):
        if (repo, name) not in self.cache:
            root, sub = self.roots[repo]
            path = root / sub / name
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != PINNED[(repo, name)]:
                sys.exit(f"{path}: SHA-256 {digest} is not the pinned file's; check out the pinned commit")
            self.cache[(repo, name)] = json.loads(data)
        return self.cache[(repo, name)]


def src(repo, name, path):
    sub = PAYKIT_DIR if repo == "paykit-rs" else SWITCH_DIR
    return {"file": f"{repo}:{sub}/{name}", "path": path}


def take(inputs, repo, name, path):
    """The case at a JSON path such as $.messages[3].x, with its source."""
    node = inputs.load(repo, name)
    for part in re.findall(r"\.([A-Za-z_0-9]+)|\[(\d+)\]", path[1:]):
        node = node[part[0]] if part[0] else node[int(part[1])]
    case = copy.deepcopy(node)
    if isinstance(case, dict):
        case["source"] = src(repo, name, path)
    return case


def foreign_content(value, parent=None):
    """Reasons a value names something other than Bitcoin."""
    found = []
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "asset" and isinstance(v, str) and v.split("-")[0].lower() != "btc":
                found.append(f"asset {v}")
            if k == "rail" and v == "fake":
                found.append("rail fake")
            if parent in ENDPOINT_MEMBERS and k.split("-")[0].lower() != "btc" and "-" in k:
                found.append(f"endpoint {k}")
            if k in ("payment_endpoint_identifier",) and isinstance(v, str) and v.split("-")[0].lower() != "btc":
                found.append(f"endpoint {v}")
            if k in IDENTIFIER_LISTS and isinstance(v, list):
                for x in v:
                    if isinstance(x, str) and "-" in x and x.split("-")[0].lower() != "btc":
                        found.append(f"endpoint {x}")
            if k in ("json", "body") and isinstance(v, str) and v.startswith("{"):
                try:
                    found += foreign_content(json.loads(v))
                except ValueError:
                    pass
            if k not in ("name", "note", "reason", "why", "description", "source", "rule"):
                found += foreign_content(v, k)
    elif isinstance(value, list):
        for v in value:
            found += foreign_content(v, parent)
    elif isinstance(value, str) and parent not in ("name", "note", "reason", "why", "description"):
        if FOREIGN_TEXT.search(value) and not value.startswith(("ey", "pubky")):
            found.append(f"text {value[:40]}")
    return found


def bitcoin_only(case):
    reasons = foreign_content(case)
    if reasons:
        sys.exit(f"case {case.get('name')!r} ({case.get('source')}) names {reasons}")
    return case


def group(description, cases_key="cases", **parts):
    out = {"description": description}
    for k, v in parts.items():
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# Shared parts


def keys_group(inputs, with_switch):
    pk = inputs.load("paykit-rs", "keys.json")
    identities = []
    for i, ident in enumerate(pk["identities"]):
        identities.append(
            {
                "name": ident["name"],
                "naming_key": ident["naming_key"],
                "pubky_id": ident["pubky_id"],
                "public_hex": ident["public_hex"],
                "secret_hex": ident["secret_hex"],
                "seed_label": ident["seed_label"],
                "source": src("paykit-rs", "keys.json", f"$.identities[{i}]"),
                "switch_root_hex": ident["switch_root_hex"],
            }
        )
    apps = []
    for i, app in enumerate(pk["apps"]):
        apps.append(
            {
                "app_id": app["app_id"],
                "app_id_bytes_hex": app["app_id_bytes_hex"],
                "identity": app["identity"],
                "name": app["name"],
                "permissions": app["permissions"],
                "scopes": app["scopes"],
                "signing_public": app["signing_public"],
                "signing_secret_hex": app["signing_secret_hex"],
                "signing_seed_label": app["signing_seed_label"],
                "source": src("paykit-rs", "keys.json", f"$.apps[{i}]"),
            }
        )
    out = {
        "description": "The fixed test keys. Each secret is BLAKE3(seed_prefix + seed label), a 32-byte Ed25519 seed; the public key, Pubky ID (z-base-32), App ID (first 16 bytes of BLAKE3 of the signing key, z-base-32), Switch root derive(\"pubky-switch/v1/scope-root\", secret) and naming key derive(\"pubky-switch/v1/naming\", root) follow from it. These keys are published test values and must never hold funds.",
        "paykit": {"apps": apps, "identities": identities, "seed_prefix": "paykit/v1/test-vectors/"},
    }
    if with_switch:
        sk = inputs.load("pubky-switch", "keys.json")
        s_ids = []
        for i, ident in enumerate(sk["identities"]):
            s_ids.append(
                {
                    "name": ident["name"],
                    "naming_key": ident["naming_key"],
                    "pubky_id": ident["pubky_id"],
                    "public_hex": ident["public_hex"],
                    "secret_hex": ident["secret_hex"],
                    "seed_label": ident["seed_label"],
                    "source": src("pubky-switch", "keys.json", f"$.identities[{i}]"),
                    "switch_root_hex": ident["switch_root_hex"],
                }
            )
        s_apps = []
        for i, app in enumerate(sk["apps"]):
            s_apps.append(
                {
                    "app_id": app["app_id"],
                    "app_id_bytes_hex": app["app_id_bytes_hex"],
                    "identity": app["identity"],
                    "name": app["name"],
                    "signing_public": app["signing_public"],
                    "signing_secret_hex": app["signing_secret_hex"],
                    "signing_seed_label": app["signing_seed_label"],
                    "source": src("pubky-switch", "keys.json", f"$.apps[{i}]"),
                }
            )
        out["switch"] = {"apps": s_apps, "identities": s_ids, "seed_prefix": "pubky-switch/v1/test-vectors/"}
    return out


def base_certificates(inputs):
    doc = inputs.load("paykit-rs", "documents.json")
    cases = [take(inputs, "paykit-rs", "documents.json", f"$.certificates.cases[{i}]") for i in range(len(doc["certificates"]["cases"]))]
    return {
        "description": "Each Paykit app's certificate, signed by its identity key. Every verifier, the Switch's and Paykit's, accepts each.",
        "cases": [bitcoin_only(c) for c in cases],
    }


def messages_by_name(inputs):
    m = inputs.load("paykit-rs", "messages.json")
    return {c["name"]: i for i, c in enumerate(m["messages"])}


def message_cases(inputs, names):
    idx = messages_by_name(inputs)
    return [bitcoin_only(take(inputs, "paykit-rs", "messages.json", f"$.messages[{idx[n]}]")) for n in names]


def subgroup(inputs, repo, name, key, parts, keep=None):
    """A group whose cases sit under key.<part>[i], filtered by keep(name)."""
    node = inputs.load(repo, name)[key]
    out = {"description": node["description"]} if isinstance(node, dict) and "description" in node else {}
    for part in parts:
        cases = []
        for i, c in enumerate(node[part]):
            if keep is None or keep(c):
                cases.append(bitcoin_only(take(inputs, repo, name, f"$.{key}.{part}[{i}]")))
        out[part] = cases
    return out


# ---------------------------------------------------------------------------
# payment-endpoint-discovery


ENDPOINT_IDENTIFIER_CASES = [
    # identifier, valid (wire 1.4), recommended form (three lower-case segments)
    ("btc-bitcoin-p2pkh", True, True),
    ("btc-bitcoin-p2sh", True, True),
    ("btc-bitcoin-p2wpkh", True, True),
    ("btc-bitcoin-p2tr", True, True),
    ("btc-testnet-p2wpkh", True, True),
    ("btc-signet-p2tr", True, True),
    ("btc-regtest-p2sh", True, True),
    ("btc-lightning-bolt11", True, True),
    ("btc-lightning-bolt12", True, True),
    ("btc-lightning-lnurl", True, True),
    ("BTC-Bitcoin-P2TR", True, False),
    ("btc-bitcoin", True, False),
    ("btc-bitcoin-p2tr-x", True, False),
    ("btc_bitcoin_p2tr", True, False),
    ("a.b_c-d", True, False),
    ("...", True, False),
    ("a" * 64, True, False),
    ("a" * 65, False, False),
    ("", False, False),
    (".", False, False),
    ("..", False, False),
    ("private", False, False),
    ("Private", True, False),
    ("a/b", False, False),
    ("a b", False, False),
    ("btc-bitcoin-p2wpkh/", False, False),
    ("btc-lightning/bolt11", False, False),
    ("btc-lightning-bolt11\n", False, False),
    ("btc-bitcoin-p2tr\u00e9", False, False),
]

# (name, updated_at, expires_at, record_max_age seconds or None, device_time, service_time, usable)
RECORD_USABILITY_CASES = [
    ("fresh record, no service time", "2026-01-01T00:00:00.000Z", None, None, "2026-01-02T00:00:00.000Z", None, True),
    ("one millisecond before the 90-day default", "2026-01-01T00:00:00.000Z", None, None, "2026-03-31T23:59:59.999Z", None, True),
    ("at the 90-day default", "2026-01-01T00:00:00.000Z", None, None, "2026-04-01T00:00:00.000Z", None, False),
    ("service time past the 90-day default, device before", "2026-01-01T00:00:00.000Z", None, None, "2026-03-31T00:00:00.000Z", "2026-04-01T00:00:00.000Z", False),
    ("record_max_age of 30 days, day 29", "2026-01-01T00:00:00.000Z", None, 2592000, "2026-01-30T00:00:00.000Z", None, True),
    ("record_max_age of 30 days, at day 30", "2026-01-01T00:00:00.000Z", None, 2592000, "2026-01-31T00:00:00.000Z", None, False),
    ("finite expires_at earlier than the age limit, before it", "2026-01-01T00:00:00.000Z", "2026-01-30T00:00:00.000Z", None, "2026-01-29T23:59:59.999Z", None, True),
    ("finite expires_at earlier than the age limit, at it", "2026-01-01T00:00:00.000Z", "2026-01-30T00:00:00.000Z", None, "2026-01-30T00:00:00.000Z", None, False),
    ("service time at expires_at, device before", "2026-01-01T00:00:00.000Z", "2026-01-30T00:00:00.000Z", None, "2026-01-29T00:00:00.000Z", "2026-01-30T00:00:00.000Z", False),
    ("expires_at with four fraction digits, compared at milliseconds", "2026-01-01T00:00:00.000Z", "2026-01-30T00:00:00.0009Z", None, "2026-01-30T00:00:00.000Z", None, False),
    ("updated_at 5 minutes ahead of the device clock", "2026-01-01T00:05:00.000Z", None, None, "2026-01-01T00:00:00.000Z", None, True),
    ("updated_at more than 5 minutes ahead of the device clock", "2026-01-01T00:05:00.001Z", None, None, "2026-01-01T00:00:00.000Z", None, False),
    ("updated_at more than 5 minutes ahead of the device clock, service time later", "2026-01-01T00:05:00.001Z", None, None, "2026-01-01T00:00:00.000Z", "2026-01-01T00:10:00.000Z", False),
]


LOOKUP_BASIS = (
    "Payment Endpoint Discovery, application record checks 1 and 2 (Switch wire 3.2): a record read from "
    "/pub/pubky-switch/v1/apps/<app_id>.json on an identity's homeserver is valid only if its identity is the "
    "identity being resolved and its app_id the <app_id> of that path. lookup names both."
)


def key_app(inputs, repo, name):
    return next(a for a in inputs.load(repo, "keys.json")["apps"] if a["name"] == name)


def key_identity(inputs, repo, name):
    return next(i for i in inputs.load(repo, "keys.json")["identities"] if i["name"] == name)


def with_lookup(inputs, repo, app_name, cases):
    """Each record case with the identity and path App ID it was read under: those of app_name."""
    app = key_app(inputs, repo, app_name)
    for c in cases:
        c["lookup"] = {"app_id": app["app_id"], "identity": app["identity"]}
    return cases


def app_record_group(inputs):
    group = subgroup(inputs, "paykit-rs", "documents.json", "app_records", ["accepted", "refused"])
    for part in ("accepted", "refused"):
        with_lookup(inputs, "paykit-rs", "shop", group[part])
    shop = key_app(inputs, "paykit-rs", "shop")
    group["description"] += " lookup is the identity and path App ID each record was read under; two records are refused for theirs alone."
    record = group["accepted"][0]
    for name, lookup in (
        ("the shop's record read from another identity's homeserver", {"app_id": shop["app_id"], "identity": key_identity(inputs, "paykit-rs", "alice")["pubky_id"]}),
        ("the shop's record read from another application's path", {"app_id": key_app(inputs, "paykit-rs", "wallet")["app_id"], "identity": shop["identity"]}),
    ):
        group["refused"].append(
            {
                "basis": LOOKUP_BASIS,
                "body": record["body"],
                "hand_written": True,
                "lookup": lookup,
                "name": name,
                "signed": record["signed"],
                "switch_accepts": False,
            }
        )
    return group


def discovery(inputs):
    sw_enc = inputs.load("pubky-switch", "encoding.json")
    sw_sig = inputs.load("pubky-switch", "signatures.json")
    sw_doc = inputs.load("pubky-switch", "documents.json")
    sw_ids = inputs.load("pubky-switch", "identifiers.json")
    pk_doc = inputs.load("paykit-rs", "documents.json")
    pk_keys = inputs.load("paykit-rs", "keys.json")
    periods = inputs.load("paykit-rs", "periods.json")

    def enc(part, path):
        return [take(inputs, "pubky-switch", "encoding.json", f"$.{path}[{i}]") for i in range(len(eval_path(sw_enc, path)))]

    app_ids = [
        {"app_id": a["app_id"], "name": a["name"], "set": "paykit", "signing_public": a["signing_public"], "source": src("paykit-rs", "keys.json", f"$.apps[{i}]")}
        for i, a in enumerate(pk_keys["apps"])
    ]
    app_ids += [take(inputs, "pubky-switch", "identifiers.json", f"$.app_id[{i}]") for i in range(len(sw_ids["app_id"]))]

    labels = {"pubky-switch/v1/app-cert", "pubky-switch/v1/app-record", "pubky-switch/v1/identity", "pubky-switch/v1/msg"}
    signature_inputs = [
        take(inputs, "pubky-switch", "signatures.json", f"$.signatures[{i}]")
        for i, c in enumerate(sw_sig["signatures"])
        if c["label"] in labels
    ]
    step = {
        "non-canonical S": 1,
        "non-canonical R": 2,
        "non-canonical public key": 2,
        "small-order public key": 3,
        "small-order R": 3,
        "small-order public key of order 8": 3,
        "another label": 4,
        "cofactored equation only": 4,
    }
    rejections = []
    for i, c in enumerate(sw_sig["rejections"]):
        case = take(inputs, "pubky-switch", "signatures.json", f"$.rejections[{i}]")
        case["refused_at_step"] = step[c["name"]]
        rejections.append(case)
    accepted = [take(inputs, "pubky-switch", "signatures.json", f"$.accepted[{i}]") for i in range(len(sw_sig["accepted"]))]

    sw_docs_kept = {
        "wallet certificate",
        "shop certificate",
        "wallet app record",
        "shop app record",
        "alice identity.json",
        "bob identity.json",
        "alice identity.json, first delivery (version 1)",
        "alice identity.json, record age limit (version 6)",
    }
    signed_documents = [
        take(inputs, "pubky-switch", "documents.json", f"$.documents[{i}]")
        for i, d in enumerate(sw_doc["documents"])
        if d["name"] in sw_docs_kept
    ]

    identity_docs = [d for d in signed_documents if d["label"] == "pubky-switch/v1/identity"]
    listing = []
    for ident in identity_docs:
        body = json.loads(ident["body"])
        for cert in (d for d in signed_documents if d["label"] == "pubky-switch/v1/app-cert"):
            cbody = json.loads(cert["body"])
            if cbody["identity"] != body["identity"]:
                continue
            listing.append({"certificate": cert["name"], "identity_document": ident["name"]})
    listing_expected = {
        ("alice identity.json", "wallet certificate"): True,
        ("alice identity.json, first delivery (version 1)", "wallet certificate"): True,
        ("alice identity.json, record age limit (version 6)", "wallet certificate"): True,
        ("bob identity.json", "shop certificate"): True,
    }
    for item in listing:
        item["listed"] = listing_expected[(item["identity_document"], item["certificate"])]
        item["hand_written"] = True
        item["basis"] = "Switch wire 3.3: an app is listed when apps holds its app_id with the document hash of its certificate"
    age_expected = {
        "alice identity.json": 7776000,
        "bob identity.json": 7776000,
        "alice identity.json, first delivery (version 1)": 7776000,
        "alice identity.json, record age limit (version 6)": 2592000,
    }

    def cert_groups():
        out = {}
        out["certificates"] = base_certificates(inputs)
        out["certificate_rejections"] = subgroup(inputs, "paykit-rs", "documents.json", "certificate_rejections", ["cases"])
        out["labelled_scope_rejections"] = subgroup(inputs, "paykit-rs", "documents.json", "labelled_scope_rejections", ["cases"])
        out["multi_protocol_certificates"] = subgroup(inputs, "paykit-rs", "documents.json", "multi_protocol_certificates", ["accepted", "refused"])
        out["extension_certificate"] = {
            "description": pk_doc["extension_app"]["description"],
            "cases": [bitcoin_only(take(inputs, "paykit-rs", "documents.json", "$.extension_app.certificate"))],
        }
        out["switch_scope_rule"] = subgroup(inputs, "pubky-switch", "documents.json", "scope_rule", ["accepted", "refused"])
        out["switch_permission_rejections"] = subgroup(inputs, "pubky-switch", "documents.json", "permission_rejections", ["cases"])
        return out

    usability = []
    for name, updated, expires, age, device, service, usable in RECORD_USABILITY_CASES:
        usability.append(
            {
                "basis": "Paykit wire 3.2 Expiry and Record age limit, spec 4 and 7.2; Switch wire 1.6 comparisons",
                "device_time": device,
                "expires_at": expires,
                "hand_written": True,
                "name": name,
                "record_max_age": age,
                "service_time": service,
                "updated_at": updated,
                "usable": usable,
            }
        )

    out = {
        "document": "Payment Endpoint Discovery",
        "sources": sources(),
        "notes": NOTES + ["Members added to upstream cases, naming inputs the checker needs: `refused_at_step` (ed25519_strict), `record_max_age` and `listed` (identity_documents), `lookup` (app_records, extension_app_record, switch_app_record_protocols).", "App records taken from the identity service's vectors at the pinned revision carry `label`. Paykit adopts the identity service revision that keeps display names out of the signed record (Paykit spec 4), and readers ignore unknown members (Switch wire 1.1), so `label` changes no verdict."],
        "keys": keys_group(inputs, with_switch=True),
        "pkarr_record": PKARR_RECORD,
        "zbase32": {"description": sw_enc["description"], "valid": enc(None, "zbase32.valid"), "invalid": enc(None, "zbase32.invalid")},
        "base64url": {"valid": enc(None, "base64url.valid"), "invalid": enc(None, "base64url.invalid")},
        "lp": {"cases": enc(None, "lp")},
        "u64_be": {"cases": enc(None, "u64_be")},
        "derive": {"cases": enc(None, "derive")},
        "rfc3339": {
            "format": enc(None, "rfc3339.format"),
            "parse": enc(None, "rfc3339.parse"),
            "invalid": enc(None, "rfc3339.invalid"),
        },
        "json": {"cases": [c for c in enc(None, "json") if "read_as" not in c]},
        "app_ids": {"cases": app_ids},
        "ed25519_strict": {
            "description": sw_sig["description"],
            "accepted": accepted,
            "rejections": rejections,
        },
        "signature_inputs": {"cases": signature_inputs},
        "signed_documents": {"description": sw_doc["description"], "cases": signed_documents},
        "identity_documents": {
            "description": "Switch wire 3.3: identity.json documents of signed_documents. Each verifies with its identity's key and has every required member; record_max_age is the limit a reader takes, 7776000 (90 days) when the member is absent. listing says whether each document lists each certificate of its identity in signed_documents.",
            "documents": [
                {
                    "basis": "Switch wire 3.3 record_max_age: absent means 90 days (7776000)",
                    "hand_written": True,
                    "name": d["name"],
                    "record_max_age": age_expected[d["name"]],
                }
                for d in identity_docs
            ],
            "listing": listing,
            "rejections": subgroup(inputs, "pubky-switch", "documents.json", "identity_rejections", ["cases"])["cases"],
            "constraints": identity_constraint_cases(inputs, identity_docs[0]),
        },
        **cert_groups(),
        "app_records": app_record_group(inputs),
        "extension_app_record": {
            "description": pk_doc["extension_app"]["description"],
            "cases": with_lookup(inputs, "paykit-rs", "cap", [bitcoin_only(take(inputs, "paykit-rs", "documents.json", "$.extension_app.app_record"))]),
        },
        "switch_app_record_protocols": {
            part: (with_lookup(inputs, "pubky-switch", "wallet", cases) if part != "description" else cases)
            for part, cases in subgroup(inputs, "pubky-switch", "documents.json", "app_record_protocols", ["accepted", "refused"]).items()
        },
        "endpoint_identifiers": {
            "description": "Payment Endpoint Identifiers (wire 1.4): valid is the identifier rule, recommended the three lower-case segment form <asset>-<rail>-<format>.",
            "cases": [
                {
                    "basis": "Paykit wire 1.4 and specs/payment-endpoint-identifier.md",
                    "hand_written": True,
                    "identifier": ident,
                    "recommended_form": rec,
                    "valid": valid,
                }
                for ident, valid, rec in ENDPOINT_IDENTIFIER_CASES
            ],
        },
        "destination_expiry": {
            "description": periods["destination_expiry"]["description"],
            "expires_at": periods["destination_expiry"]["expires_at"],
            "cases": [take(inputs, "paykit-rs", "periods.json", f"$.destination_expiry.cases[{i}]") for i in range(len(periods["destination_expiry"]["cases"]))],
        },
        "record_usability": {
            "description": "When a payer may use a record's public endpoints: strictly before updated_at plus record_max_age (7776000 s when absent) and strictly before a finite expires_at, by the later of the device clock and the highest verified service time, and not at all when updated_at is more than 5 minutes ahead of the device clock.",
            "cases": usability,
        },
    }
    for k in ("zbase32",):
        out[k].pop("description")
    return out


def eval_path(root, path):
    node = root
    for part in path.split("."):
        node = node[part]
    return node


# ---------------------------------------------------------------------------
# requests-lists-receipts

REQUEST_MESSAGES = [
    "payment_request",
    "payment_request_acceptance",
    "payment_request_rejection",
    "payment_request_cancellation",
    "payment_proof",
    "private_payment_list",
    "payment_proof_unrequested",
    "payment_receipt",
    "resend_request",
    "resend_request_ids",
    "private_payment_list_request",
    "resend_request_period",
    "payment_request_labelled",
    "payment_request_acceptance_labelled",
]

ALLOWANCE_MESSAGES = [
    "allowance_proposal",
    "allowance_acceptance",
    "allowance_rejection",
    "allowance_end",
    "executor_notice",
]

# Which certificate (keys.json app) receives each message: the sender's own
# certificate is named by sender_app.
RECIPIENT_APP = {
    "payment_request": "wallet",
    "payment_request_acceptance": "shop",
    "payment_request_rejection": "shop",
    "payment_request_cancellation": "wallet",
    "payment_proof": "shop",
    "private_payment_list": "wallet",
    "payment_proof_unrequested": "shop",
    "payment_receipt": "wallet",
    "resend_request": "shop",
    "resend_request_ids": "wallet",
    "private_payment_list_request": "shop",
    "resend_request_period": "shop",
    "payment_request_labelled": "wallet",
    "payment_request_acceptance_labelled": "hosted",
    "payment_request_recurring": "wallet",
    "payment_period_details": "wallet",
    "payment_proof_period": "shop",
    "payment_request_required_app": "wallet",
    "allowance_proposal": "phone",
    "allowance_acceptance": "shop",
    "allowance_rejection": "shop",
    "allowance_end": "shop",
    "executor_notice": "executor",
}

# Natural keys of wire 1.5, as parts of lp(): (type, value).
NATURAL_KEYS = {
    "payer request record": [["pubky", "bob"], ["b64", "request_hash:payment_request"]],
    "payer record of a payment without a request": [["pubky", "alice"], ["b64", "attempt_id:mAFdg5_0tVNjmrgiTUZW4g"]],
    "payee request record": [["pubky", "bob"], ["b64", "request_hash:payment_request"]],
    "payee record of a payment without a request": [["text", "btc-bitcoin-p2wpkh"], ["settlement_id", "payment_proof_unrequested"]],
    "payment_lists record of the shop app": [["pubky", "bob"], ["app_id", "shop"]],
    "payee request record of the request labelled shop1": [["pubky", "bob"], ["b64", "request_hash:payment_request_labelled"]],
    "settlements bucket of the bitcoin-txid settlement of the payment without a request": [["u64", "bucket"]],
    "shop publication for Alice": [["app_id", "shop"], ["pubky", "alice"], ["u64", 1]],
    "pending Allowance proposal": [["pubky", "bob"], ["text", "d0efffb7-191b-4709-b6c7-e343af5500b4"]],
    "Allowance record": [["pubky", "bob"], ["text", "d0efffb7-191b-4709-b6c7-e343af5500b4"]],
    "Allowance ledger": [["pubky", "bob"], ["text", "d0efffb7-191b-4709-b6c7-e343af5500b4"]],
    "Allowance ledger when bob is the payer": [["pubky", "alice"], ["text", "d0efffb7-191b-4709-b6c7-e343af5500b4"]],
}
REQUEST_RECORD_KEYS = [
    "payer request record",
    "payer record of a payment without a request",
    "payee request record",
    "payee record of a payment without a request",
    "payment_lists record of the shop app",
    "payee request record of the request labelled shop1",
    "settlements bucket of the bitcoin-txid settlement of the payment without a request",
    "shop publication for Alice",
]
ALLOWANCE_RECORD_KEYS = [
    "pending Allowance proposal",
    "Allowance record",
    "Allowance ledger",
    "Allowance ledger when bob is the payer",
]
REQUEST_POLICIES = ["payer_activity", "payee_activity", "payment_lists", "settlements", "payee_activity of a request labelled shop1"]
ALLOWANCE_POLICIES = ["allowance_proposals", "allowances", "allowance_ledgers"]

SETTLEMENT_ID_CASES = [
    ("the vectors' txid", {"type": "bitcoin-txid", "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"}, "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
    ("a vout is not part of it", {"type": "bitcoin-txid", "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", "vout": 1}, "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
    ("upper-case txid", {"type": "bitcoin-txid", "txid": "4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB2127B7AFDEDA33B"}, None),
    ("63 characters", {"type": "bitcoin-txid", "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33"}, None),
    ("65 characters", {"type": "bitcoin-txid", "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0"}, None),
    ("not hex", {"type": "bitcoin-txid", "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33g"}, None),
    ("no txid", {"type": "bitcoin-txid"}, None),
    ("txid not a string", {"type": "bitcoin-txid", "txid": 1}, None),
]


def record_key_cases(inputs, names):
    ids = inputs.load("paykit-rs", "identifiers.json")
    by_name = {c["name"]: i for i, c in enumerate(ids["record_keys"]["cases"])}
    out = []
    for n in names:
        case = bitcoin_only(take(inputs, "paykit-rs", "identifiers.json", f"$.record_keys.cases[{by_name[n]}]"))
        case["natural_key_parts"] = NATURAL_KEYS[n]
        out.append(case)
    return out


def policy_cases(inputs, names):
    ids = inputs.load("paykit-rs", "identifiers.json")
    by_name = {c["name"]: i for i, c in enumerate(ids["policies"]["cases"])}
    return [take(inputs, "paykit-rs", "identifiers.json", f"$.policies.cases[{by_name[n]}]") for n in names]


def message_group(inputs, names, extra=()):
    cases = message_cases(inputs, names) + list(extra)
    for c in cases:
        c["recipient_app"] = RECIPIENT_APP[c["name"]]
    m = inputs.load("paykit-rs", "messages.json")
    description = m["description"].split(" payment_request_labelled")[0]
    if extra:
        description += " " + BITCOIN_FORMS_NOTE
    return {"description": description, "cases": cases}


BITCOIN_FORMS_NOTE = (
    "payment_request_recurring, payment_period_details, payment_proof_period and payment_request_required_app are "
    "the upstream messages of those names written in Bitcoin, since upstream requests them in another asset: each "
    "keeps its upstream envelope and is signed again by its sender, with base naming the upstream message."
)
BITCOIN_FORMS_BASIS = (
    "Paykit wire 4.4, 4.5, 4.9 and 4.10: the upstream message of the same name, its body in Bitcoin and every "
    "other member as upstream; refs name the hashes of the messages here."
)


def base_message(inputs, name):
    m = inputs.load("paykit-rs", "messages.json")
    return m["messages"][messages_by_name(inputs)[name]]


def bitcoin_messages(inputs):
    """The recurring request, its period details and period proof, and a request with fixed rates, in Bitcoin."""
    rec_base = base_message(inputs, "payment_request_recurring")
    body = json.loads(rec_base["json"])["body"]
    del body["conversion"]
    body["amount"] = {"asset": "btc", "value": "0.0001"}
    recurring = resign_message(
        inputs, rec_base, "payment_request_recurring", body, BITCOIN_FORMS_BASIS,
        "Monthly request of 0.0001 btc anchored on January 31; later periods get their destination from period details.",
    )
    det_base = base_message(inputs, "payment_period_details")
    body = json.loads(det_base["json"])["body"]
    del body["rates"]
    details = resign_message(
        inputs, det_base, "payment_period_details", body, BITCOIN_FORMS_BASIS,
        "Destination for the February period (anchor Jan 31, clamped to Feb 28) of payment_request_recurring.",
        refs=[recurring["hash"]],
    )
    proof_base = base_message(inputs, "payment_proof_period")
    proof = resign_message(
        inputs, proof_base, "payment_proof_period", json.loads(proof_base["json"])["body"], BITCOIN_FORMS_BASIS,
        "Payment of the February period by alice's wallet to the period details' destination; refs name the request and the period details it used.",
        refs=[recurring["hash"], details["hash"]],
    )
    fixed_base = base_message(inputs, "payment_request_required_app")
    body = json.loads(fixed_base["json"])["body"]
    body["amount"] = {"asset": "btc", "value": "0.0025"}
    body["conversion"] = {"rates": [{"asset": "btc-lightning", "value": "1.01"}], "type": "fixed"}
    fixed = resign_message(
        inputs, fixed_base, "payment_request_required_app", body, BITCOIN_FORMS_BASIS,
        "A one-time request of 0.0025 btc, payable only to the shop app's Lightning endpoints, at a fixed rate of 1.01 for btc-lightning.",
    )
    return [recurring, details, proof, fixed]


CONVERSION_BASIS = (
    "Paykit wire 4.4 and 4.9 and specs/payment-conversion.md, as paykit-lib reads them: a request with conversion "
    "terms is in an asset of lower-case letters and digits and names identifiers of the form <asset>-<rail>-<format>; "
    "per_period terms only on a recurring request; rates are a non-empty array of rates above zero with unique "
    "selectors, each <asset> or <asset>-<rail> of such segments, matching the asset, and the rail when it names one, of "
    "an identifier the request names. Period details carry payment_endpoints, rates or both; against their request, "
    "the period is one of the request's, rates come only under per_period terms, and no rate is for the requested "
    "asset, bare or rail-qualified."
)


def conversion_cases(inputs, recurring, details, fixed):
    """Requests and period details with conversion terms or rates, in Bitcoin, signed again by the shop."""
    rec_body = json.loads(recurring["json"])["body"]
    det_body = json.loads(details["json"])["body"]
    fixed_body = json.loads(fixed["json"])["body"]
    req_base = base_message(inputs, "payment_request_required_app")
    rec_base = base_message(inputs, "payment_request_recurring")
    det_base = base_message(inputs, "payment_period_details")
    per_period = {"type": "per_period"}

    def request(name, change, base=None):
        body = copy.deepcopy(fixed_body if base is None else rec_body)
        change(body)
        return resign_message(inputs, req_base if base is None else rec_base, name, body, CONVERSION_BASIS, None)

    def rates(*pairs):
        return lambda b: b["conversion"].__setitem__("rates", [{"asset": a, "value": v} for a, v in pairs])

    def amount_asset(a):
        return lambda b: b["amount"].__setitem__("asset", a)

    def put(key, value):
        return lambda b: b.__setitem__(key, value)

    def details_case(name, change, request_conversion=per_period, against=True):
        body = copy.deepcopy(det_body)
        change(body)
        case = resign_message(inputs, det_base, name, body, CONVERSION_BASIS, None, refs=[recurring["hash"]])
        if against:
            case["request"] = "payment_request_recurring"
            case["request_conversion"] = request_conversion
        return case

    def with_rates(*pairs):
        return lambda b: b.__setitem__("rates", [{"asset": a, "value": v} for a, v in pairs])

    def neither(b):
        del b["payment_endpoints"]

    def rates_only(b):
        b["payment_endpoints"] = None
        with_rates(("btc-lightning", "1"))(b)

    future = {"future": "ignored", "type": "per_period"}

    accepted = [
        request("a request with an asset-wide rate", rates(("btc", "1.01"))),
        request("a recurring request with per_period conversion terms", put("conversion", per_period), base="recurring"),
        details_case("period details with payment_endpoints only, against a request with per_period conversion terms", lambda b: None),
        request("per_period conversion terms with a member Paykit v0.2 doesn't define", put("conversion", future), base="recurring"),
        details_case("period details with payment_endpoints and rates null", put("rates", None)),
        details_case(
            "period details with payment_endpoints only, against per_period conversion terms with a member Paykit v0.2 doesn't define",
            lambda b: None,
            future,
        ),
        details_case("period details with rates and payment_endpoints null, at check 10 alone", rates_only, against=False),
    ]
    refused = [
        request("a request with conversion terms in an asset in upper case", amount_asset("BTC")),
        request("a rate selector in upper case", rates(("BTC-lightning", "1.01"))),
        request("a rate selector of three segments", rates(("btc-lightning-bolt11", "1.01"))),
        request("a rate selector with an empty rail", rates(("btc-", "1.01"))),
        request("a rate selector whose rail matches no accepted endpoint", rates(("btc-bitcoin", "1.01"))),
        request("a rate selector twice", rates(("btc-lightning", "1.01"), ("btc-lightning", "1.02"))),
        request("a rate of zero", rates(("btc-lightning", "0"))),
        request("empty rates", rates()),
        request("per_period conversion terms on a one-time request", put("conversion", per_period)),
        request("a conversion type that isn't defined", put("conversion", {"type": "floating"})),
        request(
            "conversion terms beside an identifier not of the form <asset>-<rail>-<format>",
            lambda b: (b.__setitem__("accepted_payment_endpoint_identifiers", ["btc-lightning"]), rates(("btc", "1.01"))(b)),
        ),
        details_case("period details with a bare rate for the requested asset", with_rates(("btc", "1"))),
        details_case("period details with a rail-qualified rate for the requested asset", with_rates(("btc-lightning", "1"))),
        details_case("period details with a rate selector in upper case", with_rates(("BTC", "1"))),
        details_case("period details with rates against a request without conversion terms", with_rates(("btc", "1")), None),
        details_case(
            "period details with rates against a request with fixed conversion terms",
            with_rates(("btc", "1")),
            {"rates": [{"asset": "btc-lightning", "value": "1.01"}], "type": "fixed"},
        ),
        details_case("period details with neither payment_endpoints nor rates", neither),
        details_case("period details with payment_endpoints and rates both null", lambda b: (put("payment_endpoints", None)(b), put("rates", None)(b))),
        details_case("period details with rates and payment_endpoints null, against their request", rates_only),
        details_case(
            "period details naming a period that isn't one of the request's",
            put("billing_period", {"ends_at": "2026-03-31T00:00:00.000Z", "starts_at": "2026-02-27T00:00:00.000Z"}),
        ),
    ]
    return {
        "description": (
            "Requests and period details with conversion terms or rates, each from a message of messages with its body "
            "changed and signed again by the shop. Requests are checked as at check 10. Period details are checked at "
            "check 10 and, where a case names request, against payment_request_recurring of messages with its conversion "
            "terms replaced by request_conversion, or removed where it is null. A member written as null is read as "
            "missing. In a Bitcoin-only series every rate names btc, the "
            "requested asset, so period details with rates are never valid against a request."
        ),
        "accepted": [bitcoin_only(c) for c in accepted],
        "refused": [bitcoin_only(c) for c in refused],
    }


PERIOD_FORM_BASIS = (
    "Paykit wire 4.4 Billing Period, as paykit-lib reads a named period: two times, ends_at after starts_at; a "
    "period whose ends_at is at or before its starts_at is refused at check 10, before any recurrence is consulted."
)


def billing_period_form_cases(inputs, recurring, details, proof):
    equal = {"ends_at": "2026-02-28T00:00:00.000Z", "starts_at": "2026-02-28T00:00:00.000Z"}
    reversed_ = {"ends_at": "2026-02-28T00:00:00.000Z", "starts_at": "2026-03-31T00:00:00.000Z"}
    out = []
    for label, period in (("equal to its starts_at", equal), ("before its starts_at", reversed_)):
        for base, msg, refs in (
            ("payment_proof_period", proof, [recurring["hash"], details["hash"]]),
            ("payment_period_details", details, [recurring["hash"]]),
            ("resend_request_period", base_message(inputs, "resend_request_period"), None),
        ):
            body = json.loads(msg["json"])["body"]
            body["billing_period"] = period
            out.append(resign_message(inputs, base_message(inputs, base), f"{base} with ends_at {label}", body, PERIOD_FORM_BASIS, None, refs=refs))
    return {"description": "Messages naming a Billing Period whose ends_at isn't after its starts_at, signed again by their senders; recipients drop each.", "refused": [bitcoin_only(c) for c in out]}


def requests(inputs):
    pk_doc = inputs.load("paykit-rs", "documents.json")
    pk_enc = inputs.load("paykit-rs", "encoding.json")
    ids = inputs.load("paykit-rs", "identifiers.json")
    periods = inputs.load("paykit-rs", "periods.json")
    msgs = inputs.load("paykit-rs", "messages.json")

    def payee_label_keep(c):
        return c["request"] != "request_recurring" and c["request"] != "payment_request_recurring"

    payee_labels = subgroup(inputs, "paykit-rs", "messages.json", "payee_label_senders", ["accepted", "refused"], keep=payee_label_keep)
    idx = messages_by_name(inputs)
    payee_labels["proof"] = bitcoin_only(take(inputs, "paykit-rs", "messages.json", "$.payee_label_senders.proof"))
    payee_labels["requests"] = {"payment_request_labelled": bitcoin_only(take(inputs, "paykit-rs", "messages.json", f"$.messages[{idx['payment_request_labelled']}]"))}

    obligations = [
        bitcoin_only(take(inputs, "paykit-rs", "identifiers.json", f"$.obligations[{i}]"))
        for i, c in enumerate(ids["obligations"])
        if c["name"] != "recurring request, February period"
    ]
    request_hash = [
        take(inputs, "paykit-rs", "identifiers.json", f"$.request_hash[{i}]")
        for i, c in enumerate(ids["request_hash"])
        if c["message"] != "payment_request_recurring"
    ]
    settlement_ids = [
        {
            "basis": "Paykit wire 1.5 Settlement ID: bitcoin-txid is the txid member, 64 lower-case hex characters, as UTF-8 text",
            "hand_written": True,
            "name": name,
            "proof": proof,
            "settlement_id": sid,
        }
        for name, proof, sid in SETTLEMENT_ID_CASES
    ]

    recurring, details, proof, fixed = bitcoin_messages(inputs)
    return {
        "document": "Requests, Private Payment Lists and Receipts",
        "sources": sources(),
        "notes": NOTES + ["Members added to upstream cases, naming inputs the checker needs: `recipient_app` (messages), `proof` and `requests` (payee_label_senders), `natural_key_parts` (record_keys). Messages signed again here carry `base`, the upstream message they change; period details in conversion_terms carry `request` and `request_conversion`."],
        "keys": keys_group(inputs, with_switch=False),
        "certificates": base_certificates(inputs),
        "payee_certificates": subgroup(inputs, "paykit-rs", "documents.json", "payee_certificates", ["accepted", "refused"]),
        "payer_certificates": subgroup(inputs, "paykit-rs", "documents.json", "payer_certificates", ["accepted", "refused"]),
        "amounts": {
            "description": pk_enc["amounts"].get("description", pk_enc["description"]),
            "valid": [take(inputs, "paykit-rs", "encoding.json", f"$.amounts.valid[{i}]") for i in range(len(pk_enc["amounts"]["valid"]))],
            "invalid": [take(inputs, "paykit-rs", "encoding.json", f"$.amounts.invalid[{i}]") for i in range(len(pk_enc["amounts"]["invalid"]))],
        },
        "request_hashes": {"cases": request_hash},
        "messages": message_group(inputs, REQUEST_MESSAGES, [recurring, details, proof, fixed]),
        "conversion_terms": conversion_cases(inputs, recurring, details, fixed),
        "billing_period_forms": billing_period_form_cases(inputs, recurring, details, proof),
        "label_rejections": subgroup(inputs, "paykit-rs", "messages.json", "label_rejections", ["cases"]),
        "cancellation_roles": subgroup(inputs, "paykit-rs", "messages.json", "cancellation_roles", ["accepted", "refused"]),
        "multi_protocol_senders": subgroup(inputs, "paykit-rs", "messages.json", "multi_protocol_senders", ["accepted", "refused"]),
        "payee_label_senders": payee_labels,
        "proof_members": subgroup(inputs, "paykit-rs", "messages.json", "proof_members", ["refused"]),
        "receipt_members": subgroup(inputs, "paykit-rs", "messages.json", "receipt_members", ["accepted", "refused"]),
        "list_versions": subgroup(inputs, "paykit-rs", "messages.json", "list_versions", ["refused"]),
        "billing_periods": {
            "description": periods["description"],
            "cases": [take(inputs, "paykit-rs", "periods.json", f"$.cases[{i}]") for i in range(len(periods["cases"]))],
        },
        "details_rates": {
            "description": periods["details_rates"]["description"],
            "created_at": periods["details_rates"]["created_at"],
            "expires_at": periods["details_rates"]["expires_at"],
            "cases": [take(inputs, "paykit-rs", "periods.json", f"$.details_rates.cases[{i}]") for i in range(len(periods["details_rates"]["cases"]))],
        },
        "obligations": {"description": ids["description"], "cases": obligations},
        "policies": {
            "description": ids["policies"]["description"] + " The cases are the reference implementation's policy cases for the shared records the document names under Shared records, which give none for private_list_publications; block_floor, the payer's own floor for blocked counterparties, is not among those records.",
            "cases": policy_cases(inputs, REQUEST_POLICIES),
        },
        "record_keys": {
            "description": ids["record_keys"]["description"] + " natural_key_parts names the parts of the natural key's lp() (wire 1.5 Natural keys).",
            "cases": record_key_cases(inputs, REQUEST_RECORD_KEYS),
        },
        "settlement_ids": {"cases": settlement_ids},
    }


# ---------------------------------------------------------------------------
# allowances


def allowances(inputs):
    pk_doc = inputs.load("paykit-rs", "documents.json")
    sigs = inputs.load("paykit-rs", "signatures.json")
    usage = inputs.load("paykit-rs", "allowance_usage.json")
    ids = inputs.load("paykit-rs", "identifiers.json")
    term_hash = take(inputs, "paykit-rs", "identifiers.json", "$.terms_hash")
    return {
        "document": "Allowances",
        "sources": sources(),
        "notes": NOTES + ["Members added to upstream cases, naming inputs the checker needs: `recipient_app` (messages), `natural_key_parts` (record_keys), `name`, `identity`, `counterparty`, `acceptance_message` and `record_key_case` (initial_ledger), `name` (compaction). Messages signed again here carry `base`, the upstream message they change."],
        "keys": keys_group(inputs, with_switch=False),
        "certificates": base_certificates(inputs),
        "executor_certificates": subgroup(inputs, "paykit-rs", "documents.json", "executor_certificates", ["accepted", "refused"]),
        "messages": message_group(inputs, ALLOWANCE_MESSAGES),
        "terms_hash": {"cases": [term_hash]},
        "executor_grant": {
            "description": pk_doc["executor_grant_history_entry"]["description"],
            "cases": [
                {
                    "allowance_id": "d0efffb7-191b-4709-b6c7-e343af5500b4",
                    "counterparty": "bob",
                    "grant": take(inputs, "paykit-rs", "documents.json", "$.executor_grant"),
                    "history_entry": take(inputs, "paykit-rs", "documents.json", "$.executor_grant_history_entry"),
                    "identity": "alice",
                    "name": "the executor's grant at version (1, 12)",
                    "proposal": "allowance_proposal",
                    "acceptance": "allowance_acceptance",
                }
            ],
        },
        "signatures": {
            "description": sigs["description"],
            "cases": [take(inputs, "paykit-rs", "signatures.json", f"$.signatures[{i}]") for i in range(len(sigs["signatures"]))],
        },
        "policies": {"description": ids["policies"]["description"], "cases": policy_cases(inputs, ALLOWANCE_POLICIES)},
        "record_keys": {
            "description": ids["record_keys"]["description"] + " natural_key_parts names the parts of the natural key's lp() (wire 1.5 Natural keys).",
            "cases": record_key_cases(inputs, ALLOWANCE_RECORD_KEYS),
        },
        "period_limit_spellings": subgroup(inputs, "paykit-rs", "allowance_usage.json", "period_limit_spellings", ["accepted", "refused"]),
        "period_limit_members": subgroup(inputs, "paykit-rs", "allowance_usage.json", "period_limit_members", ["refused"]),
        "allowed_identifiers": allowed_identifier_cases(inputs),
        "usage": {
            "description": usage["description"],
            "cases": [bitcoin_only(take(inputs, "paykit-rs", "allowance_usage.json", f"$.cases[{i}]")) for i in range(len(usage["cases"]))],
        },
        "failure_evidence": {
            "cases": [bitcoin_only(take(inputs, "paykit-rs", "allowance_usage.json", f"$.failure_evidence[{i}]")) for i in range(len(usage["failure_evidence"]))],
        },
        "initial_ledger": {
            "cases": [bitcoin_only(initial_ledger_case(inputs))],
        },
        "compaction": {
            "cases": [bitcoin_only(compaction_case(inputs))],
        },
        "ledger_shapes": ledger_shape_cases(inputs),
        "successors": {
            "description": usage["compaction"]["successors"]["description"],
            "cases": [
                bitcoin_only(take(inputs, "paykit-rs", "allowance_usage.json", f"$.compaction.successors.cases[{i}]"))
                for i in range(len(usage["compaction"]["successors"]["cases"]))
            ]
            + [bitcoin_only(c) for c in successor_transition_cases(inputs)],
        },
    }


SUCCESSOR_BASIS = (
    "Paykit wire 5.5 From one version to the next: a held entry without an outcome or failed, once old enough, "
    "leaves into totals.failed with the same obligation and value, or into the totals; every held totals.failed "
    "item is still there unchanged or left into the totals; spent and count grow by at least what left into them."
)


def successor_transition_cases(inputs):
    """Hand-written variants of the first upstream successor case, covering the transitions it doesn't."""
    base = take(inputs, "paykit-rs", "allowance_usage.json", "$.compaction.successors.cases[0]")
    entry = base["held"]["entries"][0]
    failed_item = {"obligation": entry["obligation"], "attempt_id": entry["attempt_id"], "value": entry["value"]}

    def variant(name, accepted, held_entries, held_failed, newer_failed, spent, count):
        held = json.loads(json.dumps(base["held"]))
        newer = json.loads(json.dumps(base["newer"]))
        held["entries"] = held_entries
        if held_failed:
            held["totals"]["failed"] = held_failed
        newer["totals"] = {"count": count, "spent": spent}
        if newer_failed:
            newer["totals"]["failed"] = newer_failed
        return {
            "accepted": accepted,
            "basis": SUCCESSOR_BASIS,
            "hand_written": True,
            "held": held,
            "held_time": base["held_time"],
            "name": name,
            "newer": newer,
            "newer_time": base["newer_time"],
            "terms": base["terms"],
        }

    open_entry = dict(entry, outcome=None)
    failed_entry = dict(entry, outcome="failed")
    return [
        variant("monthly: an entry without an outcome left into totals.failed", True, [open_entry], None, [failed_item], "0.02", 2),
        variant("monthly: an entry without an outcome left into the totals", True, [open_entry], None, None, "0.03", 3),
        variant("monthly: a failed entry left into the totals", True, [failed_entry], None, None, "0.03", 3),
        variant("monthly: a totals.failed item left into the totals", True, [], [failed_item], None, "0.03", 3),
        variant("monthly: a totals.failed item dropped without entering the totals", False, [], [failed_item], None, "0.02", 2),
        variant("monthly: an entry left into totals.failed with another value", False, [open_entry], None, [dict(failed_item, value="0.005")], "0.02", 2),
    ]


ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_BY = 4 * pow(5, ED_P - 2, ED_P) % ED_P
ED_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
ED_B = (ED_BX, ED_BY, 1, ED_BX * ED_BY % ED_P)


def _ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % ED_P
    b = (y1 + x1) * (y2 + x2) % ED_P
    c = 2 * t1 * t2 * ED_D % ED_P
    d = 2 * z1 * z2 % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P)


def _ed_mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_encode(p):
    x, y, z, _ = p
    zi = pow(z, ED_P - 2, ED_P)
    x, y = x * zi % ED_P, y * zi % ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_sign(seed, message):
    """RFC 8032 Ed25519 signing (deterministic), for the hand-written identity documents below."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = _ed_encode(_ed_mul(a, ED_B))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % ED_L
    big_r = _ed_encode(_ed_mul(r, ED_B))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % ED_L
    return big_r + ((r + k * a) % ED_L).to_bytes(32, "little")


def _lp(*parts):
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


B3_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
B3_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
B3_CHUNK_START, B3_CHUNK_END, B3_PARENT, B3_ROOT = 1, 2, 4, 8


def _b3_compress(cv, words, counter, block_len, flags):
    m32 = 0xFFFFFFFF

    def rot(x, n):
        return ((x >> n) | (x << (32 - n))) & m32

    def g(s, a, b, c, d, x, y):
        s[a] = (s[a] + s[b] + x) & m32
        s[d] = rot(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & m32
        s[b] = rot(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b] + y) & m32
        s[d] = rot(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & m32
        s[b] = rot(s[b] ^ s[c], 7)

    s = list(cv) + list(B3_IV[:4]) + [counter & m32, counter >> 32, block_len, flags]
    m = list(words)
    for r in range(7):
        g(s, 0, 4, 8, 12, m[0], m[1])
        g(s, 1, 5, 9, 13, m[2], m[3])
        g(s, 2, 6, 10, 14, m[4], m[5])
        g(s, 3, 7, 11, 15, m[6], m[7])
        g(s, 0, 5, 10, 15, m[8], m[9])
        g(s, 1, 6, 11, 12, m[10], m[11])
        g(s, 2, 7, 8, 13, m[12], m[13])
        g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in B3_PERMUTATION]
    return [s[i] ^ s[i + 8] for i in range(8)]


def _b3_words(block):
    block = block.ljust(64, b"\0")
    return [int.from_bytes(block[i : i + 4], "little") for i in range(0, 64, 4)]


def blake3_hash(data):
    """BLAKE3 with a 32-byte output (the default hash mode), for the message hashes of the hand-written messages."""
    chunks = [data[i : i + 1024] for i in range(0, len(data), 1024)] or [b""]
    stack = []
    for index, chunk in enumerate(chunks):
        cv = B3_IV
        blocks = [chunk[i : i + 64] for i in range(0, len(chunk), 64)] or [b""]
        for j, block in enumerate(blocks):
            flags = B3_CHUNK_START if j == 0 else 0
            if j == len(blocks) - 1:
                out = (cv, _b3_words(block), index, len(block), flags | B3_CHUNK_END)
            else:
                cv = _b3_compress(cv, _b3_words(block), index, 64, flags)
        if index == len(chunks) - 1:
            break
        cv = _b3_compress(*out)
        total = index + 1
        while total & 1 == 0:
            left = stack.pop()
            cv = _b3_compress(B3_IV, left + cv, 0, 64, B3_PARENT)
            total >>= 1
        stack.append(cv)
    while stack:
        out = (B3_IV, stack.pop() + _b3_compress(*out), 0, 64, B3_PARENT)
    cv, words, _, block_len, flags = out
    return b"".join(w.to_bytes(4, "little") for w in _b3_compress(cv, words, 0, block_len, flags | B3_ROOT))


def _sorted_members(v):
    if isinstance(v, dict):
        return {k: _sorted_members(v[k]) for k in sorted(v)}
    if isinstance(v, list):
        return [_sorted_members(x) for x in v]
    return v


def resign_message(inputs, base, name, body, basis, note, refs=None):
    """The upstream message base with body (and refs) replaced, signed again by its sender app: the
    Switch message signature lp("pubky-switch/v1/msg", recipient identity key, message bytes)."""
    head = json.loads(base["json"])
    head["body"] = _sorted_members(body)
    if refs is not None:
        head["refs"] = refs
    raw = json.dumps(head, separators=(",", ":"), ensure_ascii=False).encode()
    keys = inputs.load("paykit-rs", "keys.json")
    app = next(a for a in keys["apps"] if a["app_id"] == base["sender_app"])
    recipient = next(i for i in keys["identities"] if i["pubky_id"] == base["recipient_identity"])
    sig = ed25519_sign(bytes.fromhex(app["signing_secret_hex"]), _lp(b"pubky-switch/v1/msg", bytes.fromhex(recipient["public_hex"]), raw))
    return {
        "base": base["name"],
        "basis": basis,
        "hand_written": True,
        "hash": _b64(blake3_hash(raw)),
        "json": raw.decode(),
        "kind": head["kind"],
        "name": name,
        **({"note": note} if note is not None else {}),
        "plaintext_hex": (bytes.fromhex(app["app_id_bytes_hex"]) + sig + len(raw).to_bytes(4, "big") + raw).hex(),
        "recipient_identity": base["recipient_identity"],
        "sender_app": base["sender_app"],
        "sender_identity": base["sender_identity"],
        "signature": _b64(sig),
    }


IDENTITY_CONSTRAINT_BASIS = (
    "Switch wire 3.3 (inbox.url is the switch origin `https://host[:port]`, no path, no trailing slash; "
    "service_keys entries {generation, key b64(32)}, ascending, each generation once, each below the "
    "document's generation, at most 256, a present [] meaning none; renewed entries {app_id, cert b64(32), "
    "until time or null, always written}) and Switch wire 7.1 Switch origins (no user info, path, query or "
    "fragment; at most 267 ASCII bytes; a domain host at most 253 bytes with labels of at most 63; the host a "
    "domain name, an IPv4 address or a bracketed IPv6 address). Whether an address is globally reachable is "
    "checked when connecting, not here."
)


def identity_constraint_cases(inputs, base_doc):
    """alice's identity.json, changed one member at a time and signed again with her identity key."""
    keys = inputs.load("pubky-switch", "keys.json")
    alice = next(i for i in keys["identities"] if i["name"] == "alice")
    seed = bytes.fromhex(alice["secret_hex"])
    base = json.loads(base_doc["body"])
    key_a = "L6IOM-v3HiTYgBIMYK5KXA6oVE6lcRcBsruRMkqbGjI"
    key_b = _b64(hashlib.sha256(b"paykit-bip/identity-constraints/service-key-b").digest())
    first_app = base["apps"][0]

    def case(name, valid, change):
        body = copy.deepcopy(base)
        change(body)
        body_bytes = json.dumps(body, separators=(",", ":")).encode()
        sig = ed25519_sign(seed, _lp(b"pubky-switch/v1/identity", body_bytes))
        return {
            "basis": IDENTITY_CONSTRAINT_BASIS,
            "body": body_bytes.decode(),
            "hand_written": True,
            "name": name,
            "signed": {"body": _b64(body_bytes), "sig": _b64(sig)},
            "valid": valid,
        }

    def url(u):
        return lambda b: b["inbox"].__setitem__("url", u)

    def gen(g, keys_list):
        def f(b):
            b["generation"] = g
            b["service_keys"] = keys_list
        return f

    def renewed(entries):
        return lambda b: b.__setitem__("renewed", entries)

    long_label = "a" * 64
    long_host = ".".join(["a" * 63] * 4)  # 255 bytes
    return [
        case("inbox.url with a port", True, url("https://inbox.example:8443")),
        case("inbox.url with an IPv4 address", True, url("https://192.0.2.1")),
        case("inbox.url with an IPv6 address and a port", True, url("https://[2001:db8::1]:8443")),
        case("service_keys of two earlier generations", True, gen(3, [{"generation": 1, "key": key_a}, {"generation": 2, "key": key_b}])),
        case("service_keys present and empty", True, gen(1, [])),
        case("renewed with an open and a closed renewal", True, renewed([
            {"app_id": first_app["app_id"], "cert": key_a, "until": None},
            {"app_id": first_app["app_id"], "cert": key_b, "until": "2026-02-01T00:00:00.000Z"},
        ])),
        case("inbox.url with a path", False, url("https://inbox.example/v1")),
        case("inbox.url with a trailing slash", False, url("https://inbox.example/")),
        case("inbox.url over http", False, url("http://inbox.example")),
        case("inbox.url with user info", False, url("https://user@inbox.example")),
        case("inbox.url with a query", False, url("https://inbox.example?a=1")),
        case("inbox.url with a fragment", False, url("https://inbox.example#a")),
        case("inbox.url with a port above 65535", False, url("https://inbox.example:65536")),
        case("inbox.url with a label of 64 bytes", False, url(f"https://{long_label}.example")),
        case("inbox.url with a host of 255 bytes", False, url(f"https://{long_host}")),
        case("inbox.url with a bracketed literal that is no IPv6 address", False, url("https://[.]")),
        case("inbox.url with an IPv6 literal of three colons", False, url("https://[:::]")),
        case("inbox.url with a label starting with a hyphen", False, url("https://-inbox.example")),
        case("inbox.url with a label ending with a hyphen", False, url("https://inbox-.example")),
        case("inbox.url with an IPv4 octet above 255", False, url("https://256.1.1.1")),
        case("service_keys not ascending", False, gen(3, [{"generation": 2, "key": key_b}, {"generation": 1, "key": key_a}])),
        case("service_keys naming a generation twice", False, gen(3, [{"generation": 1, "key": key_a}, {"generation": 1, "key": key_b}])),
        case("service_keys naming the document's generation", False, gen(3, [{"generation": 3, "key": key_a}])),
        case("service_keys of 257 entries", False, gen(300, [{"generation": g, "key": key_a} for g in range(1, 258)])),
        case("service_keys with a 31-byte key", False, gen(3, [{"generation": 1, "key": _b64(bytes(31))}])),
        case("renewed without until", False, renewed([{"app_id": first_app["app_id"], "cert": key_a}])),
        case("renewed with a 31-byte cert hash", False, renewed([{"app_id": first_app["app_id"], "cert": _b64(bytes(31)), "until": None}])),
        case("renewed with an invalid App ID", False, renewed([{"app_id": "w8amtmn13m6p5bwnmj9wejbq4", "cert": key_a, "until": None}])),
        case("renewed with until not a time", False, renewed([{"app_id": first_app["app_id"], "cert": key_a, "until": "2026-02-01"}])),
    ]


ALLOWED_IDENTIFIER_BASIS = (
    "Paykit wire 4.15 allowed_payment_endpoint_identifiers: null, or a non-empty array of unique Payment Endpoint "
    "Identifiers (wire 1.4), each read as one by paykit-lib, so a reserved or malformed identifier makes the terms invalid."
)


def allowed_identifier_cases(inputs):
    """allowance_proposal with its terms' allowed identifiers changed, signed again by the shop."""
    base = base_message(inputs, "allowance_proposal")
    phone = key_app(inputs, "paykit-rs", "phone")

    def case(name, ids):
        body = json.loads(base["json"])["body"]
        body["terms"]["allowed_payment_endpoint_identifiers"] = ids
        c = resign_message(inputs, base, name, body, ALLOWED_IDENTIFIER_BASIS, None)
        c["recipient_app"] = phone["app_id"]
        return bitcoin_only(c)

    return {
        "description": "allowance_proposal of messages with its terms' allowed_payment_endpoint_identifiers changed, signed again by the shop; accepted are proposals alice's phone takes at check 10, refused those it drops.",
        "accepted": [
            case("two identifiers", ["btc-lightning-bolt11", "btc-bitcoin-p2tr"]),
            case("no restriction", None),
        ],
        "refused": [
            case("the reserved identifier ..", [".."]),
            case("the reserved identifier .", ["."]),
            case("the reserved identifier private", ["private"]),
            case("an identifier with a slash", ["btc-lightning/bolt11"]),
            case("an empty identifier", [""]),
            case("an identifier of 65 characters", ["a" * 65]),
            case("an identifier that isn't a string", [1]),
            case("an identifier twice", ["btc-lightning-bolt11", "btc-lightning-bolt11"]),
            case("an empty array", []),
        ],
    }


LEDGER_SHAPE_BASIS = (
    "Paykit wire 5.5 allowance_ledgers, as paykit-lib reads a ledger value: v 1, counterparty a Pubky ID, "
    "allowance_id a UUID, acceptance b64(32); entries, optional, an array of {obligation b64(32), attempt_id b64(16), "
    "value an amount, asset, at a time, outcome done, failed, null or absent}; totals, optional, {spent an amount or "
    "\"\", count an integer, failed, optional, an array of {obligation b64(32), attempt_id b64(16), value an amount}}; "
    "each attempt_id once among the entries and totals.failed, and every entry in the terms' asset."
)


def ledger_shape_cases(inputs):
    """The compaction case's ledger before compaction, changed one member at a time."""
    compaction = take(inputs, "paykit-rs", "allowance_usage.json", "$.compaction")
    base = compaction["before"]
    terms = compaction["terms"]
    item = {"attempt_id": "AAAAAAAAAAAAAAAAAAAAAA", "obligation": base["entries"][0]["obligation"], "value": "0.01"}

    def case(name, change):
        ledger = copy.deepcopy(base)
        change(ledger)
        return {"basis": LEDGER_SHAPE_BASIS, "hand_written": True, "ledger": ledger, "name": name}

    def entry(member, value):
        return lambda l: l["entries"][0].__setitem__(member, value)

    def drop_entry(member):
        return lambda l: l["entries"][0].pop(member)

    def totals(member, value):
        return lambda l: l["totals"].__setitem__(member, value)

    def failed(member, value):
        def f(l):
            l["totals"]["failed"] = [dict(item, **{member: value})]
        return f

    def drop_failed(member):
        def f(l):
            l["totals"]["failed"] = [{k: v for k, v in item.items() if k != member}]
        return f

    def top(member, value):
        return lambda l: l.__setitem__(member, value)

    return {
        "description": "allowance_ledgers values: the compaction case's ledger before compaction (terms are that case's), with one member changed. accepted are ledgers usage and compaction read; refused those they refuse.",
        "terms": terms,
        "accepted": [
            case("the ledger as given", lambda l: None),
            case("an entry without outcome", drop_entry("outcome")),
            case("a totals.failed item", failed("value", "0.01")),
            case("totals.spent empty", totals("spent", "")),
            case("no entries", lambda l: l.pop("entries")),
            case("no totals", lambda l: l.pop("totals")),
        ],
        "refused": [
            case("an obligation of 31 bytes", entry("obligation", _b64(bytes(31)))),
            case("an obligation outside base64url", entry("obligation", "pMucwmH6LXML24Onv5CmiDyOn0b+nMzZnrD4iN3SLB0")),
            case("an attempt_id of 15 bytes", entry("attempt_id", _b64(bytes(15)))),
            case("an outcome other than done or failed", entry("outcome", "pending")),
            case("an entry without value", drop_entry("value")),
            case("an entry without asset", drop_entry("asset")),
            case("an entry without at", drop_entry("at")),
            case("an entry without obligation", drop_entry("obligation")),
            case("an entry that isn't an object", lambda l: l["entries"].__setitem__(0, "entry")),
            case("entries that isn't an array", top("entries", {})),
            case("totals that isn't an object", top("totals", [])),
            case("totals.count as a string", totals("count", "0")),
            case("totals.count negative", totals("count", -1)),
            case("totals without count", lambda l: l["totals"].pop("count")),
            case("totals without spent", lambda l: l["totals"].pop("spent")),
            case("totals.spent not an amount", totals("spent", "0.0.1")),
            case("totals.failed that isn't an array", totals("failed", {})),
            case("a totals.failed item without value", drop_failed("value")),
            case("a totals.failed item with an attempt_id of 15 bytes", failed("attempt_id", _b64(bytes(15)))),
            case("a totals.failed item with an obligation of 33 bytes", failed("obligation", _b64(bytes(33)))),
            case("a totals.failed item repeating an entry's attempt_id", failed("attempt_id", base["entries"][0]["attempt_id"])),
            case("acceptance of 31 bytes", top("acceptance", _b64(bytes(31)))),
            case("a counterparty that isn't a Pubky ID", top("counterparty", "bob")),
            case("an allowance_id that isn't a UUID v4", top("allowance_id", "d0efffb7-191b-3709-b6c7-e343af5500b4")),
            case("v 2", top("v", 2)),
            case("v true", top("v", True)),
            case("v 1.0", top("v", 1.0)),
        ],
    }


def initial_ledger_case(inputs):
    """alice's initial ledger; the allower_proposal variant needs the allowances record format and is left out."""
    case = take(inputs, "paykit-rs", "sealed.json", "$.allowance_initial_ledger")
    del case["allower_proposal"]
    case["refused"] = [take(inputs, "paykit-rs", "sealed.json", f"$.allowance_initial_ledger.refused[{i}]") for i in range(len(case["refused"]))]
    case.update(
        {
            "name": "alice's initial ledger for the Allowance bob proposed",
            "identity": "alice",
            "counterparty": "bob",
            "acceptance_message": "allowance_acceptance",
            "record_key_case": "Allowance ledger",
        }
    )
    return case


def compaction_case(inputs):
    case = take(inputs, "paykit-rs", "allowance_usage.json", "$.compaction")
    del case["successors"]
    case["name"] = "compaction of a monthly-limited ledger in March"
    return case


NOTES = [
    "All hexadecimal is lower case. JSON documents are given as strings; hashes and signatures cover their exact bytes.",
    "Bitcoin only: no case names another asset, the test payment method, or a conversion from another asset.",
    "source names the upstream file and the JSON path of each case; hand_written cases give the rule they follow in basis.",
    "The keys are published test values and must never hold funds.",
]


def sources():
    return {
        "paykit-rs": {"commit": PAYKIT_COMMIT, "path": PAYKIT_DIR, "repository": "https://github.com/pubky/paykit-rs"},
        "pubky-switch": {"commit": SWITCH_COMMIT, "path": SWITCH_DIR, "repository": "https://github.com/pubky/pubky-switch"},
    }


OUTPUTS = {
    "payment-endpoint-discovery/vectors.json": discovery,
    "requests-lists-receipts/vectors.json": requests,
    "allowances/vectors.json": allowances,
}


def render(obj):
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--paykit-rs", required=True)
    ap.add_argument("--pubky-switch", required=True)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "bip"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    inputs = Inputs(args.paykit_rs, args.pubky_switch)
    out = Path(args.out)
    differ = False
    for rel, build in OUTPUTS.items():
        data = render(build(inputs))
        path = out / rel
        if args.check:
            same = path.exists() and path.read_bytes() == data
            print(f"{'same' if same else 'DIFFERS'} {path}")
            differ |= not same
        else:
            path.write_bytes(data)
            print(f"wrote {path} ({len(data)} bytes)")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
