#!/usr/bin/env python3
"""Check the series' test vectors by recomputing every value and verdict.

Usage:
  run_vectors.py [--discovery FILE] [--requests FILE] [--allowances FILE]

By default it reads vectors.json beside this script and the vectors.json of
bip/requests-lists-receipts and bip/allowances. It needs Python 3.9 or later
with `cryptography`, `pynacl` and `blake3`.

Nothing is taken from the files as given: each hash, derivation, signature,
encoding, period and verdict is computed here from the rules of the
documents and the identity service's wire format, and only then compared with
the stored value. Ed25519 verification is the strict procedure of Switch
wire 2.1, implemented below; the libraries serve only to derive keys and to
produce deterministic signatures to compare with the stored ones.

It prints one line per group and exits with status 1 if any check fails.
"""

import argparse
import base64
import calendar
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

import blake3
import nacl.signing
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Reporting


class Report:
    def __init__(self):
        self.rows = []
        self.current = None
        self.failures = []

    def group(self, file, name):
        self.current = {"file": file, "group": name, "checks": 0, "cases": 0, "failed": 0}
        self.rows.append(self.current)

    def case(self):
        self.current["cases"] += 1

    def check(self, cond, what):
        self.current["checks"] += 1
        if not cond:
            self.current["failed"] += 1
            self.failures.append(f"{self.current['file']} {self.current['group']}: {what}")
        return cond

    def equal(self, got, want, what):
        return self.check(got == want, f"{what}: computed {short(got)}, stored {short(want)}")

    def print(self):
        for r in self.rows:
            state = "ok" if r["failed"] == 0 and r["checks"] > 0 else ("NO CHECKS" if r["checks"] == 0 else f"FAILED {r['failed']}")
            print(f"{r['file']:<26} {r['group']:<34} {r['cases']:>4} cases {r['checks']:>5} checks  {state}")
        for f in self.failures:
            print("  " + f)
        bad = sum(1 for r in self.rows if r["failed"] or r["checks"] == 0)
        print(f"{len(self.rows)} groups, {sum(r['cases'] for r in self.rows)} cases, {sum(r['checks'] for r in self.rows)} checks, {len(self.failures)} failures")
        return bad == 0 and not self.failures


def short(v):
    s = repr(v)
    return s if len(s) <= 90 else s[:87] + "..."


R = Report()


class Invalid(Exception):
    pass


def need(cond, why):
    if not cond:
        raise Invalid(why)


def verdict(fn, *args):
    """'valid' or 'invalid: <why>' for a validator that raises Invalid."""
    try:
        fn(*args)
        return "valid"
    except Invalid as e:
        return f"invalid: {e}"


def ok(fn, *args):
    return verdict(fn, *args) == "valid"


# ---------------------------------------------------------------------------
# Encodings (Switch wire 1)

Z32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


def z32(data):
    bits = int.from_bytes(data, "big") if data else 0
    n = len(data) * 8
    out = []
    pad = (-n) % 5
    bits <<= pad
    for i in range((n + pad) // 5 - 1, -1, -1):
        out.append(Z32[(bits >> (5 * i)) & 31])
    return "".join(out)


def unz32(text, nbytes=None):
    need(isinstance(text, str), "z-base-32: not a string")
    count = len(text) * 5 // 8
    need(nbytes is None or count == nbytes, "z-base-32: wrong length")
    need(len(text) == (count * 8 + 4) // 5, "z-base-32: wrong length")
    bits = 0
    for ch in text:
        need(ch in Z32, f"z-base-32: {ch!r} outside the alphabet")
        bits = (bits << 5) | Z32.index(ch)
    extra = len(text) * 5 - count * 8
    need(bits & ((1 << extra) - 1) == 0, "z-base-32: non-zero trailing bits")
    return (bits >> extra).to_bytes(count, "big")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


B64_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def unb64(text, nbytes=None):
    need(isinstance(text, str), "base64url: not a string")
    need(B64_RE.fullmatch(text) is not None, "base64url: character outside the alphabet")
    need(len(text) % 4 != 1, "base64url: impossible length")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    need(b64(data) == text, "base64url: non-zero trailing bits")
    need(nbytes is None or len(data) == nbytes, f"base64url: {len(data)} bytes, not {nbytes}")
    return data


def lp(*parts):
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def u64(n):
    return int(n).to_bytes(8, "big")


def hash32(data):
    return blake3.blake3(data).digest()


def derive(label, *parts):
    return blake3.blake3(lp(*parts), derive_key_context=label).digest()


# Strict JSON (Switch wire 1.1)


class Num:
    def __init__(self, text):
        self.text = text


def _pairs(pairs):
    seen = set()
    for k, _ in pairs:
        need(k not in seen, f"JSON: duplicate member {k!r}")
        seen.add(k)
    return dict(pairs)


def _constant(name):
    raise Invalid(f"JSON: {name} is not JSON")


def strict_json(data, opaque=()):
    """Parse bytes or text strictly. opaque lists member paths (tuples) whose
    numbers are exempt from the integer rule."""
    if isinstance(data, str):
        data = data.encode()
    need(not data.startswith(b"\xef\xbb\xbf"), "JSON: byte order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("JSON: not UTF-8")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=Num, parse_int=Num, parse_constant=_constant)
    except ValueError as e:
        if isinstance(e, json.JSONDecodeError):
            raise Invalid(f"JSON: {e.msg}")
        raise
    return _finish(value, (), opaque)


def _finish(v, path, opaque):
    if isinstance(v, Num):
        if any(path[: len(p)] == p for p in opaque):
            return v.text
        need(re.fullmatch(r"0|[1-9][0-9]*", v.text) is not None, f"JSON: {v.text} isn't an integer of the Switch's range")
        n = int(v.text)
        need(n <= 2**53 - 1, f"JSON: {v.text} is above 2^53 - 1")
        return n
    if isinstance(v, str):
        need(not any(0xD800 <= ord(c) <= 0xDFFF for c in v), "JSON: lone surrogate")
        return v
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            need(not any(0xD800 <= ord(c) <= 0xDFFF for c in k), "JSON: lone surrogate")
            out[k] = _finish(x, path + (k,), opaque)
        return out
    if isinstance(v, list):
        return [_finish(x, path + ("*",), opaque) for x in v]
    return v


# Times (Switch wire 1.6)

TIME_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z")


def time_ms(text):
    need(isinstance(text, str), "time: not a string")
    m = TIME_RE.fullmatch(text)
    need(m is not None, f"time {text!r} doesn't parse")
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    need(y >= 1970, "time before 1970")
    need(1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1], "time: no such date")
    need(h < 24 and mi < 60 and s < 60, "time: no such time of day")
    frac = (m.group(7) or "") + "000"
    return calendar.timegm((y, mo, d, h, mi, s)) * 1000 + int(frac[:3])


def fmt_ms(ms):
    secs, milli = divmod(ms, 1000)
    import time as _t

    return _t.strftime("%Y-%m-%dT%H:%M:%S", _t.gmtime(secs)) + f".{milli:03d}Z"


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def is_uuid4(v):
    return isinstance(v, str) and UUID_RE.fullmatch(v) is not None


def is_int(v, lo=0, hi=2**53 - 1):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def no_control(s):
    return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)


# Amounts (Paykit wire 1.2)

AMOUNT_RE = re.compile(r"^(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)$")
SCALE = 10**18


def amount(text):
    need(isinstance(text, str), "amount: not a string")
    need(AMOUNT_RE.fullmatch(text) is not None, f"amount {text!r}: not of the grammar")
    whole, _, frac = text.partition(".")
    need(len(frac) <= 18, f"amount {text!r}: more than 18 fraction digits")
    value = int(whole or "0") * SCALE + int((frac + "0" * 18)[:18] or "0")
    need(value < 2**128, f"amount {text!r}: too large")
    return value


def normalized(value):
    whole, frac = divmod(value, SCALE)
    frac_text = f"{frac:018d}".rstrip("0")
    return f"{whole}.{frac_text}" if frac_text else str(whole)


# ---------------------------------------------------------------------------
# Ed25519, verified as Switch wire 2.1 spells out

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def decode_point(b, strict=True):
    """A point in extended coordinates, or None. strict refuses y >= p."""
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        if strict:
            return None
        y -= P
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def encode_point(pt):
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")


def point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


IDENTITY = (0, 1, 1, 0)


def point_mul(k, pt):
    q = IDENTITY
    while k:
        if k & 1:
            q = point_add(q, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return q


def point_neg(pt):
    x, y, z, t = pt
    return (-x % P, y, z, -t % P)


def is_identity(pt):
    x, y, z, _ = pt
    return x % P == 0 and (y - z) % P == 0


_BY = 4 * pow(5, P - 2, P) % P
BASE = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % P)


def ed25519_refusal(public, sig, msg):
    """0 if Switch wire 2.1 accepts, else the number of the step that refuses."""
    if len(public) != 32 or len(sig) != 64:
        return 2
    r_bytes, s = sig[:32], int.from_bytes(sig[32:], "little")
    if s >= L:
        return 1
    a = decode_point(public)
    r = decode_point(r_bytes)
    if a is None or r is None or encode_point(a) != public or encode_point(r) != r_bytes:
        return 2
    if is_identity(point_mul(8, a)) or is_identity(point_mul(8, r)):
        return 3
    k = int.from_bytes(hashlib.sha512(r_bytes + public + msg).digest(), "little") % L
    if encode_point(point_add(point_mul(s, BASE), point_neg(point_mul(k, a)))) != r_bytes:
        return 4
    return 0


def ed25519_lenient(public, sig, msg):
    """RFC 8032 verification as a non-strict verifier does it: S reduced, points
    decoded with y reduced mod p, no small-order check, cofactorless."""
    r_bytes, s = sig[:32], int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    a = decode_point(public, strict=False)
    if a is None:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public + msg).digest(), "little") % L
    return encode_point(point_add(point_mul(s, BASE), point_neg(point_mul(k, a)))) == r_bytes


def ed_verify(public, sig, msg):
    return ed25519_refusal(public, sig, msg) == 0


def ed_public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed_sign(seed, msg):
    return nacl.signing.SigningKey(seed).sign(msg).signature


def x25519_low_order(key):
    try:
        X25519PrivateKey.from_private_bytes(b"\x01" * 32).exchange(X25519PublicKey.from_public_bytes(key))
        return False
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Keys


class Keys:
    """Public and secret keys by Pubky ID, App ID and name, from the keys group
    after their derivations are checked."""

    def __init__(self):
        self.identity_secret = {}
        self.identity_name = {}
        self.name_identity = {}
        self.app_secret = {}
        self.app_by_name = {}
        self.naming_key = {}


def check_keys(file, group, report_group=True):
    keys = Keys()
    if report_group:
        R.group(file, "keys")
    for set_name in ("paykit", "switch"):
        part = group.get(set_name)
        if part is None:
            continue
        prefix = part["seed_prefix"]
        for ident in part["identities"]:
            R.case()
            seed = hash32((prefix + ident["seed_label"]).encode())
            R.equal(seed.hex(), ident["secret_hex"], f"{set_name} {ident['name']} secret")
            pub = ed_public(seed)
            R.equal(pub.hex(), ident["public_hex"], f"{set_name} {ident['name']} public key")
            R.equal(z32(pub), ident["pubky_id"], f"{set_name} {ident['name']} Pubky ID")
            root = derive("pubky-switch/v1/scope-root", seed)
            R.equal(root.hex(), ident["switch_root_hex"], f"{set_name} {ident['name']} Switch root")
            naming = derive("pubky-switch/v1/naming", root)
            R.equal(b64(naming), ident["naming_key"], f"{set_name} {ident['name']} naming key")
            keys.identity_secret[z32(pub)] = seed
            keys.naming_key[z32(pub)] = naming
            keys.identity_name[z32(pub)] = (set_name, ident["name"])
            keys.name_identity[(set_name, ident["name"])] = z32(pub)
        for app in part["apps"]:
            R.case()
            seed = hash32((prefix + app["signing_seed_label"]).encode())
            R.equal(seed.hex(), app["signing_secret_hex"], f"{set_name} {app['name']} signing secret")
            pub = ed_public(seed)
            R.equal(b64(pub), app["signing_public"], f"{set_name} {app['name']} signing key")
            app_id = hash32(pub)[:16]
            R.equal(app_id.hex(), app["app_id_bytes_hex"], f"{set_name} {app['name']} App ID bytes")
            R.equal(z32(app_id), app["app_id"], f"{set_name} {app['name']} App ID")
            keys.app_secret[pub] = seed
            keys.app_by_name[(set_name, app["name"])] = {"app_id": z32(app_id), "pub": pub, "identity": app["identity"], "entry": app}
    return keys


def identity_key(text):
    return unz32(text, 32)


# ---------------------------------------------------------------------------
# Certificates (Switch wire 3.1, Paykit wire 3.1)

PERMISSIONS = ["claims.read", "claims.write", "lists.read", "lists.manage", "conversation.add"]
CERT_MEMBERS = {"v", "kind", "identity", "app_id", "signing_key", "bundle_key", "scopes", "permissions", "issued_at", "expires_at", "suite_keys"}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
SUB_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
EXT_PREFIX_RE = re.compile(r"^paykit-[a-z0-9-]{1,25}$")

PAYKIT_SCOPES = {
    "paykit_pay",
    "paykit_request",
    "paykit_settlements",
    "paykit_recovery",
    "paykit_allowance",
    "paykit_allowance_execute",
    "paykit_contacts",
    "paykit_manage_contacts",
}


def check_scope_rule(scopes):
    need(isinstance(scopes, list) and all(isinstance(s, str) for s in scopes), "scopes: not an array of strings")
    need(len(scopes) <= 32, "scopes: more than 32")
    need(len(set(scopes)) == len(scopes), "scopes: a scope twice")
    for s in scopes:
        name, colon, sub = s.partition(":")
        need(NAME_RE.fullmatch(name) is not None, f"{s!r} isn't a scope name")
        need(not colon or SUB_RE.fullmatch(sub) is not None, f"{s!r} isn't a scope name")
    names = {s for s in scopes if ":" not in s}
    for s in scopes:
        if ":" in s:
            need(s.split(":")[0] not in names, f"{s!r} beside its parent")


def check_permission_form(perms):
    need(isinstance(perms, list) and all(isinstance(p, str) for p in perms), "permissions: not an array of strings")
    for p in perms:
        need(p in PERMISSIONS, f"{p!r} isn't a switch permission")
    need(len(set(perms)) == len(perms), "permissions: a name twice")
    need(perms == sorted(perms, key=PERMISSIONS.index), "permissions: out of order")


def switch_cert(signed, identity):
    """The body of a certificate every Switch verifier accepts for identity."""
    need(isinstance(signed, dict) and isinstance(signed.get("body"), str) and isinstance(signed.get("sig"), str), "certificate: not a carrying form")
    body_bytes = unb64(signed["body"])
    sig = unb64(signed["sig"], 64)
    need(ed_verify(identity_key(identity), sig, lp(b"pubky-switch/v1/app-cert", body_bytes)), "certificate: signature")
    body = strict_json(body_bytes)
    need(isinstance(body, dict), "certificate: not an object")
    need(body.get("v") == 1, "certificate: v")
    need(body.get("kind") == "pubky-switch.app_cert", "certificate: kind")
    need(set(body) <= CERT_MEMBERS, f"certificate: unknown member {sorted(set(body) - CERT_MEMBERS)}")
    for m in CERT_MEMBERS - {"suite_keys"}:
        need(m in body, f"certificate: {m} missing")
    need(body["identity"] == identity, "certificate: identity")
    signing = unb64(body["signing_key"], 32)
    need(body["app_id"] == z32(hash32(signing)[:16]), "certificate: app_id isn't the signing key's")
    bundle = unb64(body["bundle_key"], 32)
    need(not x25519_low_order(bundle), "certificate: bundle_key of low order")
    issued = time_ms(body["issued_at"])
    need(body["expires_at"] is not None, "certificate: expires_at null")
    expires = time_ms(body["expires_at"])
    need(issued < expires <= issued + 730 * 86400000, "certificate: expires_at not after issued_at or more than 730 days after")
    if "suite_keys" in body:
        sk = body["suite_keys"]
        need(isinstance(sk, list) and 1 <= len(sk) <= 4, "certificate: suite_keys")
        last = 1
        for e in sk:
            need(isinstance(e, dict) and set(e) == {"suite", "key"}, "certificate: suite key members")
            need(is_int(e["suite"], 2, 255) and e["suite"] > last, "certificate: suite")
            last = e["suite"]
            need(1 <= len(unb64(e["key"])) <= 4096, "certificate: suite key length")
    check_scope_rule(body["scopes"])
    check_permission_form(body["permissions"])
    return body


def paykit_root(scope):
    name = scope.split(":")[0]
    return name == "paykit" or (len(name) > 7 and name[:7] in ("paykit_", "paykit-"))


def paykit_scopes(scopes):
    """The Paykit scopes a certificate holds that Paykit gives a meaning."""
    return [s for s in scopes if s in PAYKIT_SCOPES or is_label_scope(s) or is_ext_scope(s)]


def is_label_scope(s):
    return s.startswith("paykit_request:") and SUB_RE.fullmatch(s.split(":", 1)[1]) is not None


def is_ext_scope(s):
    return s.startswith("paykit_ext:") and EXT_PREFIX_RE.fullmatch(s.split(":", 1)[1]) is not None


def paykit_permissions(scopes):
    known = set(scopes)
    labels = any(is_label_scope(s) for s in scopes)
    exts = any(is_ext_scope(s) for s in scopes)
    grant = {
        "claims.read": bool(known & {"paykit_pay", "paykit_allowance"}),
        "claims.write": "paykit_pay" in known,
        "lists.read": "paykit_contacts" in known,
        "lists.manage": "paykit_manage_contacts" in known,
        "conversation.add": bool(known & {"paykit_pay", "paykit_request", "paykit_allowance"}) or labels or exts,
    }
    return [p for p in PERMISSIONS if grant[p]]


def paykit_cert(body):
    """Paykit's rules on a certificate the switch accepts (Paykit wire 3.1)."""
    scopes = body["scopes"]
    mine = [s for s in scopes if paykit_root(s)]
    exts = [s for s in mine if s.startswith("paykit_ext:")]
    for s in exts:
        need(is_ext_scope(s), f"{s!r} isn't a valid extension scope")
    need(len(exts) <= 8, "more than 8 extension scopes")
    labels = [s for s in mine if s.startswith("paykit_request:")]
    for s in labels:
        need(is_label_scope(s), f"{s!r} isn't a valid label scope")
    need(len(labels) <= 8, "more than 8 labelled selling scopes")
    have = set(mine)

    def requires(scope, *needed):
        if scope in have:
            for n in needed:
                need(n in have, f"{scope} requires {n}")

    requires("paykit_pay", "paykit_contacts")
    requires("paykit_allowance_execute", "paykit_allowance", "paykit_pay", "paykit_contacts")
    requires("paykit_manage_contacts", "paykit_contacts")
    requires("paykit_request", "paykit_settlements", "paykit_contacts")
    for s in labels:
        requires(s, "paykit_settlements", "paykit_contacts")
    derived = paykit_permissions(paykit_scopes(scopes))
    other = any(not paykit_root(s) for s in scopes)
    perms = body["permissions"]
    if other:
        need(all(p in perms for p in derived), "permissions miss what its Paykit scopes need")
    else:
        need(perms == derived, "permissions aren't exactly what its Paykit scopes need")


def full_cert(signed, identity):
    body = switch_cert(signed, identity)
    paykit_cert(body)
    return body


def holds(cert_body, scope):
    """Whether the certificate holds scope under the Switch's hierarchy."""
    scopes = cert_body["scopes"]
    if scope in scopes:
        return True
    return ":" in scope and scope.split(":")[0] in scopes


def cert_verdicts(signed, identity):
    sw = ok(switch_cert, signed, identity)
    pk = sw and ok(lambda: paykit_cert(switch_cert(signed, identity)))
    return sw, pk


def recompute_signature(keys, public, msg, stored_sig, what):
    seed = keys.app_secret.get(public)
    if seed is None:
        for pid, s in keys.identity_secret.items():
            if identity_key(pid) == public:
                seed = s
    if R.check(seed is not None, f"{what}: no secret for the signing key"):
        R.equal(b64(ed_sign(seed, msg)), b64(stored_sig), f"{what}: deterministic signature")


def check_cert_case(keys, case, expect_switch, expect_paykit, what):
    R.case()
    signed = case["signed"]
    body_bytes = unb64(signed["body"])
    if "body" in case:
        R.equal(body_bytes.decode(), case["body"], f"{what}: body text")
    body = json.loads(body_bytes)
    identity = body["identity"]
    sw, pk = cert_verdicts(signed, identity)
    R.equal(sw, expect_switch, f"{what}: Switch verdict ({verdict(switch_cert, signed, identity)})")
    if expect_paykit is not None:
        R.equal(pk, expect_paykit, f"{what}: Paykit verdict ({verdict(lambda: paykit_cert(switch_cert(signed, identity)))})")
    recompute_signature(keys, identity_key(identity), lp(b"pubky-switch/v1/app-cert", body_bytes), unb64(signed["sig"]), what)
    if "paykit_scopes" in case:
        R.equal(paykit_scopes(body["scopes"]), case["paykit_scopes"], f"{what}: Paykit's scopes")
    if "paykit_permissions" in case:
        R.equal(paykit_permissions(paykit_scopes(body["scopes"])), case["paykit_permissions"], f"{what}: Paykit's permissions")
    if "scopes" in case:
        R.equal(body["scopes"], case["scopes"], f"{what}: scopes")
    if "permissions" in case:
        R.equal(body["permissions"], case["permissions"], f"{what}: permissions")
    return body


def check_cert_group(file, name, keys, group, paykit=True):
    R.group(file, name)
    for part in ("cases", "accepted", "refused"):
        for case in group.get(part, []):
            accepted = part != "refused"
            if part == "cases":
                accepted = not ("reason" in case or name.endswith("rejections"))
            expect_switch = case.get("switch_accepts", accepted)
            check_cert_case(keys, case, expect_switch, accepted if paykit else None, f"{part} {case['name']!r}")


def base_certificates(file, keys, group):
    """Check the base certificates and return their bodies by app name."""
    R.group(file, "certificates")
    out = {}
    for case in group["cases"]:
        body = check_cert_case(keys, case, True, True, f"{case['name']!r}")
        app = keys.app_by_name[("paykit", case["app"])]
        R.equal(body["app_id"], app["app_id"], f"{case['name']!r}: App ID")
        R.equal(body["scopes"], app["entry"]["scopes"], f"{case['name']!r}: scopes")
        R.equal(body["permissions"], app["entry"]["permissions"], f"{case['name']!r}: permissions")
        out[case["app"]] = {"body": body, "signed": case["signed"]}
    return out


# ---------------------------------------------------------------------------
# App records (Switch wire 3.2, Paykit wire 3.2)

PEI_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
RECOMMENDED_RE = re.compile(r"^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+$")


def is_pei(v):
    return isinstance(v, str) and PEI_RE.fullmatch(v) is not None and v not in (".", "..", "private")


def switch_app_record(signed, paykit, lookup):
    """A record read under lookup, the identity being resolved and the <app_id> of the path it was read from."""
    need(isinstance(signed, dict) and isinstance(signed.get("body"), str), "record: not a carrying form")
    body_bytes = unb64(signed["body"])
    body = strict_json(body_bytes)
    need(isinstance(body, dict), "record: not an object")
    signing = unb64(body.get("signing_key"), 32)
    need(ed_verify(signing, unb64(signed["sig"], 64), lp(b"pubky-switch/v1/app-record", body_bytes)), "record: signature")
    need(body.get("v") == 1, "record: v")
    need(body.get("kind") == "pubky-switch.app", "record: kind")
    identity = body.get("identity")
    identity_key(identity)
    need(identity == lookup["identity"], "record: identity isn't the identity being resolved")
    need(body.get("app_id") == lookup["app_id"], "record: app_id isn't the <app_id> of the path read")
    cert = (full_cert if paykit else switch_cert)(body.get("cert"), identity)
    need(cert["app_id"] == body.get("app_id"), "record: app_id isn't the certificate's")
    need(cert["signing_key"] == body["signing_key"], "record: signing_key isn't the certificate's")
    need(isinstance(body.get("accepts"), list) and all(isinstance(k, str) for k in body["accepts"]), "record: accepts")
    time_ms(body.get("updated_at"))
    need("expires_at" in body, "record: expires_at missing")
    if body["expires_at"] is not None:
        time_ms(body["expires_at"])
    protocols = body.get("protocols", {})
    need(isinstance(protocols, dict), "record: protocols isn't an object")
    for name, member in protocols.items():
        need(NAME_RE.fullmatch(name) is not None, f"record: protocol name {name!r}")
        need(member is None or isinstance(member, dict), f"record: protocols.{name} isn't an object")
    return body


def paykit_reads(body):
    """What a Paykit reader takes from a record the switch accepts."""
    member = body.get("protocols", {}).get("paykit")
    if member is None:
        return {"endpoint_identifiers": [], "public_endpoints": {}}
    caps = member.get("capabilities")
    need(caps is None or isinstance(caps, dict), "capabilities isn't an object")
    ids = (caps or {}).get("endpoint_identifiers")
    need(ids is None or isinstance(ids, list), "endpoint_identifiers isn't an array")
    ids = ids or []
    for i in ids:
        need(isinstance(i, str), "endpoint_identifiers holds a non-string")
    pub = member.get("public_endpoints")
    need(pub is None or isinstance(pub, dict), "public_endpoints isn't an object")
    pub = pub or {}
    for k, v in pub.items():
        need(isinstance(v, str), "a public endpoint's payload isn't a string")
    for i in ids:
        need(is_pei(i), "an endpoint identifier in capabilities isn't a Payment Endpoint Identifier")
    for k, v in pub.items():
        need(is_pei(k), "a public endpoint's key isn't a Payment Endpoint Identifier")
        need(v != "", "a public endpoint's payload is empty")
    return {"endpoint_identifiers": ids, "public_endpoints": pub}


def paykit_record(signed, lookup):
    return paykit_reads(switch_app_record(signed, True, lookup))


# ---------------------------------------------------------------------------
# identity.json (Switch wire 3.3)


ORIGIN_RE = re.compile(r"https://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?")


def switch_origin(url):
    """Switch wire 3.3 inbox.url and 7.1 Switch origins: exactly https://host[:port], no user info,
    path, query, fragment or trailing slash; at most 267 ASCII bytes; a domain host at most 253 bytes
    with labels of at most 63."""
    need(isinstance(url, str) and url.isascii(), "inbox.url: not an ASCII string")
    need(len(url) <= 267, "inbox.url: longer than 267 bytes")
    m = ORIGIN_RE.fullmatch(url)
    need(m is not None, "inbox.url: not https://host[:port] without user info, path, query or fragment")
    host, port = m.group(1), m.group(2)
    if port is not None:
        need(1 <= int(port) <= 65535, "inbox.url: port out of range")
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise Invalid("inbox.url: not an IPv6 address literal")
        return
    labels = host.split(".")
    if all(label.isdigit() for label in labels):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            raise Invalid("inbox.url: not an IPv4 address literal")
        return
    need(len(host) <= 253, "inbox.url: host longer than 253 bytes")
    need(all(1 <= len(label) <= 63 for label in labels), "inbox.url: empty label or label longer than 63 bytes")
    need(all(not label.startswith("-") and not label.endswith("-") for label in labels), "inbox.url: a label starts or ends with a hyphen")


def identity_document(signed, identity):
    body_bytes = unb64(signed["body"])
    need(ed_verify(identity_key(identity), unb64(signed["sig"], 64), lp(b"pubky-switch/v1/identity", body_bytes)), "identity.json: signature")
    body = strict_json(body_bytes)
    need(isinstance(body, dict), "identity.json: not an object")
    need(body.get("v") == 1 and body.get("kind") == "pubky-switch.identity", "identity.json: v or kind")
    need(body.get("identity") == identity, "identity.json: identity")
    need(is_int(body.get("version"), 1) and is_int(body.get("generation"), 1), "identity.json: version or generation")
    unb64(body.get("signer"), 16)
    inbox = body.get("inbox")
    need(isinstance(inbox, dict), "identity.json: inbox")
    switch_origin(inbox.get("url"))
    unb64(inbox.get("service_key"), 32)
    policy = body.get("policy")
    need(isinstance(policy, dict) and policy.get("admission") == "contacts_and_conversations", "identity.json: policy")
    cr = policy.get("connect_requests")
    need(isinstance(cr, dict), "identity.json: connect_requests")
    for m in ("enabled", "max_pending", "push"):
        need(m in cr, f"identity.json: connect_requests.{m} missing")
    need(isinstance(cr["enabled"], bool) and isinstance(cr["push"], bool) and is_int(cr["max_pending"]), "identity.json: a member has the wrong type or value")
    apps = body.get("apps")
    need(isinstance(apps, list), "identity.json: apps")
    for a in apps:
        need(isinstance(a, dict), "identity.json: apps entry")
        unz32(a.get("app_id"), 16)
        unb64(a.get("cert"), 32)
    removed = body.get("removed")
    need(isinstance(removed, list), "identity.json: removed")
    for a in removed:
        unz32(a.get("app_id"), 16)
        time_ms(a.get("distrust_from"))
    ids = [a["app_id"] for a in apps]
    gone = [a["app_id"] for a in removed]
    need(len(set(ids)) == len(ids) and len(set(gone)) == len(gone) and not set(ids) & set(gone), "identity.json: an App ID twice")
    need(is_int(body.get("data_epoch"), 1), "identity.json: data_epoch")
    need("recovery_from" in body and (body["recovery_from"] is None or is_int(body["recovery_from"])), "identity.json: recovery_from")
    if "record_max_age" in body:
        need(is_int(body["record_max_age"], 1), "identity.json: record_max_age")
    if "service_keys" in body:
        sk = body["service_keys"]
        need(isinstance(sk, list) and len(sk) <= 256, "identity.json: service_keys not an array of at most 256")
        previous = 0
        for e in sk:
            need(isinstance(e, dict) and is_int(e.get("generation"), 1), "identity.json: service_keys generation")
            need(e["generation"] > previous, "identity.json: service_keys not strictly ascending")
            need(e["generation"] < body["generation"], "identity.json: service_keys names a generation not before the document's")
            previous = e["generation"]
            unb64(e.get("key"), 32)
    if "renewed" in body:
        need(isinstance(body["renewed"], list), "identity.json: renewed")
        for e in body["renewed"]:
            need(isinstance(e, dict), "identity.json: renewed entry")
            unz32(e.get("app_id"), 16)
            unb64(e.get("cert"), 32)
            need("until" in e and (e["until"] is None or time_ms(e["until"]) is not None), "identity.json: renewed until")
    return body


# ---------------------------------------------------------------------------
# Messages (Switch wire 4.5, 5.1; Paykit wire 4)


def payment_endpoints(v, what="payment_endpoints"):
    need(isinstance(v, dict) and v, f"{what}: not a non-empty object")
    for k, x in v.items():
        need(is_pei(k), f"{what}: {k!r} isn't a Payment Endpoint Identifier")
        need(isinstance(x, str) and x != "", f"{what}: empty payload")


def amount_object(v, what="amount"):
    need(isinstance(v, dict), f"{what}: not an object")
    amount(v.get("value"))
    a = v.get("asset")
    need(isinstance(a, str) and a and no_control(a), f"{what}: asset")


def billing_period(v):
    need(isinstance(v, dict), "billing_period: not an object")
    need(time_ms(v.get("ends_at")) > time_ms(v.get("starts_at")), "billing_period: ends_at isn't after starts_at")


def list_version(v):
    need(isinstance(v, dict), "list-version: not an object")
    for m in ("generation", "counter"):
        need(m in v, f"{m}: missing")
        need(is_int(v[m], 1), "generation and counter must be positive Switch integers")


def valid_label(v):
    need(isinstance(v, str) and SUB_RE.fullmatch(v) is not None, "label isn't a valid label")


def reference(v):
    need(isinstance(v, str) and 1 <= len(v) <= 256 and no_control(v), "payment_reference: 1 to 256 characters without control characters")


def settlement_id(proof):
    """The settlement ID of a proof object, or None when its method defines none here."""
    if proof.get("type") == "bitcoin-txid":
        t = proof.get("txid")
        need(isinstance(t, str) and re.fullmatch(r"[0-9a-f]{64}", t) is not None, "bitcoin-txid: txid isn't 64 lower-case hex characters")
        return t.encode()
    return None


def body_payment_request(b, refs):
    need(len(refs) == 0, "refs")
    amount_object(b.get("amount"))
    need("payment_reference" in b, "payment_reference: missing")
    reference(b["payment_reference"])
    need("proposal_expires_at" in b, "proposal_expires_at: missing")
    if b["proposal_expires_at"] is not None:
        time_ms(b["proposal_expires_at"])
    rec = b.get("recurrence")
    if rec is not None:
        need(isinstance(rec, dict), "recurrence")
        for m in ("every", "unit", "starts_at", "anchor", "ends_at"):
            need(m in rec, f"recurrence: {m} missing")
        need(is_int(rec["every"], 1) and rec["unit"] in UNITS, "recurrence: every or unit")
        s = time_ms(rec["starts_at"])
        time_ms(rec["anchor"])
        if rec["ends_at"] is not None:
            need(time_ms(rec["ends_at"]) > s, "recurrence: ends_at not after starts_at")
    if "payment_deadline" in b:
        d = b["payment_deadline"]
        need(isinstance(d, dict), "payment_deadline")
        if rec is None:
            need(d.get("type") == "at", "payment_deadline: type")
            time_ms(d.get("timestamp"))
        else:
            need(d.get("type") == "period_start" and is_int(d.get("seconds")), "payment_deadline: type")
    if "payment_endpoints" in b:
        payment_endpoints(b["payment_endpoints"])
        need("required_app_id" not in b, "payment_endpoints and required_app_id")
    if "required_app_id" in b:
        unz32(b["required_app_id"], 16)
    if "per_period_endpoints" in b:
        need(isinstance(b["per_period_endpoints"], bool) and rec is not None, "per_period_endpoints")
    if "label" in b:
        valid_label(b["label"])
    if "accepted_payment_endpoint_identifiers" in b:
        a = b["accepted_payment_endpoint_identifiers"]
        need(isinstance(a, list) and a and len(set(a)) == len(a) and all(is_pei(x) for x in a), "accepted_payment_endpoint_identifiers")
        for k in b.get("payment_endpoints", {}):
            need(k in a, "accepted_payment_endpoint_identifiers misses a key of payment_endpoints")
    if "metadata" in b:
        need(isinstance(b["metadata"], dict), "metadata: not an object")
    if "conversion" in b:
        conversion_terms(b, rec)


SEGMENT_RE = re.compile(r"[a-z0-9]+")


def rates(v, what):
    """Paykit wire 4.4 Rates: a non-empty array of {asset, value}, each asset <asset> or <asset>-<rail> of
    lower-case letters and digits, each value an amount above zero, each asset once."""
    need(isinstance(v, list) and v, f"{what}: rates: not a non-empty array")
    seen = set()
    for r in v:
        need(isinstance(r, dict) and isinstance(r.get("asset"), str), f"{what}: rate: not an object with an asset")
        parts = r["asset"].split("-")
        need(len(parts) in (1, 2) and all(SEGMENT_RE.fullmatch(x) for x in parts), f"{what}: a rate's asset is <asset> or <asset>-<rail>, each segment lower-case letters and digits")
        need(amount(r.get("value")) > 0, f"{what}: a rate is above zero")
        need(r["asset"] not in seen, f"{what}: rates: an asset selector twice")
        seen.add(r["asset"])
    return v


def selectors_match(rate_list, identifiers):
    """Each rate's asset, and its rail when it names one, is that of one of the identifiers, if there are any."""
    for r in rate_list:
        sel = r["asset"].split("-")
        need(not identifiers or any(i.split("-")[: len(sel)] == sel for i in identifiers), "a rate's asset matches no accepted endpoint")


def request_identifiers(b):
    return list(b.get("accepted_payment_endpoint_identifiers", [])) + list(b.get("payment_endpoints", {}))


def conversion_terms(b, rec):
    """Paykit wire 4.4 Conversion, with the constraints of conversion terms (specs/payment-conversion.md)."""
    c = b["conversion"]
    need(isinstance(c, dict), "conversion: not an object")
    if c.get("type") == "fixed":
        rates(c.get("rates"), "conversion")
    else:
        need(c.get("type") == "per_period" and rec is not None, "conversion: type is fixed, or per_period on a recurring request")
    ids = request_identifiers(b)
    need(all(RECOMMENDED_RE.fullmatch(i) for i in ids), "a request with conversion terms uses identifiers <asset>-<rail>-<format>")
    need(SEGMENT_RE.fullmatch(b["amount"]["asset"]) is not None, "a request with conversion terms is in an asset of lower-case letters and digits")
    if c["type"] == "fixed":
        selectors_match(c["rates"], ids)


def body_period_details(b, refs):
    """Paykit wire 4.9, the checks of check 10."""
    need(len(refs) == 1, "refs")
    billing_period(b.get("billing_period"))
    if "payment_endpoints" in b:
        payment_endpoints(b["payment_endpoints"])
    if "rates" in b:
        rates(b["rates"], "payment_period_details")
    need("payment_endpoints" in b or "rates" in b, "period details carry payment_endpoints, rates or both")
    time_ms(b.get("expires_at"))


def named_period(request, bp):
    """Paykit wire 4.4: bp is one of the request's Billing Periods."""
    rec = request.get("recurrence")
    need(rec is not None, "a Billing Period of a one-time request")
    anchor, every, unit = time_ms(rec["anchor"]), rec["every"], rec["unit"]
    k0 = period_at(anchor, every, unit, time_ms(rec["starts_at"]))
    k1 = period_at(anchor, every, unit, time_ms(rec["ends_at"]) - 1) if rec["ends_at"] else None
    s, e = time_ms(bp["starts_at"]), time_ms(bp["ends_at"])
    k = period_at(anchor, every, unit, s)
    need(boundary(anchor, every, unit, k) == s and boundary(anchor, every, unit, k + 1) == e and k >= k0 and (k1 is None or k <= k1), "billing_period isn't one of the request's")


def details_against(details, request):
    """Paykit wire 4.9, the checks that need the request."""
    details, request = present(details), present(request)
    named_period(request, details["billing_period"])
    terms = request.get("conversion")
    need("rates" not in details or (isinstance(terms, dict) and terms.get("type") == "per_period"), "period details carry rates only for a request with per_period conversion terms")
    asset = request["amount"]["asset"]
    need(not any(r["asset"].split("-")[0] == asset for r in details.get("rates", [])), "period details' rates are cross-asset only, with no bare or rail-qualified rate for the requested asset")
    selectors_match(details.get("rates", []), list(details.get("payment_endpoints", {})) + request_identifiers(request))


def body_reply(b, refs, kind):
    need(len(refs) == 1, "refs")
    if kind != "acceptance":
        r = b.get("reason")
        need(r is None or isinstance(r, str), "reason")
    if "label" in b:
        valid_label(b["label"])


def body_proof(b, refs):
    need(len(refs) <= 2, "refs")
    unb64(b.get("attempt_id"), 16)
    need(is_pei(b.get("payment_endpoint_identifier")), "payment_endpoint_identifier")
    unz32(b.get("payment_app_id"), 16)
    need(isinstance(b.get("proof"), dict), "proof: not an object")
    settlement_id(b["proof"])
    if "billing_period" in b:
        billing_period(b["billing_period"])
    if "list_version" in b:
        list_version(b["list_version"])
    if "allowance_id" in b:
        need(is_uuid4(b["allowance_id"]), "allowance_id")
    if "label" in b:
        valid_label(b["label"])
    if "payment_reference" in b:
        reference(b["payment_reference"])
    if refs:
        need("amount" not in b, "payment_proof: amount: only in a proof of a payment without a request")
        if len(refs) == 2:
            need("billing_period" in b, "payment_proof: billing_period: missing")
    else:
        for m in ("billing_period", "label", "payment_reference", "allowance_id"):
            need(m not in b, f"payment_proof: {m}: only in a proof of a request")
        need("amount" in b, "payment_proof: amount: missing")
        amount_object(b["amount"])


def body_receipt(b, refs):
    need(len(refs) in (1, 2), "refs")
    unb64(b.get("attempt_id"), 16)
    if "metadata" in b:
        need(isinstance(b["metadata"], dict), "payment_receipt: metadata: not an object")
    if "billing_period" in b:
        billing_period(b["billing_period"])
        need(len(refs) == 2, "payment_receipt: billing_period: only in a receipt of a request")
    if "payment_reference" in b:
        reference(b["payment_reference"])
        need(len(refs) == 1, "payment_receipt: payment_reference: only in a receipt of a payment without a request")


def body_resend(b, refs):
    need(len(refs) == 0, "refs")
    ids = b.get("msg_ids", [])
    need(isinstance(ids, list) and all(is_uuid4(x) for x in ids), "msg_ids")
    hashes = b.get("request_hashes", [])
    need(isinstance(hashes, list), "request_hashes")
    for h in hashes:
        unb64(h, 32)
    for m in ("accepted_from", "accepted_until"):
        if m in b:
            time_ms(b[m])
    if "billing_period" in b:
        billing_period(b["billing_period"])
    need(ids or hashes or "accepted_from" in b, "resend_request selects nothing")


def body_list(b, refs):
    need(len(refs) == 0, "refs")
    need("version" in b, "version: missing")
    list_version(b["version"])
    eps = b.get("payment_endpoints")
    need(isinstance(eps, dict), "payment_endpoints: not an object")
    for k, e in eps.items():
        need(is_pei(k), "payment_endpoints: identifier")
        need(isinstance(e, dict) and isinstance(e.get("payload"), str) and e["payload"], "payment_endpoints: payload")
        need(isinstance(e.get("single_use", False), bool), "payment_endpoints: single_use")
    need("expires_at" in b, "expires_at: missing")
    time_ms(b["expires_at"])


def body_list_request(b, refs):
    need(len(refs) == 0, "refs")
    need("held_version" in b, "held_version: missing")
    if b["held_version"] is not None:
        list_version(b["held_version"])
    if "app_id" in b:
        unz32(b["app_id"], 16)


UNITS = ("minute", "hour", "day", "week", "month", "year")
FIXED = {"minute": 60_000, "hour": 3_600_000, "day": 86_400_000, "week": 604_800_000}


def allowance_terms(t):
    need(isinstance(t, dict), "terms: not an object")
    for m in ("asset", "per_payment_amount", "period_limits", "lifetime_amount_limit", "active_from", "expires_at", "allowed_payment_endpoint_identifiers"):
        need(m in t, f"terms: {m}: missing")
    need(isinstance(t["asset"], str) and t["asset"] and no_control(t["asset"]), "terms: asset")
    ceiling = False
    pp = t["per_payment_amount"]
    if pp is not None:
        need(isinstance(pp, dict), "terms: per_payment_amount")
        need(amount(pp.get("minimum")) <= amount(pp.get("maximum")), "terms: per_payment_amount minimum above maximum")
        ceiling = True
    limits = t["period_limits"]
    need(isinstance(limits, list), "terms: period_limits")
    seen = set()
    for pl in limits:
        need(isinstance(pl, dict), "terms: period limit")
        need("amount_limit" in pl, "terms: amount_limit: missing; a period limit carries both limits")
        need("payment_count_limit" in pl, "terms: payment_count_limit: missing; a period limit carries both limits")
        a, c = pl["amount_limit"], pl["payment_count_limit"]
        need(not (a is None and c is None), "terms: a period limit with both limits null")
        if a is not None:
            amount(a)
            ceiling = True
        need(c is None or is_int(c), "terms: payment_count_limit")
        per = pl.get("period")
        need(isinstance(per, dict) and is_int(per.get("every"), 1), "terms: period")
        if per.get("kind") == "anchored":
            need(per.get("unit") in UNITS, "terms: period unit")
            time_ms(per.get("anchor"))
            key = (a, c, "anchored", per["every"], per["unit"], per["anchor"])
        else:
            need(per.get("kind") == "rolling" and per.get("unit") in FIXED, "terms: period kind or unit")
            key = (a, c, "rolling", per["every"], per["unit"], None)
        need(key not in seen, "terms: period_limits: an entry twice")
        seen.add(key)
    if t["lifetime_amount_limit"] is not None:
        amount(t["lifetime_amount_limit"])
        ceiling = True
    start = time_ms(t["active_from"]) if t["active_from"] is not None else None
    if t["expires_at"] is not None:
        end = time_ms(t["expires_at"])
        need(start is None or end > start, "terms: expires_at not after active_from")
        ceiling = True
    ids = t["allowed_payment_endpoint_identifiers"]
    if ids is not None:
        need(isinstance(ids, list) and ids and all(is_pei(x) for x in ids) and len(set(ids)) == len(ids), "terms: allowed_payment_endpoint_identifiers: a non-empty array of distinct Payment Endpoint Identifiers")
    need(ceiling, "terms: no monetary ceiling and no expiry")


def body_allowance(b, refs, kind):
    need(is_uuid4(b.get("allowance_id")), "allowance_id isn't a UUID v4")
    if kind == "allowance_proposal":
        need(len(refs) == 0, "refs")
        need(b.get("proposer_role") in ("allower", "allowee"), "proposer_role")
        need(is_int(b.get("allower_generation"), 1), "allower_generation")
        allowance_terms(b.get("terms"))
    else:
        need(len(refs) in ((1, 2) if kind == "allowance_end" else (1,)), "refs")
        if "executor_app_id" in b:
            need(kind == "allowance_acceptance", "executor_app_id outside an acceptance")
            unz32(b["executor_app_id"], 16)


def body_notice(b, refs):
    need(len(refs) == 0, "refs")
    need(b.get("reason") in ("ended", "handed_off"), "executor_notice: reason")
    unb64(b.get("allowance_record"), 32)


ALWAYS_WRITTEN = ("proposal_expires_at", "held_version")


def present(b):
    """b without its null members, which readers treat as missing (Switch wire 1.1), except those a body always writes."""
    need(isinstance(b, dict), "body: not an object")
    return {k: v for k, v in b.items() if v is not None or k in ALWAYS_WRITTEN}


def check_body(kind, b, refs):
    name = kind.split(".", 1)[1] if kind.startswith("paykit.") else None
    need(name is not None, "a kind this recipient doesn't handle")
    b = present(b)
    if name == "payment_request":
        body_payment_request(b, refs)
    elif name == "payment_request_acceptance":
        body_reply(b, refs, "acceptance")
    elif name in ("payment_request_rejection", "payment_request_cancellation"):
        body_reply(b, refs, name)
    elif name == "payment_proof":
        body_proof(b, refs)
    elif name == "payment_receipt":
        body_receipt(b, refs)
    elif name == "payment_period_details":
        body_period_details(b, refs)
    elif name == "resend_request":
        body_resend(b, refs)
    elif name == "private_payment_list":
        body_list(b, refs)
    elif name == "private_payment_list_request":
        body_list_request(b, refs)
    elif name in ("allowance_proposal", "allowance_acceptance", "allowance_rejection", "allowance_end"):
        body_allowance(b, refs, name)
    elif name == "executor_notice":
        body_notice(b, refs)
    else:
        raise Invalid("a kind this recipient doesn't handle")


def selling(cert):
    return holds(cert, "paykit_request") or any(is_label_scope(s) for s in paykit_scopes(cert["scopes"]))


def label_rule(cert, label):
    """A reply with label (or none) may reach an app holding cert."""
    if label is None:
        return "paykit_request" in cert["scopes"]
    return holds(cert, f"paykit_request:{label}")


def check8(kind, b, refs, sender, recipient):
    """Scopes (Switch wire 5.1 check 8, Paykit wire 4.1 and 4.3). recipient may
    be None when the vector gives no recipient certificate."""
    s_has = lambda x: x in paykit_scopes(sender["scopes"])
    r_has = (lambda x: x in paykit_scopes(recipient["scopes"])) if recipient else (lambda x: True)
    label = b.get("label")
    name = kind.split(".", 1)[1]
    if name == "payment_request":
        need(label_rule(sender, label) if label is not None else "paykit_request" in sender["scopes"], "the sender's certificate doesn't hold the request's label")
        need(r_has("paykit_pay"), "the recipient's certificate doesn't receive the kind")
    elif name in ("payment_request_acceptance", "payment_request_rejection", "payment_proof"):
        need(s_has("paykit_pay"), "the sender's certificate holds no scope that sends the kind")
        if recipient:
            need(label_rule(recipient, label), "the reply's label is outside the recipient's certificate")
    elif name == "payment_request_cancellation":
        payer = s_has("paykit_pay") and (recipient is None or label_rule(recipient, label))
        payee = label is None and selling(sender) and r_has("paykit_pay")
        need(payer or payee, "a cancellation's recipient doesn't hold the other role than its sender")
    elif name == "payment_period_details":
        need(selling(sender), "the sender's certificate holds no scope that sends the kind")
        need(r_has("paykit_pay"), "the recipient's certificate doesn't receive the kind")
    elif name == "payment_receipt":
        if len(refs) == 1:
            need("paykit_request" in sender["scopes"], "a receipt naming no request needs paykit_request")
        else:
            need(selling(sender), "the sender's certificate holds no scope that sends the kind")
        need(r_has("paykit_pay"), "the recipient's certificate doesn't receive the kind")
    elif name == "resend_request":
        need(s_has("paykit_contacts"), "the sender's certificate holds no scope that sends the kind")
        if recipient:
            need(bool(paykit_scopes(recipient["scopes"])), "the recipient holds no Paykit scope")
    elif name == "private_payment_list":
        need("paykit_request" in sender["scopes"], "the sender's certificate holds no scope that sends the kind")
        need(r_has("paykit_pay"), "the recipient's certificate doesn't receive the kind")
    elif name == "private_payment_list_request":
        need(s_has("paykit_pay"), "the sender's certificate holds no scope that sends the kind")
        need(recipient is None or "paykit_request" in recipient["scopes"], "the recipient's certificate doesn't receive the kind")
    elif name in ("allowance_proposal", "allowance_acceptance", "allowance_rejection"):
        need(s_has("paykit_allowance") and s_has("paykit_contacts"), "the sender's certificate holds no scope that sends the kind")
        need(r_has("paykit_allowance"), "the recipient's certificate doesn't receive the kind")
    elif name == "allowance_end":
        need(s_has("paykit_allowance"), "the sender's certificate holds no scope that sends the kind")
        need(r_has("paykit_allowance"), "the recipient's certificate doesn't receive the kind")
    elif name == "executor_notice":
        need(s_has("paykit_allowance"), "the sender's certificate holds no scope that sends the kind")
        need(r_has("paykit_allowance_execute"), "the recipient's certificate doesn't receive the kind")
    else:
        raise Invalid("a kind this recipient doesn't handle")


def message(json_text, signature, sender_signed, recipient_identity, recipient_cert):
    """Recipient checks 2 to 10 of Switch wire 5.1, except 3, 7 and 9, which
    need an inbox entry. Returns the parsed message."""
    raw = json_text.encode()
    head = json.loads(raw)
    sender_identity = head["from"]["identity"]
    cert = full_cert(sender_signed, sender_identity)
    sig = unb64(signature, 64)
    need(ed_verify(unb64(cert["signing_key"], 32), sig, lp(b"pubky-switch/v1/msg", identity_key(recipient_identity), raw)), "signature")
    opaque = [("body", "metadata")]
    if head.get("kind") == "paykit.payment_proof":
        opaque.append(("body", "proof"))
    msg = strict_json(raw, opaque=tuple(opaque))
    need(msg.get("v") == 1, "v")
    need(isinstance(msg.get("kind"), str), "kind")
    need(is_uuid4(msg.get("msg_id")), "msg_id")
    time_ms(msg.get("created_at"))
    frm = msg.get("from")
    need(isinstance(frm, dict), "from")
    need(frm.get("app_id") == cert["app_id"] and frm.get("identity") == cert["identity"], "from isn't the certificate's")
    need(msg.get("to") == recipient_identity, "to isn't the recipient")
    refs = msg.get("refs")
    need(isinstance(refs, list), "refs")
    for r in refs:
        unb64(r, 32)
    need(isinstance(msg.get("body"), dict), "body")
    if msg["kind"] == "paykit.executor_notice":
        need(frm["identity"] == recipient_identity, "executor_notice between identities")
    check8(msg["kind"], msg["body"], refs, cert, recipient_cert)
    check_body(msg["kind"], msg["body"], refs)
    return msg


def cert_of(certs, app_id):
    for c in certs.values():
        if c["body"]["app_id"] == app_id:
            return c
    return None


def check_message_group(file, name, keys, certs, group, by_name=None):
    R.group(file, name)
    for case in group["cases"]:
        R.case()
        what = case["name"]
        raw = case["json"].encode()
        head = json.loads(raw)
        sender = cert_of(certs, case["sender_app"])
        recipient = certs[case["recipient_app"]]
        R.equal(head["from"]["app_id"], case["sender_app"], f"{what}: sender App ID")
        R.equal(head["from"]["identity"], case["sender_identity"], f"{what}: sender identity")
        R.equal(head["to"], case["recipient_identity"], f"{what}: recipient identity")
        R.equal(recipient["body"]["identity"], case["recipient_identity"], f"{what}: recipient certificate's identity")
        R.equal(head["kind"], case["kind"], f"{what}: kind")
        R.equal(b64(hash32(raw)), case["hash"], f"{what}: message hash")
        sig = unb64(case["signature"], 64)
        plaintext = unz32(case["sender_app"], 16) + sig + len(raw).to_bytes(4, "big") + raw
        R.equal(plaintext.hex(), case["plaintext_hex"], f"{what}: signed plaintext")
        signed_input = lp(b"pubky-switch/v1/msg", identity_key(case["recipient_identity"]), raw)
        recompute_signature(keys, unb64(sender["body"]["signing_key"]), signed_input, sig, what)
        R.equal(verdict(message, case["json"], case["signature"], sender["signed"], case["recipient_identity"], recipient["body"]), "valid", f"{what}: recipient checks")
        if by_name is not None:
            by_name[what] = case


def rejection_group(file, name, keys, certs, group, msgs, recipient_default=None):
    """Cases a recipient takes (accepted) or drops (refused, cases)."""
    R.group(file, name)
    for part in ("accepted", "refused", "cases"):
        for case in group.get(part, []):
            R.case()
            what = f"{part} {case['name']!r}"
            head = json.loads(case["json"])
            if "sender_cert" in case:
                sender_signed = case["sender_cert"]
            else:
                sender_signed = cert_of(certs, case["sender_app"])["signed"]
            sender_body = json.loads(unb64(sender_signed["body"]))
            R.equal(sender_body["app_id"], case["sender_app"], f"{what}: sender App ID")
            if "recipient_cert" in case:
                recipient = switch_cert(case["recipient_cert"], json.loads(unb64(case["recipient_cert"]["body"]))["identity"])
            elif "recipient_app" in case:
                recipient = cert_of(certs, case["recipient_app"])["body"]
            else:
                recipient = recipient_default(head)
            want = part == "accepted"
            got = verdict(message, case["json"], case["signature"], sender_signed, head["to"], recipient)
            R.equal(got == "valid", want, f"{what}: verdict ({got})")
            recompute_signature(keys, unb64(sender_body["signing_key"]), lp(b"pubky-switch/v1/msg", identity_key(head["to"]), case["json"].encode()), unb64(case["signature"]), what)


# ---------------------------------------------------------------------------
# Billing Periods (Paykit wire 4.4)


def add_months(ms, months):
    secs, milli = divmod(ms, 1000)
    import time as _t

    t = _t.gmtime(secs)
    total = t.tm_year * 12 + (t.tm_mon - 1) + months
    y, m = divmod(total, 12)
    m += 1
    day = min(t.tm_mday, calendar.monthrange(y, m)[1])
    return calendar.timegm((y, m, day, t.tm_hour, t.tm_min, t.tm_sec)) * 1000 + milli


def boundary(anchor, every, unit, k):
    if unit in FIXED:
        return anchor + k * every * FIXED[unit]
    return add_months(anchor, k * every * (12 if unit == "year" else 1))


def period_at(anchor, every, unit, t):
    """The k whose period contains t."""
    if unit in FIXED:
        return (t - anchor) // (every * FIXED[unit])
    step = every * (12 if unit == "year" else 1)
    k = int((t - anchor) // (step * 30.436875 * 86_400_000))
    while boundary(anchor, every, unit, k) > t:
        k -= 1
    while boundary(anchor, every, unit, k + 1) <= t:
        k += 1
    return k


def period_dict(anchor, every, unit, k):
    s, e = boundary(anchor, every, unit, k), boundary(anchor, every, unit, k + 1)
    return {"ends_at": fmt_ms(e), "k": k, "start_secs": s // 1000, "starts_at": fmt_ms(s)}


# ---------------------------------------------------------------------------
# Groups of payment-endpoint-discovery


def pkarr_check(file, rec):
    R.group(file, "pkarr_record")
    R.case()
    secret = bytes.fromhex(rec["identity"]["secret_hex"])
    pub = ed_public(secret)
    R.equal(pub.hex(), rec["identity"]["public_hex"], "identity public key")
    R.equal(z32(pub), rec["identity"]["public"], "identity Pubky ID")
    packet = bytes.fromhex(rec["signed_packet_hex"])
    R.equal(packet[:32], pub, "packet public key")
    sig, ts, dns = packet[32:96], int.from_bytes(packet[96:104], "big"), packet[104:]
    R.equal(ts, rec["timestamp_micros"], "packet timestamp")
    R.equal(dns.hex(), rec["dns_packet_hex"], "packet DNS bytes")
    signable = b"3:seqi%de1:v%d:" % (ts, len(dns)) + dns
    R.equal(signable.hex(), rec["signable_hex"], "signable bytes")
    R.check(ed_verify(pub, sig, signable), "packet signature (Switch wire 2.1 verification)")
    R.equal(ed_sign(secret, signable), sig, "deterministic packet signature")
    try:
        need(dns[:12] == bytes.fromhex("000080000000000100000000"), "DNS header: a response with one answer")
        pos = 12
        labels = []
        while dns[pos]:
            labels.append(dns[pos + 1 : pos + 1 + dns[pos]].decode())
            pos += 1 + dns[pos]
        pos += 1
        rtype, rclass, ttl, rdlen = int.from_bytes(dns[pos : pos + 2], "big"), int.from_bytes(dns[pos + 2 : pos + 4], "big"), int.from_bytes(dns[pos + 4 : pos + 8], "big"), int.from_bytes(dns[pos + 8 : pos + 10], "big")
        rdata = dns[pos + 10 : pos + 10 + rdlen]
        need(pos + 10 + rdlen == len(dns), "DNS: trailing bytes")
        need(labels == ["_pubky", z32(pub)], f"DNS name {labels}")
        need((rtype, rclass, ttl) == (65, 1, 3600), "DNS: an HTTPS record of class IN, TTL 3600")
        need(rdata[:2] == b"\x00\x00", "HTTPS record: alias mode")
        target, p2 = [], 2
        while rdata[p2]:
            target.append(rdata[p2 + 1 : p2 + 1 + rdata[p2]].decode())
            p2 += 1 + rdata[p2]
        need(p2 + 1 == len(rdata), "HTTPS record: trailing bytes")
        need(target == [rec["homeserver_public"]], "HTTPS record: target isn't the homeserver")
        unz32(rec["homeserver_public"], 32)
        R.check(True, "DNS packet")
    except Invalid as e:
        R.check(False, f"DNS packet: {e}")


def encodings(file, v):
    R.group(file, "zbase32")
    for c in v["zbase32"]["valid"]:
        R.case()
        data = bytes.fromhex(c["hex"])
        R.equal(z32(data), c["zbase32"], "encode")
        R.equal(verdict(unz32, c["zbase32"], len(data)), "valid", f"decode {c['zbase32']}")
        if ok(unz32, c["zbase32"]):
            R.equal(unz32(c["zbase32"]), data, "decode")
    for c in v["zbase32"]["invalid"]:
        R.case()
        R.check(not ok(unz32, c["zbase32"], 32), f"refuse {c['zbase32']!r} ({c['why']})")
    R.group(file, "base64url")
    for c in v["base64url"]["valid"]:
        R.case()
        data = bytes.fromhex(c["hex"])
        R.equal(b64(data), c["base64url"], "encode")
        R.equal(verdict(unb64, c["base64url"]), "valid", f"decode {c['base64url']}")
        if ok(unb64, c["base64url"]):
            R.equal(unb64(c["base64url"]), data, "decode")
    for c in v["base64url"]["invalid"]:
        R.case()
        R.check(not ok(unb64, c["base64url"]), f"refuse {c['base64url']!r} ({c['why']})")
    R.group(file, "lp")
    for c in v["lp"]["cases"]:
        R.case()
        R.equal(lp(*(bytes.fromhex(x) for x in c["parts_hex"])).hex(), c["output_hex"], "lp")
    R.group(file, "u64_be")
    for c in v["u64_be"]["cases"]:
        R.case()
        R.equal(u64(int(c["value"])).hex(), c["hex"], f"u64 {c['value']}")
    R.group(file, "derive")
    for c in v["derive"]["cases"]:
        R.case()
        parts = [bytes.fromhex(x) for x in c["parts_hex"]]
        R.equal(lp(*parts).hex(), c["key_material_hex"], "key material")
        R.equal(derive(c["label"], *parts).hex(), c["output_hex"], "derive")
    R.group(file, "rfc3339")
    for c in v["rfc3339"]["format"]:
        R.case()
        R.equal(fmt_ms(c["unix_ms"]), c["text"], "format")
    for c in v["rfc3339"]["parse"]:
        R.case()
        R.equal(verdict(time_ms, c["text"]), "valid", f"parse {c['text']}")
        if ok(time_ms, c["text"]):
            R.equal(time_ms(c["text"]), c["unix_ms"], f"parse {c['text']}")
    for c in v["rfc3339"]["invalid"]:
        R.case()
        R.check(not ok(time_ms, c["text"]), f"refuse {c['text']!r}")
    R.group(file, "json")
    for c in v["json"]["cases"]:
        R.case()
        data = bytes.fromhex(c["json_hex"]) if "json_hex" in c else c["json"].encode()
        R.equal(ok(strict_json, data), c["valid"], f"strict parse {c.get('json', c.get('json_hex'))!r}")


def app_ids(file, group):
    R.group(file, "app_ids")
    for c in group["cases"]:
        R.case()
        digest = hash32(unb64(c["signing_public"], 32))
        if "blake3_hex" in c:
            R.equal(digest.hex(), c["blake3_hex"], f"{c['name']}: BLAKE3")
        if "app_id_bytes_hex" in c:
            R.equal(digest[:16].hex(), c["app_id_bytes_hex"], f"{c['name']}: App ID bytes")
        R.equal(z32(digest[:16]), c["app_id"], f"{c['name']}: App ID")
        R.equal(unz32(c["app_id"], 16), digest[:16], f"{c['name']}: App ID decodes")


def ed25519_group(file, group):
    R.group(file, "ed25519_strict")
    for c in group["accepted"]:
        R.case()
        args = (unb64(c["public_key"]), unb64(c["signature"]), bytes.fromhex(c["signed_bytes_hex"]))
        R.equal(ed25519_refusal(*args), 0, f"accept {c['name']!r}")
        R.check(bytes.fromhex(c["signed_bytes_hex"]).startswith(lp(c["label"].encode())[:4 + len(c["label"])]), f"{c['name']!r}: signed bytes start with the label")
    for c in group["rejections"]:
        R.case()
        args = (unb64(c["public_key"]), unb64(c["signature"]), bytes.fromhex(c["signed_bytes_hex"]))
        R.equal(ed25519_refusal(*args), c["refused_at_step"], f"refuse {c['name']!r} at step")
        R.equal(ed25519_lenient(*args), c["lenient_accepts"], f"{c['name']!r}: non-strict verdict")


def signature_inputs(file, group):
    R.group(file, "signature_inputs")
    for c in group["cases"]:
        R.case()
        fields = [bytes.fromhex(f["hex"]) for f in c["fields"]]
        msg = lp(c["label"].encode(), *fields)
        R.equal(msg.hex(), c["signed_bytes_hex"], f"{c['label']}: signed bytes")
        R.equal(ed25519_refusal(unb64(c["public_key"], 32), unb64(c["signature"], 64), msg), 0, f"{c['label']}: signature")


def signer_key(keys, signer):
    """The public key a Switch document names as its signer."""
    who, _, kind = signer.partition(" ")
    if kind == "identity key":
        return identity_key(keys.name_identity[("switch", who)])
    return keys.app_by_name[("switch", who)]["pub"]


def signed_documents(file, keys, group):
    R.group(file, "signed_documents")
    out = {}
    for c in group["cases"]:
        R.case()
        what = c["name"]
        body = unb64(c["signed"]["body"])
        sig = unb64(c["signed"]["sig"], 64)
        R.equal(body.decode(), c["body"], f"{what}: body")
        R.equal(c["signed"]["body"] + "." + c["signed"]["sig"], c["compact"], f"{what}: compact form")
        doc = lp(body, sig)
        R.equal(doc.hex(), c["doc_bytes_hex"], f"{what}: signed document bytes")
        R.equal(b64(hash32(doc)), c["doc_hash"], f"{what}: document hash")
        R.equal(ed25519_refusal(signer_key(keys, c["signer"]), sig, lp(c["label"].encode(), body)), 0, f"{what}: signature")
        out[what] = c
    return out


def identity_documents(file, keys, group, docs):
    R.group(file, "identity_documents")
    for d in group["documents"]:
        R.case()
        c = docs[d["name"]]
        body = json.loads(c["body"])
        got = verdict(identity_document, c["signed"], body["identity"])
        R.equal(got, "valid", f"{d['name']}: identity.json")
        if got == "valid":
            read = identity_document(c["signed"], body["identity"])
            R.equal(read.get("record_max_age", 7776000), d["record_max_age"], f"{d['name']}: record age limit")
    for item in group["listing"]:
        R.case()
        ident = identity_document(docs[item["identity_document"]]["signed"], json.loads(docs[item["identity_document"]]["body"])["identity"])
        cert_doc = docs[item["certificate"]]
        cert = switch_cert(cert_doc["signed"], ident["identity"])
        doc_hash = b64(hash32(lp(unb64(cert_doc["signed"]["body"]), unb64(cert_doc["signed"]["sig"]))))
        listed = any(a["app_id"] == cert["app_id"] and a["cert"] == doc_hash for a in ident["apps"])
        R.equal(listed, item["listed"], f"{item['identity_document']} lists {item['certificate']}")
    for c in group["rejections"]:
        R.case()
        body = json.loads(c["body"])
        R.equal(unb64(c["signed"]["body"]).decode(), c["body"], f"{c['name']}: body")
        R.check(ed_verify(identity_key(body["identity"]), unb64(c["signed"]["sig"]), lp(b"pubky-switch/v1/identity", unb64(c["signed"]["body"]))), f"{c['name']}: signature verifies")
        R.check(not ok(identity_document, c["signed"], body["identity"]), f"refuse {c['name']!r}")
    for c in group["constraints"]:
        R.case()
        body = json.loads(c["body"])
        R.equal(unb64(c["signed"]["body"]).decode(), c["body"], f"{c['name']}: body")
        R.check(ed_verify(identity_key(body["identity"]), unb64(c["signed"]["sig"]), lp(b"pubky-switch/v1/identity", unb64(c["signed"]["body"]))), f"{c['name']}: signature verifies")
        R.equal(ok(identity_document, c["signed"], body["identity"]), c["valid"], f"{c['name']}: valid")


def app_records(file, keys, group, paykit=True, name="app_records"):
    R.group(file, name)
    for part in ("accepted", "refused", "cases"):
        for c in group.get(part, []):
            R.case()
            what = f"{part} {c['name']!r}"
            signed = c["signed"]
            if "body" in c:
                R.equal(unb64(signed["body"]).decode(), c["body"], f"{what}: body")
            body = json.loads(unb64(signed["body"]))
            lookup = c["lookup"]
            sw = ok(switch_app_record, signed, paykit, lookup)
            if "protocols" in c:
                R.equal(body.get("protocols"), c["protocols"], f"{what}: protocols")
            if "expires_at" in c:
                R.equal(body.get("expires_at"), c["expires_at"], f"{what}: expires_at")
            pub = unb64(body["signing_key"], 32)
            recompute_signature(keys, pub, lp(b"pubky-switch/v1/app-record", unb64(signed["body"])), unb64(signed["sig"]), what)
            if not paykit:
                R.equal(sw, part != "refused", f"{what}: Switch verdict ({verdict(switch_app_record, signed, False, lookup)})")
                continue
            R.equal(sw, c.get("switch_accepts", part != "refused"), f"{what}: Switch verdict ({verdict(switch_app_record, signed, True, lookup)})")
            got = verdict(paykit_record, signed, lookup)
            R.equal(got == "valid", part != "refused", f"{what}: Paykit verdict ({got})")
            if "reads" in c and got == "valid":
                R.equal(paykit_record(signed, lookup), c["reads"], f"{what}: what the reader takes")


def endpoint_identifiers(file, group):
    R.group(file, "endpoint_identifiers")
    for c in group["cases"]:
        R.case()
        R.equal(is_pei(c["identifier"]), c["valid"], f"{c['identifier']!r} valid")
        R.equal(is_pei(c["identifier"]) and RECOMMENDED_RE.fullmatch(c["identifier"]) is not None, c["recommended_form"], f"{c['identifier']!r} recommended form")


def destination_expiry(file, group):
    R.group(file, "destination_expiry")
    exp = time_ms(group["expires_at"])
    for c in group["cases"]:
        R.case()
        now = time_ms(c["device_time"])
        if c["service_time"] is not None:
            now = max(now, time_ms(c["service_time"]))
        R.equal(exp <= now, c["expired"], c["name"])


def record_usability(file, group):
    R.group(file, "record_usability")
    for c in group["cases"]:
        R.case()
        updated = time_ms(c["updated_at"])
        device = time_ms(c["device_time"])
        now = max(device, time_ms(c["service_time"])) if c["service_time"] is not None else device
        limit = updated + 1000 * (c["record_max_age"] or 7776000)
        if c["expires_at"] is not None:
            limit = min(limit, time_ms(c["expires_at"]))
        usable = now < limit and updated <= device + 300_000
        R.equal(usable, c["usable"], c["name"])


def run_discovery(path):
    file = "payment-endpoint-discovery"
    v = load(path)
    keys = check_keys(file, v["keys"])
    pkarr_check(file, v["pkarr_record"])
    encodings(file, v)
    app_ids(file, v["app_ids"])
    ed25519_group(file, v["ed25519_strict"])
    signature_inputs(file, v["signature_inputs"])
    docs = signed_documents(file, keys, v["signed_documents"])
    identity_documents(file, keys, v["identity_documents"], docs)
    base_certificates(file, keys, v["certificates"])
    for g in ("certificate_rejections", "labelled_scope_rejections", "multi_protocol_certificates"):
        check_cert_group(file, g, keys, v[g])
    R.group(file, "extension_certificate")
    for c in v["extension_certificate"]["cases"]:
        check_cert_case(keys, c, True, True, c["name"])
    check_cert_group(file, "switch_scope_rule", keys, v["switch_scope_rule"], paykit=False)
    check_cert_group(file, "switch_permission_rejections", keys, v["switch_permission_rejections"], paykit=False)
    app_records(file, keys, v["app_records"])
    app_records(file, keys, {"accepted": v["extension_app_record"]["cases"]}, name="extension_app_record")
    app_records(file, keys, v["switch_app_record_protocols"], paykit=False, name="switch_app_record_protocols")
    endpoint_identifiers(file, v["endpoint_identifiers"])
    destination_expiry(file, v["destination_expiry"])
    record_usability(file, v["record_usability"])


# ---------------------------------------------------------------------------
# requests-lists-receipts


def amounts(file, group):
    R.group(file, "amounts")
    for c in group["valid"]:
        R.case()
        got = verdict(amount, c["text"])
        R.equal(got, "valid", f"{c['text']!r}")
        if got == "valid":
            R.equal(normalized(amount(c["text"])), c["normalized"], f"{c['text']!r} normalized")
    for c in group["invalid"]:
        R.case()
        R.check(not ok(amount, c["text"]), f"refuse {c['text']!r} ({c['why']})")


def billing_periods(file, group):
    R.group(file, "billing_periods")
    for c in group["cases"]:
        R.case()
        rec = c["recurrence"]
        anchor, every, unit = time_ms(rec["anchor"]), rec["every"], rec["unit"]
        k0 = period_at(anchor, every, unit, time_ms(rec["starts_at"]))
        k1 = period_at(anchor, every, unit, time_ms(rec["ends_at"]) - 1) if rec["ends_at"] else None
        R.equal(period_dict(anchor, every, unit, k0), c["first"], f"{c['name']}: first")
        R.equal(period_dict(anchor, every, unit, k1) if k1 is not None else None, c["last"], f"{c['name']}: last")
        count = (k1 - k0 + 1) if k1 is not None else len(c["periods"])
        R.equal([period_dict(anchor, every, unit, k) for k in range(k0, k0 + count)], c["periods"], f"{c['name']}: periods")
        for lk in c["lookups"]:
            k = period_at(anchor, every, unit, time_ms(lk["t"]))
            inside = k >= k0 and (k1 is None or k <= k1)
            R.equal(period_dict(anchor, every, unit, k) if inside else None, lk["period"], f"{c['name']}: period at {lk['t']}")
        for nm in c["named"]:
            bp = nm["billing_period"]
            s, e = time_ms(bp["starts_at"]), time_ms(bp["ends_at"])
            k = period_at(anchor, every, unit, s)
            valid = boundary(anchor, every, unit, k) == s and boundary(anchor, every, unit, k + 1) == e and k >= k0 and (k1 is None or k <= k1)
            R.equal(valid, nm["valid"], f"{c['name']}: named {bp}")


def details_rates(file, group):
    R.group(file, "details_rates")
    start = time_ms(group["created_at"]) // 1000 * 1000
    end = time_ms(group["expires_at"])
    for c in group["cases"]:
        R.case()
        t = time_ms(c["verified_payment_time"])
        R.equal(start <= t <= end, c["rates_apply"], f"at {c['verified_payment_time']}")


def blind(keys, identity, x):
    return derive("pubky-switch/v1/name", keys.naming_key[identity], x)


def obligations(file, keys, group, msgs):
    R.group(file, "obligations")
    for c in group["cases"]:
        R.case()
        ident = c["identity"]
        if "request_hash" in c:
            req = [m for m in msgs.values() if b64(hash32(m["json"].encode())) == c["request_hash"]]
            R.check(len(req) == 1, f"{c['name']}: the request is a message of this file")
            payee = blind(keys, ident, identity_key(c["payee"]))
            rh = blind(keys, ident, unb64(c["request_hash"], 32))
            R.equal(b64(payee), c["blinded_payee"], f"{c['name']}: blinded payee")
            R.equal(b64(rh), c["blinded_request_hash"], f"{c['name']}: blinded request hash")
            material = lp(b"request", payee, rh, u64(c["period_start_secs"]))
        else:
            att = blind(keys, ident, unb64(c["attempt_id"], 16))
            R.equal(b64(att), c["blinded_attempt_id"], f"{c['name']}: blinded attempt ID")
            material = lp(b"payment", att)
        R.equal(material.hex(), c["key_material_hex"], f"{c['name']}: key material")
        R.equal(b64(blake3.blake3(material, derive_key_context="paykit/v1/obligation").digest()), c["obligation"], f"{c['name']}: obligation")


def policy_hash(read, writes, permanent=None):
    writes = sorted(w.encode() for w in writes)
    if permanent is None:
        return lp(b"pubky-switch/v1/policy", read.encode(), u64(len(writes)), *writes)
    gen = permanent.get("generation") or 0
    return lp(b"pubky-switch/v1/permanent-policy", read.encode(), u64(len(writes)), *writes, u64(gen))


def policies(file, group):
    R.group(file, "policies")
    out = {}
    for c in group["cases"]:
        R.case()
        material = policy_hash(c["read_scope"], c["write_scopes"], c.get("permanent"))
        R.equal(material.hex(), c["hashed_bytes_hex"], f"{c['name']}: hashed bytes")
        R.equal(b64(hash32(material)), c["policy_hash"], f"{c['name']}: policy hash")
        out[c["name"]] = b64(hash32(material))
    return out


def settlement_tag(keys, identity, sid):
    tag_input = lp(sid)
    blinded = blind(keys, identity, tag_input)
    tag = blake3.blake3(lp(b"tag", blinded), derive_key_context="paykit/v1/settlement").digest()
    return tag_input, blinded, tag, int.from_bytes(tag[:2], "big") >> 6


def record_keys(file, keys, group, pol, msgs, apps):
    R.group(file, "record_keys")
    computed = {}
    record_key_of = {}
    for c in group["cases"]:
        R.case()
        what = c["name"]
        ident = c["identity"]
        extra = {}
        parts = []
        for kind, val in c["natural_key_parts"]:
            if kind == "pubky":
                parts.append(identity_key(keys.name_identity[("paykit", val)]))
            elif kind == "app_id":
                parts.append(unz32(apps[("paykit", val)]["app_id"], 16))
            elif kind == "text":
                parts.append(val.encode())
            elif kind == "u64" and val == "bucket":
                proof = json.loads(msgs["payment_proof_unrequested"]["json"])["body"]["proof"]
                tag_input, blinded, tag, bucket = settlement_tag(keys, ident, settlement_id(proof))
                extra = {"tag_input": tag_input, "blinded": blinded, "tag": tag, "bucket": bucket}
                parts.append(u64(bucket))
            elif kind == "u64":
                parts.append(u64(val))
            elif kind == "settlement_id":
                parts.append(settlement_id(json.loads(msgs[val]["json"])["body"]["proof"]))
            elif kind == "b64" and val.startswith("request_hash:"):
                parts.append(hash32(msgs[val.split(":", 1)[1]]["json"].encode()))
            elif kind == "b64" and val.startswith("attempt_id:"):
                parts.append(unb64(val.split(":", 1)[1], 16))
        natural = lp(*parts)
        R.equal(natural.hex(), c["natural_key_hex"], f"{what}: natural key")
        R.equal(b64(natural), c["natural_key"], f"{what}: natural key text")
        blinded_key = blind(keys, ident, natural)
        R.equal(b64(blinded_key), c["blinded_natural_key"], f"{what}: blinded natural key")
        if "policy" in c:
            p = c["policy"]
            material = policy_hash(p["read_scope"], p["write_scopes"], p.get("permanent"))
            R.equal(material.hex(), c["policy_material_hex"], f"{what}: policy bytes")
            ph = b64(hash32(material))
        elif "labelled" in what:
            ph = pol["payee_activity of a request labelled shop1"]
        else:
            ph = pol[c["collection"]]
        R.equal(ph, c["policy_hash"], f"{what}: policy hash")
        material = lp(c["collection"].encode(), blinded_key, unb64(ph, 32))
        R.equal(material.hex(), c["key_material_hex"], f"{what}: key material")
        record_key_of[what] = b64(derive("pubky-switch/v1/record", c["collection"].encode(), blinded_key, unb64(ph, 32)))
        R.equal(record_key_of[what], c["record_key"], f"{what}: record key")
        computed[what] = natural
        if extra:
            R.equal(extra["tag_input"].hex(), c["settlement_tag_input_hex"], f"{what}: settlement tag input")
            R.equal(b64(extra["blinded"]), c["blinded_settlement_tag_input"], f"{what}: blinded tag input")
            R.equal(extra["tag"].hex(), c["settlement_tag_hex"], f"{what}: settlement tag")
            R.equal(extra["bucket"], c["bucket"], f"{what}: bucket")
            R.equal(extra["tag"][2:14].hex(), c["mark_settlement_tag_hex"], f"{what}: mark")
            occ = computed[c["occurrence"]]
            occ_blind = blind(keys, ident, occ)
            R.equal(b64(occ_blind), c["occurrence_blinded_natural_key"], f"{what}: occurrence blind")
            occ_tag = blake3.blake3(lp(b"occurrence", occ_blind), derive_key_context="paykit/v1/settlement").digest()[:8]
            R.equal(occ_tag.hex(), c["occurrence_tag_hex"], f"{what}: occurrence tag")
            R.equal(settlement_id(json.loads(msgs["payment_proof_unrequested"]["json"])["body"]["proof"]).decode(), c["settlement_id"], f"{what}: settlement ID")
    return record_key_of


def settlement_ids(file, group):
    R.group(file, "settlement_ids")
    for c in group["cases"]:
        R.case()
        got = verdict(settlement_id, c["proof"])
        R.equal(settlement_id(c["proof"]).decode() if got == "valid" else None, c["settlement_id"], c["name"])


def payee_label_senders(file, keys, certs, group):
    """Payee messages about a request: check 8 at the payer, then the authority
    of the sender's certificate over the referenced request (spec 3.4)."""
    R.group(file, "payee_label_senders")
    requests = {}
    for name, m in group["requests"].items():
        requests[name] = m
    proof = group["proof"]
    proof_hash = b64(hash32(proof["json"].encode()))
    for part in ("accepted", "refused"):
        for c in group[part]:
            R.case()
            what = f"{part} {c['name']!r}"
            head = json.loads(c["json"])
            sender_body = json.loads(unb64(c["sender_cert"]["body"]))
            R.equal(sender_scope_of(sender_body), c["sender_scope"], f"{what}: sender scope")
            got = verdict(message, c["json"], c["signature"], c["sender_cert"], head["to"], certs["wallet"]["body"])
            if got == "valid" and c["request"] is not None:
                req = requests[c["request"]]
                rh = b64(hash32(req["json"].encode()))
                refs = head["refs"]
                named = refs[-1] if head["kind"] == "paykit.payment_receipt" else refs[0]
                R.equal(named, rh, f"{what}: names the request")
                label = json.loads(req["json"])["body"].get("label")
                authorized = "paykit_request" in sender_body["scopes"] or (label is not None and f"paykit_request:{label}" in sender_body["scopes"])
                got = "valid" if authorized else "invalid: the sender's certificate holds neither paykit_request nor the label of the request"
            if head["kind"] == "paykit.payment_receipt":
                R.equal(head["refs"][0], proof_hash if c["request"] is not None else head["refs"][0], f"{what}: names the proof")
            R.equal(got == "valid", part == "accepted", f"{what}: verdict ({got})")
            recompute_signature(keys, unb64(sender_body["signing_key"]), lp(b"pubky-switch/v1/msg", identity_key(head["to"]), c["json"].encode()), unb64(c["signature"]), what)


def sender_scope_of(body):
    for s in body["scopes"]:
        if s == "paykit_request" or s.startswith("paykit_request:"):
            return s
    return None


def conversion_group(file, keys, certs, group, msgs):
    """Requests at check 10; period details at check 10 and then against their request (Paykit wire 4.4, 4.9)."""
    R.group(file, "conversion_terms")
    for part in ("accepted", "refused"):
        for c in group[part]:
            R.case()
            what = f"{part} {c['name']!r}"
            raw = c["json"].encode()
            head = json.loads(raw)
            sender = cert_of(certs, c["sender_app"])
            R.equal(b64(hash32(raw)), c["hash"], f"{what}: message hash")
            recompute_signature(keys, unb64(sender["body"]["signing_key"]), lp(b"pubky-switch/v1/msg", identity_key(head["to"]), raw), unb64(c["signature"]), what)
            got = verdict(message, c["json"], c["signature"], sender["signed"], head["to"], certs["wallet"]["body"])
            if got == "valid" and "request" in c:
                request = msgs[c["request"]]
                body = dict(json.loads(request["json"])["body"])
                body.pop("conversion", None)
                if c["request_conversion"] is not None:
                    body["conversion"] = c["request_conversion"]
                R.equal(verdict(check_body, "paykit.payment_request", body, []), "valid", f"{what}: its request")
                R.equal(head["refs"], [request["hash"]], f"{what}: refs name the request")
                got = verdict(details_against, head["body"], body)
            R.equal(got == "valid", part == "accepted", f"{what}: verdict ({got})")


def request_hashes(file, group, msgs):
    R.group(file, "request_hashes")
    for c in group["cases"]:
        R.case()
        R.equal(b64(hash32(msgs[c["message"]]["json"].encode())), c["hash"], c["message"])


def run_requests(path):
    file = "requests-lists-receipts"
    v = load(path)
    keys = check_keys(file, v["keys"])
    certs = base_certificates(file, keys, v["certificates"])
    check_cert_group(file, "payee_certificates", keys, v["payee_certificates"])
    check_cert_group(file, "payer_certificates", keys, v["payer_certificates"])
    amounts(file, v["amounts"])
    msgs = {}
    check_message_group(file, "messages", keys, certs, v["messages"], msgs)
    request_hashes(file, v["request_hashes"], msgs)
    conversion_group(file, keys, certs, v["conversion_terms"], msgs)

    def default_recipient(head):
        return certs["wallet"]["body"] if head["to"] == certs["wallet"]["body"]["identity"] else certs["shop"]["body"]

    for g in ("label_rejections", "cancellation_roles", "multi_protocol_senders", "proof_members", "receipt_members", "list_versions", "billing_period_forms"):
        rejection_group(file, g, keys, certs, v[g], msgs, default_recipient)
    payee_label_senders(file, keys, certs, v["payee_label_senders"])
    billing_periods(file, v["billing_periods"])
    details_rates(file, v["details_rates"])
    obligations(file, keys, v["obligations"], msgs)
    pol = policies(file, v["policies"])
    record_keys(file, keys, v["record_keys"], pol, msgs, keys.app_by_name)
    settlement_ids(file, v["settlement_ids"])


# ---------------------------------------------------------------------------
# allowances


def terms_hash(file, group, msgs):
    R.group(file, "terms_hash")
    for c in group["cases"]:
        R.case()
        material = lp(msgs[c["proposal"]]["json"].encode(), msgs[c["acceptance"]]["json"].encode())
        R.equal(material.hex(), c["key_material_hex"], "key material")
        R.equal(b64(hash32(material)), c["terms_hash"], "terms hash")


def executor_grant(file, keys, group, msgs):
    R.group(file, "executor_grant")
    for c in group["cases"]:
        R.case()
        g = c["grant"]
        h = c["history_entry"]
        R.equal(h["grant"], {k: g[k] for k in g if k != "source"}, "history entry holds the grant")
        identity = keys.name_identity[("paykit", c["identity"])]
        counterparty = keys.name_identity[("paykit", c["counterparty"])]
        got = verdict(full_cert, g["cert"], identity)
        R.equal(got, "valid", f"grant certificate ({got})")
        cert = full_cert(g["cert"], identity)
        R.equal(cert["app_id"], g["app_id"], "certificate names app_id")
        R.check(holds(cert, "paykit_allowance_execute"), "certificate holds paykit_allowance_execute")
        th = hash32(lp(msgs[c["proposal"]]["json"].encode(), msgs[c["acceptance"]]["json"].encode()))
        R.equal(b64(th), g["terms_hash"], "terms hash of the proposal and acceptance")
        proposal = json.loads(msgs[c["proposal"]]["json"])
        R.equal(proposal["body"]["allowance_id"], c["allowance_id"], "allowance_id is the proposal's")
        signed = lp(b"paykit/v1/executor-grant", identity_key(identity), identity_key(counterparty), c["allowance_id"].encode(), th, u64(g["confirmed_generation"]), u64(h["generation"]), u64(h["version"]))
        pub = unb64(cert["signing_key"], 32)
        R.equal(ed25519_refusal(pub, unb64(g["sig"], 64), signed), 0, "grant signature at its history version")
        R.check(ed25519_refusal(pub, unb64(g["sig"], 64), lp(b"paykit/v1/executor-grant", identity_key(identity), identity_key(counterparty), c["allowance_id"].encode(), th, u64(g["confirmed_generation"]), u64(h["generation"]), u64(h["version"] + 1))) != 0, "grant refused at another version")
        recompute_signature(keys, pub, signed, unb64(g["sig"]), "grant")


def paykit_signatures(file, keys, group):
    R.group(file, "signatures")
    for c in group["cases"]:
        R.case()
        fields = [bytes.fromhex(f["hex"]) for f in c["fields"]]
        msg = lp(c["label"].encode(), *fields)
        R.equal(msg.hex(), c["signed_bytes_hex"], f"{c['label']}: signed bytes")
        pub = unb64(c["public_key"], 32)
        R.equal(ed25519_refusal(pub, unb64(c["signature"], 64), msg), 0, f"{c['label']}: signature")
        recompute_signature(keys, pub, msg, unb64(c["signature"]), c["label"])
        names = [f["name"] for f in c["fields"]]
        R.equal(names[:3], ["identity", "counterparty identity", "allowance_id"], f"{c['label']}: field order")


def terms_groups(file, v):
    R.group(file, "period_limit_spellings")
    for part in ("accepted", "refused"):
        for c in v["period_limit_spellings"][part]:
            R.case()
            got = verdict(allowance_terms, c["terms"])
            R.equal(got == "valid", part == "accepted", f"{part} {c['name']!r} ({got})")
    R.group(file, "period_limit_members")
    for c in v["period_limit_members"]["refused"]:
        R.case()
        got = verdict(allowance_terms, c["terms"])
        R.equal(got == "valid", False, f"refused {c['name']!r} ({got})")


def entry_state(entry_outcome, claim, never_dispatched, paid):
    """'spent', 'reserved' or 'released' (Paykit wire 5.5, spec 8.3)."""
    if entry_outcome == "done" or (claim and claim["state"] == "done") or paid:
        return "spent"
    if entry_outcome == "failed" or (claim and claim["state"] == "failed"):
        return "released" if never_dispatched else "spent"
    if claim and claim["state"] in ("open", "unknown"):
        return "reserved"
    return "spent"


def usage(terms, ledger, claims, t, evidence=None, evidence_attempt=None):
    ledger = valid_ledger(terms, ledger)
    claims = {c["attempt_id"]: c for c in claims}
    counts = {"spent": 0, "reserved": 0, "released": 0}
    counted = []
    lifetime = 0
    for e in ledger["entries"]:
        ev = evidence if evidence and e["attempt_id"] == evidence_attempt else {"never_dispatched": False, "paid": False}
        state = entry_state(e["outcome"], claims.get(e["attempt_id"]), ev["never_dispatched"], ev["paid"])
        counts[state] += 1
        if state != "released":
            counted.append(e)
            lifetime += amount(e["value"])
    totals = ledger["totals"]
    lifetime += amount(totals["spent"]) if totals["spent"] != "" else 0
    for f in totals.get("failed", []):
        ev = evidence if evidence and f["attempt_id"] == evidence_attempt else {"never_dispatched": False, "paid": False}
        if entry_state("failed", claims.get(f["attempt_id"]), ev["never_dispatched"], ev["paid"]) != "released":
            lifetime += amount(f["value"])
    tm = time_ms(t)
    periods = []
    for pl in terms["period_limits"]:
        per = pl["period"]
        if per["kind"] == "anchored":
            anchor = time_ms(per["anchor"])
            k = period_at(anchor, per["every"], per["unit"], tm)
            lo, hi = boundary(anchor, per["every"], per["unit"], k), boundary(anchor, per["every"], per["unit"], k + 1)
            inside = [e for e in counted if lo <= time_ms(e["at"]) < hi]
        else:
            length = per["every"] * FIXED[per["unit"]]
            inside = [e for e in counted if tm < time_ms(e["at"]) + 60_000 + length]
        periods.append((sum(amount(e["value"]) for e in inside), len(inside)))
    return counts, lifetime, periods


def candidate(terms, lifetime, periods, value):
    pp = terms["per_payment_amount"]
    if pp is not None and not (amount(pp["minimum"]) <= value <= amount(pp["maximum"])):
        return "per_payment"
    for pl, (amt, cnt) in zip(terms["period_limits"], periods):
        if pl["amount_limit"] is not None and amt + value > amount(pl["amount_limit"]):
            return "period_amount"
        if pl["payment_count_limit"] is not None and cnt + 1 > pl["payment_count_limit"]:
            return "period_count"
    if terms["lifetime_amount_limit"] is not None and lifetime + value > amount(terms["lifetime_amount_limit"]):
        return "lifetime"
    return None


def usage_groups(file, v):
    for gname in ("usage", "failure_evidence"):
        R.group(file, gname)
        for c in v[gname]["cases"]:
            R.case()
            what = c["name"]
            R.equal(verdict(allowance_terms, c["terms"]), "valid", f"{what}: terms")
            counts, lifetime, periods = usage(c["terms"], c["ledger"], c["claims"], c["t"], c.get("evidence"), c.get("attempt_id"))
            want = c["usage"]
            R.equal(normalized(lifetime), want["lifetime"], f"{what}: lifetime")
            R.equal([{"amount": normalized(a), "count": n} for a, n in periods], want["periods"], f"{what}: periods")
            for k in ("spent", "reserved", "released"):
                R.equal(counts[k], want[k], f"{what}: {k}")
            cands = c["candidates"] if "candidates" in c else [c["candidate"]]
            for cand in cands:
                refused = candidate(c["terms"], lifetime, periods, amount(cand["amount"]))
                R.equal(refused is None, cand["allowed"], f"{what}: candidate {cand['amount']}")
                if "refused_by" in cand or (refused and "candidates" in c):
                    R.equal(refused, cand.get("refused_by"), f"{what}: candidate {cand['amount']} refused by")


def initial_ledger(value, counterparty, allowance_id, acceptance):
    """Paykit wire 5.9: the initial ledger names the original signed acceptance."""
    v = strict_json(value)
    need(isinstance(v, dict) and set(v) == {"v", "counterparty", "allowance_id", "acceptance"}, "initial ledger: members")
    need(v["v"] == 1, "initial ledger: v")
    need(v["counterparty"] == counterparty, "initial ledger: counterparty")
    need(v["allowance_id"] == allowance_id, "initial ledger: allowance_id")
    need(isinstance(v["acceptance"], str) and v["acceptance"] == acceptance, "initial ledger: acceptance isn't the original signed acceptance")


def initial_ledger_group(file, keys, group, msgs, record_key_of):
    R.group(file, "initial_ledger")
    for c in group["cases"]:
        R.case()
        what = c["name"]
        counterparty = keys.name_identity[("paykit", c["counterparty"])]
        acc = msgs[c["acceptance_message"]]
        acceptance = b64(hash32(acc["json"].encode()))
        allowance_id = json.loads(acc["json"])["body"]["allowance_id"]
        R.equal(acceptance, c["acceptance"], f"{what}: acceptance hash")
        R.equal(record_key_of[c["record_key_case"]], c["record_key"], f"{what}: record key")
        expected = json.dumps({"v": 1, "counterparty": counterparty, "allowance_id": allowance_id, "acceptance": acceptance}, separators=(",", ":"))
        R.equal(expected, c["value"], f"{what}: initial ledger bytes")
        R.equal(verdict(initial_ledger, c["value"], counterparty, allowance_id, acceptance), "valid", f"{what}: verdict")
        for r in c["refused"]:
            R.equal(verdict(initial_ledger, r["value"], counterparty, allowance_id, acceptance) == "valid", False, f"refused {r['name']!r}")


def longest_period(terms, s):
    """The longest period of the terms' limits at time s (Paykit wire 5.5 Compaction)."""
    longest = 0
    for pl in terms["period_limits"]:
        per = pl["period"]
        if per["kind"] == "anchored":
            anchor = time_ms(per["anchor"])
            k = period_at(anchor, per["every"], per["unit"], s)
            length = boundary(anchor, per["every"], per["unit"], k + 1) - boundary(anchor, per["every"], per["unit"], k)
        else:
            length = per["every"] * FIXED[per["unit"]]
        longest = max(longest, length)
    return longest


def valid_ledger(terms, ledger):
    """Paykit wire 5.5: the ledger value's form and A valid ledger. Returns it with entries, totals and
    outcomes written out where they are absent."""
    need(isinstance(ledger, dict) and is_int(ledger.get("v")) and ledger["v"] == 1, "ledger: v")
    identity_key(ledger.get("counterparty"))
    need(is_uuid4(ledger.get("allowance_id")), "ledger: allowance_id isn't a UUID v4")
    unb64(ledger.get("acceptance"), 32)
    entries = ledger.get("entries")
    entries = [] if entries is None else entries
    need(isinstance(entries, list), "ledger: entries isn't an array")
    out_entries = []
    for e in entries:
        need(isinstance(e, dict), "ledger: an entry isn't an object")
        unb64(e.get("obligation"), 32)
        unb64(e.get("attempt_id"), 16)
        amount(e.get("value"))
        need(isinstance(e.get("asset"), str), "ledger: an entry's asset")
        need(e["asset"] == terms["asset"], "ledger: an entry of another asset")
        time_ms(e.get("at"))
        need(e.get("outcome") in (None, "done", "failed"), "ledger: an outcome other than done or failed")
        out_entries.append(dict(e, outcome=e.get("outcome")))
    totals = ledger.get("totals")
    if totals is None:
        totals = {"count": 0, "spent": ""}
    need(isinstance(totals, dict), "ledger: totals isn't an object")
    need(isinstance(totals.get("spent"), str), "ledger: totals.spent")
    if totals["spent"] != "":
        amount(totals["spent"])
    need(is_int(totals.get("count")), "ledger: totals.count isn't an integer of the Switch's range")
    failed = totals.get("failed")
    failed = [] if failed is None else failed
    need(isinstance(failed, list), "ledger: totals.failed isn't an array")
    for f in failed:
        need(isinstance(f, dict), "ledger: a totals.failed item isn't an object")
        unb64(f.get("obligation"), 32)
        unb64(f.get("attempt_id"), 16)
        amount(f.get("value"))
    ids = [e["attempt_id"] for e in entries] + [f["attempt_id"] for f in failed]
    need(len(ids) == len(set(ids)), "ledger: an attempt_id appears twice")
    return dict(ledger, entries=out_entries, totals=totals)


def compact(terms, ledger, now):
    """The ledger after compaction at service time now."""
    ledger = valid_ledger(terms, ledger)
    keep, spent, count = [], amount(ledger["totals"]["spent"] or "0"), ledger["totals"]["count"]
    failed = [dict(f) for f in ledger["totals"].get("failed", [])]
    horizon = longest_period(terms, now) + 60_000
    for e in ledger["entries"]:
        if e["outcome"] in ("done", "failed") and time_ms(e["at"]) + horizon < now:
            if e["outcome"] == "done":
                spent += amount(e["value"])
                count += 1
            else:
                failed.append({"attempt_id": e["attempt_id"], "obligation": e["obligation"], "value": e["value"]})
        else:
            keep.append(e)
    out = dict(ledger, entries=keep)
    out["totals"] = {"count": count, "spent": normalized(spent)}
    if failed:
        out["totals"]["failed"] = failed
    return out


def compaction_times(terms, held_time, newer_time):
    """Service times from held_time to newer_time at which a compaction is judged: newer_time and the last instant of each
    anchored period ending in between, since the longest period is constant within a period."""
    if held_time > newer_time:
        return [newer_time]
    times = {newer_time}
    for pl in terms["period_limits"]:
        per = pl["period"]
        if per["kind"] != "anchored":
            continue
        anchor = time_ms(per["anchor"])
        for k in range(period_at(anchor, per["every"], per["unit"], held_time) + 1, period_at(anchor, per["every"], per["unit"], newer_time) + 1):
            b = boundary(anchor, per["every"], per["unit"], k)
            if b - 1 >= held_time:
                times.add(b - 1)
    return sorted(times)


def successor_ok(terms, held, held_time, newer, newer_time):
    """Paykit wire 5.5 From one version to the next: does newer count no less than held?"""
    held = valid_ledger(terms, held)
    newer = valid_ledger(terms, newer)
    now = {e["attempt_id"]: e for e in newer["entries"]}
    newer_failed = {f["attempt_id"]: f for f in newer["totals"].get("failed", [])}
    gone_spent, gone_count = 0, 0
    times = compaction_times(terms, held_time, newer_time)
    for e in held["entries"]:
        n = now.get(e["attempt_id"])
        if n is not None:
            if any(n[k] != e[k] for k in ("obligation", "attempt_id", "value", "asset", "at")):
                return False
            if n["outcome"] != e["outcome"] and (e["outcome"], n["outcome"]) not in ((None, "done"), (None, "failed"), ("failed", "done")):
                return False
            continue
        if not any(time_ms(e["at"]) + longest_period(terms, s) + 60_000 < s for s in times):
            return False
        f = newer_failed.get(e["attempt_id"])
        if e["outcome"] != "done" and f is not None:
            if f["obligation"] != e["obligation"] or f["value"] != e["value"]:
                return False
            continue
        # A held done entry leaves into the totals; one without an outcome or failed may
        # also leave into them, since it may have become done between the two versions.
        if f is not None:
            return False
        gone_spent += amount(e["value"])
        gone_count += 1
    for f in held["totals"].get("failed", []):
        g = newer_failed.get(f["attempt_id"])
        if g is not None:
            if g != f:
                return False
            continue
        if f["attempt_id"] in now:
            return False
        gone_spent += amount(f["value"])
        gone_count += 1
    held_spent = amount(held["totals"]["spent"] or "0")
    return amount(newer["totals"]["spent"] or "0") >= held_spent + gone_spent and newer["totals"]["count"] >= held["totals"]["count"] + gone_count


def compaction_groups(file, v):
    R.group(file, "compaction")
    for c in v["compaction"]["cases"]:
        R.case()
        what = c["name"]
        R.equal(verdict(allowance_terms, c["terms"]), "valid", f"{what}: terms")
        now = time_ms(c["now"])
        after = compact(c["terms"], c["before"], now)
        R.equal(after, c["after"], f"{what}: compacted ledger")
        R.equal(after != c["before"], c["changed"], f"{what}: changed")
        for side in ("before", "after"):
            _, lifetime, _ = usage(c["terms"], c[side], c["claims"], c["now"])
            R.equal(normalized(lifetime), c[f"lifetime_{side}"], f"{what}: lifetime {side}")
        R.equal(successor_ok(c["terms"], c["before"], now, after, now), True, f"{what}: the compacted ledger is a successor")
    R.group(file, "ledger_shapes")
    for part in ("accepted", "refused"):
        for c in v["ledger_shapes"][part]:
            R.case()
            got = verdict(valid_ledger, v["ledger_shapes"]["terms"], c["ledger"])
            R.equal(got == "valid", part == "accepted", f"{part} {c['name']!r} ({got})")
    R.group(file, "successors")
    for c in v["successors"]["cases"]:
        R.case()
        got = successor_ok(c["terms"], c["held"], time_ms(c["held_time"]), c["newer"], time_ms(c["newer_time"]))
        R.equal(got, c["accepted"], f"{c['name']!r} accepted")


def run_allowances(path):
    file = "allowances"
    v = load(path)
    keys = check_keys(file, v["keys"])
    certs = base_certificates(file, keys, v["certificates"])
    check_cert_group(file, "executor_certificates", keys, v["executor_certificates"])
    msgs = {}
    check_message_group(file, "messages", keys, certs, v["messages"], msgs)
    terms_hash(file, v["terms_hash"], msgs)
    executor_grant(file, keys, v["executor_grant"], msgs)
    paykit_signatures(file, keys, v["signatures"])
    pol = policies(file, v["policies"])
    record_key_of = record_keys(file, keys, v["record_keys"], pol, msgs, keys.app_by_name)
    initial_ledger_group(file, keys, v["initial_ledger"], msgs, record_key_of)
    terms_groups(file, v)
    rejection_group(file, "allowed_identifiers", keys, certs, v["allowed_identifiers"], msgs)
    usage_groups(file, v)
    compaction_groups(file, v)


def load(path):
    """The vector file, refusing duplicate members and non-JSON constants."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (Invalid, OSError, ValueError) as e:
        sys.exit(f"{path}: {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--discovery", default=str(HERE / "vectors.json"))
    ap.add_argument("--requests", default=str(HERE.parent / "requests-lists-receipts" / "vectors.json"))
    ap.add_argument("--allowances", default=str(HERE.parent / "allowances" / "vectors.json"))
    args = ap.parse_args()
    files = (
        ("payment-endpoint-discovery", run_discovery, args.discovery),
        ("requests-lists-receipts", run_requests, args.requests),
        ("allowances", run_allowances, args.allowances),
    )
    for name, run, path in files:
        try:
            run(path)
        except (Invalid, KeyError, TypeError, ValueError) as e:
            R.group(name, "aborted")
            R.check(False, f"{type(e).__name__}: {e}")
    return 0 if R.print() else 1


if __name__ == "__main__":
    sys.exit(main())
