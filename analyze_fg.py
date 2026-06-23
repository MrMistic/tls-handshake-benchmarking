#!/usr/bin/env python3
"""
Operation-level analysis of handshake flamegraphs.

Reads collapsed-stack files (from stackcollapse-perf.pl), buckets samples into
crypto/protocol operations, and converts CPU shares into absolute
microseconds-per-handshake using each implementation's measured hot-loop mean
(Option 1 from the methodology doc — NOT raw perf wall time).

Usage:
    python3 analyze_fg.py \
        --s2n /tmp/s2n_folded.txt --s2n-mean 606.4 \
        --rustls /tmp/rustls_folded.txt --rustls-mean 609.0
"""
import argparse
import re

# Operation buckets. Each sample is attributed to the FIRST matching bucket,
# based on substrings appearing anywhere in its stack. Order matters: more
# specific patterns first.
BUCKETS = [
    ("RSA sign",          [r"rsa.*sign", r"BN_mod_exp", r"rsa_blinding", r"RSA_sign", r"_rsa_.*priv", r"rsa.*private"]),
    ("RSA verify",        [r"rsa.*verify", r"RSA_verify", r"pkcs1.*verify", r"rsa.*public"]),
    # Bignum modular arithmetic — the core of RSA modexp. These symbols don't
    # contain "rsa" but are dominated by RSA private-key work in a handshake
    # (verified: bn_sqrx8x_internal is the single largest symbol in both libs).
    ("RSA (bignum modexp)",[r"\brsa", r"bn_mul", r"BN_mod", r"montgomery", r"\bmont\b",
                            r"bn_sqr", r"bn_sqrx", r"bn_postx", r"\bmulx\d", r"sqrx8x", r"sqr8x"]),
    # EC field arithmetic (P-256/P-384) used by ECDSA + ECDHE.
    ("ECDSA/EC",          [r"ecdsa", r"EC_POINT", r"ec_GFp", r"\bp256", r"\bp384",
                            r"ecp_nistz", r"nistz256", r"montinv_p256", r"montinv_p384"]),
    ("X25519/ECDHE",      [r"25519", r"curve25519", r"\becdh"]),
    ("ML-KEM/PQ",         [r"kyber", r"mlkem", r"ml_kem", r"pqcrystals"]),
    ("Cert/X509 validate",[r"x509", r"asn1", r"\bder_", r"webpki", r"verify_cert", r"cert.*chain", r"parse.*cert"]),
    ("HKDF/key schedule", [r"hkdf", r"hmac", r"key_schedule", r"derive.*traffic", r"expand_label", r"\bprf\b"]),
    # Tightened: require digit/format context so "handshake", "SharedSecret" don't match.
    ("SHA/hash",          [r"sha256", r"sha512", r"sha384", r"sha1\b", r"sha3", r"sha1_block",
                           r"md5_block", r"md5", r"_md_", r"digest"]),
    ("AES/GCM/AEAD",      [r"\baes", r"_aes", r"\bgcm", r"aead", r"chacha", r"poly1305"]),
    # s2n-specific buffer/blob management layer (no rustls equivalent of
    # comparable cost). Named explicitly so it isn't hidden in "other".
    ("Buffer mgmt (s2n stuffer/blob)", [r"s2n_stuffer", r"s2n_blob", r"s2n_record_", r"s2n_array"]),
    ("RNG",               [r"rdrand", r"rand_bytes", r"CRYPTO_.*rand", r"drbg"]),
    ("alloc/memory",      [r"malloc", r"\bfree\b", r"alloc", r"memcpy", r"memset", r"memmove",
                           r"OPENSSL_free", r"drop_in_place"]),
]


def load(path):
    total = 0
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stack, _, cnt = line.rpartition(" ")
            try:
                cnt = int(cnt)
            except ValueError:
                continue
            total += cnt
            rows.append((stack, cnt))
    return rows, total


def bucketize(rows):
    counts = {name: 0 for name, _ in BUCKETS}
    counts["other"] = 0
    pats = [(name, [re.compile(p, re.IGNORECASE) for p in pl]) for name, pl in BUCKETS]
    for stack, cnt in rows:
        matched = None
        for name, plist in pats:
            if any(p.search(stack) for p in plist):
                matched = name
                break
        counts[matched if matched else "other"] += cnt
    return counts


def report(label, path, mean_us):
    rows, total = load(path)
    counts = bucketize(rows)
    print(f"\n=== {label} (mean handshake {mean_us:.1f} us) ===")
    print(f"  {'Operation':<24} {'Share':>7}   {'us/handshake':>12}")
    print(f"  {'-'*24} {'-'*7}   {'-'*12}")
    result = {}
    for name in [b[0] for b in BUCKETS] + ["other"]:
        c = counts[name]
        if c == 0:
            continue
        share = c / total
        us = share * mean_us
        result[name] = (share, us)
        # 2 sig figs on the absolute number per the methodology's resolution note.
        print(f"  {name:<24} {100*share:6.1f}%   {us:10.1f}")
    return result


def make_comparison_chart(s2n, rustls, cert_type, out_path):
    """Operation-level grouped bar chart: the SOUND cross-implementation comparison."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("(matplotlib not available; skipping comparison chart)")
        return

    names = [b[0] for b in BUCKETS] + ["other"]
    names = [n for n in names if s2n.get(n, (0, 0))[1] > 0 or rustls.get(n, (0, 0))[1] > 0]
    s2n_us = [s2n.get(n, (0, 0))[1] for n in names]
    rustls_us = [rustls.get(n, (0, 0))[1] for n in names]

    y = np.arange(len(names))
    h = 0.38
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.barh(y - h / 2, s2n_us, h, label="s2n-tls", color="#4682b4", edgecolor="black", linewidth=0.4)
    ax.barh(y + h / 2, rustls_us, h, label="rustls", color="#e68c3c", edgecolor="black", linewidth=0.4)
    ax.set_yticks(y)
    ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xlabel("µs per handshake (CPU share × hot-loop mean)")
    ax.set_title(
        f"Operation-level comparison — {cert_type}\n"
        f"Sound cross-implementation view (from flamegraphs)"
    )
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n  ✓ wrote comparison chart: {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--s2n", required=True)
    ap.add_argument("--s2n-mean", type=float, required=True)
    ap.add_argument("--rustls", required=True)
    ap.add_argument("--rustls-mean", type=float, required=True)
    ap.add_argument("--cert-type", default="rsa2048")
    ap.add_argument("--chart", help="path to write the operation-level comparison PNG")
    args = ap.parse_args()

    s2n = report("s2n-tls", args.s2n, args.s2n_mean)
    rustls = report("rustls", args.rustls, args.rustls_mean)

    # Side-by-side delta on the operations that matter for the writeup.
    print("\n=== s2n vs rustls (us/handshake, ~2 sig figs) ===")
    print(f"  {'Operation':<24} {'s2n':>8} {'rustls':>8} {'delta':>8}")
    print(f"  {'-'*24} {'-'*8} {'-'*8} {'-'*8}")
    for name in [b[0] for b in BUCKETS] + ["other"]:
        s = s2n.get(name, (0, 0))[1]
        r = rustls.get(name, (0, 0))[1]
        if s == 0 and r == 0:
            continue
        print(f"  {name:<24} {s:8.1f} {r:8.1f} {s-r:+8.1f}")

    if args.chart:
        make_comparison_chart(s2n, rustls, args.cert_type, args.chart)


if __name__ == "__main__":
    main()
