#!/usr/bin/env python3
"""
Operation-level analysis of handshake flamegraphs (LEAF-attributed).

⚠️  ACCURACY NOTE — READ THIS:
    This script reads collapsed FRAME-POINTER stacks. Frame-pointer unwinding
    breaks through hand-written crypto assembly (aws-lc), producing broken call
    chains. An EARLIER version of this script bucketed a sample if ANY frame in
    its (possibly broken) stack matched — which badly MISATTRIBUTED small
    buckets (e.g. it once reported HKDF at ~37us and cert-validate at ~25us when
    the DWARF-verified self-time values were ~5us and ~10us). Those were
    artifacts of stale frames in broken stacks.

    This version attributes each sample to its LEAF frame only (the innermost
    function = where the instruction pointer actually landed), which is
    unwinding-independent and far more robust. It still uses FP captures, so:

    >>> For the AUTHORITATIVE operation breakdown, use analyze_selftime.py,
    >>> which parses `perf report --sort symbol` SELF time from a DWARF capture.
    >>> Treat this script's output as an approximation; verify any sub-2%
    >>> bucket against analyze_selftime.py before citing absolute numbers.

Converts leaf shares into absolute microseconds-per-handshake using each
implementation's measured hot-loop mean (share x mean).

Usage:
    python3 analyze_fg.py \
        --s2n /tmp/s2n_folded.txt --s2n-mean 606.4 \
        --rustls /tmp/rustls_folded.txt --rustls-mean 609.0
"""
import argparse
import re

# Reuse the SAME bucket patterns as analyze_selftime.py — they are written for
# leaf-symbol (instruction-pointer) matching, e.g. RSA modexp asm like
# `rsaz_amm52x20_x2_ifma256` which doesn't contain "rsa". Importing keeps the
# two tools consistent; analyze_selftime.py remains the authoritative source.
try:
    from analyze_selftime import BUCKETS
except ImportError:
    # Fallback if run from a different cwd: minimal inline copy.
    BUCKETS = [
        ("RSA modexp/bignum", [r"rsaz_amm", r"bn_sqrx", r"bn_sqr8x", r"bn_mulx", r"bn_mul",
                               r"mulx4x", r"extract_multiplier", r"bn_mod_exp", r"bn_from_montgomery",
                               r"bn_mont", r"rsa_", r"\brsa\b", r"mod_exp"]),
        ("ECDSA/EC P-256",    [r"ecp_nistz", r"nistz256", r"\bp256", r"ecdsa", r"bignum_montinv_p256"]),
        ("X25519/ECDHE",      [r"25519", r"curve25519", r"x25519"]),
        ("ML-KEM (Keccak/SHA3)", [r"keccak", r"sha3", r"kyber", r"mlkem", r"ml_kem"]),
        ("SHA-2 hashing",     [r"sha256_block", r"sha512_block", r"sha1_block", r"sha256", r"sha512", r"md5_block"]),
        ("HKDF/key schedule", [r"hkdf", r"hmac", r"secrets_update", r"key_schedule", r"derive", r"expand_label", r"tls13_"]),
        ("AES/GCM/AEAD",      [r"aes", r"gcm", r"aead", r"chacha", r"poly1305", r"ghash"]),
        ("Cert/X509 validate",[r"x509", r"asn1", r"\bcbs_", r"parse_asn1", r"cache_extensions",
                               r"verify_cert", r"name_constraints", r"name_canon", r"\bder_", r"webpki"]),
        ("Buffer mgmt (s2n stuffer/blob)", [r"s2n_stuffer", r"s2n_blob", r"s2n_record_"]),
        ("RNG",               [r"rdrand", r"rand_bytes", r"drbg", r"ctr_drbg"]),
        ("alloc/memory",      [r"malloc", r"\bfree\b", r"cfree", r"alloc", r"memcpy", r"memset", r"memmove", r"OPENSSL_free", r"OPENSSL_malloc"]),
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
    """Attribute each sample to a bucket by its LEAF frame (innermost function).

    Matching the leaf only — rather than 'any frame in the stack' — makes this
    robust to broken frame-pointer call chains: a sample is counted as cert/RSA/
    etc. based on where the instruction pointer actually landed, not on whatever
    stale frames happen to be above it in a mis-unwound stack.
    """
    counts = {name: 0 for name, _ in BUCKETS}
    counts["other"] = 0
    pats = [(name, [re.compile(p, re.IGNORECASE) for p in pl]) for name, pl in BUCKETS]
    for stack, cnt in rows:
        leaf = stack.rsplit(";", 1)[-1]  # innermost frame only
        matched = None
        for name, plist in pats:
            if any(p.search(leaf) for p in plist):
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

    print("=" * 72)
    print("NOTE: FP-stack approximation (leaf-attributed). For authoritative")
    print("      numbers use analyze_selftime.py (DWARF self-time). Verify any")
    print("      sub-2% bucket there before citing absolute values.")
    print("=" * 72)

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
