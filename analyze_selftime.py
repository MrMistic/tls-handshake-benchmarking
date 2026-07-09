#!/usr/bin/env python3
"""
Operation-level analysis from DWARF self-time (trustworthy).

Unlike analyze_fg.py (which buckets folded FP stacks and counts a stack if ANY
frame matches — unreliable because frame-pointer unwinding breaks through
aws-lc's hand-written crypto assembly), this reads `perf report --sort symbol`
SELF time. Self-time is the instruction-pointer leaf and does NOT depend on
unwinding, so it is correct even when call chains are broken.

Input: the text output of
    perf report -i <data.dwarf> --stdio --sort symbol
Pass the file (or stdin). Multiply shares by the hot-loop mean for absolute us.

Usage:
    perf report -i perf_s2n_dwarf.data --stdio --sort symbol > s2n.rpt
    python3 analyze_selftime.py --report s2n.rpt --mean 590.5 --label s2n-tls
"""
import argparse
import re

BUCKETS = [
    ("RSA modexp/bignum", [r"rsaz_amm", r"bn_sqrx", r"bn_sqr8x", r"bn_mulx", r"bn_mul",
                           r"mulx4x", r"extract_multiplier", r"bn_mod_exp", r"bn_from_montgomery",
                           r"bn_mont", r"rsa_", r"\brsa\b", r"mod_exp"]),
    ("ECDSA/EC P-256",    [r"ecp_nistz", r"nistz256", r"p256", r"ecdsa", r"bignum_montinv_p256"]),
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


def parse_report(path):
    """Return list of (self_pct, symbol). Reads perf report --sort symbol stdio."""
    rows = []
    # Match lines like:  44.21%    44.20%  [.] symbol_name
    line_re = re.compile(r"^\s*([\d.]+)%\s+([\d.]+)%\s+\[[^\]]*\]\s+(.*?)\s*$")
    with open(path) as f:
        for line in f:
            m = line_re.match(line)
            if not m:
                continue
            self_pct = float(m.group(2))  # second column is self
            sym = m.group(3)
            if self_pct > 0:
                rows.append((self_pct, sym))
    return rows


def bucketize(rows):
    pats = [(name, [re.compile(p, re.IGNORECASE) for p in pl]) for name, pl in BUCKETS]
    counts = {name: 0.0 for name, _ in BUCKETS}
    counts["other"] = 0.0
    for self_pct, sym in rows:
        matched = None
        for name, plist in pats:
            if any(p.search(sym) for p in plist):
                matched = name
                break
        counts[matched if matched else "other"] += self_pct
    return counts


def report_counts(report, mean, label):
    rows = parse_report(report)
    counts = bucketize(rows)
    accounted = sum(counts.values())
    print(f"\n=== {label} (DWARF self-time; mean {mean:.1f} us) ===")
    print(f"  {'Operation':<28} {'self%':>7} {'us/handshake':>13}")
    print(f"  {'-'*28} {'-'*7} {'-'*13}")
    for name in [b[0] for b in BUCKETS] + ["other"]:
        pct = counts[name]
        if pct <= 0:
            continue
        print(f"  {name:<28} {pct:6.1f}% {pct/100*mean:11.1f}")
    print(f"  (accounted: {accounted:.1f}% of self-time samples)")
    return {name: counts[name] / 100 * mean for name, _ in BUCKETS}, counts["other"] / 100 * mean


def make_chart(s2n_us, rustls_us, cert_type, out_path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    names = [b[0] for b in BUCKETS] + ["other"]
    names = [n for n in names if s2n_us.get(n, 0) > 0.05 or rustls_us.get(n, 0) > 0.05]
    s = [s2n_us.get(n, 0) for n in names]
    r = [rustls_us.get(n, 0) for n in names]
    y = np.arange(len(names))
    h = 0.38
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.barh(y - h / 2, s, h, label="s2n-tls", color="#4682b4", edgecolor="black", linewidth=0.4)
    ax.barh(y + h / 2, r, h, label="rustls", color="#e68c3c", edgecolor="black", linewidth=0.4)
    ax.set_yticks(y)
    ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xlabel("µs per handshake (DWARF self-time × hot-loop mean)")
    ax.set_title(f"Operation-level comparison — {cert_type}\nDWARF self-time (authoritative)")
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n  ✓ wrote {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--mean", type=float, required=True, help="hot-loop mean handshake us")
    ap.add_argument("--label", default="impl")
    # Optional second implementation + chart (produces the comparison PNG).
    ap.add_argument("--report2", help="second implementation's report (for comparison chart)")
    ap.add_argument("--mean2", type=float, help="second implementation's mean us")
    ap.add_argument("--label2", default="rustls")
    ap.add_argument("--cert-type", default="rsa2048")
    ap.add_argument("--chart", help="path to write the comparison PNG")
    args = ap.parse_args()

    us1, other1 = report_counts(args.report, args.mean, args.label)
    us1["other"] = other1

    if args.report2 and args.mean2:
        us2, other2 = report_counts(args.report2, args.mean2, args.label2)
        us2["other"] = other2
        if args.chart:
            make_chart(us1, us2, args.cert_type, args.chart)


if __name__ == "__main__":
    main()
