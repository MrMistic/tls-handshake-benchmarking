#!/usr/bin/env python3
"""Show the top LEAF functions that fall into the 'other' bucket, classified."""
import re
import sys
from collections import defaultdict

# Reuse the same bucket patterns as analyze_fg.py (keep in sync).
BUCKET_PATS = [
    r"rsa.*sign", r"BN_mod_exp", r"rsa_blinding", r"RSA_sign", r"_rsa_.*priv", r"rsa.*private",
    r"rsa.*verify", r"RSA_verify", r"pkcs1.*verify", r"rsa.*public",
    r"\brsa", r"bn_mul", r"BN_mod", r"montgomery", r"\bmont\b",
    r"bn_sqr", r"bn_sqrx", r"bn_postx", r"\bmulx\d", r"sqrx8x", r"sqr8x",
    r"ecdsa", r"EC_POINT", r"ec_GFp", r"\bp256", r"\bp384",
    r"ecp_nistz", r"nistz256", r"montinv_p256", r"montinv_p384",
    r"25519", r"curve25519", r"\becdh",
    r"kyber", r"mlkem", r"ml_kem", r"pqcrystals",
    r"x509", r"asn1", r"\bder_", r"webpki", r"verify_cert", r"cert.*chain", r"parse.*cert",
    r"hkdf", r"hmac", r"key_schedule", r"derive.*traffic", r"expand_label", r"\bprf\b",
    r"sha256", r"sha512", r"sha384", r"sha1\b", r"sha3", r"sha1_block", r"md5_block", r"md5", r"_md_", r"digest",
    r"\baes", r"_aes", r"\bgcm", r"aead", r"chacha", r"poly1305",
    r"s2n_stuffer", r"s2n_blob", r"s2n_record_", r"s2n_array",
    r"rdrand", r"rand_bytes", r"CRYPTO_.*rand", r"drbg",
    r"malloc", r"\bfree\b", r"alloc", r"memcpy", r"memset", r"memmove", r"OPENSSL_free", r"drop_in_place",
]
PATS = [re.compile(p, re.IGNORECASE) for p in BUCKET_PATS]

# Scaffolding / framework frames we expect and consider "not real handshake work".
SCAFFOLD = re.compile(
    r"^(main|_start|__libc|run_hotloop|run_.*_handshake|catch_unwind|lang_start|"
    r"do_call|call_init|__rust|std$|core$|poll_negotiate|handshake$|tls$|"
    r"into_result|expect|process_new_packets|read_tls|write_tls|negotiate|"
    r"__GI_|_dl_|clone|start_thread|isize|i32|usize)",
    re.IGNORECASE,
)


def classify(path):
    other_leaves = defaultdict(int)
    total = 0
    other_total = 0
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
            if any(p.search(stack) for p in PATS):
                continue  # categorized elsewhere
            other_total += cnt
            leaf = stack.split(";")[-1]
            other_leaves[leaf] += cnt

    print(f"\n=== {path} ===")
    print(f"  total samples:        {total}")
    print(f"  'other' samples:      {other_total}  ({100*other_total/total:.1f}%)")
    scaffold_sum = sum(c for leaf, c in other_leaves.items() if SCAFFOLD.search(leaf))
    real_sum = other_total - scaffold_sum
    print(f"    scaffolding leaves: {scaffold_sum}  ({100*scaffold_sum/total:.1f}% of total)")
    print(f"    real/uncategorized: {real_sum}  ({100*real_sum/total:.1f}% of total)")
    print("  top 'other' leaves (real work candidates marked *):")
    for leaf, c in sorted(other_leaves.items(), key=lambda x: -x[1])[:25]:
        mark = " " if SCAFFOLD.search(leaf) else "*"
        print(f"   {mark} {c:>8}  {leaf[:70]}")


for p in sys.argv[1:]:
    classify(p)
