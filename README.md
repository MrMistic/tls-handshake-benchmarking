# TLS Handshake Benchmarking

Per-message and operation-level timing comparison of **s2n-tls** and **rustls**
TLS 1.3 handshake performance.

## Two-track methodology

These two libraries decompose the TLS handshake state machine differently, so a
naive per-message comparison is unsound (the same message name measures different
work in each). This harness therefore produces two distinct kinds of output:

1. **Per-message profiles (within-implementation only).** Each implementation's
   own breakdown of where handshake time goes, message by message. Useful as a
   navigation aid; NOT overlaid across implementations.
2. **Operation-level comparison (cross-implementation).** The sound comparison —
   derived from flamegraphs, comparing the cost of actual operations (RSA sign,
   cert validation, key derivation, etc.) that exist identically in both libs.

How each works:
- **Per-message:** s2n-tls (C) emits a monotonic timestamp checkpoint after each
  handshake message handler; rustls (forked, `timing` feature) emits equivalent
  checkpoints. The harness drives in-memory handshakes (no sockets), collects
  checkpoints, and computes per-message durations as deltas. Both pinned to
  AES-128-GCM-SHA256 so the comparison is cipher-suite-matched.
- **Operation-level:** the harness runs a tight handshake loop under `perf`,
  builds a flamegraph, and converts CPU shares to absolute µs using the loop's
  own measured mean handshake time. Validated against an isolated crypto
  microbenchmark.

## Dependencies

- **s2n-tls** — local checkout at `../s2n-tls` (timing-instrumented branch)
- **rustls** — local checkout at `../rustls` (timing-instrumented branch, `timing` feature)
- Python 3 with matplotlib, seaborn, pandas, plotly (visualization only)
- For operation-level analysis: `perf`, and the FlameGraph scripts on PATH
  (`stackcollapse-perf.pl`, `flamegraph.pl`)

## Quick start

```bash
cargo build --release
```

### 1. Per-message timing (both impls, JSON + charts)

```bash
# Runs s2n-tls AND rustls, writes combined JSON. Cert types:
#   rsa2048 | rsa3072 | rsa4096 | ecdsa256 | ecdsa384
S2N_DONT_MLOCK=1 ./target/release/tls-handshake-benchmarking rsa2048 results.json

# Per-implementation charts -> charts/<cert>/<impl>/
pip install -r visualize/requirements.txt
python3 visualize/visualize.py results.json --output-dir charts/
```

### 2. Operation-level cross-implementation comparison (one command)

```bash
# One-time: perf access + FlameGraph scripts
git clone https://github.com/brendangregg/FlameGraph ~/FlameGraph
export PATH="$HOME/FlameGraph:$PATH"
sudo sysctl kernel.perf_event_paranoid=1
sudo sysctl kernel.kptr_restrict=0

# Build with frame pointers + debuginfo
RUSTFLAGS="-C force-frame-pointers=yes" CFLAGS="-fno-omit-frame-pointer -g" \
  cargo build --profile bench-fg

# Record both impls, fold, capture means, analyze, chart — all in one step
S2N_DONT_MLOCK=1 PATH="$HOME/FlameGraph:$PATH" \
  ./target/bench-fg/tls-handshake-benchmarking --compare rsa2048
# -> prints the operation table and writes
#    charts/rsa2048/operation_comparison_rsa2048.png
```

### 3. Ground-truth crypto anchor (optional, validates the conversion)

```bash
./target/release/tls-handshake-benchmarking --microbench rsa2048
```

## Other modes

```bash
# Single-implementation flamegraph only (no comparison):
./target/bench-fg/tls-handshake-benchmarking --flamegraph --impl s2n-tls rsa2048

# Manual operation analysis from existing folded stacks:
python3 analyze_fg.py --s2n folded_s2n-tls_rsa2048.txt --s2n-mean <us> \
    --rustls folded_rustls_rsa2048.txt --rustls-mean <us> \
    --cert-type rsa2048 --chart out.png

# What's in the 'other' bucket (debugging aid):
python3 analyze_other.py folded_s2n-tls_rsa2048.txt
```

## JSON output format

```json
{
  "metadata": { "cpu_model": "...", "warmup_iterations": 200,
                "measurement_iterations": 1000, "cert_type": "rsa2048" },
  "measurements": [
    { "implementation": "s2n-tls" | "rustls", "handshake_type": "tls13_full",
      "iteration": 0, "message_name": "SERVER_CERT_VERIFY",
      "role": "server", "direction": "write", "duration_ns": 295000 }
  ],
  "reproducibility": {
    "<impl>|<MESSAGE>_<role>_<direction>": { "mean_ns": ..., "stddev_ns": ..., "cv_percent": ... }
  }
}
```

Reproducibility keys are namespaced by implementation AND direction
(`s2n-tls|SERVER_CERT_VERIFY_server_write`) so the two are never merged and
read (processing) vs write (producing) costs stay distinct.

## Comparing across implementations (read this before making claims)

Both libraries now emit read + write checkpoints, and both use the same
handler-local delta rule (cost measured from the preceding `RECORD_READ`, so
peer-wait is excluded). But they structure their state machines differently, so
only some buckets are 1:1 comparable:

- **Cleanly 1:1 — `SERVER_CERT_VERIFY` server/write (RSA sign):** both isolate the
  signature op. This is the headline number. (Measured: s2n ~355 µs vs rustls
  ~356 µs — identical, as expected on shared aws-lc.)
- **Compare as a SUM, not per-bucket — client cert path:** s2n puts chain
  validation in `SERVER_CERT`; rustls bundles it into `SERVER_CERT_VERIFY`. Only
  `SERVER_CERT + SERVER_CERT_VERIFY` combined is comparable (s2n ~68 µs vs rustls
  ~53 µs).
- **NOT comparable per-bucket — Finished, HKDF/key-schedule:** rustls bundles
  verify+derive+produce into one handler; s2n splits across handlers and
  transition gaps. Use operation-level (flamegraph) comparison instead.

See the rustls fork's `OPERATION_BUCKET_COMPARISON.md` for the full source-verified
bucket map.

## Notes

- Both implementations run full handshakes (rustls resumption is disabled) so the
  certificate flight — where RSA/ECDSA verify cost lives — is present every time.
- Cross-implementation per-message bars are intentionally NOT produced; only
  operation-level comparison is sound across the two libraries.
