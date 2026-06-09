# TLS Handshake Benchmarking

Per-message timing benchmark that compares **s2n-tls** and **Rustls** TLS 1.3
handshake performance at the individual message level.

## How it works

The s2n-tls C library emits a monotonic timestamp checkpoint after each
handshake message handler completes. This Rust harness:

1. Drives in-memory TLS 1.3 handshakes (no real sockets)
2. Collects checkpoint timestamps via the `EventSubscriber` trait
3. Computes per-message durations as deltas between consecutive checkpoints
4. Writes structured JSON output
5. A Python script renders comparison charts

## Build & Run

```bash
# Build
cargo build --release

# Run (cert types: rsa2048, rsa3072, rsa4096, ecdsa256, ecdsa384)
./target/release/tls-handshake-benchmarking rsa2048 results.json

# Visualize
pip install -r visualize/requirements.txt
python visualize/visualize.py results.json --output-dir charts/
```

## Dependencies

- **s2n-tls** (via path dependency to a local checkout at `../s2n-tls`)
- Python 3 with matplotlib, seaborn, pandas (for visualization only)

## JSON Output Format

```json
{
  "metadata": {
    "cpu_model": "...",
    "warmup_iterations": 200,
    "measurement_iterations": 1000,
    "cert_type": "rsa2048"
  },
  "measurements": [
    {
      "implementation": "s2n-tls",
      "handshake_type": "tls13_full",
      "iteration": 0,
      "message_name": "SERVER_CERT_VERIFY",
      "role": "server",
      "duration_ns": 295000
    }
  ],
  "reproducibility": {
    "SERVER_CERT_VERIFY_server": {
      "mean_ns": 300000,
      "stddev_ns": 15000,
      "cv_percent": 5.0
    }
  }
}
```
