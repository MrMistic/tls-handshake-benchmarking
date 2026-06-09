// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handshake timing tool — runs TLS 1.3 handshakes via s2n-tls and prints
//! per-message timing data, then serializes results to JSON.
//!
//! The C library emits a single monotonic timestamp per dispatched message
//! (a "checkpoint"). This harness collects checkpoints into per-iteration
//! batches, computes per-message durations as deltas between consecutive
//! checkpoints, and writes the results to JSON in the same shape this tool
//! produced before the redesign.
//!
//! Usage: handshake-timing [rsa2048|rsa3072|rsa4096|ecdsa256|ecdsa384] [output.json]

use std::{collections::BTreeMap, sync::Mutex, time::Instant};

use serde::Serialize;

use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::Builder,
    connection::Connection,
    events::{EventSubscriber, HandshakeEvent, TimingCheckpoint},
    testing::TestPair,
};

// ============================================================================
// Output data model — kept identical to the pre-redesign shape so existing
// tooling (visualize.py, dashboards) continues to work.
// ============================================================================

#[derive(Serialize, Clone)]
struct MeasurementRecord {
    implementation: String,
    handshake_type: String,
    iteration: u64,
    message_name: String,
    role: String,
    duration_ns: u64,
}

#[derive(Serialize, Clone)]
struct MessageStats {
    mean_ns: f64,
    stddev_ns: f64,
    cv_percent: f64,
}

#[derive(Serialize)]
struct Metadata {
    cpu_model: String,
    warmup_iterations: u64,
    measurement_iterations: u64,
    cert_type: String,
}

#[derive(Serialize)]
struct OutputFile {
    metadata: Metadata,
    measurements: Vec<MeasurementRecord>,
    reproducibility: BTreeMap<String, MessageStats>,
}

const HANDSHAKE_ORDER: &[&str] = &[
    // used for sorted printing of the summary table
    "CLIENT_HELLO",
    "SERVER_HELLO",
    "ENCRYPTED_EXTENSIONS",
    "SERVER_CERT_REQ",
    "SERVER_CERT",
    "SERVER_CERT_VERIFY",
    "SERVER_FINISHED",
    "CLIENT_CERT",
    "CLIENT_CERT_VERIFY",
    "CLIENT_FINISHED",
    "CLIENT_CHANGE_CIPHER_SPEC",
    "SERVER_CHANGE_CIPHER_SPEC",
];

// ============================================================================
// Timing subscriber
//
// The C library emits checkpoints (name + monotonic timestamp). The harness
// stores the raw checkpoints first, then converts them to per-message
// durations after each handshake completes by computing deltas between
// consecutive checkpoints.
// ============================================================================

#[derive(Debug, Clone)]
struct RawCheckpoint {
    name: String,
    role: String,
    timestamp_ns: u64,
}

/// Global checkpoint buffer. Each handshake's checkpoints are appended in
/// order. After each handshake we walk the buffer, compute deltas, and
/// produce one MeasurementRecord per consecutive pair.
static CHECKPOINTS: Mutex<Vec<RawCheckpoint>> = Mutex::new(Vec::new());

struct TimingSubscriber;

impl EventSubscriber for TimingSubscriber {
    fn on_handshake_event(&self, _connection: &Connection, _event: &HandshakeEvent) {
        // The aggregate handshake event is not used by this tool.
    }

    fn on_timing_checkpoint(&self, _connection: &Connection, checkpoint: &TimingCheckpoint) {
        let record = RawCheckpoint {
            name: checkpoint.name().to_string(),
            role: if checkpoint.is_server() {
                "server".to_string()
            } else {
                "client".to_string()
            },
            timestamp_ns: checkpoint.timestamp_ns(),
        };
        if let Ok(mut buf) = CHECKPOINTS.lock() {
            buf.push(record);
        }
    }
}

/// Convert a raw checkpoint buffer into per-message duration records.
///
/// Walks the buffer, groups by (iteration, role), sorts each group by
/// timestamp, and emits one record per consecutive pair. The duration of
/// message N is `checkpoint[N].timestamp - checkpoint[N-1].timestamp`. The
/// first checkpoint in each group (typically `NEGOTIATE_START`) is the
/// anchor and does not produce a duration record itself.
fn compute_durations(checkpoints: &[RawCheckpoint], iterations: u64) -> Vec<MeasurementRecord> {
    if checkpoints.is_empty() || iterations == 0 {
        return Vec::new();
    }

    // We don't track iteration index directly in the checkpoint, so we infer
    // it: each handshake fires the same number of checkpoints, so we split
    // the buffer evenly. Both server and client produce checkpoints during
    // a single handshake (TestPair drives both sides in process), so the
    // total per handshake is server_count + client_count.
    let total = checkpoints.len() as u64;
    let per_handshake = total.checked_div(iterations).unwrap_or(0);
    if per_handshake == 0 {
        return Vec::new();
    }

    let mut records = Vec::new();
    for (idx, ckpt_chunk) in checkpoints.chunks(per_handshake as usize).enumerate() {
        let iteration = idx as u64;

        // Split server-side and client-side checkpoints; sort each by timestamp.
        let mut server_ckpts: Vec<&RawCheckpoint> =
            ckpt_chunk.iter().filter(|c| c.role == "server").collect();
        let mut client_ckpts: Vec<&RawCheckpoint> =
            ckpt_chunk.iter().filter(|c| c.role == "client").collect();
        server_ckpts.sort_by_key(|c| c.timestamp_ns);
        client_ckpts.sort_by_key(|c| c.timestamp_ns);

        for group in &[&server_ckpts, &client_ckpts] {
            for window in group.windows(2) {
                let prev = window[0];
                let curr = window[1];
                let duration_ns = curr.timestamp_ns.saturating_sub(prev.timestamp_ns);
                records.push(MeasurementRecord {
                    implementation: "s2n-tls".to_string(),
                    handshake_type: "tls13_full".to_string(),
                    iteration,
                    message_name: curr.name.clone(),
                    role: curr.role.clone(),
                    duration_ns,
                });
            }
        }
    }
    records
}

// ============================================================================
// Helpers
// ============================================================================

fn get_cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn fmt_ns(ns: f64) -> String {
    if ns >= 1_000_000.0 {
        format!("{:.3} ms", ns / 1e6)
    } else if ns >= 1000.0 {
        format!("{:.3} us", ns / 1e3)
    } else {
        format!("{:.0} ns", ns)
    }
}

pub struct InsecureAcceptAllCertificatesHandler {}
impl VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let sig_type = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "rsa2048".to_string());

    let output_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "results.json".to_string());

    let cert_dir = match sig_type.as_str() {
        "rsa2048" => "rsae_pkcs_2048_sha256",
        "rsa3072" => "rsae_pkcs_3072_sha384",
        "rsa4096" => "rsae_pkcs_4096_sha384",
        "ecdsa256" => "ec_ecdsa_p256_sha256",
        "ecdsa384" => "ec_ecdsa_p384_sha384",
        other => {
            eprintln!("Unknown: {other}. Use: rsa2048|rsa3072|rsa4096|ecdsa256|ecdsa384");
            std::process::exit(1);
        }
    };

    let warmup = 200u64;
    let measure = 1000u64;

    println!("s2n-tls per-message handshake timing");
    println!("============================================");
    println!("Cert: {sig_type}, Warmup iterations: {warmup}, Measurement iterations: {measure}");
    println!("Output: {output_path}");

    let repo_root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../..");
    let cert_path = format!("{repo_root}/tests/pems/permutations/{cert_dir}/server-chain.pem");
    let key_path = format!("{repo_root}/tests/pems/permutations/{cert_dir}/server-key.pem");
    let ca_path = format!("{repo_root}/tests/pems/permutations/{cert_dir}/ca-cert.pem");
    let cert_pem = std::fs::read(&cert_path).unwrap_or_else(|_| panic!("Cannot read {cert_path}"));
    let key_pem = std::fs::read(&key_path).unwrap_or_else(|_| panic!("Cannot read {key_path}"));
    let ca_pem = std::fs::read(&ca_path).unwrap_or_else(|_| panic!("Cannot read {ca_path}"));

    struct AcceptLocalhost;
    impl s2n_tls::callbacks::VerifyHostNameCallback for AcceptLocalhost {
        fn verify_host_name(&self, hostname: &str) -> bool {
            hostname == "localhost"
        }
    }

    let server_config = {
        let mut builder = Builder::new();
        builder.load_pem(&cert_pem, &key_pem).unwrap();
        builder.set_event_subscriber(TimingSubscriber).unwrap();
        builder.build().unwrap()
    };

    let client_config = {
        let mut builder = Builder::new();
        builder.trust_pem(&ca_pem).unwrap();
        builder.set_verify_host_callback(AcceptLocalhost).unwrap();
        builder.set_event_subscriber(TimingSubscriber).unwrap();
        builder.build().unwrap()
    };

    // Warmup
    print!("Warming up...");
    for _ in 0..warmup {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.client.set_server_name("localhost").unwrap();
        pair.handshake().expect("warmup handshake failed");
    }
    println!(" done.");
    CHECKPOINTS.lock().unwrap().clear();

    // Measurement
    print!("Measuring...");
    let t0 = Instant::now();
    for _ in 0..measure {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.client.set_server_name("localhost").unwrap();
        pair.handshake().expect("measurement handshake failed");
    }
    let elapsed = t0.elapsed();
    println!(" done.");

    let e2e_mean_us = elapsed.as_micros() as f64 / measure as f64;

    // Convert raw checkpoints into per-message duration records.
    let raw = CHECKPOINTS.lock().unwrap().clone();
    let measurements = compute_durations(&raw, measure);

    // Group durations by (message_name, role) for stats and the summary table.
    let mut grouped: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for r in &measurements {
        let key = format!("{}_{}", r.message_name, r.role);
        grouped.entry(key).or_default().push(r.duration_ns);
    }

    let reproducibility: BTreeMap<String, MessageStats> = grouped
        .iter()
        .map(|(key, samples)| {
            let n = samples.len() as f64;
            let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n;
            let var: f64 = samples
                .iter()
                .map(|&x| (x as f64 - mean).powi(2))
                .sum::<f64>()
                / n;
            let stddev = var.sqrt();
            let cv = if mean > 0.0 {
                stddev / mean * 100.0
            } else {
                0.0
            };
            (
                key.clone(),
                MessageStats {
                    mean_ns: mean,
                    stddev_ns: stddev,
                    cv_percent: cv,
                },
            )
        })
        .collect();

    let output = OutputFile {
        metadata: Metadata {
            cpu_model: get_cpu_model(),
            warmup_iterations: warmup,
            measurement_iterations: measure,
            cert_type: sig_type.clone(),
        },
        measurements,
        reproducibility: reproducibility.clone(),
    };

    // Write JSON
    let file = std::fs::File::create(&output_path).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot create {output_path}: {e}");
        std::process::exit(1);
    });
    if let Err(e) = serde_json::to_writer_pretty(file, &output) {
        eprintln!("ERROR: JSON serialization failed: {e}");
        std::process::exit(1);
    }

    // Print summary
    println!("\n=== End-to-end ===");
    println!("  mean = {e2e_mean_us:.1} us per handshake");
    println!("  Total checkpoints collected: {}", raw.len());

    println!(
        "\n{:<32}  {:<8}  {:>12}  {:>10}  {:>15}",
        "Message", "Role", "Mean", "Median", "% of Handshake"
    );
    println!(
        "{:<32}  {:<8}  {:>12}  {:>10}  {:>15}",
        "-------", "----", "----", "------", "--------------"
    );

    for msg in HANDSHAKE_ORDER {
        for role in &["server", "client"] {
            let key = format!("{}_{}", msg, role);
            if let Some(stats) = reproducibility.get(&key) {
                let samples = &grouped[&key];
                let mut sorted = samples.clone();
                sorted.sort();
                let median = sorted[sorted.len() / 2];
                let pct = (stats.mean_ns / (e2e_mean_us * 1000.0)) * 100.0;
                let pct_str = format!("{:.1}%", pct);
                println!(
                    "{:<32}  {:<8}  {:>12}  {:>10}  {:>15}",
                    msg,
                    role,
                    fmt_ns(stats.mean_ns),
                    fmt_ns(median as f64),
                    pct_str
                );
            }
        }
    }
}
