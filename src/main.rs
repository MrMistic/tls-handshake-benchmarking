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

use rcgen::{
    CertificateParams, KeyPair, RsaKeySize, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256,
};
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
    "CLIENT_HELLO",
    "RECORD_READ",
    "RECORD_WRITE",
    "SERVER_HELLO",
    "SERVER_CHANGE_CIPHER_SPEC",
    "ENCRYPTED_EXTENSIONS",
    "SERVER_CERT_REQ",
    "SERVER_CERT",
    "SERVER_CERT_VERIFY",
    "SERVER_FINISHED",
    "CLIENT_CERT",
    "CLIENT_CERT_VERIFY",
    "CLIENT_CHANGE_CIPHER_SPEC",
    "CLIENT_FINISHED",
    "NEGOTIATE_END",
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
/// Uses the global timeline: all checkpoints are sorted by timestamp, and
/// each message's duration is the delta from the immediately preceding
/// checkpoint (regardless of role). This correctly handles single-threaded
/// cooperative I/O where one side's work happens between the other side's
/// checkpoints.
///
/// The first checkpoint per iteration (`NEGOTIATE_START`) is an anchor and
/// does not produce a duration record.
fn compute_durations(checkpoints: &[RawCheckpoint], iterations: u64) -> Vec<MeasurementRecord> {
    if checkpoints.is_empty() || iterations == 0 {
        return Vec::new();
    }

    let total = checkpoints.len() as u64;
    let per_handshake = total.checked_div(iterations).unwrap_or(0);
    if per_handshake == 0 {
        return Vec::new();
    }

    let mut records = Vec::new();
    for (idx, ckpt_chunk) in checkpoints.chunks(per_handshake as usize).enumerate() {
        let iteration = idx as u64;

        // Sort all checkpoints in this iteration by timestamp (global timeline).
        let mut sorted: Vec<&RawCheckpoint> = ckpt_chunk.iter().collect();
        sorted.sort_by_key(|c| c.timestamp_ns);

        // Walk the global timeline. Each message's duration is the delta from
        // the immediately preceding checkpoint, regardless of which side it
        // came from. This means cross-side handoff time is not inflated.
        for window in sorted.windows(2) {
            let prev = window[0];
            let curr = window[1];

            // Skip NEGOTIATE_START — it's only an anchor.
            if curr.name == "NEGOTIATE_START" {
                continue;
            }

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
// Certificate generation
// ============================================================================

/// Generate a CA certificate and a server certificate signed by it, using the
/// requested algorithm/key size. Returns (ca_pem, cert_chain_pem, key_pem) as
/// byte vectors ready to pass to s2n-tls.
fn generate_certs(sig_type: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let alg: &'static SignatureAlgorithm = match sig_type {
        "rsa2048" | "rsa3072" | "rsa4096" => &PKCS_RSA_SHA256,
        "ecdsa256" => &PKCS_ECDSA_P256_SHA256,
        "ecdsa384" => &PKCS_ECDSA_P384_SHA384,
        _ => &PKCS_RSA_SHA256,
    };

    let rsa_key_size: Option<RsaKeySize> = match sig_type {
        "rsa2048" => Some(RsaKeySize::_2048),
        "rsa3072" => Some(RsaKeySize::_3072),
        "rsa4096" => Some(RsaKeySize::_4096),
        _ => None,
    };

    // Generate CA key pair
    let ca_key = if let Some(size) = rsa_key_size {
        KeyPair::generate_rsa_for(alg, size).expect("failed to generate CA RSA key")
    } else {
        KeyPair::generate_for(alg).expect("failed to generate CA key")
    };

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Benchmark CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Generate server key pair
    let server_key = if let Some(size) = rsa_key_size {
        KeyPair::generate_rsa_for(alg, size).expect("failed to generate server RSA key")
    } else {
        KeyPair::generate_for(alg).expect("failed to generate server key")
    };

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    // Build the chain: server cert + CA cert
    let cert_chain_pem = format!("{}{}", server_cert.pem(), ca_cert.pem());

    (
        ca_cert.pem().into_bytes(),
        cert_chain_pem.into_bytes(),
        server_key.serialize_pem().into_bytes(),
    )
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

    match sig_type.as_str() {
        "rsa2048" | "rsa3072" | "rsa4096" | "ecdsa256" | "ecdsa384" => {}
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

    // Generate CA and server certs at runtime using rcgen.
    let (ca_pem, cert_pem, key_pem) = generate_certs(&sig_type);

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
