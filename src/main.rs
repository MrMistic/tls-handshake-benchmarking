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

use std::{collections::BTreeMap, sync::Arc, sync::Mutex, time::Instant};

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

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::timing::{TimingCheckpoint as RustlsCheckpoint, TimingSubscriber as RustlsTimingSubscriber};

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

/// Convert a raw checkpoint buffer into per-message duration records (s2n-tls).
///
/// Uses the global timeline: all checkpoints in an iteration are sorted by
/// timestamp, and each message's duration is the delta from the immediately
/// preceding checkpoint (regardless of role). This is valid for s2n-tls
/// because both sides share one absolute monotonic clock, so client and
/// server checkpoints can be interleaved on a single timeline. This correctly
/// handles single-threaded cooperative I/O where one side's work happens
/// between the other side's checkpoints.
///
/// The first checkpoint per iteration (`NEGOTIATE_START`) is an anchor and
/// does not produce a duration record.
fn compute_durations_s2n(checkpoints: &[RawCheckpoint], iterations: u64) -> Vec<MeasurementRecord> {
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

/// Convert per-stream rustls checkpoints into per-message duration records.
///
/// IMPORTANT: rustls uses a *per-connection relative epoch* (each side's
/// `NEGOTIATE_START` is timestamp 0), and is *inbound-only* (each connection
/// only checkpoints messages it receives). The client and server streams
/// therefore CANNOT be merged onto a single global timeline the way s2n's can
/// — their clocks start independently. Each stream is processed separately:
/// within one side's stream, a message's duration is the delta from the
/// previous checkpoint on that same side.
///
/// `client_iters` and `server_iters` are slices of per-iteration checkpoint
/// vectors (one Vec per handshake) for each side.
fn compute_durations_rustls(
    client_iters: &[Vec<RawCheckpoint>],
    server_iters: &[Vec<RawCheckpoint>],
) -> Vec<MeasurementRecord> {
    let mut records = Vec::new();

    for (side_iters, _role) in [(client_iters, "client"), (server_iters, "server")] {
        for (idx, stream) in side_iters.iter().enumerate() {
            let iteration = idx as u64;
            // Checkpoints within one connection share that connection's epoch,
            // so sorting by timestamp is safe and gives chronological order.
            let mut sorted: Vec<&RawCheckpoint> = stream.iter().collect();
            sorted.sort_by_key(|c| c.timestamp_ns);

            for window in sorted.windows(2) {
                let prev = window[0];
                let curr = window[1];
                if curr.name == "NEGOTIATE_START" {
                    continue;
                }
                let duration_ns = curr.timestamp_ns.saturating_sub(prev.timestamp_ns);
                records.push(MeasurementRecord {
                    implementation: "rustls".to_string(),
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
// Certificate generation
// ============================================================================

/// Certificate material in both PEM (for s2n-tls) and DER (for rustls) forms.
struct CertMaterial {
    // PEM forms for s2n-tls
    ca_pem: Vec<u8>,
    cert_chain_pem: Vec<u8>,
    key_pem: Vec<u8>,
    // DER forms for rustls
    server_cert_der: Vec<u8>,
    ca_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
}

/// Generate a CA certificate and a server certificate signed by it, using the
/// requested algorithm/key size. Returns both PEM (s2n-tls) and DER (rustls)
/// encodings so the same cert material drives both implementations.
fn generate_certs(sig_type: &str) -> CertMaterial {
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

    // PEM chain: server cert + CA cert
    let cert_chain_pem = format!("{}{}", server_cert.pem(), ca_cert.pem());

    CertMaterial {
        ca_pem: ca_cert.pem().into_bytes(),
        cert_chain_pem: cert_chain_pem.into_bytes(),
        key_pem: server_key.serialize_pem().into_bytes(),
        server_cert_der: server_cert.der().to_vec(),
        ca_cert_der: ca_cert.der().to_vec(),
        server_key_der: server_key.serialize_der(),
    }
}

// ============================================================================
// Rustls timing driver
//
// rustls is inbound-only: each connection emits checkpoints for the messages
// it RECEIVES. We run a client and a server connection in-memory (no sockets),
// each with its own subscriber, then collect both streams. Per the handoff,
// rustls uses a per-connection relative epoch, so the two streams are kept
// separate and never merged onto one global timeline.
// ============================================================================

/// A rustls subscriber that records checkpoints into a shared buffer for one
/// connection (one handshake, one side).
struct RustlsRecorder {
    role: &'static str,
    buf: Arc<Mutex<Vec<RawCheckpoint>>>,
}

impl RustlsTimingSubscriber for RustlsRecorder {
    fn on_timing_checkpoint(&self, checkpoint: &RustlsCheckpoint) {
        if let Ok(mut b) = self.buf.lock() {
            b.push(RawCheckpoint {
                name: checkpoint.name.clone(),
                role: self.role.to_string(),
                timestamp_ns: checkpoint.timestamp_ns,
            });
        }
    }
}

/// Build rustls client and server configs from the generated cert material.
fn build_rustls_configs(
    certs: &CertMaterial,
) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    use rustls::crypto::aws_lc_rs;

    let server_cert = CertificateDer::from(certs.server_cert_der.clone());
    let ca_cert = CertificateDer::from(certs.ca_cert_der.clone());
    let key = PrivateKeyDer::try_from(certs.server_key_der.clone())
        .expect("failed to parse server key DER");

    // Crypto provider restricted to the single TLS 1.3 suite that MATCHES
    // s2n-tls's default preference (AES-128-GCM-SHA256). Without this, rustls
    // defaults to AES-256-GCM-SHA384, so the two would run different transcript
    // hashes (SHA-256 vs SHA-384) and the SHA/HKDF comparison would be a
    // confound rather than a real difference.
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let provider = Arc::new(provider);

    // Server: present server cert + CA chain.
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![server_cert.clone(), ca_cert.clone()], key)
        .expect("server config build failed");

    // Client: trust the CA.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert).expect("failed to add CA to root store");
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Disable session resumption so every measured handshake is a FULL
    // handshake. The default client config shares an in-memory ticket store,
    // which would make iteration 1 full and all subsequent iterations resume
    // (skipping the cert flight entirely). The s2n-tls side does not enable
    // resumption, so disabling it here keeps the comparison apples-to-apples:
    // full handshakes on both sides, where the RSA cert-verify cost is present.
    client_config.resumption = rustls::client::Resumption::disabled();

    (Arc::new(client_config), Arc::new(server_config))
}

/// Drive one in-memory rustls handshake, returning the client and server
/// checkpoint streams for this handshake.
fn run_rustls_handshake(
    client_config: &Arc<rustls::ClientConfig>,
    server_config: &Arc<rustls::ServerConfig>,
) -> (Vec<RawCheckpoint>, Vec<RawCheckpoint>) {
    let client_buf = Arc::new(Mutex::new(Vec::new()));
    let server_buf = Arc::new(Mutex::new(Vec::new()));

    // Each connection needs its own config carrying its own subscriber. Clone
    // the shared config and attach a fresh recorder.
    let mut cc = (**client_config).clone();
    cc.set_timing_subscriber(Arc::new(RustlsRecorder {
        role: "client",
        buf: client_buf.clone(),
    }));
    let mut sc = (**server_config).clone();
    sc.set_timing_subscriber(Arc::new(RustlsRecorder {
        role: "server",
        buf: server_buf.clone(),
    }));

    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client =
        rustls::ClientConnection::new(Arc::new(cc), server_name).expect("client conn");
    let mut server = rustls::ServerConnection::new(Arc::new(sc)).expect("server conn");

    // In-memory cooperative handshake loop (no sockets).
    let mut buf = Vec::new();
    while client.is_handshaking() || server.is_handshaking() {
        // client -> server
        buf.clear();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = server.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        server.process_new_packets().unwrap();

        // server -> client
        buf.clear();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = client.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        client.process_new_packets().unwrap();
    }

    let c = client_buf.lock().unwrap().clone();
    let s = server_buf.lock().unwrap().clone();
    (c, s)
}

/// Build s2n-tls client and server configs from the cert material. The
/// `with_subscriber` flag controls whether the timing subscriber is attached
/// (off for the flamegraph hot loop, which wants minimal bookkeeping).
fn build_s2n_configs(
    certs: &CertMaterial,
    with_subscriber: bool,
) -> (s2n_tls::config::Config, s2n_tls::config::Config) {
    struct AcceptLocalhost;
    impl s2n_tls::callbacks::VerifyHostNameCallback for AcceptLocalhost {
        fn verify_host_name(&self, hostname: &str) -> bool {
            hostname == "localhost"
        }
    }

    let server_config = {
        let mut builder = Builder::new();
        builder
            .load_pem(&certs.cert_chain_pem, &certs.key_pem)
            .unwrap();
        if with_subscriber {
            builder.set_event_subscriber(TimingSubscriber).unwrap();
        }
        builder.build().unwrap()
    };

    let client_config = {
        let mut builder = Builder::new();
        builder.trust_pem(&certs.ca_pem).unwrap();
        builder.set_verify_host_callback(AcceptLocalhost).unwrap();
        if with_subscriber {
            builder.set_event_subscriber(TimingSubscriber).unwrap();
        }
        builder.build().unwrap()
    };

    (client_config, server_config)
}

/// Run one s2n-tls in-memory handshake with no timing subscriber (used by the
/// flamegraph hot loop).
fn run_s2n_handshake_plain(
    client_config: &s2n_tls::config::Config,
    server_config: &s2n_tls::config::Config,
) {
    let mut pair = TestPair::from_configs(client_config, server_config);
    pair.client.set_server_name("localhost").unwrap();
    pair.handshake().expect("handshake failed");
}

/// Run one rustls in-memory handshake with no timing subscriber (used by the
/// flamegraph hot loop). Mirrors `run_rustls_handshake` minus the recorders.
fn run_rustls_handshake_plain(
    client_config: &Arc<rustls::ClientConfig>,
    server_config: &Arc<rustls::ServerConfig>,
) {
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client =
        rustls::ClientConnection::new(client_config.clone(), server_name).expect("client conn");
    let mut server = rustls::ServerConnection::new(server_config.clone()).expect("server conn");

    let mut buf = Vec::new();
    while client.is_handshaking() || server.is_handshaking() {
        buf.clear();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = server.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        server.process_new_packets().unwrap();

        buf.clear();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = client.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        client.process_new_packets().unwrap();
    }
}

/// The flamegraph hot loop: run one implementation + one cert type in a tight
/// loop for a fixed wall-clock duration with minimal bookkeeping, so a `perf`
/// profile attributing samples to operations isn't polluted by JSON writing,
/// stats, or per-iteration printing.
fn run_hotloop(impl_name: &str, sig_type: &str, duration_secs: u64) {
    let certs = generate_certs(sig_type);
    let deadline = Instant::now() + std::time::Duration::from_secs(duration_secs);
    let mut count: u64 = 0;

    // Warm up briefly so the steady-state mean isn't polluted by cold-start
    // costs (modexp tables, allocator warmup).
    let warmup_n = 200;

    let loop_start;
    match impl_name {
        "s2n-tls" => {
            let (client_config, server_config) = build_s2n_configs(&certs, false);
            for _ in 0..warmup_n {
                run_s2n_handshake_plain(&client_config, &server_config);
            }
            loop_start = Instant::now();
            while Instant::now() < deadline {
                for _ in 0..50 {
                    run_s2n_handshake_plain(&client_config, &server_config);
                }
                count += 50;
            }
        }
        "rustls" => {
            let (client_config, server_config) = build_rustls_configs(&certs);
            for _ in 0..warmup_n {
                run_rustls_handshake_plain(&client_config, &server_config);
            }
            loop_start = Instant::now();
            while Instant::now() < deadline {
                for _ in 0..50 {
                    run_rustls_handshake_plain(&client_config, &server_config);
                }
                count += 50;
            }
        }
        other => {
            eprintln!("Unknown implementation: {other}. Use: s2n-tls|rustls");
            std::process::exit(1);
        }
    }

    let elapsed = loop_start.elapsed();
    let mean_us = elapsed.as_secs_f64() * 1e6 / count as f64;
    // Emit a machine-parseable line the analysis script can read for the
    // share -> absolute-time conversion (Option 1: share x hot-loop mean).
    eprintln!(
        "[hotloop] impl={impl_name} cert={sig_type} handshakes={count} \
         elapsed_s={:.3} mean_us={mean_us:.3}",
        elapsed.as_secs_f64()
    );
    // Also write the mean to a sidecar file so the --compare driver (which runs
    // this under perf and can't easily scrape stderr) can read it back.
    let sidecar = format!("hotloop_mean_{impl_name}_{sig_type}.txt");
    let _ = std::fs::write(&sidecar, format!("{mean_us:.3}"));
}

/// Check that perf + FlameGraph tools are on PATH; exit with guidance if not.
fn check_perf_tools() {
    use std::process::Command;
    for tool in ["perf", "stackcollapse-perf.pl", "flamegraph.pl"] {
        let found = Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            eprintln!(
                "ERROR: required tool '{tool}' not found on PATH.\n\
                 Install perf, and clone https://github.com/brendangregg/FlameGraph\n\
                 then add it to PATH (provides stackcollapse-perf.pl and flamegraph.pl)."
            );
            std::process::exit(1);
        }
    }
}

/// Record one implementation under perf, render its SVG, fold its stacks, and
/// return (folded_stacks_path, hot_loop_mean_us). Shared by --flamegraph and
/// --compare so the mean is captured automatically (no manual copy from stderr).
fn record_and_fold(impl_name: &str, sig_type: &str, duration_secs: u64) -> (String, f64) {
    use std::process::Command;

    let self_exe = std::env::current_exe().expect("cannot find own executable path");
    let perf_data = format!("perf_{impl_name}_{sig_type}.data");
    let svg_out = format!("flamegraph_{impl_name}_{sig_type}.svg");
    let folded_out = format!("folded_{impl_name}_{sig_type}.txt");
    let sidecar = format!("hotloop_mean_{impl_name}_{sig_type}.txt");

    println!("Recording {impl_name} ({sig_type}) under perf for ~{duration_secs}s...");
    let status = Command::new("perf")
        .args(["record", "-F", "999", "-g", "--call-graph", "fp", "-o", &perf_data, "--"])
        .arg(&self_exe)
        .args(["--hotloop", impl_name, sig_type, &duration_secs.to_string()])
        .status()
        .expect("failed to launch perf record");
    if !status.success() {
        eprintln!("ERROR: perf record failed. Is kernel.perf_event_paranoid <= 1?");
        std::process::exit(1);
    }

    // perf script -> folded stacks file (kept for analyze_fg.py).
    println!("Folding stacks -> {folded_out} ...");
    let perf_script = Command::new("perf")
        .args(["script", "-i", &perf_data])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to launch perf script");
    let folded_file = std::fs::File::create(&folded_out).expect("cannot create folded output");
    let collapse = Command::new("stackcollapse-perf.pl")
        .stdin(perf_script.stdout.unwrap())
        .stdout(folded_file)
        .status()
        .expect("failed to launch stackcollapse-perf.pl");
    if !collapse.success() {
        eprintln!("ERROR: stackcollapse-perf.pl failed.");
        std::process::exit(1);
    }

    // folded stacks -> SVG.
    println!("Rendering {svg_out} ...");
    let svg_file = std::fs::File::create(&svg_out).expect("cannot create SVG output");
    let flame = Command::new("flamegraph.pl")
        .arg("--title")
        .arg(format!("{impl_name} {sig_type} handshake"))
        .arg(&folded_out)
        .stdout(svg_file)
        .status()
        .expect("failed to launch flamegraph.pl");
    if !flame.success() {
        eprintln!("ERROR: flamegraph.pl failed.");
        std::process::exit(1);
    }

    // Read the hot-loop mean the subprocess wrote.
    let mean_us = std::fs::read_to_string(&sidecar)
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(0.0);

    (folded_out, mean_us)
}

/// Driver for `--flamegraph`: record one implementation and render its SVG.
fn run_flamegraph(impl_name: &str, sig_type: &str) {
    check_perf_tools();
    let (folded, mean_us) = record_and_fold(impl_name, sig_type, 20);
    println!("Done: flamegraph_{impl_name}_{sig_type}.svg");
    println!("  folded stacks: {folded}");
    println!("  hot-loop mean: {mean_us:.1} us");
}

/// Driver for `--compare`: run the FULL operation-level cross-implementation
/// analysis end to end with one command. Records both implementations under
/// perf, folds both, captures each hot-loop mean automatically, and shells out
/// to analyze_fg.py to produce the operation comparison table + chart.
fn run_compare(sig_type: &str) {
    use std::process::Command;

    check_perf_tools();

    // Locate analyze_fg.py next to the manifest (repo root).
    let script = format!("{}/analyze_fg.py", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&script).exists() {
        eprintln!("ERROR: analyze_fg.py not found at {script}");
        std::process::exit(1);
    }
    // python3 must be present.
    let have_py = Command::new("which")
        .arg("python3")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !have_py {
        eprintln!("ERROR: python3 not found on PATH (needed for analyze_fg.py).");
        std::process::exit(1);
    }

    println!("=== Operation-level comparison: {sig_type} ===\n");
    let (s2n_folded, s2n_mean) = record_and_fold("s2n-tls", sig_type, 20);
    println!();
    let (rustls_folded, rustls_mean) = record_and_fold("rustls", sig_type, 20);

    if s2n_mean == 0.0 || rustls_mean == 0.0 {
        eprintln!("ERROR: could not read hot-loop mean(s); aborting analysis.");
        std::process::exit(1);
    }

    let chart = format!("charts/{sig_type}/operation_comparison_{sig_type}.png");
    // Ensure the chart dir exists.
    if let Some(parent) = std::path::Path::new(&chart).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    println!("\nRunning operation-level analysis (means: s2n {s2n_mean:.1}us, rustls {rustls_mean:.1}us)...\n");
    let status = Command::new("python3")
        .arg(&script)
        .args(["--s2n", &s2n_folded, "--s2n-mean", &format!("{s2n_mean:.3}")])
        .args(["--rustls", &rustls_folded, "--rustls-mean", &format!("{rustls_mean:.3}")])
        .args(["--cert-type", sig_type, "--chart", &chart])
        .status()
        .expect("failed to launch analyze_fg.py");
    if !status.success() {
        eprintln!("ERROR: analyze_fg.py failed.");
        std::process::exit(1);
    }
    println!("\nDone. Comparison chart: {chart}");
}

// ============================================================================
// Ground-truth crypto microbenchmark
//
// Per the methodology doc, the share->absolute-time conversion is validated by
// directly timing an isolated RSA-2048 sign and verify on the same core, using
// the same backend (aws-lc-rs) both libraries use. If `share x mean` says RSA
// sign ~= 280us and this isolated microbench agrees, the method is anchored to
// ground truth.
// ============================================================================

fn run_microbench(sig_type: &str) {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        KeyPair, RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256,
    };
    use std::time::Instant;

    if !sig_type.starts_with("rsa") {
        eprintln!(
            "microbench currently anchors RSA sign/verify only; got '{sig_type}'. \
             Use rsa2048|rsa3072|rsa4096."
        );
        std::process::exit(1);
    }

    // Generate a server key of the requested size via rcgen, hand the PKCS#8
    // DER to aws-lc-rs so we time the exact same primitive the handshake uses.
    let certs = generate_certs(sig_type);
    let key_pair = RsaKeyPair::from_pkcs8(&certs.server_key_der)
        .expect("failed to load RSA key into aws-lc-rs");

    let rng = SystemRandom::new();
    let msg = b"handshake transcript hash stand-in (32 bytes!!)";

    let iters = 5000u32;

    // Warm up.
    let mut sig = vec![0u8; key_pair.public_modulus_len()];
    for _ in 0..200 {
        key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign failed");
    }

    // Time signing.
    let t0 = Instant::now();
    for _ in 0..iters {
        key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign failed");
    }
    let sign_us = t0.elapsed().as_secs_f64() * 1e6 / iters as f64;

    // Time verifying (using the public key from the same pair).
    let public_key_der = key_pair.public_key().as_ref().to_vec();
    let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der);
    for _ in 0..200 {
        public_key.verify(msg, &sig).expect("verify failed");
    }
    let t1 = Instant::now();
    for _ in 0..iters {
        public_key.verify(msg, &sig).expect("verify failed");
    }
    let verify_us = t1.elapsed().as_secs_f64() * 1e6 / iters as f64;

    println!("=== Crypto microbenchmark (ground-truth anchor) ===");
    println!("Backend: aws-lc-rs (same as both s2n-tls and rustls)");
    println!("Cert/key: {sig_type}, iterations: {iters}");
    println!("  RSA sign   (server private key): {sign_us:.2} us/op");
    println!("  RSA verify (client public key):  {verify_us:.2} us/op");
    println!(
        "\nCompare against the flamegraph estimate (share x hot-loop mean) and the\n\
         per-message SERVER_CERT_VERIFY_server measurement to validate the method."
    );
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Dispatch special modes first.
    //   --hotloop <impl> <cert> <secs>   (internal: run under perf)
    //   --flamegraph --impl <impl> <cert>  OR  --flamegraph <impl> <cert>
    if let Some(pos) = args.iter().position(|a| a == "--hotloop") {
        let impl_name = args.get(pos + 1).map(String::as_str).unwrap_or("s2n-tls");
        let sig_type = args.get(pos + 2).map(String::as_str).unwrap_or("rsa2048");
        let secs: u64 = args
            .get(pos + 3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);
        run_hotloop(impl_name, sig_type, secs);
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--microbench") {
        let sig_type = args.get(pos + 1).map(String::as_str).unwrap_or("rsa2048");
        run_microbench(sig_type);
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--microbench") {
        let sig_type = args.get(pos + 1).map(String::as_str).unwrap_or("rsa2048");
        run_microbench(sig_type);
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--compare") {
        let sig_type = args.get(pos + 1).map(String::as_str).unwrap_or("rsa2048");
        run_compare(sig_type);
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--flamegraph") {
        // Accept "--flamegraph --impl <impl> <cert>" or "--flamegraph <impl> <cert>".
        let rest: Vec<&str> = args[pos + 1..]
            .iter()
            .filter(|a| a.as_str() != "--impl")
            .map(String::as_str)
            .collect();
        let impl_name = rest.first().copied().unwrap_or("s2n-tls");
        let sig_type = rest.get(1).copied().unwrap_or("rsa2048");
        run_flamegraph(impl_name, sig_type);
        return;
    }

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

    // Generate CA and server certs at runtime using rcgen (shared by both impls).
    let certs = generate_certs(&sig_type);

    let (client_config, server_config) = build_s2n_configs(&certs, true);

    // ====================================================================
    // s2n-tls run
    // ====================================================================
    print!("[s2n-tls] Warming up...");
    for _ in 0..warmup {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.client.set_server_name("localhost").unwrap();
        pair.handshake().expect("warmup handshake failed");
    }
    println!(" done.");
    CHECKPOINTS.lock().unwrap().clear();

    print!("[s2n-tls] Measuring...");
    let t0 = Instant::now();
    for _ in 0..measure {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.client.set_server_name("localhost").unwrap();
        pair.handshake().expect("measurement handshake failed");
    }
    let s2n_elapsed = t0.elapsed();
    println!(" done.");

    let s2n_raw = CHECKPOINTS.lock().unwrap().clone();
    let mut measurements = compute_durations_s2n(&s2n_raw, measure);

    // ====================================================================
    // rustls run
    // ====================================================================
    let (rustls_client_cfg, rustls_server_cfg) = build_rustls_configs(&certs);

    print!("[rustls] Warming up...");
    for _ in 0..warmup {
        let _ = run_rustls_handshake(&rustls_client_cfg, &rustls_server_cfg);
    }
    println!(" done.");

    print!("[rustls] Measuring...");
    let mut rustls_client_iters: Vec<Vec<RawCheckpoint>> = Vec::with_capacity(measure as usize);
    let mut rustls_server_iters: Vec<Vec<RawCheckpoint>> = Vec::with_capacity(measure as usize);
    let t1 = Instant::now();
    for _ in 0..measure {
        let (c, s) = run_rustls_handshake(&rustls_client_cfg, &rustls_server_cfg);
        rustls_client_iters.push(c);
        rustls_server_iters.push(s);
    }
    let rustls_elapsed = t1.elapsed();
    println!(" done.");

    let rustls_measurements =
        compute_durations_rustls(&rustls_client_iters, &rustls_server_iters);
    measurements.extend(rustls_measurements);

    let s2n_e2e_mean_us = s2n_elapsed.as_micros() as f64 / measure as f64;
    let rustls_e2e_mean_us = rustls_elapsed.as_micros() as f64 / measure as f64;

    // Group durations by (implementation, message_name, role) for stats so the
    // two implementations stay separate and role-matched (never name-only).
    let mut grouped: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for r in &measurements {
        let key = format!("{}|{}_{}", r.implementation, r.message_name, r.role);
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

    // Print per-implementation summary tables.
    println!("\n=== End-to-end ===");
    println!("  s2n-tls mean = {s2n_e2e_mean_us:.1} us per handshake");
    println!("  rustls  mean = {rustls_e2e_mean_us:.1} us per handshake");

    for (impl_name, e2e_mean_us) in [
        ("s2n-tls", s2n_e2e_mean_us),
        ("rustls", rustls_e2e_mean_us),
    ] {
        println!("\n--- {impl_name} (per-message receiving/processing cost) ---");
        println!(
            "{:<28}  {:<8}  {:>12}  {:>10}  {:>15}",
            "Message", "Role", "Mean", "Median", "% of Handshake"
        );
        println!(
            "{:<28}  {:<8}  {:>12}  {:>10}  {:>15}",
            "-------", "----", "----", "------", "--------------"
        );

        for msg in HANDSHAKE_ORDER {
            for role in &["server", "client"] {
                let key = format!("{}|{}_{}", impl_name, msg, role);
                if let Some(stats) = reproducibility.get(&key) {
                    let samples = &grouped[&key];
                    let mut sorted = samples.clone();
                    sorted.sort();
                    let median = sorted[sorted.len() / 2];
                    let pct = (stats.mean_ns / (e2e_mean_us * 1000.0)) * 100.0;
                    let pct_str = format!("{:.1}%", pct);
                    println!(
                        "{:<28}  {:<8}  {:>12}  {:>10}  {:>15}",
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
}
