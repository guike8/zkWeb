// SPDX-License-Identifier: AGPL-3.0-or-later
use ark_bn254::Fr;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Method, blocking::Client};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::TcpStream,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zkweb_zk_listener::{
    MAX_BODY, PROOF_BYTES, Result, client, crypto, fail, profile,
    protocol::{self, Challenge},
    server,
};

#[derive(Clone)]
struct WireAuthorization {
    challenge: Challenge,
    proof_base64: String,
    tag: String,
}

fn authorize(
    member: &profile::ClientProfile,
    challenge: &Challenge,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<WireAuthorization> {
    let digest = protocol::request_digest(challenge, method, path, body);
    let authorization = crypto::prove(
        &member.proving_key,
        &member.credential,
        &member.manifest.group_root,
        &digest,
    )?;
    assert_eq!(authorization.proof.len(), PROOF_BYTES);
    Ok(WireAuthorization {
        challenge: challenge.clone(),
        proof_base64: STANDARD.encode(authorization.proof),
        tag: authorization.tag,
    })
}

fn rejected_and_burned(
    state: &mut server::State,
    authorization: &WireAuthorization,
    method: &str,
    path: &str,
    body: &[u8],
    expected_verifications: u64,
) {
    let executions = state.execution_count();
    let mutations = state.mutation_count();
    let revision = state.revision();
    let attempts = state.verification_attempt_count();
    assert!(
        state
            .execute(
                &authorization.challenge.challenge_id,
                method,
                path,
                body,
                &authorization.proof_base64,
                &authorization.tag,
            )
            .is_err(),
        "invalid authorization reached CRUD"
    );
    assert_eq!(
        state.verification_attempt_count(),
        attempts + expected_verifications
    );
    let attempts = state.verification_attempt_count();
    assert!(
        state
            .execute(
                &authorization.challenge.challenge_id,
                method,
                path,
                body,
                &authorization.proof_base64,
                &authorization.tag,
            )
            .is_err(),
        "an invalid proof's nonce was reusable"
    );
    assert_eq!(
        state.verification_attempt_count(),
        attempts,
        "a burned nonce verified twice"
    );
    assert_eq!(
        state.execution_count(),
        executions,
        "invalid authorization accessed CRUD"
    );
    assert_eq!(state.mutation_count(), mutations);
    assert_eq!(state.revision(), revision);
}

#[derive(Debug)]
struct Metrics {
    attempts: u64,
    executions: u64,
    mutations: u64,
    revision: u64,
}

struct RunningListener {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<Metrics>>>,
}

impl RunningListener {
    fn start(server_directory: &Path, database: &Path) -> Result<Self> {
        let listener = server::bind("127.0.0.1:0")?;
        let url = server::url(&listener)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let directory = server_directory.to_owned();
        let database = database.to_owned();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<std::result::Result<(), String>>(1);
        let worker = thread::spawn(move || -> Result<Metrics> {
            let initialized = (|| -> Result<server::State> {
                server::State::open(profile::load_server(&directory)?, &database)
            })();
            let mut state = match initialized {
                Ok(state) => {
                    let _ = ready_tx.send(Ok(()));
                    state
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return Err(error);
                }
            };
            server::run(&listener, &mut state, Some(&worker_stop))?;
            Ok(Metrics {
                attempts: state.verification_attempt_count(),
                executions: state.execution_count(),
                mutations: state.mutation_count(),
                revision: state.revision(),
            })
        });
        let running = Self {
            url,
            stop,
            worker: Some(worker),
        };
        match ready_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(running),
            Ok(Err(message)) => Err(format!("listener fixture startup failed: {message}").into()),
            Err(error) => Err(format!("listener fixture startup timed out: {error}").into()),
        }
    }

    fn finish(mut self) -> Result<Metrics> {
        self.stop.store(true, Ordering::Relaxed);
        self.worker
            .take()
            .ok_or_else(|| fail("listener already joined"))?
            .join()
            .map_err(|_| fail("listener fixture panicked"))?
    }
}

impl Drop for RunningListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn issue_challenge(http: &Client, url: &str, member: &profile::ClientProfile) -> Result<Challenge> {
    let response = http.get(format!("{url}/challenge")).send()?;
    assert_eq!(response.status(), 200);
    let challenge: Challenge = serde_json::from_slice(&response.bytes()?)?;
    challenge.validate(&member.manifest.profile_id)?;
    Ok(challenge)
}

fn send_authorized(
    http: &Client,
    url: &str,
    authorization: &WireAuthorization,
    method: &str,
    path: &str,
    body: &[u8],
    duplicate_proof: bool,
) -> Result<(u16, Vec<u8>)> {
    let mut request = http
        .request(
            Method::from_bytes(method.as_bytes())?,
            format!("{url}{path}"),
        )
        .header(
            protocol::CHALLENGE_HEADER,
            &authorization.challenge.challenge_id,
        )
        .header(protocol::PROOF_HEADER, &authorization.proof_base64)
        .header(protocol::TAG_HEADER, &authorization.tag)
        .body(body.to_vec());
    if duplicate_proof {
        request = request.header(protocol::PROOF_HEADER, &authorization.proof_base64);
    }
    if matches!(method, "POST" | "PUT") {
        request = request.header("Content-Type", "application/octet-stream");
    }
    let response = request.send()?;
    let status = response.status().as_u16();
    Ok((status, response.bytes()?.to_vec()))
}

fn application(
    member: &profile::ClientProfile,
    url: &str,
    method: &str,
    key: &str,
    input: &[u8],
    expected_status: u16,
    expected_body: Option<&[u8]>,
) -> Result<()> {
    let result = client::request(member, url, method, key, input)?;
    assert_eq!(result.method, method);
    assert_eq!(result.key, key);
    assert_eq!(result.status, expected_status);
    let body = STANDARD.decode(result.body_base64)?;
    if let Some(expected) = expected_body {
        assert_eq!(body, expected);
    }
    Ok(())
}

fn raw_bounded(url: &str, request: &[u8], deadline: Duration) -> Result<()> {
    let mut stream = TcpStream::connect(url.strip_prefix("http://").unwrap())?;
    stream.set_read_timeout(Some(deadline))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    if let Err(error) = stream.write_all(request) {
        if matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ) {
            return Ok(());
        }
        return Err(error.into());
    }
    let mut bytes = Vec::new();
    match stream.take(16 * 1024).read_to_end(&mut bytes) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => return Err(error.into()),
    }
    assert!(
        !bytes.starts_with(b"HTTP/1.1 2"),
        "malformed request was successful"
    );
    Ok(())
}

fn transport_bounds(http: &Client, url: &str) -> Result<()> {
    raw_bounded(
        url,
        b"GET /challenge HTTP/1.1\r\nHost: localhost\r\nX-Slow:",
        Duration::from_secs(8),
    )?;
    let stalled = format!(
        "POST /records/stalled HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: 100\r\nX-ZkWeb-Challenge: {}\r\n\r\nx",
        "0".repeat(64)
    );
    raw_bounded(url, stalled.as_bytes(), Duration::from_secs(13))?;
    let oversized = format!(
        "GET /challenge HTTP/1.1\r\nHost: localhost\r\nX-Large: {}\r\n\r\n",
        "a".repeat(20 * 1024)
    );
    raw_bounded(url, oversized.as_bytes(), Duration::from_secs(3))?;
    let headers = format!(
        "GET /challenge HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
        "X-Header: a\r\n".repeat(40)
    );
    raw_bounded(url, headers.as_bytes(), Duration::from_secs(3))?;
    assert_eq!(http.get(format!("{url}/challenge")).send()?.status(), 200);
    Ok(())
}

struct RestoreDirectoryMode {
    path: PathBuf,
    armed: bool,
}
impl RestoreDirectoryMode {
    fn restrict(path: &Path) -> Result<Self> {
        let guard = Self {
            path: path.into(),
            armed: true,
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
        Ok(guard)
    }
    fn restore(&mut self) -> Result<()> {
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700))?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for RestoreDirectoryMode {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
        }
    }
}

fn failed_commit(
    server_directory: &Path,
    database: &Path,
    member: &profile::ClientProfile,
) -> Result<()> {
    let mut state = server::State::open(profile::load_server(server_directory)?, database)?;
    let revision = state.revision();
    let saved = fs::read(database)?;
    let challenge = state.challenge()?;
    let authorization = authorize(
        member,
        &challenge,
        "POST",
        "/records/uncommitted",
        b"not saved",
    )?;
    let parent = database.parent().unwrap();
    let mut guard = RestoreDirectoryMode::restrict(parent)?;
    let probe_path = parent.join("permission-probe");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe_path)
    {
        Ok(probe) => {
            drop(probe);
            guard.restore()?;
            fs::remove_file(probe_path)?;
            eprintln!("SKIPPED commit-I/O permission case: privileged permission bypass");
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(error.into()),
    }
    assert!(
        state
            .execute(
                &challenge.challenge_id,
                "POST",
                "/records/uncommitted",
                b"not saved",
                &authorization.proof_base64,
                &authorization.tag
            )
            .is_err()
    );
    assert_eq!(state.verification_attempt_count(), 1);
    assert_eq!(
        state.execution_count(),
        1,
        "failure must happen after proof verification"
    );
    assert_eq!(state.mutation_count(), 0);
    assert_eq!(state.revision(), revision);
    assert_eq!(fs::read(database)?, saved);
    assert!(state.is_poisoned());
    assert!(state.challenge().is_err());
    assert!(
        state
            .execute(
                &challenge.challenge_id,
                "POST",
                "/records/uncommitted",
                b"not saved",
                &authorization.proof_base64,
                &authorization.tag
            )
            .is_err()
    );
    assert_eq!(
        state.verification_attempt_count(),
        1,
        "failed mutation retried"
    );
    guard.restore()?;
    drop(state);
    let mut recovered = server::State::open(profile::load_server(server_directory)?, database)?;
    let challenge = recovered.challenge()?;
    let authorization = authorize(member, &challenge, "GET", "/records/uncommitted", b"")?;
    let result = recovered.execute(
        &challenge.challenge_id,
        "GET",
        "/records/uncommitted",
        b"",
        &authorization.proof_base64,
        &authorization.tag,
    )?;
    assert_eq!(result.status, 404);
    assert_eq!(recovered.revision(), revision);
    eprintln!("post-verification commit failure/recovery passed");
    Ok(())
}

#[test]
fn real_groth16_listener_crud_and_failure_boundaries() -> Result<()> {
    let started = Instant::now();
    let temporary = tempfile::tempdir()?;
    let provision = profile::setup(&temporary.path().join("profile"), 2)?;
    let member0 = profile::load_client(&provision.client_dirs[0])?;
    let member1 = profile::load_client(&provision.client_dirs[1])?;
    let names = fs::read_dir(&provision.server_dir)?
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 2);
    assert!(names.iter().any(|name| name == "verifying-key.g16"));
    assert!(
        !names
            .iter()
            .any(|name| name.contains("credential") || name.contains("proving"))
    );
    let manifest = fs::read_to_string(provision.server_dir.join("manifest.json"))?;
    assert!(!manifest.contains("credential_sha256") && !manifest.contains("secret"));
    for directory in provision
        .client_dirs
        .iter()
        .chain(std::iter::once(&provision.server_dir))
    {
        assert_eq!(fs::metadata(directory)?.permissions().mode() & 0o777, 0o700);
        for entry in fs::read_dir(directory)? {
            assert_eq!(entry?.metadata()?.permissions().mode() & 0o777, 0o600);
        }
    }
    let store_directory = temporary.path().join("store");
    fs::DirBuilder::new().mode(0o700).create(&store_directory)?;
    let database = store_directory.join("records.json");
    let mut state = server::State::open(profile::load_server(&provision.server_dir)?, &database)?;
    assert!(server::State::open(profile::load_server(&provision.server_dir)?, &database).is_err());
    let initial = fs::read(&database)?;

    for field in ["body", "method", "path", "instance", "nonce", "expiry"] {
        let challenge = state.challenge()?;
        let mut claimed = challenge.clone();
        if field == "instance" {
            claimed.server_instance = protocol::random_id();
        }
        if field == "nonce" {
            claimed.challenge_id = protocol::random_id();
        }
        if field == "expiry" {
            claimed.expires_unix -= 1;
        }
        let mut wire = authorize(&member0, &claimed, "POST", "/records/tamper", b"original")?;
        // The listener receives its real issued ID, while the proof may claim a
        // different audience/nonce/expiry inside the SHA-256 transcript.
        wire.challenge = challenge;
        rejected_and_burned(
            &mut state,
            &wire,
            if field == "method" { "PUT" } else { "POST" },
            if field == "path" {
                "/records/changed"
            } else {
                "/records/tamper"
            },
            if field == "body" {
                b"changed"
            } else {
                b"original"
            },
            1,
        );
    }
    for variant in ["tag", "proof", "length", "base64", "missing-tag"] {
        let challenge = state.challenge()?;
        let mut wire = authorize(&member0, &challenge, "POST", "/records/tamper", b"original")?;
        let expected_verifications = match variant {
            "tag" => {
                wire.tag = crypto::field_hex(&(crypto::parse_field(&wire.tag)? + Fr::from(1u64)));
                1
            }
            "proof" => {
                let mut proof = STANDARD.decode(&wire.proof_base64)?;
                proof[0] ^= 1;
                wire.proof_base64 = STANDARD.encode(proof);
                1
            }
            "length" => {
                let mut proof = STANDARD.decode(&wire.proof_base64)?;
                proof.pop();
                wire.proof_base64 = STANDARD.encode(proof);
                0
            }
            "base64" => {
                wire.proof_base64 = "!".repeat(wire.proof_base64.len());
                0
            }
            "missing-tag" => {
                wire.tag.clear();
                0
            }
            _ => unreachable!(),
        };
        rejected_and_burned(
            &mut state,
            &wire,
            "POST",
            "/records/tamper",
            b"original",
            expected_verifications,
        );
    }
    // A valid proof made with this same proving key but a different authorized
    // root must not be accepted by this listener's pinned group root.
    let challenge = state.challenge()?;
    let digest = protocol::request_digest(&challenge, "POST", "/records/tamper", b"original");
    let mut alien = member0.credential.clone();
    alien.secret += Fr::from(1u64);
    if alien.secret == Fr::from(0u64) {
        alien.secret += Fr::from(1u64);
    }
    let alien_root = crypto::field_hex(&crypto::credential_root(&alien)?);
    let authorization = crypto::prove(&member0.proving_key, &alien, &alien_root, &digest)?;
    assert!(crypto::verify(
        &member0.proving_key.vk,
        &alien_root,
        &digest,
        &authorization.proof,
        &authorization.tag
    )?);
    let wire = WireAuthorization {
        challenge,
        proof_base64: STANDARD.encode(authorization.proof),
        tag: authorization.tag,
    };
    rejected_and_burned(&mut state, &wire, "POST", "/records/tamper", b"original", 1);
    assert_eq!(state.execution_count(), 0);
    assert_eq!(state.mutation_count(), 0);
    assert_eq!(
        fs::read(&database)?,
        initial,
        "invalid authorization changed durable bytes"
    );
    drop(state);

    let listener = RunningListener::start(&provision.server_dir, &database)?;
    let http = client::http_client()?;
    let binary = [0u8, 255, 128, 1, 0];
    application(
        &member0,
        &listener.url,
        "POST",
        "alpha",
        &binary,
        201,
        Some(&binary),
    )?;
    application(
        &member1,
        &listener.url,
        "GET",
        "alpha",
        b"",
        200,
        Some(&binary),
    )?;
    application(
        &member1,
        &listener.url,
        "POST",
        "alpha",
        b"duplicate",
        409,
        None,
    )?;
    let maximum = (0..MAX_BODY).map(|index| index as u8).collect::<Vec<_>>();
    application(
        &member1,
        &listener.url,
        "PUT",
        "alpha",
        &maximum,
        200,
        Some(&maximum),
    )?;
    application(
        &member0,
        &listener.url,
        "GET",
        "alpha",
        b"",
        200,
        Some(&maximum),
    )?;
    application(
        &member1,
        &listener.url,
        "DELETE",
        "alpha",
        b"",
        200,
        Some(&maximum),
    )?;
    application(&member0, &listener.url, "GET", "alpha", b"", 404, None)?;
    application(
        &member0,
        &listener.url,
        "PUT",
        "alpha",
        b"missing",
        404,
        None,
    )?;
    application(&member0, &listener.url, "DELETE", "alpha", b"", 404, None)?;
    application(
        &member0,
        &listener.url,
        "POST",
        "empty",
        b"",
        201,
        Some(b""),
    )?;
    application(&member1, &listener.url, "GET", "empty", b"", 200, Some(b""))?;

    let challenge = issue_challenge(&http, &listener.url, &member0)?;
    let persisted = authorize(
        &member0,
        &challenge,
        "POST",
        "/records/persisted",
        b"survive",
    )?;
    let (status, body) = send_authorized(
        &http,
        &listener.url,
        &persisted,
        "POST",
        "/records/persisted",
        b"survive",
        false,
    )?;
    assert_eq!((status, body), (201, b"survive".to_vec()));
    assert_eq!(
        send_authorized(
            &http,
            &listener.url,
            &persisted,
            "POST",
            "/records/persisted",
            b"survive",
            false
        )?
        .0,
        401
    );
    let challenge = issue_challenge(&http, &listener.url, &member0)?;
    let changed = authorize(
        &member0,
        &challenge,
        "PUT",
        "/records/persisted",
        b"authorized",
    )?;
    assert_eq!(
        send_authorized(
            &http,
            &listener.url,
            &changed,
            "PUT",
            "/records/persisted",
            b"changed",
            false
        )?
        .0,
        401
    );
    application(
        &member1,
        &listener.url,
        "GET",
        "persisted",
        b"",
        200,
        Some(b"survive"),
    )?;

    let challenge = issue_challenge(&http, &listener.url, &member0)?;
    let duplicated = authorize(&member0, &challenge, "GET", "/records/persisted", b"")?;
    assert_eq!(
        send_authorized(
            &http,
            &listener.url,
            &duplicated,
            "GET",
            "/records/persisted",
            b"",
            true
        )?
        .0,
        401
    );
    assert_eq!(
        send_authorized(
            &http,
            &listener.url,
            &duplicated,
            "GET",
            "/records/persisted",
            b"",
            false
        )?
        .0,
        401,
        "malformed proof header did not burn its nonce"
    );
    let challenge = issue_challenge(&http, &listener.url, &member0)?;
    let missing_headers = authorize(&member0, &challenge, "GET", "/records/persisted", b"")?;
    assert_eq!(
        http.get(format!("{}/records/persisted", listener.url))
            .header(protocol::CHALLENGE_HEADER, &challenge.challenge_id)
            .send()?
            .status(),
        401
    );
    assert_eq!(
        send_authorized(
            &http,
            &listener.url,
            &missing_headers,
            "GET",
            "/records/persisted",
            b"",
            false
        )?
        .0,
        401,
        "missing proof/tag headers did not burn their recognized challenge"
    );
    let existing = http
        .get(format!("{}/records/persisted", listener.url))
        .send()?;
    let missing = http
        .get(format!("{}/records/not-present", listener.url))
        .send()?;
    assert_eq!(existing.status(), 401);
    assert_eq!(missing.status(), 401);
    assert_eq!(
        existing.bytes()?,
        missing.bytes()?,
        "unauthenticated requests disclosed record existence"
    );
    assert_eq!(
        http.get(format!("{}/records/persisted?query=1", listener.url))
            .send()?
            .status(),
        400
    );
    for path in ["/records/a%2Fb", "/records/a.b", "/records/%2e%2e"] {
        assert_eq!(
            http.get(format!("{}{path}", listener.url)).send()?.status(),
            404,
            "invalid record path reached authorization or storage"
        );
    }
    assert_eq!(
        http.get(format!("{}/records/persisted", listener.url))
            .header("Origin", "http://untrusted.invalid")
            .send()?
            .status(),
        403
    );
    assert_eq!(
        http.post(format!("{}/records/oversized", listener.url))
            .header("Content-Type", "application/octet-stream")
            .body(vec![0; MAX_BODY + 1])
            .send()?
            .status(),
        413
    );
    transport_bounds(&http, &listener.url)?;

    let old_challenge = issue_challenge(&http, &listener.url, &member0)?;
    let old_instance = authorize(&member0, &old_challenge, "GET", "/records/persisted", b"")?;
    let metrics = listener.finish()?;
    assert_eq!(metrics.executions, 13, "unverified requests reached CRUD");
    assert_eq!(
        metrics.attempts, 14,
        "replayed or malformed requests were reverified"
    );
    assert_eq!(metrics.mutations, 5);
    assert_eq!(metrics.revision, 5);

    let listener = RunningListener::start(&provision.server_dir, &database)?;
    assert_eq!(
        send_authorized(
            &http,
            &listener.url,
            &old_instance,
            "GET",
            "/records/persisted",
            b"",
            false
        )?
        .0,
        401
    );
    assert_eq!(
        send_authorized(
            &http,
            &listener.url,
            &persisted,
            "POST",
            "/records/persisted",
            b"survive",
            false
        )?
        .0,
        401
    );
    application(
        &member1,
        &listener.url,
        "GET",
        "persisted",
        b"",
        200,
        Some(b"survive"),
    )?;
    application(&member0, &listener.url, "GET", "empty", b"", 200, Some(b""))?;
    application(
        &member0,
        &listener.url,
        "PUT",
        "persisted",
        b"after-restart",
        200,
        Some(b"after-restart"),
    )?;
    application(
        &member1,
        &listener.url,
        "GET",
        "persisted",
        b"",
        200,
        Some(b"after-restart"),
    )?;
    let metrics = listener.finish()?;
    assert_eq!(
        (
            metrics.attempts,
            metrics.executions,
            metrics.mutations,
            metrics.revision
        ),
        (4, 4, 1, 6)
    );

    failed_commit(&provision.server_dir, &database, &member0)?;
    let saved = fs::read(&database)?;
    let mut wrong_profile: serde_json::Value = serde_json::from_slice(&saved)?;
    wrong_profile["profile_id"] = serde_json::Value::String("f".repeat(64));
    let wrong = serde_json::to_vec(&wrong_profile)?;
    fs::write(&database, &wrong)?;
    assert!(server::State::open(profile::load_server(&provision.server_dir)?, &database).is_err());
    assert_eq!(fs::read(&database)?, wrong);
    fs::write(&database, b"corrupt store")?;
    assert!(server::State::open(profile::load_server(&provision.server_dir)?, &database).is_err());
    assert_eq!(fs::read(&database)?, b"corrupt store");
    fs::write(&database, &saved)?;
    let recovered = server::State::open(profile::load_server(&provision.server_dir)?, &database)?;
    assert_eq!(recovered.revision(), 6);
    assert_eq!(fs::metadata(&database)?.permissions().mode() & 0o777, 0o600);
    eprintln!(
        "real Groth16 membership/CRUD/listener fixture completed in {:?}",
        started.elapsed()
    );
    Ok(())
}
