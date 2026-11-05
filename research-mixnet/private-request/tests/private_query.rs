// SPDX-License-Identifier: AGPL-3.0-or-later
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tfhe::{ProvenCompactCiphertextList, zk::ZkComputeLoad};
use zkweb_private::{MAX_PROOF, client, crypto, profile, protocol::Query, server};

fn query(challenge: &zkweb_private::protocol::Challenge, proof: Vec<u8>) -> Query {
    Query {
        challenge_id: challenge.challenge_id.clone(),
        proof_base64: STANDARD.encode(proof),
    }
}

fn rejected_and_burned(state: &mut server::State, query: &Query) {
    assert!(state.execute(query).is_err());
    let attempts = state.verification_attempt_count();
    assert!(state.execute(query).is_err());
    assert_eq!(
        state.verification_attempt_count(),
        attempts,
        "a failed nonce must not verify twice"
    );
    assert_eq!(
        state.evaluation_count(),
        0,
        "invalid proofs must not execute"
    );
}

fn raw_bounded(url: &str, request: &[u8], timeout: Duration) -> zkweb_private::Result<()> {
    let address = url.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(timeout))?;
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
    let mut response = Vec::new();
    match stream.take(16 * 1024).read_to_end(&mut response) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn transport_bounds(url: &str) -> zkweb_private::Result<()> {
    raw_bounded(
        url,
        b"GET /challenge HTTP/1.1\r\nHost: localhost\r\nX-Stalled:",
        Duration::from_secs(8),
    )?;
    raw_bounded(url, b"POST /query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{", Duration::from_secs(13))?;
    let oversized = format!(
        "GET /challenge HTTP/1.1\r\nHost: localhost\r\nX-Large: {}\r\n\r\n",
        "a".repeat(20 * 1024)
    );
    raw_bounded(url, oversized.as_bytes(), Duration::from_secs(3))?;
    let too_many = format!(
        "GET /challenge HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
        "X-Header: a\r\n".repeat(40)
    );
    raw_bounded(url, too_many.as_bytes(), Duration::from_secs(3))?;
    assert_eq!(
        client::http_client()?
            .get(format!("{url}/challenge"))
            .send()?
            .status(),
        200
    );
    Ok(())
}

#[test]
fn real_zk_fhe_fixture_and_http() -> zkweb_private::Result<()> {
    let started = std::time::Instant::now();
    let temporary = tempfile::tempdir()?;
    let provision = profile::setup(&temporary.path().join("profile"))?;
    eprintln!("trusted setup completed in {:?}", started.elapsed());
    assert!(profile::setup(&temporary.path().join("profile")).is_err());
    let names = fs::read_dir(&provision.server_dir)?
        .map(|p| p.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 4);
    assert!(!names.iter().any(|n| n == "client-key.tfhe"));
    let server_manifest = fs::read_to_string(provision.server_dir.join("manifest.json"))?;
    assert!(!server_manifest.contains("client_key_sha256"));
    use std::os::unix::fs::PermissionsExt;
    for directory in [&provision.client_dir, &provision.server_dir] {
        assert_eq!(fs::metadata(directory)?.permissions().mode() & 0o777, 0o700);
        for entry in fs::read_dir(directory)? {
            assert_eq!(entry?.metadata()?.permissions().mode() & 0o777, 0o600);
        }
    }
    let client_profile = profile::load_client(&provision.client_dir)?;
    let mut state = server::State::new(profile::load_server(&provision.server_dir)?);
    let challenge = state.challenge()?;
    let bad_context = crypto::prove(
        0,
        &client_profile.public.public_key,
        &client_profile.public.crs,
        b"wrong-context",
    )?;
    rejected_and_burned(&mut state, &query(&challenge, bad_context));
    let challenge = state.challenge()?;
    let mut tampered = crypto::prove(
        0,
        &client_profile.public.public_key,
        &client_profile.public.crs,
        &challenge.metadata(),
    )?;
    let position = tampered.len() / 2;
    tampered[position] ^= 1;
    rejected_and_burned(&mut state, &query(&challenge, tampered));
    let challenge = state.challenge()?;
    let empty = ProvenCompactCiphertextList::builder(&client_profile.public.public_key)
        .build_with_proof_packed(
            &client_profile.public.crs,
            &challenge.metadata(),
            ZkComputeLoad::Proof,
        )?;
    rejected_and_burned(
        &mut state,
        &query(&challenge, crypto::serialize(&empty, MAX_PROOF)?),
    );
    let challenge = state.challenge()?;
    let boolean = ProvenCompactCiphertextList::builder(&client_profile.public.public_key)
        .push(true)
        .build_with_proof_packed(
            &client_profile.public.crs,
            &challenge.metadata(),
            ZkComputeLoad::Proof,
        )?;
    rejected_and_burned(
        &mut state,
        &query(&challenge, crypto::serialize(&boolean, MAX_PROOF)?),
    );
    let challenge = state.challenge()?;
    let two = ProvenCompactCiphertextList::builder(&client_profile.public.public_key)
        .push_with_num_bits(0u8, 2)?
        .push_with_num_bits(1u8, 2)?
        .build_with_proof_packed(
            &client_profile.public.crs,
            &challenge.metadata(),
            ZkComputeLoad::Proof,
        )?;
    rejected_and_burned(
        &mut state,
        &query(&challenge, crypto::serialize(&two, MAX_PROOF)?),
    );
    // This is a well-formed upstream proof under the same keys, but an unaccepted
    // compute-load mode. Conformance rejects it before verify_and_expand.
    let challenge = state.challenge()?;
    let verifier_heavy = ProvenCompactCiphertextList::builder(&client_profile.public.public_key)
        .push_with_num_bits(0u8, 2)?
        .build_with_proof_packed(
            &client_profile.public.crs,
            &challenge.metadata(),
            ZkComputeLoad::Verify,
        )?;
    let verifier_heavy = crypto::serialize(&verifier_heavy, MAX_PROOF)?;
    assert!(
        crypto::verify_selector(
            &verifier_heavy,
            &client_profile.public.public_key,
            &client_profile.public.crs,
            &challenge.metadata()
        )
        .is_err()
    );
    rejected_and_burned(&mut state, &query(&challenge, verifier_heavy));
    // A safe-serialized object of an unaccepted type cannot enter the evaluator either.
    let challenge = state.challenge()?;
    rejected_and_burned(
        &mut state,
        &query(
            &challenge,
            crypto::serialize(&client_profile.public.public_key, MAX_PROOF)?,
        ),
    );
    let challenge = state.challenge()?;
    rejected_and_burned(
        &mut state,
        &Query {
            challenge_id: challenge.challenge_id,
            proof_base64: "!invalid".into(),
        },
    );
    assert_eq!(
        state.evaluation_count(),
        0,
        "invalid proofs must never execute the lookup"
    );
    let challenge = state.challenge()?;
    let good = crypto::prove(
        0,
        &client_profile.public.public_key,
        &client_profile.public.crs,
        &challenge.metadata(),
    )?;
    let first_query = query(&challenge, good);
    let wire = serde_json::to_value(&first_query)?;
    let object = wire.as_object().unwrap();
    assert_eq!(object.len(), 2);
    assert!(object.contains_key("challenge_id") && object.contains_key("proof_base64"));
    assert!(!object.contains_key("index") && !object.contains_key("client_key"));
    let first = state.execute(&first_query)?;
    assert_eq!(
        crypto::decrypt(
            &STANDARD.decode(first.ciphertext_base64)?,
            &client_profile.client_key
        )?,
        11
    );
    let attempts = state.verification_attempt_count();
    assert!(state.execute(&first_query).is_err());
    assert_eq!(state.verification_attempt_count(), attempts);
    assert_eq!(state.evaluation_count(), 1, "replays must never execute");
    for (index, expected) in [(1, 22), (2, 33), (3, 44)] {
        let challenge = state.challenge()?;
        let proof = crypto::prove(
            index,
            &client_profile.public.public_key,
            &client_profile.public.crs,
            &challenge.metadata(),
        )?;
        let response = state.execute(&query(&challenge, proof))?;
        assert_eq!(
            crypto::decrypt(
                &STANDARD.decode(response.ciphertext_base64)?,
                &client_profile.client_key
            )?,
            expected
        );
    }
    assert_eq!(state.evaluation_count(), 4);
    for _ in 0..zkweb_private::protocol::MAX_CHALLENGES {
        state.challenge()?;
    }
    assert!(
        state.challenge().is_err(),
        "challenge cache must be bounded"
    );
    drop(state);
    tfhe::unset_server_key();
    let listener = server::bind("127.0.0.1:0")?;
    let url = server::url(&listener)?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let server_dir = provision.server_dir.clone();
    let worker = thread::spawn(move || -> zkweb_private::Result<u64> {
        let mut state = server::State::new(profile::load_server(&server_dir)?);
        server::run(&listener, &mut state, Some(&worker_stop))?;
        Ok(state.evaluation_count())
    });
    let result = client::query(&client_profile, &url, 3);
    let transport = if result.is_ok() {
        transport_bounds(&url)
    } else {
        Ok(())
    };
    stop.store(true, Ordering::Relaxed);
    let count = worker.join().unwrap()?;
    let result = result?;
    transport?;
    assert_eq!(count, 1);
    assert_eq!(result.value, 44);
    eprintln!(
        "real proof/FHE/HTTP fixture completed in {:?}",
        started.elapsed()
    );
    Ok(())
}

#[test]
fn strict_schemas_and_loopback_urls() {
    for url in [
        "https://127.0.0.1:80",
        "http://localhost:80",
        "http://127.0.0.1.evil:80",
        "http://127.1:80",
        "http://2130706433:80",
        "http://user@127.0.0.1:80",
        "http://127.0.0.1:80/x",
        "http://127.0.0.1:80?index=2",
        "http://1.2.3.4:80",
    ] {
        assert!(client::validated_url(url).is_err(), "accepted {url}");
    }
    assert!(client::validated_url("http://127.0.0.1:5000").is_ok());
    assert!(client::validated_url("http://127.0.0.1:80").is_ok());
    assert!(client::validated_url("http://[::1]:5000").is_ok());
    assert!(server::bind("0.0.0.0:0").is_err());
    assert!(server::bind("localhost:0").is_err());
    assert!(
        serde_json::from_str::<Query>(r#"{"challenge_id":"a","proof_base64":"b","index":0}"#)
            .is_err()
    );
    let expired = zkweb_private::protocol::Challenge {
        protocol: zkweb_private::PROTOCOL.into(),
        profile_id: "a".repeat(64),
        server_instance: "b".repeat(64),
        challenge_id: "c".repeat(64),
        expires_unix: 0,
    };
    assert!(expired.validate(&"a".repeat(64)).is_err());
}
