// SPDX-License-Identifier: AGPL-3.0-or-later
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};
use zkweb_tlsn_verify::{
    ByteRange, MAX_TRANSCRIPT_BYTES, Policy, VerifiedOutput, verify, verify_json,
};

const KEY: &str = "035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c";
const TIME: u64 = 1_671_637_529;
const FIXTURE: &[u8] = include_bytes!("fixtures/presentation.json");

fn policy() -> Policy {
    Policy {
        server_name: "tlsnotary.org".into(),
        notary_key_hex: KEY.into(),
        min_time: TIME,
        max_time: TIME,
        sent_ranges: vec![],
        received_ranges: vec![],
    }
}

fn request(presentation: &[u8], policy: &Policy) -> Vec<u8> {
    serde_json::to_vec(&json!({"format":"zkweb-tlsn-verify-v1", "presentation_base64": STANDARD.encode(presentation), "policy": policy})).unwrap()
}

fn mutate_fixture(f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(FIXTURE).unwrap();
    f(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn upstream_fixture_provenance_is_pinned() {
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "fixtures/upstream-presentation.bin"
        ))),
        "cb9b3befb43df5157a4d5ac52080ba19d842f191fa346bfda1dfc4927b37e5b6"
    );
    assert_eq!(
        hex::encode(Sha256::digest(FIXTURE)),
        "1e1532e257963f258dca3aaa6927d3a423e79ffd4f9b6f7f5a2fc35edad585f8"
    );
}

#[test]
fn standalone_binary_returns_static_errors_without_artifact_data() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zkweb-tlsn-verify"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"secret":"do-not-print-this-fixture-value"}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"zkweb-tlsn-verify: verification failed\n");
}

#[test]
fn real_upstream_signature_certificate_and_commitments_verify_offline() {
    let bytes = verify_json(&request(FIXTURE, &policy())).unwrap();
    let output: VerifiedOutput = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(output.format, "zkweb-tlsn-verified-v1");
    assert_eq!(output.backend_commit, zkweb_tlsn_verify::BACKEND_COMMIT);
    assert_eq!(output.server_name, "tlsnotary.org");
    assert_eq!(output.notary_key_hex, KEY);
    assert_eq!(output.time, TIME);
    assert_eq!(output.sent_length, 35);
    assert_eq!(output.received_length, 145);
    assert!(output.sent.is_empty() && output.received.is_empty());
    assert!(!String::from_utf8(bytes).unwrap().contains("cookie"));
}

#[test]
fn only_explicit_authenticated_byte_ranges_are_returned() {
    let mut policy = policy();
    policy.sent_ranges = vec![ByteRange { start: 0, end: 3 }];
    policy.received_ranges = vec![ByteRange { start: 0, end: 8 }];
    let output = verify(&STANDARD.encode(FIXTURE), &policy).unwrap();
    assert_eq!(output.sent.len(), 1);
    assert_eq!(
        STANDARD.decode(&output.sent[0].data_base64).unwrap(),
        b"GET"
    );
    assert_eq!(output.received.len(), 1);
    assert_eq!(
        STANDARD.decode(&output.received[0].data_base64).unwrap(),
        b"HTTP/1.1"
    );
}

#[test]
fn wrong_key_domain_and_time_fail() {
    let mut wrong_key = policy();
    wrong_key.notary_key_hex = format!("02{}", &KEY[2..]);
    let mut wrong_domain = policy();
    wrong_domain.server_name = "other.example".into();
    let mut stale = policy();
    stale.min_time = TIME + 1;
    stale.max_time = TIME + 10;
    let mut future = policy();
    future.min_time = TIME - 10;
    future.max_time = TIME - 1;
    for policy in [wrong_key, wrong_domain, stale, future] {
        assert!(verify(&STANDARD.encode(FIXTURE), &policy).is_err());
    }
}

#[test]
fn tampered_signature_transcript_identity_and_missing_proofs_fail() {
    let paths = [
        "/attestation/signature/data/0",
        "/transcript/transcript/received_authed/0",
        "/identity/opening/data/binding/v1_2/client_random/0",
    ];
    for path in paths {
        let bytes = mutate_fixture(|value| {
            let slot = value.pointer_mut(path).unwrap();
            *slot = json!((slot.as_u64().unwrap() + 1) % 256);
        });
        assert!(
            verify(&STANDARD.encode(bytes), &policy()).is_err(),
            "tamper accepted: {path}"
        );
    }
    for field in ["identity", "transcript"] {
        let bytes = mutate_fixture(|value| value[field] = Value::Null);
        assert!(verify(&STANDARD.encode(bytes), &policy()).is_err());
    }
    let unsupported = mutate_fixture(|value| {
        value["attestation"]["body"]["body"]["verifying_key"]["data"]["alg"] = json!(2)
    });
    assert!(verify(&STANDARD.encode(unsupported), &policy()).is_err());
}

#[test]
fn sparse_transcript_expansion_is_rejected_before_typed_deserialization() {
    for path in [
        "/transcript/transcript/sent_total",
        "/transcript/transcript/recv_total",
        "/attestation/body/body/connection_info/data/transcript_length/sent",
        "/attestation/body/body/connection_info/data/transcript_length/received",
    ] {
        let bytes = mutate_fixture(|value| *value.pointer_mut(path).unwrap() = json!(usize::MAX));
        assert!(verify(&STANDARD.encode(bytes), &policy()).is_err());
    }
    let bytes =
        mutate_fixture(|value| value["transcript"]["hash_secrets"] = json!(vec![Value::Null; 257]));
    assert!(verify(&STANDARD.encode(bytes), &policy()).is_err());
}

#[test]
fn malformed_duplicate_unknown_trailing_and_binary_inputs_fail() {
    let valid = request(FIXTURE, &policy());
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b" {}");
    let mut duplicate: Value = serde_json::from_slice(&valid).unwrap();
    duplicate["unknown"] = json!(true);
    for input in [
        b"null".to_vec(),
        b"{}".to_vec(),
        trailing,
        serde_json::to_vec(&duplicate).unwrap(),
        b"{\"format\":\"x\",\"format\":\"y\"}".to_vec(),
    ] {
        assert!(verify_json(&input).is_err());
    }
    let mut duplicated_inner = FIXTURE.to_vec();
    duplicated_inner.splice(1..1, b"\"identity\":null,".iter().copied());
    assert!(verify(&STANDARD.encode(duplicated_inner), &policy()).is_err());
    assert!(
        verify(
            &STANDARD.encode(include_bytes!("fixtures/upstream-presentation.bin")),
            &policy()
        )
        .is_err()
    );
    assert!(verify("not+base64!", &policy()).is_err());
    assert!(verify(&format!("{}\n", STANDARD.encode(FIXTURE)), &policy()).is_err());
}

#[test]
fn invalid_policies_and_range_limits_fail() {
    let mut cases = Vec::new();
    let mut zero = policy();
    zero.min_time = 0;
    cases.push(zero);
    let mut reverse = policy();
    reverse.max_time = TIME - 1;
    cases.push(reverse);
    let mut upper = policy();
    upper.notary_key_hex = KEY.to_ascii_uppercase();
    cases.push(upper);
    let mut empty = policy();
    empty.received_ranges = vec![ByteRange { start: 1, end: 1 }];
    cases.push(empty);
    let mut overlap = policy();
    overlap.sent_ranges = vec![
        ByteRange { start: 0, end: 3 },
        ByteRange { start: 2, end: 4 },
    ];
    cases.push(overlap);
    let mut outside = policy();
    outside.sent_ranges = vec![ByteRange { start: 0, end: 36 }];
    cases.push(outside);
    let mut oversized = policy();
    oversized.sent_ranges = vec![ByteRange {
        start: 0,
        end: MAX_TRANSCRIPT_BYTES + 1,
    }];
    cases.push(oversized);
    let mut count = policy();
    count.sent_ranges = vec![ByteRange { start: 0, end: 1 }; 65];
    cases.push(count);
    let mut total = policy();
    total.sent_ranges = vec![ByteRange {
        start: 0,
        end: MAX_TRANSCRIPT_BYTES,
    }];
    total.received_ranges = vec![ByteRange { start: 0, end: 1 }];
    cases.push(total);
    for policy in cases {
        assert!(verify(&STANDARD.encode(FIXTURE), &policy).is_err());
    }
}

#[test]
fn redacted_bytes_cannot_be_selected_even_in_an_otherwise_valid_proof() {
    let presentation = partial_fixture();
    let encoded = STANDARD.encode(serde_json::to_vec(&presentation).unwrap());
    let mut partial = policy();
    partial.sent_ranges = vec![ByteRange { start: 0, end: 3 }];
    partial.received_ranges = vec![ByteRange { start: 0, end: 8 }];
    assert!(verify(&encoded, &partial).is_ok());
    partial.received_ranges[0].end = 9;
    assert!(verify(&encoded, &partial).is_err());
    partial.received_ranges.clear();
    partial.sent_ranges[0].end = 4;
    assert!(verify(&encoded, &partial).is_err());
}

// A genuine selective presentation signed with the public upstream fixture
// key. Construction adapts TLSN's alpha.15 fixture generator (see provenance).
fn partial_fixture() -> tlsn_attestation::presentation::Presentation {
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rangeset::set::RangeSet;
    use tlsn_attestation::{
        Attestation, AttestationConfig, CryptoProvider,
        request::{Request, RequestConfig},
        signing::SignatureAlgId,
    };
    use tlsn_core::{
        connection::{CertBinding, CertBindingV1_2},
        fixtures::ConnectionFixture,
        hash::{Blake3, Blinder, HashAlgId},
        transcript::{
            Direction, Transcript, TranscriptCommitment, TranscriptSecret,
            hash::{PlaintextHash, PlaintextHashSecret, hash_plaintext},
        },
    };
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    let mut rng = StdRng::seed_from_u64(0);
    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1(&[42; 32]).unwrap();
    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let connection = ConnectionFixture::tlsnotary(transcript.length());
    let CertBinding::V1_2(CertBindingV1_2 {
        server_ephemeral_key,
        ..
    }) = connection.server_cert_data.binding.clone()
    else {
        panic!("upstream fixture must use TLS1.2")
    };
    let hasher = Blake3::default();
    let mut secrets = Vec::new();
    let mut commitments = Vec::new();
    for (direction, idx, data) in [
        (Direction::Sent, 0..3, &transcript.sent()[0..3]),
        (Direction::Received, 0..8, &transcript.received()[0..8]),
    ] {
        let blinder: Blinder = rng.random();
        let idx = RangeSet::from(idx);
        let hash = hash_plaintext(&hasher, data, &blinder);
        secrets.push(TranscriptSecret::Hash(PlaintextHashSecret {
            direction,
            idx: idx.clone(),
            alg: HashAlgId::BLAKE3,
            blinder,
        }));
        commitments.push(TranscriptCommitment::Hash(PlaintextHash {
            direction,
            idx,
            hash,
        }));
    }
    let config = RequestConfig::default();
    let mut builder = Request::builder(&config);
    builder
        .server_name(connection.server_name)
        .handshake_data(connection.server_cert_data)
        .transcript(transcript)
        .transcript_commitments(secrets, commitments.clone());
    let (request, secrets) = builder.build(&provider).unwrap();
    let config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();
    let mut builder = Attestation::builder(&config)
        .accept_request(request)
        .unwrap();
    builder
        .connection_info(connection.connection_info)
        .server_ephemeral_key(server_ephemeral_key)
        .transcript_commitments(commitments);
    let attestation = builder.build(&provider).unwrap();
    let mut proof = secrets.transcript_proof_builder();
    proof
        .reveal(&(0..3), Direction::Sent)
        .unwrap()
        .reveal(&(0..8), Direction::Received)
        .unwrap();
    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(proof.build().unwrap());
    builder.build().unwrap()
}
