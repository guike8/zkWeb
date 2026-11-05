// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verify API authorization before any upstream connection is attempted.
use base64::{Engine, engine::general_purpose::STANDARD};
use zkweb_zk_listener::{Result, crypto, forward, profile, protocol, server};

#[test]
fn api_proofs_bind_upstream_method_query_headers_body_and_one_use_challenge() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let setup = profile::setup(&temporary.path().join("profile"), 1)?;
    let client = profile::load_client(&setup.client_dirs[0])?;
    // No send() is performed in this test. This literal selects a local policy
    // realm without relying on DNS or contacting a real external service.
    let origin = "https://127.0.0.1:9443";
    let config = forward::Config {
        origin: origin.into(),
        allowed_methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        path_prefix: "/v1".into(),
        allow_private: true,
        ca_file: None,
        headers_file: None,
    };
    let mut state = server::State::open_gateway(profile::load_server(&setup.server_dir)?, config)?;
    let headers = protocol::canonical_api_headers(&[
        protocol::ApiHeader {
            name: "content-type".into(),
            value: "application/octet-stream".into(),
        },
        protocol::ApiHeader {
            name: "x-test".into(),
            value: "first".into(),
        },
    ])?;
    let path = "/v1/items?q=one%20two";
    let body = b"binary\0\xff";

    for changed in 0..9 {
        let challenge = state.challenge()?;
        assert_eq!(challenge.upstream_origin.as_deref(), Some(origin));
        let mut signed_challenge = challenge.clone();
        let signed_origin = if changed == 6 {
            "https://other.example.com"
        } else {
            origin
        };
        if changed == 7 {
            signed_challenge.upstream_origin = None;
        }
        let digest = if changed == 8 {
            protocol::request_digest(&signed_challenge, "POST", path, body)
        } else {
            protocol::api_request_digest(
                &signed_challenge,
                signed_origin,
                "POST",
                path,
                &headers,
                body,
            )
        };
        let proof = crypto::prove(
            &client.proving_key,
            &client.credential,
            &client.manifest.group_root,
            &digest,
        )?;
        let mut proof_bytes = proof.proof;
        let mut tag = proof.tag;
        let method = if changed == 0 { "PUT" } else { "POST" };
        let actual_path = if changed == 1 {
            "/v1/items?q=changed"
        } else {
            path
        };
        let mut actual_headers = headers.clone();
        if changed == 2 {
            actual_headers[1].value = "changed".into();
        }
        let actual_body = if changed == 3 {
            &b"binary\0\xfe"[..]
        } else {
            &body[..]
        };
        if changed == 4 {
            tag = "0".repeat(64);
        }
        if changed == 5 {
            proof_bytes[40] ^= 1;
        }
        let encoded_proof = STANDARD.encode(proof_bytes);
        let encoded_path = STANDARD.encode(actual_path);
        let encoded_headers = STANDARD.encode(serde_json::to_vec(&actual_headers)?);
        assert!(
            state
                .prepare_api(
                    &challenge.challenge_id,
                    method,
                    &encoded_path,
                    &encoded_headers,
                    actual_body,
                    &encoded_proof,
                    &tag
                )
                .is_err(),
            "accepted changed API field {changed}"
        );
        assert_eq!(
            state.execution_count(),
            0,
            "invalid API proof reached dispatch"
        );
        let attempts = state.verification_attempt_count();
        assert!(
            state
                .prepare_api(
                    &challenge.challenge_id,
                    method,
                    &encoded_path,
                    &encoded_headers,
                    actual_body,
                    &encoded_proof,
                    &tag
                )
                .is_err()
        );
        assert_eq!(
            state.verification_attempt_count(),
            attempts,
            "a failed nonce verified twice"
        );
    }

    let challenge = state.challenge()?;
    let digest = protocol::api_request_digest(&challenge, origin, "POST", path, &headers, body);
    let proof = crypto::prove(
        &client.proving_key,
        &client.credential,
        &client.manifest.group_root,
        &digest,
    )?;
    let encoded_proof = STANDARD.encode(proof.proof);
    let encoded_path = STANDARD.encode(path);
    let encoded_headers = STANDARD.encode(serde_json::to_vec(&headers)?);
    let authorized = state.prepare_api(
        &challenge.challenge_id,
        "POST",
        &encoded_path,
        &encoded_headers,
        body,
        &encoded_proof,
        &proof.tag,
    )?;
    drop(authorized);
    assert_eq!(state.execution_count(), 1);
    let attempts = state.verification_attempt_count();
    assert!(
        state
            .prepare_api(
                &challenge.challenge_id,
                "POST",
                &encoded_path,
                &encoded_headers,
                body,
                &encoded_proof,
                &proof.tag
            )
            .is_err()
    );
    assert_eq!(state.verification_attempt_count(), attempts);

    let challenge = state.challenge()?;
    assert!(
        state
            .prepare_api(
                &challenge.challenge_id,
                "POST",
                "!invalid",
                &encoded_headers,
                body,
                &encoded_proof,
                &proof.tag
            )
            .is_err()
    );
    let attempts = state.verification_attempt_count();
    assert!(
        state
            .prepare_api(
                &challenge.challenge_id,
                "POST",
                &encoded_path,
                &encoded_headers,
                body,
                &encoded_proof,
                &proof.tag
            )
            .is_err()
    );
    assert_eq!(state.verification_attempt_count(), attempts);
    assert_eq!(state.execution_count(), 1);
    Ok(())
}
