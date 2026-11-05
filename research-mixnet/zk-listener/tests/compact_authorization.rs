// SPDX-License-Identifier: AGPL-3.0-or-later
use zkweb_zk_listener::{Result, compact, crypto, forward, profile, protocol, server};

#[test]
fn compact_records_burn_malformed_nonces_before_verification_and_preserve_crud() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let setup = profile::setup(&directory.path().join("profile"), 2)?;
    let member = profile::load_client(&setup.client_dirs[0])?;
    let mut state = server::State::open(
        profile::load_server(&setup.server_dir)?,
        &directory.path().join("records.json"),
    )?;
    for changed in 0..6 {
        let issued = state.challenge()?;
        let challenge = compact::decode_challenge(
            &compact::encode_challenge(&issued)?,
            &member.manifest.profile_id,
            None,
        )?;
        let body = b"binary\0\xff";
        let digest = protocol::request_digest(&challenge, "POST", "/records/a", body);
        let authorization = crypto::prove(
            &member.proving_key,
            &member.credential,
            &member.manifest.group_root,
            &digest,
        )?;
        let correct = compact::encode_request(
            compact::Kind::Records,
            &challenge.challenge_id,
            &authorization,
            "POST",
            "a",
            &[],
            body,
        )?;
        let mut malformed = correct.clone();
        match changed {
            0 => malformed.truncate(32),
            1 => malformed.truncate(191),
            2 => malformed[192] = 255,
            3 => {
                malformed.splice(193..194, [0x81, 0]);
            }
            4 => malformed[32..64].fill(255),
            5 => malformed[194] = b'/',
            _ => unreachable!(),
        }
        let attempts = state.verification_attempt_count();
        assert!(
            state.execute_compact(&malformed).is_err(),
            "accepted malformed field {changed}"
        );
        assert_eq!(
            state.verification_attempt_count(),
            attempts,
            "malformed frame reached crypto"
        );
        assert!(
            state.execute_compact(&correct).is_err(),
            "malformed attempt left a reusable nonce"
        );
        assert_eq!(state.verification_attempt_count(), attempts);
        assert_eq!(state.execution_count(), 0);
        assert_eq!(state.mutation_count(), 0);
        assert_eq!(state.revision(), 0);
    }
    for (method, body, status) in [
        ("POST", &b"first\0\xff"[..], 201),
        ("GET", &b""[..], 200),
        ("PUT", &b"second\0\xfe"[..], 200),
        ("DELETE", &b""[..], 200),
        ("GET", &b""[..], 404),
    ] {
        let challenge = state.challenge()?;
        let digest = protocol::request_digest(&challenge, method, "/records/a", body);
        let authorization = crypto::prove(
            &member.proving_key,
            &member.credential,
            &member.manifest.group_root,
            &digest,
        )?;
        let frame = compact::encode_request(
            compact::Kind::Records,
            &challenge.challenge_id,
            &authorization,
            method,
            "a",
            &[],
            body,
        )?;
        assert_eq!(frame.len(), 195 + body.len());
        let reply = state.execute_compact(&frame)?;
        assert_eq!(reply.status, status);
        if method == "GET" && status == 200 {
            assert_eq!(reply.body, b"first\0\xff");
        }
        let attempts = state.verification_attempt_count();
        assert!(state.execute_compact(&frame).is_err());
        assert_eq!(state.verification_attempt_count(), attempts);
    }
    assert_eq!(state.execution_count(), 5);
    assert_eq!(state.mutation_count(), 3);
    Ok(())
}

#[test]
fn compact_gateway_keeps_omitted_profile_and_origin_bound_to_proof() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let setup = profile::setup(&directory.path().join("profile"), 1)?;
    let member = profile::load_client(&setup.client_dirs[0])?;
    let origin = "https://127.0.0.1:9443";
    let mut state = server::State::open_gateway(
        profile::load_server(&setup.server_dir)?,
        forward::Config {
            origin: origin.into(),
            allowed_methods: vec!["GET".into()],
            path_prefix: "/v1".into(),
            allow_private: true,
            ca_file: None,
            headers_file: None,
        },
    )?;
    for changed in 0..3 {
        let issued = state.challenge()?;
        let expected_profile = if changed == 0 {
            "a".repeat(64)
        } else {
            member.manifest.profile_id.clone()
        };
        let expected_origin = if changed == 1 {
            "https://different.example"
        } else {
            origin
        };
        let challenge = compact::decode_challenge(
            &compact::encode_challenge(&issued)?,
            &expected_profile,
            Some(expected_origin),
        )?;
        let digest =
            protocol::api_request_digest(&challenge, expected_origin, "GET", "/v1", &[], &[]);
        let authorization = crypto::prove(
            &member.proving_key,
            &member.credential,
            &member.manifest.group_root,
            &digest,
        )?;
        let frame = compact::encode_request(
            compact::Kind::Api,
            &challenge.challenge_id,
            &authorization,
            "GET",
            "/v1",
            &[],
            &[],
        )?;
        if changed < 2 {
            assert!(
                state.prepare_api_compact(&frame).is_err(),
                "omitted context lost its proof binding"
            );
            assert_eq!(state.execution_count(), 0);
        } else {
            drop(state.prepare_api_compact(&frame)?);
            assert_eq!(state.execution_count(), 1);
        }
        let attempts = state.verification_attempt_count();
        assert!(state.prepare_api_compact(&frame).is_err());
        assert_eq!(state.verification_attempt_count(), attempts);
    }
    // No upstream send() was called: this checks verified dispatch preparation.
    Ok(())
}
