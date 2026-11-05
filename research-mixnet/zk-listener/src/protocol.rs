// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{CHALLENGE_LIFETIME, PROTOCOL, Result, fail};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHALLENGE_HEADER: &str = "x-zkweb-challenge";
pub const PROOF_HEADER: &str = "x-zkweb-proof";
pub const TAG_HEADER: &str = "x-zkweb-tag";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub protocol: String,
    pub profile_id: String,
    pub server_instance: String,
    pub challenge_id: String,
    pub expires_unix: u64,
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn random_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub fn valid_key(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
pub fn valid_method(value: &str) -> bool {
    matches!(value, "POST" | "GET" | "PUT" | "DELETE")
}
pub fn record_path(key: &str) -> Result<String> {
    if !valid_key(key) {
        return Err(fail(
            "record key must contain 1–128 ASCII letters, digits, underscores or hyphens",
        ));
    }
    Ok(format!("/records/{key}"))
}

impl Challenge {
    pub fn validate(&self, expected_profile: &str) -> Result<()> {
        let time = now()?;
        if self.protocol != PROTOCOL
            || self.profile_id != expected_profile
            || !valid_id(&self.profile_id)
            || !valid_id(&self.server_instance)
            || !valid_id(&self.challenge_id)
            || self.expires_unix <= time
            || self.expires_unix > time + CHALLENGE_LIFETIME
        {
            return Err(fail("invalid or expired authorization challenge"));
        }
        Ok(())
    }
}

/// The listener recomputes this transcript from its own challenge and the bytes it
/// actually executes. Public 128-bit circuit limbs preserve all 256 digest bits.
pub fn request_digest(challenge: &Challenge, method: &str, path: &str, body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"zkweb-authorized-http-request-v1\0");
    for field in [
        PROTOCOL,
        challenge.protocol.as_str(),
        challenge.profile_id.as_str(),
        challenge.server_instance.as_str(),
        challenge.challenge_id.as_str(),
        method,
        path,
    ] {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.update(challenge.expires_unix.to_be_bytes());
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_transcript_binds_exact_request_and_audience() {
        let challenge = Challenge {
            protocol: PROTOCOL.into(),
            profile_id: "a".repeat(64),
            server_instance: "b".repeat(64),
            challenge_id: "c".repeat(64),
            expires_unix: 123456,
        };
        let expected = request_digest(&challenge, "POST", "/records/a", b"binary\0\xff");
        for (method, path, body) in [
            ("PUT", "/records/a", &b"binary\0\xff"[..]),
            ("POST", "/records/b", &b"binary\0\xff"[..]),
            ("POST", "/records/a", &b"binary\0\xfe"[..]),
            ("POST", "/records/a", &b"binary\0\xff\0"[..]),
        ] {
            assert_ne!(request_digest(&challenge, method, path, body), expected);
        }
        for field in 0..5 {
            let mut changed = challenge.clone();
            match field {
                0 => changed.protocol.push('x'),
                1 => changed.profile_id = "d".repeat(64),
                2 => changed.server_instance = "d".repeat(64),
                3 => changed.challenge_id = "d".repeat(64),
                _ => changed.expires_unix += 1,
            }
            assert_ne!(
                request_digest(&changed, "POST", "/records/a", b"binary\0\xff"),
                expected
            );
        }
        assert_ne!(
            request_digest(&challenge, "POST", "/records/ab", b"c"),
            request_digest(&challenge, "POST", "/records/a", b"bc"),
        );
    }
}
