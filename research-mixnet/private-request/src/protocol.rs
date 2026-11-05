// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{PROTOCOL, Result, fail};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const LIFETIME: u64 = 120;
pub const MAX_CHALLENGES: usize = 1024;
pub const FUNCTION: &str = "lookup-four-u8-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub protocol: String,
    pub profile_id: String,
    pub server_instance: String,
    pub challenge_id: String,
    pub expires_unix: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub challenge_id: String,
    pub proof_base64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryResult {
    pub protocol: String,
    pub profile_id: String,
    pub server_instance: String,
    pub challenge_id: String,
    pub ciphertext_base64: String,
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn random_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Challenge {
    pub fn validate(&self, profile_id: &str) -> Result<()> {
        let time = now()?;
        if self.protocol != PROTOCOL
            || self.profile_id != profile_id
            || !valid_id(&self.server_instance)
            || !valid_id(&self.challenge_id)
            || self.expires_unix <= time
            || self.expires_unix > time + LIFETIME
        {
            return Err(fail("invalid or expired challenge"));
        }
        Ok(())
    }

    /// Fixed field order and length prefixes make the ZK context unambiguous.
    pub fn metadata(&self) -> Vec<u8> {
        let mut output = b"zkweb-private-proof-context-v1\0".to_vec();
        for field in [
            self.protocol.as_str(),
            FUNCTION,
            self.profile_id.as_str(),
            self.server_instance.as_str(),
            self.challenge_id.as_str(),
        ] {
            output.extend_from_slice(&(field.len() as u32).to_be_bytes());
            output.extend_from_slice(field.as_bytes());
        }
        output.extend_from_slice(&self.expires_unix.to_be_bytes());
        output
    }
}
