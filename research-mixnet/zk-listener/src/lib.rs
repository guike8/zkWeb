// SPDX-License-Identifier: AGPL-3.0-or-later
//! Groth16 group authorization for exact, challenge-bound HTTP CRUD requests.
pub mod client;
pub mod compact;
pub mod crypto;
pub mod forward;
pub mod profile;
pub mod protocol;
pub mod server;
pub mod storage;

pub const PROTOCOL: &str = "zkweb-zk-authorized-crud-v1";
pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_DB: usize = 128 * 1024 * 1024;
pub const MAX_CHALLENGES: usize = 1024;
pub const CHALLENGE_LIFETIME: u64 = 120;
pub const PROOF_BYTES: usize = 128;
pub const MAX_API_BODY: usize = 1024 * 1024;
pub const MAX_API_RESPONSE: usize = 1024 * 1024;
pub const MAX_API_ENVELOPE: usize = 3 * 1024 * 1024;
pub const MAX_API_HEADERS: usize = 32;
pub const MAX_API_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_API_PATH: usize = 8 * 1024;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
pub fn fail(message: &'static str) -> Error {
    message.into()
}
