// SPDX-License-Identifier: AGPL-3.0-or-later
//! Groth16 group authorization for exact, challenge-bound HTTP CRUD requests.
pub mod client;
pub mod crypto;
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

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
pub fn fail(message: &'static str) -> Error {
    message.into()
}
