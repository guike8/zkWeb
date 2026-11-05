// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private cooperative lookup: ZK-proven encryption, FHE evaluation and local decryption.

pub mod client;
pub mod crypto;
pub mod profile;
pub mod protocol;
pub mod server;

pub const PROTOCOL: &str = "zkweb-private-query-v1";
pub const TFHE_VERSION: &str = "1.8.2";
pub const MAX_WIRE: usize = 8 * 1024 * 1024;
pub const MAX_KEY: usize = 2 * 1024 * 1024 * 1024;
pub const MAX_CRS: usize = 32 * 1024 * 1024;
pub const MAX_PROOF: usize = 4 * 1024 * 1024;
pub const MAX_RESULT: usize = 1024 * 1024;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub fn fail(message: &'static str) -> Error {
    message.into()
}
