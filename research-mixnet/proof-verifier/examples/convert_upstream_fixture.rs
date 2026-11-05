// SPDX-License-Identifier: AGPL-3.0-or-later
// Development-only converter for one vendored, trusted upstream test fixture.
// It does not accept a filename or bytes supplied by a user.
use sha2::{Digest, Sha256};
use tlsn_attestation::presentation::Presentation;

fn main() {
    let bytes = include_bytes!("../tests/fixtures/upstream-presentation.bin");
    let presentation: Presentation = bincode::deserialize(bytes).expect("trusted upstream fixture");
    let json = serde_json::to_vec_pretty(&presentation).expect("fixture JSON");
    println!(
        "notary_key_hex={}",
        hex::encode(&presentation.verifying_key().data)
    );
    println!("upstream_sha256={}", hex::encode(Sha256::digest(bytes)));
    println!("json_sha256={}", hex::encode(Sha256::digest(&json)));
    std::fs::write("tests/fixtures/presentation.json", json).expect("fixture write");
}
