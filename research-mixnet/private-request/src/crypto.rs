// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{MAX_PROOF, MAX_RESULT, Result, fail};
use serde::{Serialize, de::DeserializeOwned};
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::named::Named;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_deserialize_conformant, safe_serialize};
use tfhe::shortint::parameters::{
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{
    ClientKey, CompactCiphertextList, CompactPublicKey, Config, ConfigBuilder, FheTypes, FheUint2,
    FheUint8, FheUint8ConformanceParams, MatchValues, ProvenCompactCiphertextList, Unversionize,
    Versionize,
};

pub const PARAMETERS: &str = "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128+PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128+PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;crs_bits=2";

pub fn config() -> Config {
    ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
        .use_dedicated_compact_public_key_parameters((
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ))
        .build()
}

pub fn serialize<T: Serialize + Versionize + Named>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    safe_serialize(value, &mut bytes, limit as u64)?;
    Ok(bytes)
}

/// Only used for hash-pinned local setup files. Network objects use conformance checks below.
pub fn deserialize_trusted<T: DeserializeOwned + Unversionize + Named>(
    bytes: &[u8],
    limit: usize,
) -> Result<T> {
    if bytes.len() > limit {
        return Err(fail("local key file exceeds limit"));
    }
    Ok(safe_deserialize(bytes, limit as u64)?)
}

pub fn prove(
    index: u8,
    pk: &CompactPublicKey,
    crs: &CompactPkeCrs,
    metadata: &[u8],
) -> Result<Vec<u8>> {
    if index > 3 {
        return Err(fail("index must be between 0 and 3"));
    }
    let proof = ProvenCompactCiphertextList::builder(pk)
        .push_with_num_bits(index, 2)?
        .build_with_proof_packed(crs, metadata, ZkComputeLoad::Proof)?;
    serialize(&proof, MAX_PROOF)
}

/// Never expand before verifying. The selected plaintext is unavailable to this function.
pub fn verify_selector(
    bytes: &[u8],
    pk: &CompactPublicKey,
    crs: &CompactPkeCrs,
    metadata: &[u8],
) -> Result<FheUint2> {
    if bytes.len() > MAX_PROOF {
        return Err(fail("proof exceeds limit"));
    }
    let params = IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
        pk.parameters(),
        crs,
    )
    .forbid_compute_load(ZkComputeLoad::Verify);
    let proof: ProvenCompactCiphertextList =
        safe_deserialize_conformant(bytes, MAX_PROOF as u64, &params)?;
    // Upstream accepts empty proven lists as conformant. They are invalid in this protocol.
    if proof.len() != 1 || proof.get_kind_of(0) != Some(FheTypes::Uint2) {
        return Err(fail("proof must contain exactly one encrypted FheUint2"));
    }
    let expanded = proof.verify_and_expand(crs, pk, metadata)?;
    expanded
        .get(0)?
        .ok_or_else(|| fail("missing encrypted selector"))
}

pub fn evaluate(selector: &FheUint2, pk: &CompactPublicKey) -> Result<Vec<u8>> {
    let table = MatchValues::new(vec![(0u8, 11u8), (1, 22), (2, 33), (3, 44)])?;
    let result: FheUint8 = selector.match_value_or(&table, 0u8)?;
    // match_value_or pads the known-zero upper block with a trivial ciphertext.
    // Add fresh public-key encrypted zero so every output block has the standard
    // encrypted FheUint8 degree/noise shape required by client conformance checks.
    let zero_list = CompactCiphertextList::builder(pk).push(0u8).build();
    let zero: FheUint8 = zero_list
        .expand()?
        .get(0)?
        .ok_or_else(|| fail("missing encrypted zero"))?;
    let normalized = result + zero;
    serialize(&normalized, MAX_RESULT)
}

pub fn decrypt(bytes: &[u8], ck: &ClientKey) -> Result<u8> {
    if bytes.len() > MAX_RESULT {
        return Err(fail("result exceeds limit"));
    }
    let params = FheUint8ConformanceParams::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    let result: FheUint8 = safe_deserialize_conformant(bytes, MAX_RESULT as u64, &params)?;
    Ok(result.decrypt(ck))
}
