// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline verification of pinned TLSNotary alpha.15 presentations.
//!
//! The wire artifact is JSON, not bincode. Sparse transcript expansion is
//! preflighted before TLSN's typed deserializer can allocate full transcripts.

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use tlsn_attestation::{CryptoProvider, presentation::Presentation, signing::KeyAlgId};

pub const BACKEND_COMMIT: &str = "47aee45b53e06648c1b2ad3689b367b8c923fdec";
pub const MAX_INPUT_BYTES: usize = 24 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TRANSCRIPT_BYTES: usize = 1024 * 1024;
pub const MAX_DISCLOSED_BYTES: usize = 1024 * 1024;
const MAX_RANGES: usize = 64;
const MAX_CONTAINER_ITEMS: usize = 4096;
const MAX_HASH_OPENINGS: usize = 256;

#[derive(Debug)]
pub struct VerificationError;

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("verification failed")
    }
}
impl std::error::Error for VerificationError {}

type Result<T> = std::result::Result<T, VerificationError>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub format: String,
    pub presentation_base64: String,
    pub policy: Policy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub server_name: String,
    pub notary_key_hex: String,
    pub min_time: u64,
    pub max_time: u64,
    #[serde(default)]
    pub sent_ranges: Vec<ByteRange>,
    #[serde(default)]
    pub received_ranges: Vec<ByteRange>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedOutput {
    pub format: String,
    pub backend_commit: String,
    pub server_name: String,
    pub notary_key_hex: String,
    pub time: u64,
    pub sent_length: usize,
    pub received_length: usize,
    pub sent: Vec<DisclosedRange>,
    pub received: Vec<DisclosedRange>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosedRange {
    pub start: usize,
    pub end: usize,
    pub data_base64: String,
}

pub fn verify_json(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err(VerificationError);
    }
    // Struct decoding rejects duplicate/unknown fields, nulls and trailing JSON.
    let request: VerifyRequest = serde_json::from_slice(input).map_err(|_| VerificationError)?;
    if request.format != "zkweb-tlsn-verify-v1" {
        return Err(VerificationError);
    }
    let output = verify(&request.presentation_base64, &request.policy)?;
    serde_json::to_vec(&output).map_err(|_| VerificationError)
}

pub fn verify(encoded_presentation: &str, policy: &Policy) -> Result<VerifiedOutput> {
    let pinned_key = validate_policy(policy)?;
    if encoded_presentation.len() > 4 * MAX_PROOF_BYTES.div_ceil(3) {
        return Err(VerificationError);
    }
    let bytes = STANDARD
        .decode(encoded_presentation)
        .map_err(|_| VerificationError)?;
    if bytes.is_empty() || bytes.len() > MAX_PROOF_BYTES {
        return Err(VerificationError);
    }

    // Do not use bincode::deserialize on caller artifacts: upstream's sparse
    // PartialTranscript expands sent_total/recv_total before cryptoverification.
    let raw: UniqueValue = serde_json::from_slice(&bytes).map_err(|_| VerificationError)?;
    preflight(&raw.0)?;
    let presentation: Presentation =
        serde_json::from_value(raw.0).map_err(|_| VerificationError)?;
    let key = presentation.verifying_key();
    if key.alg != KeyAlgId::K256 || key.data != pinned_key {
        return Err(VerificationError);
    }

    let output = presentation
        .verify(&CryptoProvider::default())
        .map_err(|_| VerificationError)?;
    let server_name = output.server_name.ok_or(VerificationError)?.to_string();
    if server_name != policy.server_name
        || output.connection_info.time < policy.min_time
        || output.connection_info.time > policy.max_time
    {
        return Err(VerificationError);
    }
    let transcript = output.transcript.ok_or(VerificationError)?;
    if transcript.len_sent() > MAX_TRANSCRIPT_BYTES
        || transcript.len_received() > MAX_TRANSCRIPT_BYTES
    {
        return Err(VerificationError);
    }
    let sent = select_ranges(
        transcript.sent_unsafe(),
        transcript.sent_authed().iter(),
        &policy.sent_ranges,
    )?;
    let received = select_ranges(
        transcript.received_unsafe(),
        transcript.received_authed().iter(),
        &policy.received_ranges,
    )?;
    Ok(VerifiedOutput {
        format: "zkweb-tlsn-verified-v1".into(),
        backend_commit: BACKEND_COMMIT.into(),
        server_name,
        notary_key_hex: policy.notary_key_hex.clone(),
        time: output.connection_info.time,
        sent_length: transcript.len_sent(),
        received_length: transcript.len_received(),
        sent,
        received,
    })
}

fn validate_policy(policy: &Policy) -> Result<Vec<u8>> {
    if policy.server_name.is_empty()
        || policy.server_name.len() > 253
        || policy.server_name != policy.server_name.to_ascii_lowercase()
        || policy.min_time == 0
        || policy.max_time < policy.min_time
    {
        return Err(VerificationError);
    }
    if policy.notary_key_hex.len() != 66 {
        return Err(VerificationError);
    }
    let key = hex::decode(&policy.notary_key_hex).map_err(|_| VerificationError)?;
    if key.len() != 33 || !matches!(key[0], 2 | 3) || hex::encode(&key) != policy.notary_key_hex {
        return Err(VerificationError);
    }
    let mut total = 0;
    for ranges in [&policy.sent_ranges, &policy.received_ranges] {
        if ranges.len() > MAX_RANGES {
            return Err(VerificationError);
        }
        let mut previous_end = 0;
        for range in ranges {
            if range.start >= range.end
                || range.end > MAX_TRANSCRIPT_BYTES
                || range.start < previous_end
            {
                return Err(VerificationError);
            }
            total += range.end - range.start;
            if total > MAX_DISCLOSED_BYTES {
                return Err(VerificationError);
            }
            previous_end = range.end;
        }
    }
    Ok(key)
}

fn preflight(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or(VerificationError)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "attestation" | "identity" | "transcript"))
    {
        return Err(VerificationError);
    }
    if !value.get("identity").is_some_and(Value::is_object)
        || !value.get("transcript").is_some_and(Value::is_object)
    {
        return Err(VerificationError);
    }
    let sent = bounded_number(value, "/transcript/transcript/sent_total")?;
    let received = bounded_number(value, "/transcript/transcript/recv_total")?;
    let signed_sent = bounded_number(
        value,
        "/attestation/body/body/connection_info/data/transcript_length/sent",
    )?;
    let signed_received = bounded_number(
        value,
        "/attestation/body/body/connection_info/data/transcript_length/received",
    )?;
    if sent != signed_sent || received != signed_received {
        return Err(VerificationError);
    }
    let openings = value
        .pointer("/transcript/hash_secrets")
        .and_then(Value::as_array)
        .ok_or(VerificationError)?;
    if openings.len() > MAX_HASH_OPENINGS {
        return Err(VerificationError);
    }
    Ok(())
}

fn bounded_number(value: &Value, pointer: &str) -> Result<u64> {
    let length = value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or(VerificationError)?;
    if length > MAX_TRANSCRIPT_BYTES as u64 {
        return Err(VerificationError);
    }
    Ok(length)
}

fn select_ranges(
    data: &[u8],
    authenticated: impl Iterator<Item = std::ops::Range<usize>>,
    selected: &[ByteRange],
) -> Result<Vec<DisclosedRange>> {
    let authenticated: Vec<_> = authenticated.collect();
    let mut output = Vec::with_capacity(selected.len());
    for range in selected {
        if range.end > data.len() {
            return Err(VerificationError);
        }
        let mut next = range.start;
        for authed in &authenticated {
            if authed.end <= next {
                continue;
            }
            if authed.start > next {
                break;
            }
            next = range.end.min(authed.end);
            if next == range.end {
                break;
            }
        }
        if next != range.end {
            return Err(VerificationError);
        }
        output.push(DisclosedRange {
            start: range.start,
            end: range.end,
            data_base64: STANDARD.encode(&data[range.start..range.end]),
        });
    }
    Ok(output)
}

// serde_json::Value normally accepts duplicate object keys. Reject them at
// every depth before converting to the pinned upstream presentation types.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
                Ok(Value::Number(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
                Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
                if value.len() > MAX_TRANSCRIPT_BYTES {
                    return Err(E::custom("string limit"));
                }
                Ok(Value::String(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> {
                if value.len() > MAX_TRANSCRIPT_BYTES {
                    return Err(E::custom("string limit"));
                }
                Ok(Value::String(value))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Value, A::Error> {
                let mut values = Vec::new();
                let mut bytes_only = true;
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    bytes_only &= value.0.as_u64().is_some_and(|value| value <= 255);
                    values.push(value.0);
                    if values.len() > MAX_TRANSCRIPT_BYTES
                        || (!bytes_only && values.len() > MAX_CONTAINER_ITEMS)
                    {
                        return Err(de::Error::custom("array limit"));
                    }
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key.len() > 256
                        || values.len() >= MAX_CONTAINER_ITEMS
                        || values.contains_key(&key)
                    {
                        return Err(de::Error::custom("duplicate field or object limit"));
                    }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(UniqueVisitor).map(UniqueValue)
    }
}
