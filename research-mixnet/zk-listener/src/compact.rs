// SPDX-License-Identifier: AGPL-3.0-or-later
//! Versioned binary transport for the existing authorization statement. The
//! route selects the schema; HTTP frames the raw payload tail without another
//! length, and installed configuration supplies the profile and destination.
use crate::{
    MAX_API_BODY, MAX_API_HEADER_BYTES, MAX_API_HEADERS, MAX_API_PATH, MAX_API_RESPONSE, MAX_BODY,
    PROOF_BYTES, PROTOCOL, Result, crypto, fail, forward,
    protocol::{self, ApiHeader, ApiResponse, Challenge},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::{HeaderName, HeaderValue};

pub const CHALLENGE_PATH: &str = "/b1/c";
pub const RECORD_PATH: &str = "/b1/r";
pub const API_PATH: &str = "/b1/a";
pub const CONTENT_TYPE: &str = "application/octet-stream";
pub const AUTH_BYTES: usize = 32 + 32 + PROOF_BYTES;
pub const CHALLENGE_BYTES: usize = 32 + 32 + 8;
pub const MAX_RECORD_REQUEST: usize = AUTH_BYTES + 1 + 2 + 128 + MAX_BODY;
pub const MAX_API_REQUEST: usize =
    AUTH_BYTES + 1 + 2 + MAX_API_PATH + MAX_API_HEADER_BYTES + MAX_API_BODY;
pub const MAX_API_REPLY: usize = 2 + MAX_API_HEADER_BYTES + MAX_API_RESPONSE;
// Seven methods x 33 header counts fit in one byte. Four hundred response
// statuses x 33 counts fit in one or two canonical ULEB128 bytes. Unused codes
// are invalid, not aliases.
const HEADER_COUNTS: u16 = 33;
const MAX_API_CODE: u8 = 230;
const MAX_REPLY_CODE: u16 = 13199;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Records,
    Api,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub challenge_id: String,
    pub tag: String,
    pub proof: Vec<u8>,
    pub method: String,
    /// A record key in record mode; the exact escaped path/query in API mode.
    pub resource: String,
    pub headers: Vec<ApiHeader>,
    pub body: Vec<u8>,
}

impl Kind {
    fn maximum(self) -> usize {
        match self {
            Self::Records => MAX_RECORD_REQUEST,
            Self::Api => MAX_API_REQUEST,
        }
    }
}

/// Read only the nonce so the listener can burn it before decoding metadata,
/// tags or proofs, including malformed attempts using a recognized challenge.
pub fn nonce(bytes: &[u8]) -> Result<String> {
    Ok(hex::encode(
        bytes
            .get(..32)
            .ok_or_else(|| fail("truncated compact nonce"))?,
    ))
}

pub fn encode_challenge(challenge: &Challenge) -> Result<Vec<u8>> {
    challenge.validate(&challenge.profile_id)?;
    let mut bytes = Vec::with_capacity(CHALLENGE_BYTES);
    bytes.extend_from_slice(&hex::decode(&challenge.server_instance)?);
    bytes.extend_from_slice(&hex::decode(&challenge.challenge_id)?);
    bytes.extend_from_slice(&challenge.expires_unix.to_be_bytes());
    Ok(bytes)
}

pub fn decode_challenge(
    bytes: &[u8],
    profile_id: &str,
    upstream_origin: Option<&str>,
) -> Result<Challenge> {
    if bytes.len() != CHALLENGE_BYTES {
        return Err(fail("compact challenge must contain exactly 72 bytes"));
    }
    let challenge = Challenge {
        protocol: PROTOCOL.into(),
        profile_id: profile_id.into(),
        server_instance: hex::encode(&bytes[..32]),
        challenge_id: hex::encode(&bytes[32..64]),
        expires_unix: u64::from_be_bytes(bytes[64..72].try_into()?),
        upstream_origin: upstream_origin.map(str::to_owned),
    };
    // Profile and upstream are deliberately reconstructed from the client's
    // configuration. The server's own values remain bound into its digest, so
    // mismatched configuration cannot authorize execution.
    challenge.validate(profile_id)?;
    Ok(challenge)
}

fn method_code(method: &str) -> Result<u8> {
    match method {
        "GET" => Ok(0),
        "HEAD" => Ok(1),
        "POST" => Ok(2),
        "PUT" => Ok(3),
        "PATCH" => Ok(4),
        "DELETE" => Ok(5),
        "OPTIONS" => Ok(6),
        _ => Err(fail("invalid compact method")),
    }
}

fn method_name(code: u8) -> Result<&'static str> {
    match code {
        0 => Ok("GET"),
        1 => Ok("HEAD"),
        2 => Ok("POST"),
        3 => Ok("PUT"),
        4 => Ok("PATCH"),
        5 => Ok("DELETE"),
        6 => Ok("OPTIONS"),
        _ => Err(fail("invalid compact method")),
    }
}

fn check_request(
    kind: Kind,
    method: &str,
    resource: &str,
    headers: &[ApiHeader],
    body: &[u8],
) -> Result<()> {
    match kind {
        Kind::Records => {
            if !protocol::valid_method(method)
                || !protocol::valid_key(resource)
                || !headers.is_empty()
                || body.len() > MAX_BODY
                || (matches!(method, "GET" | "DELETE") && !body.is_empty())
            {
                return Err(fail("invalid compact record request"));
            }
        }
        Kind::Api => {
            if !protocol::valid_api_method(method)
                || body.len() > MAX_API_BODY
                || (matches!(method, "GET" | "HEAD") && !body.is_empty())
            {
                return Err(fail("invalid compact API request"));
            }
            protocol::validate_api_path(resource)?;
            if protocol::canonical_api_headers(headers)? != headers {
                return Err(fail("compact API headers must be canonical"));
            }
        }
    }
    Ok(())
}

// Canonical unsigned LEB128. Every logical length has only one wire encoding.
fn write_len(bytes: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        bytes.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    bytes.push(value as u8);
}

fn write_text(bytes: &mut Vec<u8>, value: &str) {
    write_len(bytes, value.len());
    bytes.extend_from_slice(value.as_bytes());
}

fn write_headers(bytes: &mut Vec<u8>, headers: &[ApiHeader]) {
    for header in headers {
        write_text(bytes, &header.name);
        write_text(bytes, &header.value);
    }
}

pub fn encode_request(
    kind: Kind,
    challenge_id: &str,
    authorization: &crypto::Authorization,
    method: &str,
    resource: &str,
    headers: &[ApiHeader],
    body: &[u8],
) -> Result<Vec<u8>> {
    check_request(kind, method, resource, headers, body)?;
    if !protocol::valid_id(challenge_id) || authorization.proof.len() != PROOF_BYTES {
        return Err(fail("invalid compact authorization"));
    }
    crypto::parse_field(&authorization.tag)?;
    let mut bytes = Vec::with_capacity(AUTH_BYTES + resource.len() + body.len() + 8);
    bytes.extend_from_slice(&hex::decode(challenge_id)?);
    bytes.extend_from_slice(&hex::decode(&authorization.tag)?);
    bytes.extend_from_slice(&authorization.proof);
    let method = method_code(method)?;
    bytes.push(if kind == Kind::Api {
        method * HEADER_COUNTS as u8 + headers.len() as u8
    } else {
        method
    });
    write_text(&mut bytes, resource);
    if kind == Kind::Api {
        write_headers(&mut bytes, headers);
    }
    bytes.extend_from_slice(body);
    if bytes.len() > kind.maximum() {
        return Err(fail("compact request exceeds limit"));
    }
    Ok(bytes)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| fail("truncated compact message"))?;
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn length(&mut self, maximum: usize) -> Result<usize> {
        let mut value = 0u32;
        for index in 0..5 {
            let byte = self.byte()?;
            let payload = byte & 127;
            if index == 4 && payload > 15 {
                return Err(fail("compact length overflow"));
            }
            value |= u32::from(payload) << (index * 7);
            if byte & 128 == 0 {
                if (index > 0 && value < (1 << (index * 7))) || value as usize > maximum {
                    return Err(fail("noncanonical or oversized compact length"));
                }
                return Ok(value as usize);
            }
        }
        Err(fail("compact length overflow"))
    }

    fn text(&mut self, maximum: usize) -> Result<&'a str> {
        let length = self.length(maximum)?;
        Ok(std::str::from_utf8(self.take(length)?)?)
    }

    fn remainder(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
}

fn read_headers(reader: &mut Reader<'_>, count: usize, request: bool) -> Result<Vec<ApiHeader>> {
    if count > MAX_API_HEADERS {
        return Err(fail("too many compact headers"));
    }
    let mut headers = Vec::with_capacity(count);
    let mut raw_bytes = 0usize;
    for _ in 0..count {
        let name = reader.text(if request { 128 } else { MAX_API_HEADER_BYTES })?;
        let value = reader.text(MAX_API_HEADER_BYTES)?;
        raw_bytes += name.len() + value.len();
        if raw_bytes > MAX_API_HEADER_BYTES {
            return Err(fail("compact headers exceed limit"));
        }
        headers.push(ApiHeader {
            name: name.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(headers)
}

pub fn decode_request(kind: Kind, bytes: &[u8]) -> Result<Request> {
    if bytes.len() > kind.maximum() {
        return Err(fail("compact request exceeds limit"));
    }
    let mut reader = Reader::new(bytes);
    let challenge_id = hex::encode(reader.take(32)?);
    let tag = hex::encode(reader.take(32)?);
    crypto::parse_field(&tag)?;
    let proof = reader.take(PROOF_BYTES)?.to_vec();
    let code = reader.byte()?;
    let (method, count) = if kind == Kind::Api {
        if code > MAX_API_CODE {
            return Err(fail("invalid compact method/header code"));
        }
        (code / HEADER_COUNTS as u8, code % HEADER_COUNTS as u8)
    } else {
        (code, 0)
    };
    let method = method_name(method)?.to_owned();
    let resource = reader
        .text(if kind == Kind::Records {
            128
        } else {
            MAX_API_PATH
        })?
        .to_owned();
    let headers = if kind == Kind::Api {
        read_headers(&mut reader, usize::from(count), true)?
    } else {
        Vec::new()
    };
    let body = reader.remainder();
    check_request(kind, &method, &resource, &headers, body)?;
    Ok(Request {
        challenge_id,
        tag,
        proof,
        method,
        resource,
        headers,
        body: body.to_vec(),
    })
}

fn check_response_headers(headers: &[ApiHeader]) -> Result<()> {
    if headers.len() > MAX_API_HEADERS || serde_json::to_vec(headers)?.len() > MAX_API_HEADER_BYTES
    {
        return Err(fail("compact response headers exceed limit"));
    }
    for header in headers {
        HeaderName::from_bytes(header.name.as_bytes())?;
        HeaderValue::from_str(&header.value)?;
    }
    Ok(())
}

pub fn encode_api_response(response: &ApiResponse) -> Result<Vec<u8>> {
    if response.format != "zkweb-zk-api-response-v1"
        || forward::canonical_origin(&response.upstream)? != response.upstream
        || !(200..=599).contains(&response.status)
        || response.body_base64.len() > MAX_API_RESPONSE.div_ceil(3) * 4
    {
        return Err(fail("invalid compact API response"));
    }
    check_response_headers(&response.headers)?;
    let body = STANDARD.decode(&response.body_base64)?;
    if body.len() > MAX_API_RESPONSE || STANDARD.encode(&body) != response.body_base64 {
        return Err(fail("invalid compact API response body"));
    }
    let mut bytes = Vec::with_capacity(2 + body.len());
    let code = (response.status - 200) * HEADER_COUNTS + response.headers.len() as u16;
    write_len(&mut bytes, usize::from(code));
    write_headers(&mut bytes, &response.headers);
    bytes.extend_from_slice(&body);
    if bytes.len() > MAX_API_REPLY {
        return Err(fail("compact API response exceeds limit"));
    }
    Ok(bytes)
}

pub fn decode_api_response(bytes: &[u8], expected_origin: &str) -> Result<ApiResponse> {
    if bytes.len() > MAX_API_REPLY || forward::canonical_origin(expected_origin)? != expected_origin
    {
        return Err(fail("invalid compact API response context or size"));
    }
    let mut reader = Reader::new(bytes);
    let code = reader.length(usize::from(MAX_REPLY_CODE))? as u16;
    let status = 200 + code / HEADER_COUNTS;
    let headers = read_headers(&mut reader, usize::from(code % HEADER_COUNTS), false)?;
    check_response_headers(&headers)?;
    let body = reader.remainder();
    if body.len() > MAX_API_RESPONSE {
        return Err(fail("compact API response body exceeds limit"));
    }
    Ok(ApiResponse {
        format: "zkweb-zk-api-response-v1".into(),
        upstream: expected_origin.into(),
        status,
        headers,
        body_base64: STANDARD.encode(body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> crypto::Authorization {
        crypto::Authorization {
            proof: vec![0x22; PROOF_BYTES],
            tag: "00".repeat(32),
        }
    }

    fn request(
        kind: Kind,
        method: &str,
        resource: &str,
        headers: &[ApiHeader],
        body: &[u8],
    ) -> Vec<u8> {
        encode_request(
            kind,
            &"11".repeat(32),
            &authorization(),
            method,
            resource,
            headers,
            body,
        )
        .unwrap()
    }

    #[test]
    fn golden_minimal_record_and_api_requests() {
        let record = request(Kind::Records, "GET", "a", &[], &[]);
        let mut expected = vec![0x11; 32];
        expected.extend_from_slice(&[0; 32]);
        expected.extend_from_slice(&[0x22; PROOF_BYTES]);
        expected.extend_from_slice(&[0, 1, b'a']);
        assert_eq!(record, expected);
        assert_eq!(record.len(), 195);
        assert_eq!(nonce(&record).unwrap(), "11".repeat(32));
        let decoded = decode_request(Kind::Records, &record).unwrap();
        assert_eq!(decoded.resource, "a");
        assert_eq!(decoded.method, "GET");
        assert!(decoded.body.is_empty());
        assert_eq!(request(Kind::Api, "GET", "/", &[], &[]).len(), 195);
        for end in 0..record.len() {
            assert!(decode_request(Kind::Records, &record[..end]).is_err());
        }
    }

    #[test]
    fn challenge_is_exactly_72_bytes_and_reconstructs_installed_context() {
        let challenge = Challenge {
            protocol: PROTOCOL.into(),
            profile_id: "aa".repeat(32),
            server_instance: "bb".repeat(32),
            challenge_id: "cc".repeat(32),
            expires_unix: protocol::now().unwrap() + 60,
            upstream_origin: Some("https://api.example.com".into()),
        };
        let encoded = encode_challenge(&challenge).unwrap();
        assert_eq!(encoded.len(), 72);
        assert_eq!(&encoded[..32], &[0xbb; 32]);
        assert_eq!(&encoded[32..64], &[0xcc; 32]);
        assert_eq!(&encoded[64..], &challenge.expires_unix.to_be_bytes());
        let decoded = decode_challenge(
            &encoded,
            &challenge.profile_id,
            challenge.upstream_origin.as_deref(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&decoded).unwrap(),
            serde_json::to_vec(&challenge).unwrap()
        );
        for end in 0..encoded.len() {
            assert!(decode_challenge(&encoded[..end], &challenge.profile_id, None).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_challenge(&trailing, &challenge.profile_id, None).is_err());
        let mut expired = encoded;
        expired[64..].copy_from_slice(&0u64.to_be_bytes());
        assert!(decode_challenge(&expired, &challenge.profile_id, None).is_err());
    }

    #[test]
    fn api_preserves_query_header_order_and_maximum_binary_payload() {
        let headers = vec![
            ApiHeader {
                name: "x-repeat".into(),
                value: "first".into(),
            },
            ApiHeader {
                name: "x-repeat".into(),
                value: "second".into(),
            },
        ];
        let body: Vec<u8> = (0..MAX_API_BODY).map(|index| index as u8).collect();
        let encoded = request(
            Kind::Api,
            "PUT",
            "/items?raw=%2F&same=1&same=2",
            &headers,
            &body,
        );
        let decoded = decode_request(Kind::Api, &encoded).unwrap();
        assert_eq!(decoded.resource, "/items?raw=%2F&same=1&same=2");
        assert_eq!(decoded.headers, headers);
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.proof, authorization().proof);
        assert_eq!(decoded.tag, authorization().tag);
        let mut extra = encoded;
        extra.push(0);
        assert!(decode_request(Kind::Api, &extra).is_err());
    }

    #[test]
    fn rejects_noncanonical_lengths_fields_methods_and_headers() {
        let record = request(Kind::Records, "GET", "a", &[], &[]);
        for replacement in [
            vec![0x81, 0],
            vec![0x80],
            vec![0xff, 0xff, 0xff, 0xff, 0x10],
            vec![0x81, 1],
        ] {
            let mut bad = record.clone();
            bad.splice(AUTH_BYTES + 1..AUTH_BYTES + 2, replacement);
            assert!(decode_request(Kind::Records, &bad).is_err());
        }
        let mut bad = record.clone();
        bad[32..64].fill(0xff);
        assert!(decode_request(Kind::Records, &bad).is_err());
        let mut bad = record.clone();
        bad[AUTH_BYTES] = 255;
        assert!(decode_request(Kind::Records, &bad).is_err());
        let mut bad = record;
        bad[AUTH_BYTES] = 1; // HEAD is not a record operation.
        assert!(decode_request(Kind::Records, &bad).is_err());
        for (name, value) in [
            ("X-UPPER", "value"),
            ("x-ok", " padded "),
            ("authorization", "secret"),
        ] {
            assert!(
                encode_request(
                    Kind::Api,
                    &"11".repeat(32),
                    &authorization(),
                    "GET",
                    "/",
                    &[ApiHeader {
                        name: name.into(),
                        value: value.into()
                    }],
                    &[]
                )
                .is_err()
            );
        }
        let api = request(Kind::Api, "GET", "/", &[], &[]);
        for code in 231..=255 {
            let mut invalid = api.clone();
            invalid[AUTH_BYTES] = code;
            assert!(decode_request(Kind::Api, &invalid).is_err());
        }
        assert!(
            encode_request(
                Kind::Records,
                &"11".repeat(32),
                &authorization(),
                "GET",
                "a",
                &[],
                &[0]
            )
            .is_err()
        );
        assert!(
            encode_request(
                Kind::Api,
                &"11".repeat(32),
                &authorization(),
                "PUT",
                "/../escape",
                &[],
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn responses_keep_upstream_status_and_raw_bytes_without_json_expansion() {
        let response = ApiResponse {
            format: "zkweb-zk-api-response-v1".into(),
            upstream: "https://api.example.com".into(),
            status: 401,
            headers: vec![ApiHeader {
                name: "www-authenticate".into(),
                value: "Bearer realm=example".into(),
            }],
            body_base64: STANDARD.encode([0, 255, 128, 10]),
        };
        let encoded = encode_api_response(&response).unwrap();
        assert_eq!(&encoded[..2], &[0xea, 0x33]);
        assert_eq!(&encoded[encoded.len() - 4..], &[0, 255, 128, 10]);
        let decoded = decode_api_response(&encoded, &response.upstream).unwrap();
        assert_eq!(
            serde_json::to_vec(&response).unwrap(),
            serde_json::to_vec(&decoded).unwrap()
        );
        let empty = ApiResponse {
            headers: vec![],
            body_base64: String::new(),
            status: 200,
            ..response
        };
        assert_eq!(encode_api_response(&empty).unwrap(), [0]);
        for bad in [
            vec![],
            vec![0x80],
            vec![0x80, 0],    // Nonminimal representation of status200/count0.
            vec![0x90, 0x67], // 13200 is above the packed-code limit.
            vec![1],          // Status200/count1, with missing header pairs.
            vec![32],         // Maximum count, also missing header pairs.
            vec![1, 0xff, 0xff, 0xff, 0xff, 0x7f],
        ] {
            assert!(decode_api_response(&bad, "https://api.example.com").is_err());
        }
        let mut too_large = vec![0];
        too_large.resize(MAX_API_REPLY + 1, 0);
        assert!(decode_api_response(&too_large, "https://api.example.com").is_err());
    }

    #[test]
    fn packed_request_codes_cover_all_methods_and_header_counts() {
        assert_eq!(MAX_API_HEADERS, 32);
        for (method_index, method) in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
            .into_iter()
            .enumerate()
        {
            for count in 0..=MAX_API_HEADERS {
                let headers: Vec<_> = (0..count)
                    .map(|index| ApiHeader {
                        name: "x-repeat".into(),
                        value: index.to_string(),
                    })
                    .collect();
                let encoded = request(Kind::Api, method, "/", &headers, &[]);
                assert_eq!(usize::from(encoded[AUTH_BYTES]), method_index * 33 + count);
                let decoded = decode_request(Kind::Api, &encoded).unwrap();
                assert_eq!(decoded.method, method);
                assert_eq!(decoded.headers, headers);
                assert!(decoded.body.is_empty());
            }
        }
    }

    #[test]
    fn packed_response_codes_cover_status_boundaries_and_reject_spares() {
        for status in 200..=599 {
            for count in [0, 1, 31, 32] {
                let headers: Vec<_> = (0..count)
                    .map(|index| ApiHeader {
                        name: "x-repeat".into(),
                        value: index.to_string(),
                    })
                    .collect();
                let response = ApiResponse {
                    format: "zkweb-zk-api-response-v1".into(),
                    upstream: "https://api.example.com".into(),
                    status,
                    headers: headers.clone(),
                    body_base64: String::new(),
                };
                let encoded = encode_api_response(&response).unwrap();
                let code = (usize::from(status) - 200) * 33 + count;
                let mut reader = Reader::new(&encoded);
                assert_eq!(reader.length(13199).unwrap(), code);
                assert_eq!(reader.offset, if code < 128 { 1 } else { 2 });
                let decoded = decode_api_response(&encoded, &response.upstream).unwrap();
                assert_eq!(decoded.status, status);
                assert_eq!(decoded.headers, headers);
                assert!(decoded.body_base64.is_empty());
            }
        }
        for code in [13200, 16383, 16384, u32::MAX as usize] {
            let mut invalid = Vec::new();
            write_len(&mut invalid, code);
            assert!(decode_api_response(&invalid, "https://api.example.com").is_err());
        }
    }
}
