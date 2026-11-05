// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    CHALLENGE_LIFETIME, MAX_API_HEADER_BYTES, MAX_API_HEADERS, MAX_API_PATH, PROTOCOL, Result, fail,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHALLENGE_HEADER: &str = "x-zkweb-challenge";
pub const PROOF_HEADER: &str = "x-zkweb-proof";
pub const TAG_HEADER: &str = "x-zkweb-tag";
pub const API_METHOD_HEADER: &str = "x-zkweb-api-method";
pub const API_PATH_HEADER: &str = "x-zkweb-api-path";
pub const API_HEADERS_HEADER: &str = "x-zkweb-api-headers";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub protocol: String,
    pub profile_id: String,
    pub server_instance: String,
    pub challenge_id: String,
    pub expires_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_origin: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiResponse {
    pub format: String,
    pub upstream: String,
    pub status: u16,
    pub headers: Vec<ApiHeader>,
    pub body_base64: String,
}

pub fn valid_api_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    )
}

pub fn forbidden_api_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "authorization"
            | "cookie"
            | "set-cookie"
            | "forwarded"
            | "via"
            | "x-real-ip"
            | "origin"
            | "referer"
            | "expect"
            | "accept-encoding"
    ) || name.starts_with("x-forwarded-")
        || name.starts_with("x-zkweb-")
}

/// Normalize only the explicitly selected upstream headers. Unselected transport
/// headers never become upstream headers; duplicate-value ordering is preserved.
pub fn canonical_api_headers(headers: &[ApiHeader]) -> Result<Vec<ApiHeader>> {
    if headers.len() > MAX_API_HEADERS {
        return Err(fail("too many API headers"));
    }
    let mut result = Vec::with_capacity(headers.len());
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || forbidden_api_header(&name)
            || !header.value.bytes().all(|b| (32..=126).contains(&b))
        {
            return Err(fail("invalid or forbidden API header"));
        }
        result.push(ApiHeader {
            name,
            value: header.value.trim_matches(' ').to_owned(),
        });
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    if serde_json::to_vec(&result)?.len() > MAX_API_HEADER_BYTES {
        return Err(fail("API headers exceed limit"));
    }
    Ok(result)
}

/// Preserve the signed escaped path/query exactly. Restrict path forms that
/// different URL parsers could normalize into another configured path scope.
pub fn validate_api_path(path_query: &str) -> Result<()> {
    if path_query.is_empty()
        || path_query.len() > MAX_API_PATH
        || !path_query.starts_with('/')
        || path_query.starts_with("//")
        || path_query
            .bytes()
            .any(|b| !(33..=126).contains(&b) || b == b'\\' || b == b'#')
    {
        return Err(fail(
            "API path must be an escaped origin-relative path and query",
        ));
    }
    let path_end = path_query.find('?').unwrap_or(path_query.len());
    if path_query[..path_end]
        .split('/')
        .any(|part| part == "." || part == "..")
    {
        return Err(fail("API dot segments are not supported"));
    }
    let bytes = path_query.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] == b'%' {
            if offset + 2 >= bytes.len()
                || !bytes[offset + 1].is_ascii_hexdigit()
                || !bytes[offset + 2].is_ascii_hexdigit()
            {
                return Err(fail("invalid API percent escape"));
            }
            let value = u8::from_str_radix(&path_query[offset + 1..offset + 3], 16)?;
            if offset < path_end
                && (value <= 32 || value == 127 || matches!(value, b'/' | b'\\' | b'.' | b'%'))
            {
                return Err(fail("ambiguous encoded API path"));
            }
            offset += 3;
        } else {
            offset += 1;
        }
    }
    let url = reqwest::Url::parse(&format!("https://zkweb.invalid{path_query}"))?;
    let actual = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    if actual != path_query {
        return Err(fail("API URL normalization changed the signed path"));
    }
    Ok(())
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
        if let Some(origin) = &self.upstream_origin {
            if crate::forward::canonical_origin(origin)? != *origin {
                return Err(fail("invalid gateway upstream origin"));
            }
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

pub fn api_request_digest(
    challenge: &Challenge,
    origin: &str,
    method: &str,
    path_query: &str,
    headers: &[ApiHeader],
    body: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"zkweb-authorized-api-request-v1\0");
    for field in [
        PROTOCOL,
        challenge.protocol.as_str(),
        challenge.profile_id.as_str(),
        challenge.server_instance.as_str(),
        challenge.challenge_id.as_str(),
        origin,
        challenge.upstream_origin.as_deref().unwrap_or(""),
        method,
        path_query,
    ] {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.update(challenge.expires_unix.to_be_bytes());
    digest.update((headers.len() as u32).to_be_bytes());
    for header in headers {
        for field in [header.name.as_str(), header.value.as_str()] {
            digest.update((field.len() as u32).to_be_bytes());
            digest.update(field.as_bytes());
        }
    }
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_transcript_binds_destination_query_headers_and_binary_bytes() {
        let mut challenge = Challenge {
            protocol: PROTOCOL.into(),
            profile_id: "a".repeat(64),
            server_instance: "b".repeat(64),
            challenge_id: "c".repeat(64),
            expires_unix: 123456,
            upstream_origin: Some("https://api.example.com".into()),
        };
        let headers = canonical_api_headers(&[
            ApiHeader {
                name: "X-Order".into(),
                value: " first ".into(),
            },
            ApiHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
            ApiHeader {
                name: "x-order".into(),
                value: "second".into(),
            },
        ])
        .unwrap();
        assert_eq!(headers[1].value, "first");
        assert_eq!(headers[2].value, "second");
        let origin = "https://api.example.com";
        let path = "/v1/items?q=a%20b&next=%2Fother";
        validate_api_path(path).unwrap();
        let expected = api_request_digest(&challenge, origin, "POST", path, &headers, b"a\0\xff");
        assert_ne!(
            expected,
            api_request_digest(
                &challenge,
                "https://other.example.com",
                "POST",
                path,
                &headers,
                b"a\0\xff"
            )
        );
        assert_ne!(
            expected,
            api_request_digest(&challenge, origin, "PUT", path, &headers, b"a\0\xff")
        );
        assert_ne!(
            expected,
            api_request_digest(
                &challenge,
                origin,
                "POST",
                "/v1/items?q=changed",
                &headers,
                b"a\0\xff"
            )
        );
        assert_ne!(
            expected,
            api_request_digest(&challenge, origin, "POST", path, &headers, b"a\0\xfe")
        );
        let mut changed = headers.clone();
        changed[1].value = "changed".into();
        assert_ne!(
            expected,
            api_request_digest(&challenge, origin, "POST", path, &changed, b"a\0\xff")
        );
        challenge.upstream_origin = None;
        assert_ne!(
            expected,
            api_request_digest(&challenge, origin, "POST", path, &headers, b"a\0\xff")
        );
        assert_ne!(
            expected,
            request_digest(&challenge, "POST", path, b"a\0\xff")
        );
    }

    #[test]
    fn api_metadata_rejects_scope_escapes_and_transport_identity_headers() {
        for path in [
            "//other.example/path",
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/%252e/admin",
            "/v1/%2fadmin",
            "/v1/%5cadmin",
            "/v1/x#fragment",
            "/v1/%",
            "/v1/a\\b",
        ] {
            assert!(validate_api_path(path).is_err(), "accepted {path}");
        }
        for name in [
            "Host",
            "Authorization",
            "Cookie",
            "Connection",
            "Content-Length",
            "X-Forwarded-For",
            "X-ZkWeb-Proof",
        ] {
            assert!(
                canonical_api_headers(&[ApiHeader {
                    name: name.into(),
                    value: "value".into()
                }])
                .is_err(),
                "accepted {name}"
            );
        }
        assert!(
            canonical_api_headers(&[ApiHeader {
                name: "X-Test".into(),
                value: "bad\r\nInjected: yes".into()
            }])
            .is_err()
        );
    }

    #[test]
    fn authorization_transcript_binds_exact_request_and_audience() {
        let challenge = Challenge {
            protocol: PROTOCOL.into(),
            profile_id: "a".repeat(64),
            server_instance: "b".repeat(64),
            challenge_id: "c".repeat(64),
            expires_unix: 123456,
            upstream_origin: None,
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
