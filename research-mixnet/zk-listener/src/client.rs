// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{MAX_BODY, Result, compact, crypto, fail, forward, profile::ClientProfile, protocol};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Method, Url,
    blocking::{Client, Response},
    redirect::Policy,
};
use serde::Serialize;
use std::{io::Read, net::IpAddr, time::Duration};

#[derive(Serialize)]
pub struct PlainResult {
    pub format: &'static str,
    pub method: String,
    pub key: String,
    pub status: u16,
    pub body_base64: String,
}

/// The listener may have committed a mutation before the client lost its reply.
#[derive(Debug)]
pub struct DeliveryUnknown;
impl std::fmt::Display for DeliveryUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ZK request delivery unknown; do not retry automatically")
    }
}
impl std::error::Error for DeliveryUnknown {}
fn unknown() -> crate::Error {
    Box::new(DeliveryUnknown)
}

pub fn validated_url(input: &str) -> Result<Url> {
    let url = Url::parse(input)?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(fail("URL must be an HTTP numeric-loopback origin"));
    }
    let authority = input
        .strip_prefix("http://")
        .ok_or_else(|| fail("invalid URL"))?
        .trim_end_matches('/');
    let socket: std::net::SocketAddr = authority
        .parse()
        .map_err(|_| fail("numeric loopback IP and port required"))?;
    let host: IpAddr = url
        .host_str()
        .unwrap_or("")
        .trim_matches(['[', ']'])
        .parse()
        .map_err(|_| fail("numeric loopback IP required"))?;
    if !host.is_loopback()
        || !socket.ip().is_loopback()
        || socket.ip() != host
        || socket.port() == 0
    {
        return Err(fail("numeric loopback IP and nonzero port required"));
    }
    Ok(url)
}

pub fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(45))
        .build()?)
}

fn bounded_body(mut response: Response, maximum: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(fail("listener response exceeds limit"));
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(fail("listener response exceeds limit"));
    }
    Ok(bytes)
}

fn compact_content_type(response: &Response) -> bool {
    let all = response.headers().get_all(reqwest::header::CONTENT_TYPE);
    let mut values = all.iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(compact::CONTENT_TYPE)
        && values.next().is_none()
}

fn challenge(
    client: &Client,
    endpoint: &Url,
    profile_id: &str,
    upstream: Option<&str>,
    binary: bool,
) -> Result<protocol::Challenge> {
    let path = if binary {
        compact::CHALLENGE_PATH
    } else {
        "/challenge"
    };
    let response = client.get(endpoint.join(path)?).send()?;
    if response.status() != 200 {
        return Err(fail("listener did not issue an authorization challenge"));
    }
    let challenge = if binary {
        if !compact_content_type(&response) {
            return Err(fail("listener did not return a compact challenge"));
        }
        compact::decode_challenge(&bounded_body(response, 72)?, profile_id, upstream)?
    } else {
        serde_json::from_slice::<protocol::Challenge>(&bounded_body(response, 8 * 1024)?)?
    };
    challenge.validate(profile_id)?;
    if challenge.upstream_origin.as_deref() != upstream {
        return Err(fail(
            "listener mode or upstream differs from the expected origin",
        ));
    }
    Ok(challenge)
}

/// Compatibility client for the legacy HTTP-header transport.
pub fn request(
    profile: &ClientProfile,
    endpoint: &str,
    method: &str,
    key: &str,
    body: &[u8],
) -> Result<PlainResult> {
    request_with_wire(profile, endpoint, method, key, body, false)
}

/// Compact binary record transport used by the CLI by default.
pub fn request_compact(
    profile: &ClientProfile,
    endpoint: &str,
    method: &str,
    key: &str,
    body: &[u8],
) -> Result<PlainResult> {
    request_with_wire(profile, endpoint, method, key, body, true)
}

fn request_with_wire(
    profile: &ClientProfile,
    endpoint: &str,
    method: &str,
    key: &str,
    body: &[u8],
    binary: bool,
) -> Result<PlainResult> {
    if !matches!(method, "POST" | "GET" | "PUT" | "DELETE")
        || !protocol::valid_key(key)
        || body.len() > MAX_BODY
        || (matches!(method, "GET" | "DELETE") && !body.is_empty())
    {
        return Err(fail("invalid ZK CRUD request"));
    }
    let endpoint = validated_url(endpoint)?;
    let client = http_client()?;
    let challenge = challenge(
        &client,
        &endpoint,
        &profile.manifest.profile_id,
        None,
        binary,
    )?;
    let path = format!("/records/{key}");
    let digest = protocol::request_digest(&challenge, method, &path, body);
    let authorization = crypto::prove(
        &profile.proving_key,
        &profile.credential,
        &profile.manifest.group_root,
        &digest,
    )?;
    challenge.validate(&profile.manifest.profile_id)?;
    let outgoing = if binary {
        client
            .post(endpoint.join(compact::RECORD_PATH)?)
            .header("Content-Type", compact::CONTENT_TYPE)
            .body(compact::encode_request(
                compact::Kind::Records,
                &challenge.challenge_id,
                &authorization,
                method,
                key,
                &[],
                body,
            )?)
    } else {
        let mut outgoing = client
            .request(
                Method::from_bytes(method.as_bytes())?,
                endpoint.join(&path)?,
            )
            .header("X-ZkWeb-Challenge", &challenge.challenge_id)
            .header("X-ZkWeb-Tag", &authorization.tag)
            .header("X-ZkWeb-Proof", STANDARD.encode(&authorization.proof))
            .body(body.to_vec());
        if matches!(method, "POST" | "PUT") {
            outgoing = outgoing.header("Content-Type", "application/octet-stream");
        }
        outgoing
    };
    // No automatic retry: a transport failure can occur after a durable commit.
    let response = outgoing.send().map_err(|_| unknown())?;
    let status = response.status().as_u16();
    let application_status = match (method, status) {
        ("POST", 201 | 409 | 507) | ("GET" | "PUT" | "DELETE", 200 | 404) => true,
        _ => false,
    };
    if !application_status {
        if (400..500).contains(&status) {
            return Err(fail("listener rejected ZK authorization or request"));
        }
        return Err(unknown());
    }
    if binary && !compact_content_type(&response) {
        return Err(unknown());
    }
    let bytes = bounded_body(response, MAX_BODY).map_err(|_| unknown())?;
    Ok(PlainResult {
        format: "zkweb-zk-result-v1",
        method: method.into(),
        key: key.into(),
        status,
        body_base64: STANDARD.encode(bytes),
    })
}

#[derive(Serialize)]
pub struct ApiResult {
    pub format: &'static str,
    pub method: String,
    pub path: String,
    pub upstream: String,
    pub status: u16,
    pub headers: Vec<protocol::ApiHeader>,
    pub body_base64: String,
}

/// Compatibility client for the legacy JSON/header gateway transport.
pub fn api_request(
    profile: &ClientProfile,
    endpoint: &str,
    expected_upstream: &str,
    method: &str,
    path_query: &str,
    headers: &[protocol::ApiHeader],
    body: &[u8],
) -> Result<ApiResult> {
    api_request_with_wire(
        profile,
        endpoint,
        expected_upstream,
        method,
        path_query,
        headers,
        body,
        false,
    )
}

/// Compact binary gateway transport used by the CLI by default.
pub fn api_request_compact(
    profile: &ClientProfile,
    endpoint: &str,
    expected_upstream: &str,
    method: &str,
    path_query: &str,
    headers: &[protocol::ApiHeader],
    body: &[u8],
) -> Result<ApiResult> {
    api_request_with_wire(
        profile,
        endpoint,
        expected_upstream,
        method,
        path_query,
        headers,
        body,
        true,
    )
}

fn api_request_with_wire(
    profile: &ClientProfile,
    endpoint: &str,
    expected_upstream: &str,
    method: &str,
    path_query: &str,
    headers: &[protocol::ApiHeader],
    body: &[u8],
    binary: bool,
) -> Result<ApiResult> {
    if !matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) || body.len() > crate::MAX_API_BODY
        || (matches!(method, "GET" | "HEAD") && !body.is_empty())
    {
        return Err(fail("invalid upstream API request"));
    }
    protocol::validate_api_path(path_query)?;
    let headers = protocol::canonical_api_headers(headers)?;
    let upstream = forward::canonical_origin(expected_upstream)?;
    let endpoint = validated_url(endpoint)?;
    let client = http_client()?;
    let challenge = challenge(
        &client,
        &endpoint,
        &profile.manifest.profile_id,
        Some(&upstream),
        binary,
    )?;
    let digest =
        protocol::api_request_digest(&challenge, &upstream, method, path_query, &headers, body);
    let authorization = crypto::prove(
        &profile.proving_key,
        &profile.credential,
        &profile.manifest.group_root,
        &digest,
    )?;
    challenge.validate(&profile.manifest.profile_id)?;
    // Always POST the gateway envelope, including for an upstream HEAD request.
    // Only the explicit signed metadata becomes upstream request headers.
    let outgoing = if binary {
        client
            .post(endpoint.join(compact::API_PATH)?)
            .header("Content-Type", compact::CONTENT_TYPE)
            .body(compact::encode_request(
                compact::Kind::Api,
                &challenge.challenge_id,
                &authorization,
                method,
                path_query,
                &headers,
                body,
            )?)
    } else {
        client
            .post(endpoint.join("api")?)
            .header(protocol::CHALLENGE_HEADER, &challenge.challenge_id)
            .header(protocol::TAG_HEADER, &authorization.tag)
            .header(
                protocol::PROOF_HEADER,
                STANDARD.encode(&authorization.proof),
            )
            .header(protocol::API_METHOD_HEADER, method)
            .header(
                protocol::API_PATH_HEADER,
                STANDARD.encode(path_query.as_bytes()),
            )
            .header(
                protocol::API_HEADERS_HEADER,
                STANDARD.encode(serde_json::to_vec(&headers)?),
            )
            .header("Content-Type", "application/octet-stream")
            .body(body.to_vec())
    };
    let response = outgoing.send().map_err(|_| unknown())?;
    if response.status().is_client_error() {
        return Err(fail("gateway rejected ZK authorization or API request"));
    }
    if response.status() != 200 {
        return Err(unknown());
    }
    let response: protocol::ApiResponse = if binary {
        if !compact_content_type(&response) {
            return Err(unknown());
        }
        compact::decode_api_response(
            &bounded_body(response, compact::MAX_API_REPLY).map_err(|_| unknown())?,
            &upstream,
        )
        .map_err(|_| unknown())?
    } else {
        serde_json::from_slice(
            &bounded_body(response, crate::MAX_API_ENVELOPE).map_err(|_| unknown())?,
        )
        .map_err(|_| unknown())?
    };
    if response.format != "zkweb-zk-api-response-v1"
        || response.upstream != upstream
        || !(200..=599).contains(&response.status)
        || response.headers.len() > crate::MAX_API_HEADERS
        || serde_json::to_vec(&response.headers)
            .map_err(|_| unknown())?
            .len()
            > crate::MAX_API_HEADER_BYTES
        || response.body_base64.len() > crate::MAX_API_RESPONSE.div_ceil(3) * 4
    {
        return Err(unknown());
    }
    for header in &response.headers {
        if reqwest::header::HeaderName::from_bytes(header.name.as_bytes()).is_err()
            || reqwest::header::HeaderValue::from_str(&header.value).is_err()
        {
            return Err(unknown());
        }
    }
    let bytes = STANDARD
        .decode(&response.body_base64)
        .map_err(|_| unknown())?;
    if bytes.len() > crate::MAX_API_RESPONSE || STANDARD.encode(&bytes) != response.body_base64 {
        return Err(unknown());
    }
    Ok(ApiResult {
        format: "zkweb-zk-api-result-v1",
        method: method.into(),
        path: path_query.into(),
        upstream,
        status: response.status,
        headers: response.headers,
        body_base64: response.body_base64,
    })
}
