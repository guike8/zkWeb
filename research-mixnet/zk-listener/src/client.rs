// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{MAX_BODY, Result, crypto, fail, profile::ClientProfile, protocol};
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

pub fn request(
    profile: &ClientProfile,
    endpoint: &str,
    method: &str,
    key: &str,
    body: &[u8],
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
    let response = client.get(endpoint.join("challenge")?).send()?;
    if response.status() != 200 {
        return Err(fail("listener did not issue a challenge"));
    }
    let challenge: protocol::Challenge =
        serde_json::from_slice(&bounded_body(response, 8 * 1024)?)?;
    challenge.validate(&profile.manifest.profile_id)?;
    let path = format!("/records/{key}");
    let digest = protocol::request_digest(&challenge, method, &path, body);
    let authorization = crypto::prove(
        &profile.proving_key,
        &profile.credential,
        &profile.manifest.group_root,
        &digest,
    )?;
    challenge.validate(&profile.manifest.profile_id)?;
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
    let bytes = bounded_body(response, MAX_BODY).map_err(|_| unknown())?;
    Ok(PlainResult {
        format: "zkweb-zk-result-v1",
        method: method.into(),
        key: key.into(),
        status,
        body_base64: STANDARD.encode(bytes),
    })
}
