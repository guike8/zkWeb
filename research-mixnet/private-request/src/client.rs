// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    MAX_RESULT, MAX_WIRE, PROTOCOL, Result, crypto, fail,
    profile::ClientProfile,
    protocol::{Challenge, Query, QueryResult},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Url,
    blocking::{Client, Response},
    redirect::Policy,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{io::Read, net::IpAddr, time::Duration};

#[derive(Serialize)]
pub struct PlainResult {
    pub format: &'static str,
    pub index: u8,
    pub value: u8,
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
        return Err(fail(
            "URL must be http://numeric-loopback:port with no credentials or path",
        ));
    }
    // Parse the original authority too: Url canonicalizes unusual integer/abbreviated IPv4 forms.
    let authority = input
        .strip_prefix("http://")
        .ok_or_else(|| fail("invalid URL"))?
        .trim_end_matches('/');
    let socket: std::net::SocketAddr = authority
        .parse()
        .map_err(|_| fail("URL must contain a literal numeric loopback address"))?;
    let host: IpAddr = url
        .host_str()
        .unwrap_or("")
        .trim_matches(['[', ']'])
        .parse()
        .map_err(|_| fail("invalid numeric host"))?;
    if !host.is_loopback()
        || !socket.ip().is_loopback()
        || socket.ip() != host
        || socket.port() == 0
    {
        return Err(fail("URL must contain a literal numeric loopback address"));
    }
    Ok(url)
}
pub fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(180))
        .build()?)
}
fn read_json<T: DeserializeOwned>(mut response: Response) -> Result<T> {
    if response.status() != 200 {
        return Err(fail("destination rejected private request"));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_WIRE as u64)
    {
        return Err(fail("response exceeds limit"));
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_WIRE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_WIRE {
        return Err(fail("response exceeds limit"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn query(profile: &ClientProfile, endpoint: &str, index: u8) -> Result<PlainResult> {
    if index > 3 {
        return Err(fail("index must be between 0 and 3"));
    }
    let endpoint = validated_url(endpoint)?;
    let client = http_client()?;
    let challenge: Challenge = read_json(client.get(endpoint.join("challenge")?).send()?)?;
    challenge.validate(&profile.public.manifest.profile_id)?;
    let proof = crypto::prove(
        index,
        &profile.public.public_key,
        &profile.public.crs,
        &challenge.metadata(),
    )?;
    challenge.validate(&profile.public.manifest.profile_id)?;
    let query = Query {
        challenge_id: challenge.challenge_id.clone(),
        proof_base64: STANDARD.encode(proof),
    };
    let result: QueryResult = read_json(client.post(endpoint.join("query")?).json(&query).send()?)?;
    if result.protocol != PROTOCOL
        || result.profile_id != challenge.profile_id
        || result.server_instance != challenge.server_instance
        || result.challenge_id != challenge.challenge_id
        || result.ciphertext_base64.len() > MAX_RESULT.div_ceil(3) * 4
    {
        return Err(fail("response context does not match challenge"));
    }
    let ciphertext = STANDARD.decode(result.ciphertext_base64)?;
    let value = crypto::decrypt(&ciphertext, &profile.client_key)?;
    Ok(PlainResult {
        format: "zkweb-private-result-v1",
        index,
        value,
    })
}
