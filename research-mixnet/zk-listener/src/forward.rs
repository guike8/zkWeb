// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed-origin HTTPS egress after ZK authorization. DNS answers are validated
//! once at startup and pinned while TLS continues to authenticate the URL host.
use crate::{
    MAX_API_BODY, MAX_API_HEADER_BYTES, MAX_API_HEADERS, MAX_API_RESPONSE, Result, fail,
    protocol::{self, ApiHeader, ApiResponse},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client, Method, Url,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    fs::{self, OpenOptions},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Config {
    pub origin: String,
    pub allowed_methods: Vec<String>,
    pub path_prefix: String,
    pub allow_private: bool,
    pub ca_file: Option<PathBuf>,
    pub headers_file: Option<PathBuf>,
}

pub struct Forwarder {
    origin: String,
    allowed_methods: BTreeSet<String>,
    path_prefix: String,
    injected: Vec<ApiHeader>,
    injected_names: HashSet<String>,
    client: Client,
}

fn api_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    )
}

fn dns_syntax(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    let last = labels.last().copied().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) || last.to_ascii_lowercase().starts_with("0x") {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn public_dns_name(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    dns_syntax(host)
        && host.contains('.')
        && !["localhost", "local", "localdomain", "internal", "home.arpa"]
            .iter()
            .any(|suffix| lower == *suffix || lower.ends_with(&format!(".{suffix}")))
}

/// Syntax only: clients can pin an explicitly allowed private/enterprise origin
/// without resolving it themselves. Egress policy is enforced by `Forwarder::new`.
pub fn canonical_origin(input: &str) -> Result<String> {
    if !input.is_ascii() || input.bytes().any(|b| b <= 32 || b == 127) {
        return Err(fail("upstream must be a canonical HTTPS origin"));
    }
    let authority = input
        .strip_prefix("https://")
        .ok_or_else(|| fail("upstream must be an HTTPS origin"))?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '\\', '@'])
        || authority.ends_with(':')
    {
        return Err(fail(
            "upstream origin must not contain credentials or a URL suffix",
        ));
    }
    let raw_host = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| fail("invalid upstream host"))?;
        if !suffix.is_empty() && !suffix.starts_with(':') {
            return Err(fail("invalid upstream host"));
        }
        host
    } else {
        if authority.matches(':').count() > 1 {
            return Err(fail("IPv6 upstream hosts must be bracketed"));
        }
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
    };
    let url = Url::parse(input).map_err(|_| fail("invalid upstream origin"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default().is_none_or(|port| port == 0)
    {
        return Err(fail("invalid upstream origin"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| fail("invalid upstream host"))?
        .trim_matches(['[', ']']);
    match (raw_host.parse::<IpAddr>(), host.parse::<IpAddr>()) {
        (Ok(raw), Ok(parsed)) if raw == parsed => {
            if let IpAddr::V4(ip) = raw {
                if raw_host != ip.to_string() {
                    return Err(fail("upstream IPv4 must use canonical dotted decimal"));
                }
            }
        }
        (Err(_), Err(_)) if dns_syntax(raw_host) && raw_host.eq_ignore_ascii_case(host) => {}
        _ => {
            return Err(fail(
                "upstream must use a canonical IP literal or ASCII DNS name",
            ));
        }
    }
    Ok(url.origin().ascii_serialization())
}

fn v4_prefix(ip: Ipv4Addr, network: [u8; 4], bits: u32) -> bool {
    let mask = u32::MAX << (32 - bits);
    u32::from(ip) & mask == u32::from_be_bytes(network) & mask
}
fn v6_prefix(ip: Ipv6Addr, network: [u16; 8], bits: u32) -> bool {
    let mask = u128::MAX << (128 - bits);
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(network)) & mask
}

/// Matches the conservative policy in internal/httppolicy/policy.go, including
/// mapped IPv4 and IPv6 transition exclusions. It is intentionally stricter than
/// a generic global-unicast test.
fn public_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        other => other,
    };
    match ip {
        IpAddr::V4(ip) => ![
            ([0, 0, 0, 0], 8),
            ([10, 0, 0, 0], 8),
            ([100, 64, 0, 0], 10),
            ([127, 0, 0, 0], 8),
            ([169, 254, 0, 0], 16),
            ([172, 16, 0, 0], 12),
            ([192, 0, 0, 0], 24),
            ([192, 0, 2, 0], 24),
            ([192, 88, 99, 0], 24),
            ([192, 168, 0, 0], 16),
            ([198, 18, 0, 0], 15),
            ([198, 51, 100, 0], 24),
            ([203, 0, 113, 0], 24),
            ([224, 0, 0, 0], 4),
            ([240, 0, 0, 0], 4),
        ]
        .iter()
        .any(|(network, bits)| v4_prefix(ip, *network, *bits)),
        IpAddr::V6(ip) => {
            v6_prefix(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3)
                && ![
                    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
                    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
                    ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
                    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
                ]
                .iter()
                .any(|(network, bits)| v6_prefix(ip, *network, *bits))
        }
    }
}

fn usable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(!ip.is_unspecified() && !ip.is_multicast(), |v4| {
                usable_ip(IpAddr::V4(v4))
            }),
    }
}

fn forbidden_transport(name: &str) -> bool {
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
            | "expect"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "forwarded"
            | "x-real-ip"
            | "accept-encoding"
    ) || name.starts_with("x-forwarded-")
        || name.starts_with("x-zkweb-")
}

fn read_file(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)
        .map_err(|_| fail("upstream configuration file unavailable"))?
        .is_file()
    {
        return Err(fail("upstream configuration must be a regular file"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| fail("upstream configuration file unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| fail("upstream configuration file unavailable"))?;
    if !metadata.is_file()
        || metadata.len() > limit as u64
        || (private && metadata.mode() & 0o077 != 0)
    {
        return Err(fail(
            "upstream configuration file has invalid size or permissions",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("upstream configuration file unavailable"))?;
    if bytes.len() > limit {
        return Err(fail("upstream configuration file exceeds limit"));
    }
    Ok(bytes)
}

struct HeaderFile(Vec<ApiHeader>);
impl<'de> Deserialize<'de> for HeaderFile {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = HeaderFile;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("header object or header list")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<HeaderFile, M::Error> {
                let mut headers = Vec::new();
                let mut seen = HashSet::new();
                while let Some((name, value)) = map.next_entry::<String, String>()? {
                    if !seen.insert(name.to_ascii_lowercase()) || headers.len() >= MAX_API_HEADERS {
                        return Err(de::Error::custom("duplicate or excessive upstream headers"));
                    }
                    headers.push(ApiHeader { name, value });
                }
                Ok(HeaderFile(headers))
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> std::result::Result<HeaderFile, S::Error> {
                let mut headers = Vec::new();
                while let Some(header) = seq.next_element::<ApiHeader>()? {
                    if headers.len() >= MAX_API_HEADERS {
                        return Err(de::Error::custom("excessive upstream headers"));
                    }
                    headers.push(header);
                }
                Ok(HeaderFile(headers))
            }
        }
        deserializer.deserialize_any(HeaderVisitor)
    }
}

fn injected_headers(path: Option<&Path>) -> Result<Vec<ApiHeader>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let raw = read_file(path, 64 * 1024, true)?;
    let HeaderFile(headers): HeaderFile =
        serde_json::from_slice(&raw).map_err(|_| fail("invalid upstream headers file"))?;
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(headers.len());
    let mut bytes = 0usize;
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        if forbidden_transport(&name)
            || !seen.insert(name.clone())
            || HeaderName::from_bytes(name.as_bytes()).is_err()
            || header.value.bytes().any(|b| b < 32 || b == 127)
            || HeaderValue::from_str(&header.value).is_err()
        {
            return Err(fail("invalid or reserved upstream header"));
        }
        bytes += name.len() + header.value.len() + 4;
        if bytes > MAX_API_HEADER_BYTES {
            return Err(fail("upstream headers exceed limit"));
        }
        result.push(ApiHeader {
            name,
            value: header.value,
        });
    }
    Ok(result)
}

impl Forwarder {
    pub fn new(config: Config) -> Result<Self> {
        let origin = canonical_origin(&config.origin)?;
        let parsed = Url::parse(&origin).map_err(|_| fail("invalid upstream origin"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| fail("invalid upstream host"))?
            .trim_matches(['[', ']'])
            .to_string();
        if !config.allow_private && host.parse::<IpAddr>().is_err() && !public_dns_name(&host) {
            return Err(fail(
                "upstream must use a public address or eligible DNS name",
            ));
        }
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| fail("invalid upstream port"))?;
        let mut addresses: Vec<SocketAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|_| fail("upstream DNS unavailable"))?
                .collect(),
        };
        if addresses.is_empty()
            || addresses.iter().any(|address| {
                !usable_ip(address.ip())
                    || (!config.allow_private && !public_ip(address.ip()))
                    || matches!(address,SocketAddr::V6(v6) if v6.scope_id()!=0)
            })
        {
            return Err(fail("upstream DNS includes a disallowed address"));
        }
        addresses.sort_unstable();
        addresses.dedup();
        let methods = if config.allowed_methods.is_empty() {
            vec!["GET".into(), "HEAD".into()]
        } else {
            config.allowed_methods
        };
        if methods.iter().any(|method| !api_method(method)) {
            return Err(fail("unsupported upstream method policy"));
        }
        protocol::validate_api_path(&config.path_prefix)?;
        if config.path_prefix.contains('?') {
            return Err(fail("upstream path prefix cannot contain a query"));
        }
        let path_prefix = if config.path_prefix == "/" {
            "/".into()
        } else {
            config.path_prefix.trim_end_matches('/').to_string()
        };
        let injected = injected_headers(config.headers_file.as_deref())?;
        let injected_names = injected.iter().map(|header| header.name.clone()).collect();
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .https_only(true)
            .http1_only()
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .resolve_to_addrs(&host, &addresses);
        if let Some(ca_file) = config.ca_file {
            let pem = read_file(&ca_file, 1024 * 1024, false)?;
            let roots = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| fail("invalid upstream CA file"))?;
            if roots.is_empty() {
                return Err(fail("upstream CA file contains no certificate"));
            }
            for certificate in roots {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .map_err(|_| fail("upstream HTTPS client unavailable"))?;
        Ok(Self {
            origin,
            allowed_methods: methods.into_iter().collect(),
            path_prefix,
            injected,
            injected_names,
            client,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    fn destination(&self, path_query: &str) -> Result<Url> {
        protocol::validate_api_path(path_query)?;
        let url = Url::parse(&format!("{}{path_query}", self.origin))
            .map_err(|_| fail("invalid upstream request path"))?;
        let mut serialized = url.path().to_string();
        if let Some(query) = url.query() {
            serialized.push('?');
            serialized.push_str(query);
        }
        if url.origin().ascii_serialization() != self.origin || serialized != path_query {
            return Err(fail(
                "upstream URL normalization would change the signed request",
            ));
        }
        if self.path_prefix != "/"
            && url.path() != self.path_prefix
            && !url.path().starts_with(&format!("{}/", self.path_prefix))
        {
            return Err(fail(
                "upstream request path is outside the configured scope",
            ));
        }
        Ok(url)
    }

    pub fn validate_request(
        &self,
        method: &str,
        path_query: &str,
        headers: &[ApiHeader],
        body: &[u8],
    ) -> Result<()> {
        if !self.allowed_methods.contains(method) || body.len() > MAX_API_BODY {
            return Err(fail("upstream request is outside the configured policy"));
        }
        self.destination(path_query)?;
        let headers = protocol::canonical_api_headers(headers)?;
        if headers
            .iter()
            .any(|header| self.injected_names.contains(&header.name))
        {
            return Err(fail("caller header conflicts with an upstream credential"));
        }
        Ok(())
    }

    pub async fn send(
        &self,
        method: &str,
        path_query: &str,
        headers: &[ApiHeader],
        body: &[u8],
    ) -> Result<ApiResponse> {
        self.validate_request(method, path_query, headers, body)?;
        let destination = self.destination(path_query)?;
        let mut request = self.client.request(
            Method::from_bytes(method.as_bytes()).map_err(|_| fail("invalid API method"))?,
            destination,
        );
        let mut outgoing = HeaderMap::new();
        for header in protocol::canonical_api_headers(headers)?
            .iter()
            .chain(self.injected.iter())
        {
            outgoing.append(
                HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| fail("invalid API header"))?,
                HeaderValue::from_str(&header.value).map_err(|_| fail("invalid API header"))?,
            );
        }
        outgoing.insert(
            reqwest::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        request = request.headers(outgoing).body(body.to_vec());
        let mut response = request
            .send()
            .await
            .map_err(|_| fail("upstream delivery unknown"))?;
        let status = response.status().as_u16();
        if !(200..=599).contains(&status) {
            return Err(fail("unsupported upstream response; delivery unknown"));
        }
        if method != "HEAD"
            && status != 204
            && status != 304
            && response
                .content_length()
                .is_some_and(|length| length > MAX_API_RESPONSE as u64)
        {
            return Err(fail("upstream response exceeds limit; delivery unknown"));
        }
        let headers = self.response_headers(response.headers())?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| fail("upstream response unreadable; delivery unknown"))?
        {
            if chunk.len() > MAX_API_RESPONSE - bytes.len() {
                return Err(fail("upstream response exceeds limit; delivery unknown"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(ApiResponse {
            format: "zkweb-zk-api-response-v1".into(),
            upstream: self.origin.clone(),
            status,
            headers,
            body_base64: STANDARD.encode(bytes),
        })
    }

    fn response_headers(&self, input: &HeaderMap) -> Result<Vec<ApiHeader>> {
        if input.len() > MAX_API_HEADERS {
            return Err(fail(
                "upstream response headers exceed limit; delivery unknown",
            ));
        }
        let mut blocked = self.injected_names.clone();
        for value in input.get_all(reqwest::header::CONNECTION) {
            for token in value
                .to_str()
                .map_err(|_| fail("invalid upstream response headers; delivery unknown"))?
                .split(',')
            {
                blocked.insert(token.trim().to_ascii_lowercase());
            }
        }
        let mut bytes = 0usize;
        let mut output = Vec::new();
        for (name, value) in input {
            bytes += name.as_str().len() + value.as_bytes().len() + 4;
            if bytes > MAX_API_HEADER_BYTES {
                return Err(fail(
                    "upstream response headers exceed limit; delivery unknown",
                ));
            }
            let name = name.as_str();
            if forbidden_transport(name)
                || matches!(
                    name,
                    "set-cookie" | "cookie" | "authorization" | "x-api-key" | "api-key"
                )
                || blocked.contains(name)
            {
                continue;
            }
            output.push(ApiHeader {
                name: name.into(),
                value: value
                    .to_str()
                    .map_err(|_| fail("invalid upstream response headers; delivery unknown"))?
                    .into(),
            });
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config(origin: &str) -> Config {
        Config {
            origin: origin.into(),
            allowed_methods: vec!["GET".into(), "POST".into()],
            path_prefix: "/v1".into(),
            allow_private: true,
            ca_file: None,
            headers_file: None,
        }
    }

    #[test]
    fn canonical_origins_do_not_resolve_or_accept_ambiguous_forms() {
        for origin in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://@example.com",
            "https://example.com/a",
            "https://example.com?x",
            "https://example.com#x",
            "https://example.com:",
            "https://example.com:0",
            "https://2130706433",
            "https://127.1",
            "https://0x7f000001",
            "https://127.000.0.1",
            "https://examp%6ce.com",
            "https://éxample.com",
            "https://example.com./",
        ] {
            assert!(canonical_origin(origin).is_err(), "accepted {origin}");
        }
        assert_eq!(
            canonical_origin("https://EXAMPLE.com:443/").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            canonical_origin("https://127.0.0.1:8443").unwrap(),
            "https://127.0.0.1:8443"
        );
        assert_eq!(
            canonical_origin("https://localhost:8443").unwrap(),
            "https://localhost:8443"
        );
    }

    #[test]
    fn public_address_policy_rejects_local_special_and_transition_ranges() {
        for ip in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::a00:1",
            "2001::1",
            "2001:db8::1",
            "2002:808:808::1",
            "3fff::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "accepted {ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "::ffff:8.8.8.8",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(public_ip(ip.parse().unwrap()), "rejected {ip}");
        }
        let mut disallowed = config("https://127.0.0.1:443");
        disallowed.allow_private = false;
        assert!(Forwarder::new(disallowed).is_err());
    }

    #[test]
    fn paths_and_credentials_have_no_unsigned_override() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("headers.json");
        fs::write(
            &path,
            br#"{"Authorization":"Bearer development-only","X-Api-Key":"fixture-only"}"#,
        )?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let mut input = config("https://127.0.0.1:443");
        input.headers_file = Some(path.clone());
        let forwarder = Forwarder::new(input)?;
        assert!(
            forwarder
                .validate_request("GET", "/v1/items?x=%2F", &[], &[])
                .is_ok()
        );
        for path in [
            "/v10/items",
            "/other",
            "//other/v1",
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/%2fadmin",
            "/v1/%252e/admin",
            "/v1\\admin",
            "/v1/items#fragment",
        ] {
            assert!(
                forwarder.validate_request("GET", path, &[], &[]).is_err(),
                "accepted {path}"
            );
        }
        assert!(
            forwarder
                .validate_request("DELETE", "/v1/items", &[], &[])
                .is_err()
        );
        assert!(
            forwarder
                .validate_request(
                    "GET",
                    "/v1/items",
                    &[ApiHeader {
                        name: "x-api-key".into(),
                        value: "override".into()
                    }],
                    &[]
                )
                .is_err()
        );
        assert!(
            forwarder
                .validate_request("POST", "/v1/items", &[], &vec![0; MAX_API_BODY + 1])
                .is_err()
        );
        let mut raw = HeaderMap::new();
        raw.insert("connection", HeaderValue::from_static("x-private"));
        raw.insert("x-private", HeaderValue::from_static("secret"));
        raw.insert("x-api-key", HeaderValue::from_static("secret"));
        raw.insert("authorization", HeaderValue::from_static("secret"));
        raw.insert("set-cookie", HeaderValue::from_static("session=secret"));
        raw.append("x-safe", HeaderValue::from_static("one"));
        raw.append("x-safe", HeaderValue::from_static("two"));
        let headers = forwarder.response_headers(&raw)?;
        assert_eq!(headers.len(), 2);
        assert!(headers.iter().all(|header| header.name == "x-safe"));
        assert_eq!(headers[0].value, "one");
        assert_eq!(headers[1].value, "two");
        fs::write(&path, br#"{"Authorization":"one","Authorization":"two"}"#)?;
        assert!(injected_headers(Some(&path)).is_err());
        fs::write(&path, br#"{"Host":"other.example"}"#)?;
        assert!(injected_headers(Some(&path)).is_err());
        fs::write(&path, br#"{"Authorization":"secret"}"#)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(injected_headers(Some(&path)).is_err());
        Ok(())
    }
}
