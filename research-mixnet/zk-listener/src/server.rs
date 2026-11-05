// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    CHALLENGE_LIFETIME, MAX_API_BODY, MAX_API_ENVELOPE, MAX_API_HEADER_BYTES, MAX_API_PATH,
    MAX_BODY, MAX_CHALLENGES, PROOF_BYTES, PROTOCOL, Result, crypto, fail,
    forward::{Config as ForwardConfig, Forwarder},
    profile::ServerProfile,
    protocol::{self, ApiHeader, ApiResponse, Challenge},
    storage::Database,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    HeaderMap, Method, Request, Response,
    body::Incoming,
    header::{CONTENT_LENGTH, ORIGIN, TRANSFER_ENCODING},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    cell::RefCell,
    collections::HashMap,
    convert::Infallible,
    net::{SocketAddr, TcpListener},
    path::Path,
    rc::Rc,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
pub const BODY_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_POLL: Duration = Duration::from_millis(100);

/// One active HTTP/1 connection, with bounded parsing and no task/thread fan-out.
pub struct Server {
    listener: TcpListener,
}

pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

enum Backend {
    Records(Database),
    Upstream(Arc<Forwarder>),
}

#[derive(Debug)]
struct ApiPolicyDenied;
impl std::fmt::Display for ApiPolicyDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("request rejected by upstream policy")
    }
}
impl std::error::Error for ApiPolicyDenied {}

/// Own the verified request so async dispatch cannot substitute its signed bytes.
pub struct AuthorizedApi {
    forwarder: Arc<Forwarder>,
    method: String,
    path: String,
    headers: Vec<ApiHeader>,
    body: Vec<u8>,
}
impl AuthorizedApi {
    pub async fn send(self) -> Result<ApiResponse> {
        self.forwarder
            .send(&self.method, &self.path, &self.headers, &self.body)
            .await
    }
}

pub struct State {
    profile: ServerProfile,
    instance: String,
    challenges: HashMap<String, Challenge>,
    backend: Backend,
    verification_attempts: u64,
    executions: u64,
    mutations: u64,
    poisoned: bool,
}

impl State {
    pub fn open(profile: ServerProfile, state_file: &Path) -> Result<Self> {
        let database = Database::open(state_file, &profile.manifest.profile_id)?;
        Ok(Self {
            profile,
            instance: protocol::random_id(),
            challenges: HashMap::new(),
            backend: Backend::Records(database),
            verification_attempts: 0,
            executions: 0,
            mutations: 0,
            poisoned: false,
        })
    }
    pub fn open_gateway(profile: ServerProfile, config: ForwardConfig) -> Result<Self> {
        let forwarder = Forwarder::new(config)?;
        Ok(Self {
            profile,
            instance: protocol::random_id(),
            challenges: HashMap::new(),
            backend: Backend::Upstream(Arc::new(forwarder)),
            verification_attempts: 0,
            executions: 0,
            mutations: 0,
            poisoned: false,
        })
    }
    pub fn is_gateway(&self) -> bool {
        matches!(&self.backend, Backend::Upstream(_))
    }
    pub fn upstream_origin(&self) -> Option<&str> {
        match &self.backend {
            Backend::Upstream(upstream) => Some(upstream.origin()),
            _ => None,
        }
    }
    pub fn profile_id(&self) -> &str {
        &self.profile.manifest.profile_id
    }
    pub fn verification_attempt_count(&self) -> u64 {
        self.verification_attempts
    }
    pub fn execution_count(&self) -> u64 {
        self.executions
    }
    pub fn mutation_count(&self) -> u64 {
        self.mutations
    }
    pub fn revision(&self) -> u64 {
        match &self.backend {
            Backend::Records(database) => database.revision(),
            _ => 0,
        }
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn check_available(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(fail("listener database requires recovery"));
        }
        if let Backend::Records(database) = &self.backend {
            if let Err(error) = database.check_current() {
                self.poisoned = true;
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn challenge(&mut self) -> Result<Challenge> {
        self.check_available()?;
        let time = protocol::now()?;
        self.challenges
            .retain(|_, challenge| challenge.expires_unix > time);
        if self.challenges.len() >= MAX_CHALLENGES {
            return Err(fail("challenge capacity reached"));
        }
        let challenge = Challenge {
            protocol: PROTOCOL.into(),
            profile_id: self.profile_id().into(),
            server_instance: self.instance.clone(),
            challenge_id: protocol::random_id(),
            expires_unix: time + CHALLENGE_LIFETIME,
            upstream_origin: self.upstream_origin().map(str::to_owned),
        };
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Verify authorization for the exact bytes before touching any keyed record.
    /// A recognized challenge is burned even when proof decoding/verification fails.
    pub fn execute(
        &mut self,
        challenge_id: &str,
        method: &str,
        path: &str,
        body: &[u8],
        proof_base64: &str,
        tag: &str,
    ) -> Result<Reply> {
        self.check_available()?;
        if self.is_gateway() {
            return Err(fail("record execution is unavailable in gateway mode"));
        }
        let key = path
            .strip_prefix("/records/")
            .filter(|key| protocol::valid_key(key))
            .ok_or_else(|| fail("invalid record path"))?;
        if !protocol::valid_method(method)
            || body.len() > MAX_BODY
            || (matches!(method, "GET" | "DELETE") && !body.is_empty())
            || !protocol::valid_id(challenge_id)
        {
            return Err(fail("invalid authorization request"));
        }
        let challenge = self.take_challenge(challenge_id)?;
        let digest = protocol::request_digest(&challenge, method, path, body);
        self.verify_authorization(&challenge, &digest, proof_base64, tag)?;
        self.executions += 1;
        let Backend::Records(database) = &mut self.backend else {
            return Err(fail("record mode required"));
        };
        let result = match database.execute(method, key, body) {
            Ok(result) => result,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if result.mutated {
            self.mutations += 1;
        }
        Ok(Reply {
            status: result.status,
            body: result.body,
        })
    }

    fn take_challenge(&mut self, challenge_id: &str) -> Result<Challenge> {
        if !protocol::valid_id(challenge_id) {
            return Err(fail("invalid challenge"));
        }
        let challenge = self
            .challenges
            .remove(challenge_id)
            .ok_or_else(|| fail("unknown or consumed challenge"))?;
        challenge.validate(self.profile_id())?;
        if challenge.server_instance != self.instance
            || challenge.upstream_origin.as_deref() != self.upstream_origin()
        {
            return Err(fail("invalid challenge audience"));
        }
        Ok(challenge)
    }

    fn verify_authorization(
        &mut self,
        challenge: &Challenge,
        digest: &[u8; 32],
        proof_base64: &str,
        tag: &str,
    ) -> Result<()> {
        if proof_base64.len() != PROOF_BYTES.div_ceil(3) * 4 || !protocol::valid_id(tag) {
            return Err(fail("invalid authorization"));
        }
        let proof = STANDARD.decode(proof_base64)?;
        if proof.len() != PROOF_BYTES {
            return Err(fail("invalid authorization proof"));
        }
        self.verification_attempts += 1;
        if !crypto::verify(
            &self.profile.verifying_key,
            &self.profile.manifest.group_root,
            digest,
            &proof,
            tag,
        )? {
            return Err(fail("invalid authorization proof"));
        }
        challenge.validate(self.profile_id())?;
        Ok(())
    }

    /// Burn the nonce and bind metadata before constructing an async upstream request.
    pub fn prepare_api(
        &mut self,
        challenge_id: &str,
        method: &str,
        path_base64: &str,
        headers_base64: &str,
        body: &[u8],
        proof_base64: &str,
        tag: &str,
    ) -> Result<AuthorizedApi> {
        self.check_available()?;
        if !self.is_gateway() {
            return Err(fail("upstream gateway mode required"));
        }
        let challenge = self.take_challenge(challenge_id)?;
        if !protocol::valid_api_method(method)
            || body.len() > MAX_API_BODY
            || (matches!(method, "GET" | "HEAD") && !body.is_empty())
            || path_base64.len() > MAX_API_PATH.div_ceil(3) * 4
            || headers_base64.len() > MAX_API_HEADER_BYTES.div_ceil(3) * 4
        {
            return Err(fail("invalid API metadata"));
        }
        let path = String::from_utf8(STANDARD.decode(path_base64)?)?;
        protocol::validate_api_path(&path)?;
        let headers_bytes = STANDARD.decode(headers_base64)?;
        if headers_bytes.len() > MAX_API_HEADER_BYTES {
            return Err(fail("API headers exceed limit"));
        }
        let headers: Vec<ApiHeader> = serde_json::from_slice(&headers_bytes)?;
        let headers = protocol::canonical_api_headers(&headers)?;
        let origin = self
            .upstream_origin()
            .ok_or_else(|| fail("missing upstream"))?
            .to_owned();
        let digest =
            protocol::api_request_digest(&challenge, &origin, method, &path, &headers, body);
        self.verify_authorization(&challenge, &digest, proof_base64, tag)?;
        let Backend::Upstream(forwarder) = &self.backend else {
            return Err(fail("upstream gateway mode required"));
        };
        forwarder
            .validate_request(method, &path, &headers, body)
            .map_err(|_| Box::new(ApiPolicyDenied) as crate::Error)?;
        let forwarder = forwarder.clone();
        self.executions += 1;
        Ok(AuthorizedApi {
            forwarder,
            method: method.to_owned(),
            path,
            headers,
            body: body.to_vec(),
        })
    }
}

pub fn bind(address: &str) -> Result<Server> {
    let address: SocketAddr = address
        .parse()
        .map_err(|_| fail("listen must be a numeric loopback IP:port"))?;
    if !address.ip().is_loopback() {
        return Err(fail("listen must be a numeric loopback IP:port"));
    }
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(Server { listener })
}

pub fn url(server: &Server) -> Result<String> {
    Ok(format!("http://{}", server.listener.local_addr()?))
}

fn response(
    status: u16,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .header("Connection", "close")
        .body(Full::new(body.into()))
        .expect("fixed valid response headers")
}
fn json(status: u16, body: &'static [u8]) -> Response<Full<Bytes>> {
    response(status, "application/json", body)
}
fn invalid_request() -> Response<Full<Bytes>> {
    json(400, br#"{"error":"invalid request"}"#)
}
fn unauthorized() -> Response<Full<Bytes>> {
    json(401, br#"{"error":"invalid authorization"}"#)
}
fn unavailable() -> Response<Full<Bytes>> {
    json(503, br#"{"error":"listener unavailable"}"#)
}

fn header_once<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let all = headers.get_all(name);
    let mut values = all.iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

async fn handle(
    state: Rc<RefCell<&mut State>>,
    request: Request<Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if request.headers().contains_key(ORIGIN) {
        return Ok(json(403, br#"{"error":"origin forbidden"}"#));
    }
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
        || request.headers().contains_key(TRANSFER_ENCODING)
    {
        return Ok(invalid_request());
    }
    let lengths = request.headers().get_all(CONTENT_LENGTH);
    let mut lengths = lengths.iter();
    let content_length = match lengths.next() {
        Some(value) => match value
            .to_str()
            .ok()
            .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|text| text.parse::<usize>().ok())
        {
            Some(length) => Some(length),
            None => return Ok(invalid_request()),
        },
        None => None,
    };
    if lengths.next().is_some() {
        return Ok(invalid_request());
    }
    let gateway = state.borrow().is_gateway();
    let body_limit = if gateway { MAX_API_BODY } else { MAX_BODY };
    if content_length.is_some_and(|length| length > body_limit) {
        return Ok(json(413, br#"{"error":"body too large"}"#));
    }
    let path = request.uri().path().to_owned();
    if request.method() == Method::GET && path == "/challenge" {
        if content_length.is_some_and(|length| length != 0) {
            return Ok(invalid_request());
        }
        let mut state = state.borrow_mut();
        return Ok(
            match state
                .challenge()
                .and_then(|challenge| Ok(serde_json::to_vec(&challenge)?))
            {
                Ok(body) => response(200, "application/json", body),
                Err(_) if state.poisoned => unavailable(),
                Err(_) => json(429, br#"{"error":"challenge unavailable"}"#),
            },
        );
    }
    if gateway {
        if path != "/api" {
            return Ok(json(404, br#"{"error":"unknown route"}"#));
        }
        // The API method is signed metadata. POST transport permits a HEAD
        // upstream response to carry its status/headers in a JSON envelope.
        if request.method() != Method::POST {
            return Ok(json(405, br#"{"error":"method not allowed"}"#));
        }
        if header_once(request.headers(), "content-type") != Some("application/octet-stream")
            || content_length.is_none()
        {
            return Ok(invalid_request());
        }
        let challenge = match header_once(request.headers(), protocol::CHALLENGE_HEADER) {
            Some(value) => value.to_owned(),
            None => return Ok(unauthorized()),
        };
        let target_method = header_once(request.headers(), protocol::API_METHOD_HEADER)
            .unwrap_or_default()
            .to_owned();
        let target_path = header_once(request.headers(), protocol::API_PATH_HEADER)
            .unwrap_or_default()
            .to_owned();
        let target_headers = header_once(request.headers(), protocol::API_HEADERS_HEADER)
            .unwrap_or_default()
            .to_owned();
        let proof = header_once(request.headers(), protocol::PROOF_HEADER)
            .unwrap_or_default()
            .to_owned();
        let tag = header_once(request.headers(), protocol::TAG_HEADER)
            .unwrap_or_default()
            .to_owned();
        let bytes = match tokio::time::timeout(
            BODY_TIMEOUT,
            Limited::new(request.into_body(), MAX_API_BODY).collect(),
        )
        .await
        {
            Ok(Ok(body)) => body.to_bytes(),
            _ => return Ok(invalid_request()),
        };
        if bytes.len() != content_length.unwrap_or(0) {
            return Ok(invalid_request());
        }
        let authorized = {
            state.borrow_mut().prepare_api(
                &challenge,
                &target_method,
                &target_path,
                &target_headers,
                &bytes,
                &proof,
                &tag,
            )
        };
        // No RefCell borrow crosses this await. The HTTP client is asynchronous.
        return Ok(match authorized {
            Ok(request) => match request.send().await {
                Ok(result) => match serde_json::to_vec(&result) {
                    Ok(body) if body.len() <= MAX_API_ENVELOPE => {
                        response(200, "application/json", body)
                    }
                    _ => json(
                        502,
                        br#"{"format":"zkweb-zk-api-error-v1","delivery":"unknown"}"#,
                    ),
                },
                Err(_) => json(
                    502,
                    br#"{"format":"zkweb-zk-api-error-v1","delivery":"unknown"}"#,
                ),
            },
            Err(error) if error.is::<ApiPolicyDenied>() => {
                json(403, br#"{"error":"upstream policy denied"}"#)
            }
            Err(_) => unauthorized(),
        });
    }
    if !path
        .strip_prefix("/records/")
        .is_some_and(protocol::valid_key)
    {
        return Ok(json(404, br#"{"error":"unknown route"}"#));
    }
    let method = request.method().as_str().to_owned();
    if !protocol::valid_method(&method) {
        return Ok(json(405, br#"{"error":"method not allowed"}"#));
    }
    if matches!(method.as_str(), "POST" | "PUT") {
        if header_once(request.headers(), "content-type") != Some("application/octet-stream")
            || content_length.is_none()
        {
            return Ok(invalid_request());
        }
    } else if content_length.is_some_and(|length| length != 0) {
        return Ok(invalid_request());
    }
    let challenge = match header_once(request.headers(), protocol::CHALLENGE_HEADER) {
        Some(challenge) => challenge.to_owned(),
        None => return Ok(unauthorized()),
    };
    // Missing, duplicated or non-text proof/tag headers are invalid attempts too.
    // Pass them as empty values so a recognized challenge is still consumed.
    let proof = header_once(request.headers(), protocol::PROOF_HEADER)
        .unwrap_or_default()
        .to_owned();
    let tag = header_once(request.headers(), protocol::TAG_HEADER)
        .unwrap_or_default()
        .to_owned();
    let bytes = match tokio::time::timeout(
        BODY_TIMEOUT,
        Limited::new(request.into_body(), MAX_BODY).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        _ => return Ok(invalid_request()),
    };
    if bytes.len() != content_length.unwrap_or(0) {
        return Ok(invalid_request());
    }
    let mut state = state.borrow_mut();
    Ok(
        match state.execute(&challenge, &method, &path, &bytes, &proof, &tag) {
            Ok(reply) => response(
                reply.status,
                if reply.status < 400 {
                    "application/octet-stream"
                } else {
                    "application/json"
                },
                reply.body,
            ),
            Err(_) if state.poisoned => unavailable(),
            Err(_) => unauthorized(),
        },
    )
}

/// Serial bounded HTTP/1 handling. The stop flag is polled during network I/O;
/// synchronous proof verification cannot be interrupted by the I/O timer.
pub fn run(server: &Server, state: &mut State, stop: Option<&AtomicBool>) -> Result<()> {
    let header_buffer = if state.is_gateway() {
        64 * 1024
    } else {
        16 * 1024
    };
    let connection_timeout = if state.is_gateway() {
        Duration::from_secs(60)
    } else {
        CONNECTION_TIMEOUT
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(server.listener.try_clone()?)?;
        let state = Rc::new(RefCell::new(state));
        loop {
            if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Ok(());
            }
            let (stream, _) = match tokio::time::timeout(STOP_POLL, listener.accept()).await {
                Ok(result) => result?,
                Err(_) => continue,
            };
            let state = state.clone();
            let service = service_fn(move |request| handle(state.clone(), request));
            let mut builder = http1::Builder::new();
            builder
                .keep_alive(false)
                .max_headers(32)
                .max_buf_size(header_buffer)
                .header_read_timeout(HEADER_TIMEOUT)
                .timer(TokioTimer::new());
            let connection = builder.serve_connection(TokioIo::new(stream), service);
            let mut connection = Box::pin(tokio::time::timeout(connection_timeout, connection));
            loop {
                if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                    return Ok(());
                }
                if tokio::time::timeout(STOP_POLL, connection.as_mut())
                    .await
                    .is_ok()
                {
                    break;
                }
            }
        }
    })
}
