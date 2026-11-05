// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    MAX_PROOF, MAX_WIRE, PROTOCOL, Result, crypto, fail,
    profile::{PublicProfile, ServerProfile},
    protocol::{self, Challenge, Query, QueryResult},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response,
    body::Incoming,
    header::{CONTENT_LENGTH, CONTENT_TYPE, ORIGIN, TRANSFER_ENCODING},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    cell::RefCell,
    collections::HashMap,
    convert::Infallible,
    net::{SocketAddr, TcpListener},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
pub const BODY_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_POLL: Duration = Duration::from_millis(100);

/// Only one connection is accepted at a time. Parsing does not create worker threads.
pub struct Server {
    listener: TcpListener,
}

pub struct State {
    public: PublicProfile,
    instance: String,
    challenges: HashMap<String, Challenge>,
    evaluations: u64,
    verification_attempts: u64,
}
impl State {
    /// Call and use on the same thread: TFHE's evaluation key is thread-local.
    pub fn new(profile: ServerProfile) -> Self {
        tfhe::set_server_key(profile.server_key);
        Self {
            public: profile.public,
            instance: protocol::random_id(),
            challenges: HashMap::new(),
            evaluations: 0,
            verification_attempts: 0,
        }
    }
    pub fn profile_id(&self) -> &str {
        &self.public.manifest.profile_id
    }
    pub fn evaluation_count(&self) -> u64 {
        self.evaluations
    }
    pub fn verification_attempt_count(&self) -> u64 {
        self.verification_attempts
    }
    pub fn challenge(&mut self) -> Result<Challenge> {
        let time = protocol::now()?;
        self.challenges.retain(|_, entry| entry.expires_unix > time);
        if self.challenges.len() >= protocol::MAX_CHALLENGES {
            return Err(fail("challenge capacity reached"));
        }
        let challenge = Challenge {
            protocol: PROTOCOL.into(),
            profile_id: self.profile_id().into(),
            server_instance: self.instance.clone(),
            challenge_id: protocol::random_id(),
            expires_unix: time + protocol::LIFETIME,
        };
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }
    pub fn execute(&mut self, query: &Query) -> Result<QueryResult> {
        if !protocol::valid_id(&query.challenge_id) {
            return Err(fail("invalid query"));
        }
        // Reserve the nonce before decoding or verifying attacker-controlled proof data.
        // Every attempt burns its nonce, including malformed or invalid proofs.
        let challenge = self
            .challenges
            .remove(&query.challenge_id)
            .ok_or_else(|| fail("unknown or consumed challenge"))?;
        challenge.validate(self.profile_id())?;
        if query.proof_base64.len() > MAX_PROOF.div_ceil(3) * 4 {
            return Err(fail("invalid query"));
        }
        let proof = STANDARD.decode(&query.proof_base64)?;
        self.verification_attempts += 1;
        let selector = crypto::verify_selector(
            &proof,
            &self.public.public_key,
            &self.public.crs,
            &challenge.metadata(),
        )?;
        // An expensive verification may have crossed the challenge expiration time.
        challenge.validate(self.profile_id())?;
        self.evaluations += 1;
        let ciphertext = crypto::evaluate(&selector, &self.public.public_key)?;
        Ok(QueryResult {
            protocol: PROTOCOL.into(),
            profile_id: self.profile_id().into(),
            server_instance: self.instance.clone(),
            challenge_id: challenge.challenge_id,
            ciphertext_base64: STANDARD.encode(ciphertext),
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

fn json_response(status: u16, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header("Connection", "close")
        .body(Full::new(body.into()))
        .expect("fixed valid response headers")
}

fn invalid_request() -> Response<Full<Bytes>> {
    json_response(400, &br#"{"error":"invalid request"}"#[..])
}

async fn handle(
    state: Rc<RefCell<&mut State>>,
    request: Request<Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if request.headers().contains_key(ORIGIN) {
        return Ok(json_response(403, &br#"{"error":"origin forbidden"}"#[..]));
    }
    // Accept origin-form request targets and unambiguous fixed-length bodies only.
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.headers().contains_key(TRANSFER_ENCODING)
    {
        return Ok(invalid_request());
    }
    let content_lengths = request.headers().get_all(CONTENT_LENGTH);
    let mut content_lengths = content_lengths.iter();
    let content_length = match content_lengths.next() {
        Some(value) => match value.to_str().ok().and_then(|s| s.parse::<usize>().ok()) {
            Some(length) => Some(length),
            None => return Ok(invalid_request()),
        },
        None => None,
    };
    if content_lengths.next().is_some() {
        return Ok(invalid_request());
    }
    let route = request.uri().path_and_query().map(|p| p.as_str());
    if request.method() == Method::GET && route == Some("/challenge") {
        if content_length.is_some_and(|length| length != 0) {
            return Ok(invalid_request());
        }
        return Ok(
            match state
                .borrow_mut()
                .challenge()
                .and_then(|c| Ok(serde_json::to_vec(&c)?))
            {
                Ok(body) => json_response(200, body),
                Err(_) => json_response(429, &br#"{"error":"challenge unavailable"}"#[..]),
            },
        );
    }
    if request.method() != Method::POST || route != Some("/query") {
        return Ok(json_response(404, &br#"{"error":"unknown route"}"#[..]));
    }
    let content_types = request.headers().get_all(CONTENT_TYPE);
    let mut content_types = content_types.iter();
    if content_types.next().map(|v| v.as_bytes()) != Some(b"application/json".as_slice())
        || content_types.next().is_some()
        || content_length.is_none_or(|length| length == 0 || length > MAX_WIRE)
    {
        return Ok(invalid_request());
    }
    // Limit/deadline the body before borrowing State or starting any cryptography.
    let bytes = match tokio::time::timeout(
        BODY_TIMEOUT,
        Limited::new(request.into_body(), MAX_WIRE).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected.to_bytes(),
        _ => return Ok(invalid_request()),
    };
    if bytes.len() != content_length.unwrap() {
        return Ok(invalid_request());
    }
    let result = (|| -> Result<Vec<u8>> {
        let query: Query = serde_json::from_slice(&bytes)?;
        Ok(serde_json::to_vec(&state.borrow_mut().execute(&query)?)?)
    })();
    Ok(match result {
        Ok(body) => json_response(200, body),
        Err(_) => json_response(400, &br#"{"error":"invalid proof or challenge"}"#[..]),
    })
}

/// Bounded HTTP/1 processing on the calling thread, including TFHE's thread-local key.
/// There is one active connection, no per-connection task/thread, and no keep-alive.
/// Optional stop is used by integration tests; it is checked while accepting or waiting
/// on network I/O, but cannot preempt a synchronous cryptographic operation.
pub fn run(server: &Server, state: &mut State, stop: Option<&AtomicBool>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(server.listener.try_clone()?)?;
        let state = Rc::new(RefCell::new(state));
        loop {
            if stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
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
                .max_buf_size(16 * 1024)
                .header_read_timeout(HEADER_TIMEOUT)
                .timer(TokioTimer::new());
            let connection = builder.serve_connection(TokioIo::new(stream), service);
            // Also bound a stalled response reader. This cannot preempt synchronous FHE.
            let mut connection = Box::pin(tokio::time::timeout(CONNECTION_TIMEOUT, connection));
            loop {
                if stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
                    return Ok(());
                }
                if tokio::time::timeout(STOP_POLL, connection.as_mut())
                    .await
                    .is_ok()
                {
                    // Malformed/oversized headers and disconnected clients end only this
                    // connection; no request fields or cryptographic errors are logged.
                    break;
                }
            }
        }
    })
}
