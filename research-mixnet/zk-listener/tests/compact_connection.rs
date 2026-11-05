// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zkweb_zk_listener::{Result, compact, crypto, fail, profile, protocol, server};

struct Running {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_reply(
    stream: &mut BufReader<TcpStream>,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let mut line = String::new();
    stream.read_line(&mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| fail("missing HTTP status"))?
        .parse()?;
    let mut headers = HashMap::new();
    loop {
        line.clear();
        if stream.read_line(&mut line)? == 0 {
            return Err(fail("truncated HTTP headers"));
        }
        if line == "\r\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| fail("invalid HTTP header"))?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length: usize = headers
        .get("content-length")
        .ok_or_else(|| fail("missing HTTP length"))?
        .parse()?;
    if length > 65536 {
        return Err(fail("unexpected test reply size"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok((status, headers, bytes))
}

fn connect(address: &str) -> Result<BufReader<TcpStream>> {
    let stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(BufReader::new(stream))
}

fn get_challenge(
    stream: &mut BufReader<TcpStream>,
    address: &str,
) -> Result<(HashMap<String, String>, Vec<u8>)> {
    write!(
        stream.get_mut(),
        "GET /b1/c HTTP/1.1\r\nHost: {address}\r\n\r\n"
    )?;
    stream.get_mut().flush()?;
    let (status, headers, bytes) = read_reply(stream)?;
    assert_eq!(status, 200);
    assert_eq!(bytes.len(), 72);
    Ok((headers, bytes))
}

#[test]
fn compact_reuses_one_tcp_connection_but_bounds_idle_wait_and_request_count() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let setup = profile::setup(&temporary.path().join("profile"), 1)?;
    let member = profile::load_client(&setup.client_dirs[0])?;
    let listener = server::bind("127.0.0.1:0")?;
    let address = server::url(&listener)?
        .trim_start_matches("http://")
        .to_owned();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let database = temporary.path().join("records.json");
    let server_dir = setup.server_dir;
    let worker = thread::spawn(move || {
        let mut state = server::State::open(profile::load_server(&server_dir)?, &database)?;
        server::run(&listener, &mut state, Some(&thread_stop))
    });
    let _running = Running {
        stop,
        worker: Some(worker),
    };
    let mut connection = connect(&address)?;
    let (headers, bytes) = get_challenge(&mut connection, &address)?;
    assert_ne!(headers.get("connection").map(String::as_str), Some("close"));
    let challenge = compact::decode_challenge(&bytes, &member.manifest.profile_id, None)?;
    let body = b"hello";
    let digest = protocol::request_digest(&challenge, "POST", "/records/a", body);
    let authorization = crypto::prove(
        &member.proving_key,
        &member.credential,
        &member.manifest.group_root,
        &digest,
    )?;
    let frame = compact::encode_request(
        compact::Kind::Records,
        &challenge.challenge_id,
        &authorization,
        "POST",
        "a",
        &[],
        body,
    )?;
    write!(
        connection.get_mut(),
        "POST /b1/r HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        frame.len()
    )?;
    connection.get_mut().write_all(&frame)?;
    connection.get_mut().flush()?;
    let (status, headers, bytes) = read_reply(&mut connection)?;
    assert_eq!(status, 201);
    assert_eq!(bytes, body);
    assert_eq!(headers.get("connection").map(String::as_str), Some("close"));
    assert_eq!(
        connection.read(&mut [0])?,
        0,
        "connection accepted more than two requests"
    );

    // An unauthenticated client that idles after a challenge must not retain
    // the serial accept loop for the longer operation/connection timeout.
    let mut idle = connect(&address)?;
    get_challenge(&mut idle, &address)?;
    let started = Instant::now();
    let mut waiting = connect(&address)?;
    get_challenge(&mut waiting, &address)?;
    assert!(
        started.elapsed() < server::COMPACT_IDLE_TIMEOUT + Duration::from_secs(2),
        "idle compact connection monopolized the listener"
    );
    assert_eq!(
        idle.read(&mut [0])?,
        0,
        "idle compact connection was not closed"
    );
    Ok(())
}
