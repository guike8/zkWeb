// SPDX-License-Identifier: AGPL-3.0-or-later
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use zkweb_zk_listener::{
    MAX_BODY, PROTOCOL, Result, client, fail, forward, profile, protocol, server,
};

fn option(options: &mut BTreeMap<String, String>, key: &str) -> Result<String> {
    options
        .remove(key)
        .ok_or_else(|| fail("missing required option"))
}

fn compact_wire(options: &mut BTreeMap<String, String>) -> Result<bool> {
    match options.remove("--wire").as_deref().unwrap_or("compact") {
        "compact" => Ok(true),
        "legacy" => Ok(false),
        _ => Err(fail("wire must be compact or legacy")),
    }
}

fn print_json(value: &impl serde::Serialize, uncertain: bool) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    std::io::stdout().write_all(&bytes).map_err(|error| {
        if uncertain {
            Box::new(client::DeliveryUnknown) as zkweb_zk_listener::Error
        } else {
            error.into()
        }
    })
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| fail("usage: zkweb-zk-listener setup|listen|request [options]"))?;
    let mut options = BTreeMap::new();
    while let Some(name) = args.next() {
        if !name.starts_with("--") {
            return Err(fail("expected named option"));
        }
        let value = args.next().ok_or_else(|| fail("missing option value"))?;
        if options.insert(name, value).is_some() {
            return Err(fail("duplicate option"));
        }
    }
    match command.as_str() {
        "setup" => {
            let output = option(&mut options, "--output")?;
            let members: usize = option(&mut options, "--members")?
                .parse()
                .map_err(|_| fail("invalid member count"))?;
            if !options.is_empty() {
                return Err(fail("unknown option"));
            }
            print_json(&profile::setup(Path::new(&output), members)?, false)?;
        }
        "listen" => {
            let directory = option(&mut options, "--server-dir")?;
            let address = option(&mut options, "--listen")?;
            let state_file = options.remove("--state-file");
            let upstream = options.remove("--upstream");
            if state_file.is_some() == upstream.is_some() {
                return Err(fail("choose record state or configured HTTPS upstream"));
            }
            let loaded = profile::load_server(Path::new(&directory))?;
            let mut state = if let Some(origin) = upstream {
                let allowed_methods = options
                    .remove("--allow-methods")
                    .unwrap_or_else(|| "GET,HEAD".into())
                    .split(',')
                    .map(str::to_owned)
                    .collect();
                let path_prefix = options
                    .remove("--upstream-path-prefix")
                    .unwrap_or_else(|| "/".into());
                let allow_private = options
                    .remove("--allow-private-upstream")
                    .unwrap_or_else(|| "false".into())
                    .parse()
                    .map_err(|_| fail("invalid private upstream policy"))?;
                let ca_file = options.remove("--upstream-ca-file").map(PathBuf::from);
                let headers_file = options.remove("--upstream-headers-file").map(PathBuf::from);
                if !options.is_empty() {
                    return Err(fail("unknown option"));
                }
                server::State::open_gateway(
                    loaded,
                    forward::Config {
                        origin,
                        allowed_methods,
                        path_prefix,
                        allow_private,
                        ca_file,
                        headers_file,
                    },
                )?
            } else {
                if !options.is_empty() {
                    return Err(fail("upstream options require gateway mode"));
                }
                server::State::open(loaded, Path::new(state_file.as_ref().unwrap()))?
            };
            let listener = server::bind(&address)?;
            print_json(
                &serde_json::json!({"event":"ready", "url":server::url(&listener)?, "profile_id":state.profile_id(), "protocol":PROTOCOL}),
                false,
            )?;
            std::io::stdout().flush()?;
            server::run(&listener, &mut state, None)?;
        }
        "request" => {
            let directory = option(&mut options, "--client-dir")?;
            let endpoint = option(&mut options, "--url")?;
            let method = option(&mut options, "--method")?;
            let key = option(&mut options, "--key")?;
            let encoded = option(&mut options, "--data-base64")?;
            let compact = compact_wire(&mut options)?;
            if !options.is_empty() || encoded.len() > MAX_BODY.div_ceil(3) * 4 {
                return Err(fail("invalid request options"));
            }
            let body = STANDARD.decode(&encoded)?;
            if body.len() > MAX_BODY || STANDARD.encode(&body) != encoded {
                return Err(fail("invalid request body"));
            }
            let send = if compact {
                client::request_compact
            } else {
                client::request
            };
            let result = send(
                &profile::load_client(Path::new(&directory))?,
                &endpoint,
                &method,
                &key,
                &body,
            )?;
            print_json(&result, true)?;
        }
        "api-request" => {
            let directory = option(&mut options, "--client-dir")?;
            let endpoint = option(&mut options, "--url")?;
            let upstream = option(&mut options, "--upstream")?;
            let method = option(&mut options, "--method")?;
            let path = option(&mut options, "--path")?;
            let encoded = option(&mut options, "--headers-base64")?;
            let body_file = option(&mut options, "--body-file")?;
            let compact = compact_wire(&mut options)?;
            if !options.is_empty()
                || encoded.len() > zkweb_zk_listener::MAX_API_HEADER_BYTES.div_ceil(3) * 4
            {
                return Err(fail("invalid API request options"));
            }
            let bytes = STANDARD.decode(encoded)?;
            if bytes.len() > zkweb_zk_listener::MAX_API_HEADER_BYTES {
                return Err(fail("API headers exceed limit"));
            }
            let headers: Vec<protocol::ApiHeader> = serde_json::from_slice(&bytes)?;
            if !Path::new(&body_file).is_absolute() {
                return Err(fail("absolute private body file required"));
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&body_file)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > zkweb_zk_listener::MAX_API_BODY as u64 {
                return Err(fail("invalid API body file"));
            }
            let mut body = Vec::new();
            (&mut file)
                .take(zkweb_zk_listener::MAX_API_BODY as u64 + 1)
                .read_to_end(&mut body)?;
            if body.len() > zkweb_zk_listener::MAX_API_BODY {
                return Err(fail("API body exceeds limit"));
            }
            let send = if compact {
                client::api_request_compact
            } else {
                client::api_request
            };
            let result = send(
                &profile::load_client(Path::new(&directory))?,
                &endpoint,
                &upstream,
                &method,
                &path,
                &headers,
                &body,
            )?;
            print_json(&result, true)?;
        }
        _ => return Err(fail("unknown command")),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        if error.downcast_ref::<client::DeliveryUnknown>().is_some() {
            let _ = writeln!(
                std::io::stdout(),
                "{{\"format\":\"zkweb-zk-error-v1\",\"delivery\":\"unknown\"}}"
            );
            std::process::exit(2);
        }
        // Keep credential/proof contents out of diagnostics, including parser errors.
        eprintln!("zkweb-zk-listener: operation failed; check the profile, request and listener");
        std::process::exit(1);
    }
}
