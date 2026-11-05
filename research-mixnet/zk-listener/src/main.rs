// SPDX-License-Identifier: AGPL-3.0-or-later
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{collections::BTreeMap, io::Write, path::Path};
use zkweb_zk_listener::{MAX_BODY, PROTOCOL, Result, client, fail, profile, server};

fn option(options: &mut BTreeMap<String, String>, key: &str) -> Result<String> {
    options
        .remove(key)
        .ok_or_else(|| fail("missing required option"))
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
            let state_file = option(&mut options, "--state-file")?;
            let address = option(&mut options, "--listen")?;
            if !options.is_empty() {
                return Err(fail("unknown option"));
            }
            let listener = server::bind(&address)?;
            let mut state = server::State::open(
                profile::load_server(Path::new(&directory))?,
                Path::new(&state_file),
            )?;
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
            if !options.is_empty() || encoded.len() > MAX_BODY.div_ceil(3) * 4 {
                return Err(fail("invalid request options"));
            }
            let body = STANDARD.decode(&encoded)?;
            if body.len() > MAX_BODY || STANDARD.encode(&body) != encoded {
                return Err(fail("invalid request body"));
            }
            let result = client::request(
                &profile::load_client(Path::new(&directory))?,
                &endpoint,
                &method,
                &key,
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
