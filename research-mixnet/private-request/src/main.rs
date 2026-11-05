// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{collections::BTreeMap, io::Write, path::Path};
use zkweb_private::{PROTOCOL, Result, client, fail, profile, server};

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| fail("usage: zkweb-private setup|serve|query [options]"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if !key.starts_with("--") {
            return Err(fail("expected named option"));
        }
        let value = args.next().ok_or_else(|| fail("missing option value"))?;
        if options.insert(key, value).is_some() {
            return Err(fail("duplicate option"));
        }
    }
    let mut take = |key: &str| {
        options
            .remove(key)
            .ok_or_else(|| fail("missing required option"))
    };
    match command.as_str() {
        "setup" => {
            let output = take("--output")?;
            if !options.is_empty() {
                return Err(fail("unknown option"));
            }
            let result = profile::setup(Path::new(&output))?;
            println!("{}", serde_json::to_string(&result)?);
        }
        "serve" => {
            let directory = take("--server-dir")?;
            let listen = take("--listen")?;
            if !options.is_empty() {
                return Err(fail("unknown option"));
            }
            let listener = server::bind(&listen)?;
            let mut state = server::State::new(profile::load_server(Path::new(&directory))?);
            println!(
                "{}",
                serde_json::json!({"event":"ready", "url":server::url(&listener)?, "profile_id":state.profile_id(), "protocol":PROTOCOL})
            );
            std::io::stdout().flush()?;
            server::run(&listener, &mut state, None)?;
        }
        "query" => {
            let directory = take("--client-dir")?;
            let url = take("--url")?;
            let index: u8 = take("--index")?
                .parse()
                .map_err(|_| fail("index must be between 0 and 3"))?;
            if !options.is_empty() {
                return Err(fail("unknown option"));
            }
            client::validated_url(&url)?;
            let result = client::query(&profile::load_client(Path::new(&directory))?, &url, index)?;
            println!("{}", serde_json::to_string(&result)?);
        }
        _ => return Err(fail("unknown command")),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("zkweb-private: {error}");
        std::process::exit(1);
    }
}
