// SPDX-License-Identifier: AGPL-3.0-or-later
use std::io::{self, Read, Write};

fn run() -> Result<(), ()> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(zkweb_tlsn_verify::MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    let output = zkweb_tlsn_verify::verify_json(&input).map_err(|_| ())?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output).map_err(|_| ())?;
    stdout.write_all(b"\n").map_err(|_| ())?;
    Ok(())
}

fn main() {
    // The upstream verifier is experimental. An assertion in malformed-input
    // handling must not print a presentation, disclosed bytes or other context.
    std::panic::set_hook(Box::new(|_| {}));
    if !matches!(std::panic::catch_unwind(run), Ok(Ok(()))) {
        // Never print artifact bytes, third-party errors or disclosed secrets.
        eprintln!("zkweb-tlsn-verify: verification failed");
        std::process::exit(1);
    }
}
