//! The `crawlx` binary.

use clap::Parser as _;
use crawlx_worker::{build_runtime, RuntimeConfig};
use std::io::IsTerminal as _;
use std::process::ExitCode;

// Repeated browser crawls leave large free regions in glibc's per-thread arenas.
// Keep allocator ownership at the executable boundary, not in worker/browser libraries.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    // `DEBUG=true` (the compatibility switch): print the whole error chain with a backtrace. anyhow records
    // the backtrace when an error is created, so it is requested before anything runs.
    let debug = crawlx_cli::debug_enabled(&|key| std::env::var(key).ok());
    if debug && std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    // compatibility single-dash flags (`-mdc`, `-field-scope`) are rewritten to the `--long` flags first
    let cli = crawlx_cli::Cli::parse_from(crawlx_cli::normalize_args(std::env::args_os()));
    // one runtime built here, bounded blocking pool, no `#[tokio::main]`; it also
    // installs the parse-memory budget (`CRAWLX_PARSE_MEMORY_BYTES`)
    let runtime_config = match RuntimeConfig::from_env(&|key| std::env::var(key).ok()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime = match build_runtime(&runtime_config) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let mut stdout = std::io::stdout();
    // colour on a terminal unless the user opted out (`NO_COLOR`, `--no-color`); never in a pipe
    let terminal = stdout.is_terminal();
    let getenv = move |key: &str| {
        let value = std::env::var(key).ok();
        if key == "CLICOLOR_FORCE" && value.is_none() && terminal {
            Some("1".to_owned())
        } else {
            value
        }
    };
    match runtime.block_on(crawlx_cli::execute_with_env(cli, &mut stdout, &getenv)) {
        Ok(code) => code,
        Err(e) => {
            if debug {
                eprintln!("error: {e:?}");
            } else {
                eprintln!("error: {e:#}");
            }
            ExitCode::from(2)
        }
    }
}
