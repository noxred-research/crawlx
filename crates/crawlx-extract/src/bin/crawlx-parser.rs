//! Standalone entry of the isolated page parser.
//!
//! Serves the same single request as the hidden `crawlx` helper command: it applies its own
//! resource limits, reads one request frame on standard input and writes one response frame on
//! standard output. The parent passes the same arguments as for the `crawlx` binary
//! (`__isolated-parse --address-space-bytes N ...`). Point `CRAWLX_PARSER_HELPER` at this binary
//! when the running executable is not the `crawlx` binary.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(
        crawlx_extract::isolated::dispatch(std::env::args_os())
            .unwrap_or(crawlx_extract::isolated::EXIT_USAGE),
    )
}
