//! Running an external OCR or rasteriser program with a deadline.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::OcrError;

/// Most bytes read from the stdout of a program.
const MAX_STDOUT: u64 = 64 * 1024 * 1024;
/// Most bytes kept of stderr (the head, for error messages).
const MAX_STDERR: u64 = 64 * 1024;

/// What a finished program wrote.
pub(super) struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Name of `program` for messages: the file name, never the directories of the host.
pub(super) fn program_name(program: &Path) -> String {
    program.file_name().map_or_else(
        || program.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Run `cmd` with `stdin` as its standard input, killing it after `timeout`.
///
/// Synchronous: the callers are CPU-bound parse functions that already run on blocking threads.
/// The pipes are drained on their own threads, so a program that fills a pipe cannot stall the
/// deadline loop; after a kill the threads are not waited for (a grandchild may keep a pipe
/// open), they end when the pipe closes.
pub(super) fn run(
    mut cmd: Command,
    program: &Path,
    stdin: &[u8],
    timeout: Duration,
) -> Result<Output, OcrError> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let spawn_error = |source| OcrError::Spawn {
        program: program_name(program),
        source,
    };
    let mut child = cmd.spawn().map_err(spawn_error)?;
    let deadline = Instant::now() + timeout;
    if let Some(mut pipe) = child.stdin.take() {
        let input = stdin.to_vec();
        std::thread::spawn(move || {
            // a program that exits before reading everything closes the pipe: not an error
            let _ = pipe.write_all(&input);
        });
    }
    let drain = |pipe: Option<Box<dyn Read + Send>>, cap: u64| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(pipe) = pipe {
                let _ = pipe.take(cap).read_to_end(&mut buf);
            }
            let _ = tx.send(buf);
        });
        rx
    };
    let out_rx = drain(
        child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>),
        MAX_STDOUT,
    );
    let err_rx = drain(
        child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>),
        MAX_STDERR,
    );
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(OcrError::Timeout {
                    program: program_name(program),
                    millis: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(spawn_error(e));
            }
        }
    };
    // the program has exited: its pipes reach end of file unless a grandchild holds them
    let wait = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_secs(1));
    let stdout = out_rx.recv_timeout(wait).unwrap_or_default();
    let stderr = err_rx.recv_timeout(wait).unwrap_or_default();
    Ok(Output {
        status,
        stdout,
        stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
    })
}

/// `program` as a path to run: a path with a directory part is used as is, a bare name is
/// looked up in `PATH`.
pub(super) fn resolve(program: &Path) -> Option<std::path::PathBuf> {
    if program.components().count() > 1 || program.is_absolute() {
        return program.is_file().then(|| program.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}
