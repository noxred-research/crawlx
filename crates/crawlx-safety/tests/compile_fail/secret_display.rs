//! A resolved secret has no `Display`, so it cannot reach a log line, an error
//! message or a prompt through formatting; `Debug` exists but prints `[REDACTED]`.
use crawlx_core::secret::SecretOr;

fn leak(value: SecretOr<String>) -> String {
    format!("typed {value}")
}

fn leak_to_string(value: &SecretOr<String>) -> String {
    value.to_string()
}

fn main() {}
