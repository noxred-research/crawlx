//! Offline command import into admitted, redacted native crawl JSON.
//!
//! Only one GET request is representable without the admitted-effect journal.
//! Headers use the native request-control importer. Conversion never resolves DNS,
//! opens files, resolves credentials, spawns processes, or evaluates shell syntax.
//! Output is a redacted review template, not traffic authority; execution must admit
//! it again. Query values and fragments are withheld even when their names look benign.

use clap::{Args, Subcommand};
use crawlx_core::config::CrawlMode;
use crawlx_core::request::import::ImportError;
use crawlx_core::traffic::REDACTED_PLACEHOLDER;
use crawlx_core::{CreateCrawl, SystemClock};
use crawlx_policy::{AdmissionPolicy, TenantLimits};
use std::{fmt, io::Write, process::ExitCode, sync::Arc};
use url::Url;

const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_WORDS: usize = 256;

/// Convert a local request description without executing it.
#[derive(Args, Debug)]
#[non_exhaustive]
pub struct ConvertArgs {
    /// Request description format.
    #[command(subcommand)]
    pub command: ConvertCommand,
}

/// Supported local request description formats.
#[derive(Subcommand, Debug)]
#[non_exhaustive]
pub enum ConvertCommand {
    /// Import one quoted command into a redacted native GET crawl template.
    // wire-compat: this spelling identifies the input command syntax.
    Curl(CurlArgs),
}

/// Arguments for importing a quoted request command.
#[derive(Args)]
#[non_exhaustive]
pub struct CurlArgs {
    /// Entire command as one quoted argument. Supported: URL, -X GET, -H, -A, -b, --url, --.
    #[arg(value_name = "COMMAND", allow_hyphen_values = true)]
    pub command: String,
}

impl fmt::Debug for CurlArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurlArgs")
            .field("command", &REDACTED_PLACEHOLDER)
            .finish()
    }
}

/// Bounded import refusal. No variant retains caller text or secret-bearing causes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConvertError {
    /// Input exceeds byte or word limits.
    #[error("command import limit exceeded")]
    Limit,
    /// Shell quoting is incomplete or malformed.
    #[error("invalid command quoting")]
    Quoting,
    /// Expansion, substitution, operators, or command chaining were requested.
    #[error("shell evaluation syntax is not supported")]
    ShellSyntax,
    /// The executable is not the supported request command.
    #[error("unsupported command executable")]
    Executable,
    /// An option has no faithful native mapping. Raw option text is deliberately withheld.
    #[error("unsupported request flag")]
    UnsupportedFlag,
    /// A supported flag lacks its required value.
    #[error("request flag requires a value")]
    MissingValue,
    /// Exactly one absolute request URL is required.
    #[error("exactly one valid request URL is required")]
    Url,
    /// A header cannot be imported through the native request controls.
    #[error("invalid imported request header")]
    Header,
    /// Existing request-import restrictions still apply, including the effect-journal boundary.
    #[error(transparent)]
    Request(#[from] ImportError),
    /// Existing native safety admission refused the request. Unsafe source messages are withheld.
    #[error("request rejected by native safety admission")]
    Admission,
    /// The final approved output could not be encoded.
    #[error("redacted request encoding failed")]
    Encoding,
}

/// Import one quoted command and emit only redacted native JSON.
///
/// # Errors
/// Returns a typed import refusal or an output I/O error. No import error includes input text.
pub fn run(args: ConvertArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let ConvertCommand::Curl(args) = args.command;
    let request = import_command(&args.command)?;
    let encoded = serde_json::to_string_pretty(&request).map_err(|_| ConvertError::Encoding)?;
    // Use the native typed redacted view, not generic JSON field-name masking:
    // generic masking can replace a cookie array with a string and break the schema.
    writeln!(out, "{encoded}")?;
    Ok(ExitCode::SUCCESS)
}

fn import_command(command: &str) -> Result<CreateCrawl, ConvertError> {
    let words = lex(command)?;
    // wire-compat: exact executable spelling; paths, wrappers and aliases are not executed.
    if words.first().map(String::as_str) != Some("curl") {
        return Err(ConvertError::Executable);
    }
    let mut request = None;
    let mut headers = Vec::new();
    let mut positional = false;
    let mut words = words.iter().skip(1);
    while let Some(word) = words.next() {
        if !positional && word == "--" {
            positional = true;
            continue;
        }
        if !positional && word.starts_with('-') {
            let (flag, inline) = split_flag(word);
            if !matches!(
                flag,
                "-X" | "--request" | "-H" | "--header" | "-A" | "--user-agent" | "-b" | "--cookie" | "--url"
            ) {
                return Err(ConvertError::UnsupportedFlag);
            }
            let value = match inline {
                Some(value) => value,
                None => words
                    .next()
                    .map(String::as_str)
                    .ok_or(ConvertError::MissingValue)?,
            };
            match flag {
                "-X" | "--request" => {
                    if value != "GET" {
                        return Err(ImportError::JournalRequired.into());
                    }
                }
                "-H" | "--header" => {
                    // A leading @ asks the source command to read a file. Never do that.
                    if value.starts_with('@') {
                        return Err(ConvertError::UnsupportedFlag);
                    }
                    let (name, value) = value.split_once(':').ok_or(ConvertError::Header)?;
                    if value.trim().is_empty() {
                        // Empty/removal-header semantics differ from native request controls.
                        return Err(ConvertError::UnsupportedFlag);
                    }
                    headers.push((name, value));
                }
                "-A" | "--user-agent" => headers.push(("User-Agent", value)),
                "-b" | "--cookie" => {
                    if value.starts_with('@') || !value.contains('=') {
                        return Err(ConvertError::UnsupportedFlag);
                    }
                    headers.push(("Cookie", value));
                }
                "--url" => set_url(&mut request, value)?,
                _ => return Err(ConvertError::UnsupportedFlag),
            }
        } else {
            set_url(&mut request, word)?;
        }
    }
    let mut request = CreateCrawl::new(request.ok_or(ConvertError::Url)?);
    request.mode = CrawlMode::Static;
    request.limits.urls = 1;
    request.scope.max_discovery_depth = 0;
    // Match the source command's no-redirect, no-retry defaults.
    request.fetch.follow_redirects = false;
    request.fetch.retries = 0;
    for (name, value) in headers {
        if request
            .fetch
            .extra_headers
            .get(&name.trim().to_ascii_lowercase())
            .is_some()
            || (name.trim().eq_ignore_ascii_case("cookie") && !request.fetch.cookies.is_empty())
            || (name.trim().eq_ignore_ascii_case("user-agent") && request.fetch.user_agent.is_some())
        {
            // Repeated source headers can be additive; native controls replace them.
            return Err(ConvertError::UnsupportedFlag);
        }
        request
            .fetch
            .set_header(name, value)
            .map_err(|_| ConvertError::Header)?;
    }
    // Admission checks URL schemes, pre-resolution SSRF, request controls and safe defaults.
    // No socket or DNS operation is involved. Conversion does not grant execution authority.
    AdmissionPolicy::new(Arc::new(SystemClock))
        .admit(&mut request, &TenantLimits::default(), None)
        .map_err(|_| ConvertError::Admission)?;
    let mut redacted = request.redacted();
    // Native redacted() masks extra headers and cookies, but User-Agent is normally public.
    // Here every caller-supplied header value is treated as potentially secret.
    if redacted.fetch.user_agent.is_some() {
        redacted.fetch.user_agent = Some(REDACTED_PLACEHOLDER.to_owned());
    }
    if redacted.seed_url.query().is_some() {
        let names: Vec<String> = redacted
            .seed_url
            .query_pairs()
            .map(|(name, _)| name.into_owned())
            .collect();
        let mut query = redacted.seed_url.query_pairs_mut();
        query.clear();
        for name in names {
            query.append_pair(&name, REDACTED_PLACEHOLDER);
        }
    }
    redacted.seed_url.set_fragment(None);
    Ok(redacted)
}

fn set_url(target: &mut Option<Url>, value: &str) -> Result<(), ConvertError> {
    if target.is_some() || value.contains(['{', '}']) {
        return Err(ConvertError::Url);
    }
    let url = Url::parse(value).map_err(|_| ConvertError::Url)?;
    if [
        url.path(),
        url.query().unwrap_or_default(),
        url.fragment().unwrap_or_default(),
    ]
    .iter()
    .any(|part| part.contains(['[', ']']))
    {
        // URL ranges require source-command glob expansion; literal IPv6 hosts do not.
        return Err(ConvertError::UnsupportedFlag);
    }
    // Same credential boundary as the existing declarative request importer.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ImportError::Request.into());
    }
    *target = Some(url);
    Ok(())
}

fn split_flag(word: &str) -> (&str, Option<&str>) {
    if word.starts_with("--") {
        return word
            .split_once('=')
            .map_or((word, None), |(flag, value)| (flag, Some(value)));
    }
    for flag in ["-X", "-H", "-A", "-b"] {
        if let Some(value) = word.strip_prefix(flag) {
            return (flag, (!value.is_empty()).then_some(value));
        }
    }
    (word, None)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

/// Restricted shell word lexer. Quotes and escapes are data handling, never evaluation.
fn lex(command: &str) -> Result<Vec<String>, ConvertError> {
    if command.len() > MAX_COMMAND_BYTES {
        return Err(ConvertError::Limit);
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = Quote::None;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        // Reject substitutions even inside quotes: ambiguous pasted commands fail closed.
        if matches!(ch, '$' | '`') {
            return Err(ConvertError::ShellSyntax);
        }
        if ch.is_control() && ch != '\t' {
            return Err(ConvertError::ShellSyntax);
        }
        match (quote, ch) {
            (Quote::None, '\'' | '"') => {
                quote = if ch == '\'' { Quote::Single } else { Quote::Double };
                started = true;
            }
            (Quote::Single, '\'') | (Quote::Double, '"') => quote = Quote::None,
            (Quote::None | Quote::Double, '\\') => {
                let next = chars.next().ok_or(ConvertError::Quoting)?;
                if next == '\n' {
                    continue;
                }
                if next.is_control() || matches!(next, '$' | '`') {
                    return Err(ConvertError::ShellSyntax);
                }
                if quote == Quote::Double && !matches!(next, '\\' | '"') {
                    word.push('\\');
                }
                word.push(next);
                started = true;
            }
            (Quote::None, ';' | '|' | '&' | '<' | '>' | '(' | ')' | '{' | '}' | '#') => {
                return Err(ConvertError::ShellSyntax);
            }
            (Quote::None, ch) if ch.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                    if words.len() > MAX_WORDS {
                        return Err(ConvertError::Limit);
                    }
                }
            }
            _ => {
                word.push(ch);
                started = true;
            }
        }
    }
    if quote != Quote::None {
        return Err(ConvertError::Quoting);
    }
    if started {
        words.push(word);
    }
    if words.len() > MAX_WORDS {
        return Err(ConvertError::Limit);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use clap::Parser;

    #[tokio::test]
    async fn registered_command_emits_admitted_native_json_without_network() {
        let cli = crate::Cli::try_parse_from([
            "crawlx",
            "convert",
            "curl",
            "curl -X GET -H 'Accept: text/html' --url https://fixture.test/article",
        ])
        .unwrap();
        let mut out = Vec::new();
        assert_eq!(
            crate::execute_with_env(cli, &mut out, &|_| None).await.unwrap(),
            ExitCode::SUCCESS
        );
        let mut request: CreateCrawl = serde_json::from_slice(&out).unwrap();
        assert_eq!(request.seed_url.as_str(), "https://fixture.test/article");
        assert_eq!(request.mode, CrawlMode::Static);
        assert_eq!(request.limits.urls, 1);
        assert_eq!(request.scope.max_discovery_depth, 0);
        assert!(!request.fetch.follow_redirects);
        assert_eq!(request.fetch.retries, 0);
        assert_eq!(
            request.fetch.extra_headers.get("accept"),
            Some(REDACTED_PLACEHOLDER)
        );
        AdmissionPolicy::new(Arc::new(SystemClock))
            .admit(&mut request, &TenantLimits::default(), None)
            .unwrap();
    }

    #[test]
    fn lexer_preserves_quotes_escapes_unicode_and_line_continuations() {
        assert_eq!(
            lex("curl 'https://fixture.test/文' -H \"X-Test: a\\\"b\" \\\n-H X-Other:\\ value").unwrap(),
            [
                "curl",
                "https://fixture.test/文",
                "-H",
                "X-Test: a\"b",
                "-H",
                "X-Other: value"
            ]
        );
        assert_eq!(lex("curl ''").unwrap(), ["curl", ""]);
        assert_eq!(lex("curl \"a\\zb\"").unwrap(), ["curl", "a\\zb"]);
    }

    #[test]
    fn unsupported_flags_and_methods_refuse_without_raw_values() {
        for flag in [
            "--insecure",
            "--location",
            "--proxy=private-value",
            "--data",
            "-dprivate-value",
            "-I",
            "--config",
            "--header=@private-value",
        ] {
            let error = import_command(&format!("curl {flag} https://fixture.test")).unwrap_err();
            assert_eq!(error, ConvertError::UnsupportedFlag);
            assert!(!format!("{error:?} {error}").contains("private-value"));
        }
        assert_eq!(
            import_command("curl -X POST https://fixture.test").unwrap_err(),
            ConvertError::Request(ImportError::JournalRequired)
        );
        assert_eq!(import_command("curl -H").unwrap_err(), ConvertError::MissingValue);
    }

    #[test]
    fn shell_execution_syntax_is_always_refused() {
        for command in [
            "curl $(id)",
            "curl `id`",
            "curl '${TOKEN}'",
            "curl \"$TOKEN\"",
            "curl https://fixture.test; id",
            "curl https://fixture.test | id",
            "curl https://fixture.test && id",
            "curl <(id)",
            "curl https://fixture.test > out",
            "curl https://fixture.test\nid",
            "curl https://fixture.test # comment",
        ] {
            assert_eq!(import_command(command).unwrap_err(), ConvertError::ShellSyntax);
        }
        assert_eq!(
            import_command("curl 'unterminated").unwrap_err(),
            ConvertError::Quoting
        );
        assert_eq!(
            import_command("curl https://fixture.test\\").unwrap_err(),
            ConvertError::Quoting
        );
    }

    #[test]
    fn malformed_and_unsafe_targets_use_native_safety_boundary() {
        for command in [
            "curl",
            "curl not-a-url",
            "curl https://fixture.test https://other.test",
            "curl --url=",
        ] {
            assert_eq!(import_command(command).unwrap_err(), ConvertError::Url);
        }
        for url in [
            "http://127.0.0.1/",
            "http://169.254.169.254/",
            "file:///etc/passwd",
        ] {
            assert_eq!(
                import_command(&format!("curl '{url}'")).unwrap_err(),
                ConvertError::Admission
            );
        }
        assert_eq!(
            import_command("curl https://user:private-value@fixture.test/").unwrap_err(),
            ConvertError::Request(ImportError::Request)
        );
        assert_eq!(
            import_command("other https://fixture.test").unwrap_err(),
            ConvertError::Executable
        );
    }

    #[test]
    fn header_cookie_query_fragment_and_debug_never_publish_secret_values() {
        let auth_header = format!("{}: Bearer auth-secret", "Authorization");
        let command = format!("curl 'https://fixture.test/?token=query-secret&ordinary=other-secret#fragment-secret' -H '{auth_header}' -H 'X-Custom: custom-secret' -A agent-secret -b 'session=cookie-secret'");
        let args = ConvertArgs {
            command: ConvertCommand::Curl(CurlArgs { command }),
        };
        assert!(!format!("{args:?}").contains("secret"));
        let mut out = Vec::new();
        let _exit = run(args, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        for secret in [
            "query-secret",
            "other-secret",
            "fragment-secret",
            "auth-secret",
            "custom-secret",
            "agent-secret",
            "cookie-secret",
        ] {
            assert!(!text.contains(secret), "leaked {secret}");
        }
        let request: CreateCrawl = serde_json::from_str(&text).unwrap();
        assert!(request.seed_url.fragment().is_none());
        assert!(request
            .seed_url
            .query_pairs()
            .all(|(_, value)| value == REDACTED_PLACEHOLDER));
    }

    #[test]
    fn header_import_validation_and_input_bounds_fail_closed() {
        for command in [
            "curl https://fixture.test -H malformed",
            "curl https://fixture.test -b broken",
        ] {
            assert!(import_command(command).is_err());
        }
        assert_eq!(
            import_command("curl https://fixture.test -H 'Host: other.test'").unwrap_err(),
            ConvertError::Admission
        );
        for command in [
            "curl https://fixture.test -H 'X-Test: first' -H 'x-test: second'",
            "curl https://fixture.test -A first -H 'User-Agent: second'",
            "curl https://fixture.test -b 'a=first' -H 'Cookie: b=second'",
            "curl 'https://fixture.test/[1-3]'",
        ] {
            assert_eq!(
                import_command(command).unwrap_err(),
                ConvertError::UnsupportedFlag
            );
        }
        assert_eq!(
            lex(&"x".repeat(MAX_COMMAND_BYTES + 1)).unwrap_err(),
            ConvertError::Limit
        );
        assert_eq!(lex(&"x ".repeat(MAX_WORDS + 1)).unwrap_err(), ConvertError::Limit);
    }

    #[tokio::test]
    async fn cli_refusal_keeps_output_empty_and_error_chains_secret_free() {
        let cli = crate::Cli::try_parse_from([
            "crawlx",
            "convert",
            "curl",
            "curl --proxy=https://private-secret@fixture.test https://fixture.test",
        ])
        .unwrap();
        let mut out = Vec::new();
        let error = crate::execute_with_env(cli, &mut out, &|_| None)
            .await
            .unwrap_err();
        assert!(out.is_empty());
        assert_eq!(
            error.downcast_ref::<ConvertError>(),
            Some(&ConvertError::UnsupportedFlag)
        );
        assert!(!format!("{error:?} {error:#}").contains("private-secret"));
    }
}
