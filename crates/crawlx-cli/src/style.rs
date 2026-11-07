//! ANSI colour for status words (`--no-color`).
//!
//! Colour is on when `CLICOLOR_FORCE` is set to anything but `0`, and off when `--no-color`
//! is given or `NO_COLOR` is set (<https://no-color.org>). The `crawlx` binary sets
//! `CLICOLOR_FORCE` for the process when standard output is a terminal, so colour appears
//! on a terminal and never in a pipe, a file or an embedding that captures the output.

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

/// Whether status words are wrapped in ANSI escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Style {
    enabled: bool,
}

impl Style {
    /// Decide from `--no-color` and the environment (`getenv` reads one variable).
    pub(crate) fn detect(no_color: bool, getenv: &dyn Fn(&str) -> Option<String>) -> Self {
        let forced = getenv("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0");
        let refused = no_color || getenv("NO_COLOR").is_some_and(|v| !v.is_empty());
        Self {
            enabled: forced && !refused,
        }
    }

    fn paint(self, colour: &str, text: &str) -> String {
        if self.enabled {
            format!("{colour}{text}{RESET}")
        } else {
            text.to_owned()
        }
    }

    /// A success word.
    pub(crate) fn good(self, text: &str) -> String {
        self.paint(GREEN, text)
    }

    /// A failure word.
    pub(crate) fn bad(self, text: &str) -> String {
        self.paint(RED, text)
    }

    /// A warning word.
    pub(crate) fn warn(self, text: &str) -> String {
        self.paint(YELLOW, text)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned())
    }

    #[test]
    fn colour_needs_a_force_and_respects_the_opt_outs() {
        assert!(!Style::detect(false, &env(&[])).enabled);
        assert!(Style::detect(false, &env(&[("CLICOLOR_FORCE", "1")])).enabled);
        assert!(!Style::detect(false, &env(&[("CLICOLOR_FORCE", "0")])).enabled);
        assert!(!Style::detect(true, &env(&[("CLICOLOR_FORCE", "1")])).enabled);
        assert!(!Style::detect(false, &env(&[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")])).enabled);
        let on = Style::detect(false, &env(&[("CLICOLOR_FORCE", "1")]));
        assert_eq!(on.good("ok"), "\x1b[32mok\x1b[0m");
        assert_eq!(Style::detect(true, &env(&[])).good("ok"), "ok");
    }
}
