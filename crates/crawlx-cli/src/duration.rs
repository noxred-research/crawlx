//! Duration flags (`--crawl-duration`, `--interaction-settle`, ...): Go-style compound values
//! such as `30s`, `5m`, `1h30m`, `2d`, `500ms`, or a bare integer meaning seconds.

use std::time::Duration;

/// Parse a duration: one or more `<integer><unit>` pairs with unit `ms`, `s`, `m`, `h` or `d`
/// (`1h30m`), or a bare integer that counts seconds.
///
/// # Errors
/// A message naming what is wrong: empty input, a missing or unknown unit, or an overflow.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("empty duration (examples: 30s, 5m, 1h, or bare seconds)".to_owned());
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return text
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| format!("{text:?} is too large"));
    }
    let mut total = Duration::ZERO;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(format!(
                "{text:?} is not a duration (examples: 30s, 5m, 1h30m, or bare seconds)"
            ));
        }
        let (number, tail) = rest.split_at(digits);
        let unit_len = tail.bytes().take_while(u8::is_ascii_alphabetic).count();
        let (unit, next) = tail.split_at(unit_len);
        let n: u64 = number.parse().map_err(|_| format!("{number:?} is too large"))?;
        let part = match unit {
            "ms" => Some(Duration::from_millis(n)),
            "s" => Some(Duration::from_secs(n)),
            "m" => n.checked_mul(60).map(Duration::from_secs),
            "h" => n.checked_mul(3_600).map(Duration::from_secs),
            "d" => n.checked_mul(86_400).map(Duration::from_secs),
            "" => return Err(format!("{number:?} in {text:?} has no unit (ms, s, m, h or d)")),
            other => {
                return Err(format!(
                    "unknown duration unit {other:?} in {text:?} (ms, s, m, h or d)"
                ))
            }
        };
        total = part
            .and_then(|p| total.checked_add(p))
            .ok_or_else(|| format!("{text:?} is too large"))?;
        rest = next;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn units_compound_and_bare_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3_600));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5_400));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration(" 7s ").unwrap(), Duration::from_secs(7));
    }

    #[test]
    fn malformed_values_name_the_problem() {
        assert!(parse_duration("").unwrap_err().contains("empty"));
        assert!(parse_duration("s").unwrap_err().contains("not a duration"));
        assert!(parse_duration("5x")
            .unwrap_err()
            .contains("unknown duration unit"));
        assert!(parse_duration("5m3").unwrap_err().contains("no unit"));
        assert!(parse_duration("-5s").is_err());
        assert!(parse_duration("99999999999999999999s")
            .unwrap_err()
            .contains("too large"));
        assert!(parse_duration("18446744073709551615d")
            .unwrap_err()
            .contains("too large"));
    }
}
