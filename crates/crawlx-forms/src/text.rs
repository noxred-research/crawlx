//! Label normalisation shared by the classifier and the grouper.
//!
//! Labels are lower-cased, camelCase-split, diacritic-folded (de/fr/es/tr
//! letters) and split on non-alphanumerics. Keywords match either as a
//! substring of the squashed form (`"emailaddress"`) or, when prefixed with
//! `=`, as a whole token.

/// Normalised text: whole tokens plus a squashed (separator-free) form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Norm {
    pub tokens: Vec<String>,
    pub squashed: String,
}

impl Norm {
    pub(crate) fn of(s: &str) -> Self {
        let mut tokens: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut prev_lower = false;
        for ch in s.chars() {
            // camelCase boundary: `firstName` -> `first`, `name`
            if ch.is_uppercase() && prev_lower && !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            prev_lower = ch.is_lowercase();
            for lc in ch.to_lowercase() {
                if is_combining(lc) {
                    continue;
                }
                match fold(lc) {
                    Folded::One(c) => push_char(&mut cur, &mut tokens, c),
                    Folded::Two(a, b) => {
                        push_char(&mut cur, &mut tokens, a);
                        push_char(&mut cur, &mut tokens, b);
                    }
                }
            }
        }
        if !cur.is_empty() {
            tokens.push(cur);
        }
        let squashed = tokens.concat();
        Self { tokens, squashed }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Does `kw` match? `=word` requires an exact token; `=a b` requires the
    /// adjacent tokens `a`, `b`; anything else is a substring of the squashed form.
    pub(crate) fn has(&self, kw: &str) -> bool {
        if let Some(tok) = kw.strip_prefix('=') {
            let parts: Vec<&str> = tok.split(' ').collect();
            self.tokens
                .windows(parts.len())
                .any(|w| w.iter().zip(&parts).all(|(a, b)| a == b))
        } else {
            self.squashed.contains(kw)
        }
    }

    pub(crate) fn has_any(&self, kws: &[&str]) -> bool {
        kws.iter().any(|k| self.has(k))
    }

    /// The first keyword of `kws` that matches, if any.
    pub(crate) fn first_hit<'a>(&self, kws: &[&'a str]) -> Option<&'a str> {
        kws.iter().copied().find(|k| self.has(k))
    }
}

fn push_char(cur: &mut String, tokens: &mut Vec<String>, c: char) {
    if c.is_alphanumeric() {
        cur.push(c);
    } else if !cur.is_empty() {
        tokens.push(std::mem::take(cur));
    }
}

fn is_combining(c: char) -> bool {
    ('\u{0300}'..='\u{036f}').contains(&c)
}

enum Folded {
    One(char),
    Two(char, char),
}

fn fold(c: char) -> Folded {
    let one = match c {
        'ä' | 'à' | 'â' | 'á' | 'ã' | 'å' => 'a',
        'ö' | 'ò' | 'ô' | 'ó' | 'õ' | 'ø' => 'o',
        'ü' | 'ù' | 'û' | 'ú' => 'u',
        'é' | 'è' | 'ê' | 'ë' => 'e',
        'î' | 'ï' | 'í' | 'ì' | 'ı' => 'i',
        'ç' => 'c',
        'ñ' => 'n',
        'ş' => 's',
        'ğ' => 'g',
        'ß' => return Folded::Two('s', 's'),
        'œ' => return Folded::Two('o', 'e'),
        'æ' => return Folded::Two('a', 'e'),
        other => other,
    };
    Folded::One(one)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn splits_camel_and_folds() {
        let n = Norm::of("userEmailAddress");
        assert_eq!(n.tokens, ["user", "email", "address"]);
        assert_eq!(n.squashed, "useremailaddress");
        let n = Norm::of("Kullanıcı Adı / Şifre");
        assert!(n.has("kullanici"));
        assert!(n.has("sifre"));
        assert!(Norm::of("Straße").has("strasse"));
        assert!(Norm::of("Contraseña").has("contrasena"));
    }

    #[test]
    fn token_prefix_requires_whole_token() {
        let n = Norm::of("update");
        assert!(!n.has("=date"));
        assert!(Norm::of("Date of birth").has("=date"));
    }

    #[test]
    fn empty_input() {
        assert!(Norm::of("  --  ").is_empty());
    }
}
