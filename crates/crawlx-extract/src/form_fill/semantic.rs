//! What a form control expects, decided from its `type`, `autocomplete`
//! token, then the words of its `name` and `id`.
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md
//! (`fieldSemantic`, `fieldWords`, `fixedValues`).
//! The fixed values are constants so repeated crawls submit the same form;
//! the loopback `ip` of the reference becomes an RFC 5737 documentation address so a
//! filled form never points the target at its own loopback.

use std::collections::BTreeSet;

use crate::forms::StaticInput;

/// A value family a control can expect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Semantic {
    Email,
    Phone,
    Password,
    Url,
    Date,
    Time,
    DateTime,
    Month,
    Week,
    Zip,
    Username,
    Name,
    FirstName,
    LastName,
    Address,
    City,
    State,
    Country,
    Company,
    Age,
    Amount,
    CardNumber,
    CardExpiry,
    Cvv,
    Ip,
}

impl Semantic {
    /// Constant value for the family; `None` for the three families the
    /// form config (`-fc`) or the seed decide (email, phone, password).
    pub(crate) const fn fixed_value(self) -> Option<&'static str> {
        Some(match self {
            Self::Email | Self::Phone | Self::Password => return None,
            Self::Url => "https://example.com",
            Self::Date => "2024-01-15",
            Self::Time => "12:00",
            Self::DateTime => "2024-01-15T12:00",
            Self::Month => "2024-01",
            Self::Week => "2024-W03",
            Self::Zip => "10001",
            Self::Username => "crawlx",
            Self::Name => "John Doe",
            Self::FirstName => "John",
            Self::LastName => "Doe",
            Self::Address => "1 Main St",
            Self::City => "New York",
            Self::State => "NY",
            Self::Country => "US",
            Self::Company => "Example Inc",
            Self::Age => "30",
            Self::Amount => "1",
            Self::CardNumber => "4111111111111111",
            Self::CardExpiry => "12/30",
            Self::Cvv => "123",
            Self::Ip => "192.0.2.1",
        })
    }

    /// Field role in the knowledge base (`kb::KbForm::fields`).
    pub(crate) const fn role(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Password => "password",
            Self::Url => "url",
            Self::Date => "date",
            Self::Time => "time",
            Self::DateTime => "date and time",
            Self::Month => "month",
            Self::Week => "week",
            Self::Zip => "postal code",
            Self::Username => "username",
            Self::Name => "full name",
            Self::FirstName => "first name",
            Self::LastName => "last name",
            Self::Address => "address",
            Self::City => "city",
            Self::State => "state or province",
            Self::Country => "country",
            Self::Company => "organization",
            Self::Age => "age",
            Self::Amount => "quantity or amount",
            Self::CardNumber => "card number",
            Self::CardExpiry => "card expiry",
            Self::Cvv => "card security code",
            Self::Ip => "ip address",
        }
    }
}

/// Words of a field name that select a family. Ordered: compound names
/// match before the shorter words they contain (`username` before `name`).
const KEYWORDS: &[(Semantic, &[&str])] = &[
    (Semantic::Email, &["email", "mail"]),
    (Semantic::Password, &["password", "passwd", "pass", "pwd"]),
    (Semantic::Username, &["username", "uname", "login", "userid"]),
    (
        Semantic::FirstName,
        &["firstname", "fname", "givenname", "forename"],
    ),
    (
        Semantic::LastName,
        &["lastname", "lname", "surname", "familyname"],
    ),
    (Semantic::Phone, &["phone", "telephone", "tel", "mobile", "cell"]),
    (
        Semantic::Zip,
        &["zip", "zipcode", "postcode", "postal", "postalcode"],
    ),
    (Semantic::Date, &["date", "dob", "birthday", "birthdate"]),
    (Semantic::Url, &["url", "uri", "website", "homepage"]),
    (Semantic::CardNumber, &["cardnumber", "ccnumber", "creditcard"]),
    (Semantic::Cvv, &["cvv", "cvc", "csc"]),
    (Semantic::Ip, &["ip", "ipaddress"]),
    (Semantic::Address, &["address", "street", "addr"]),
    (Semantic::City, &["city", "town"]),
    (Semantic::State, &["state", "province", "region"]),
    (Semantic::Country, &["country"]),
    (Semantic::Company, &["company", "organization", "organisation"]),
    (Semantic::Age, &["age"]),
    (Semantic::Amount, &["amount", "price", "quantity", "qty"]),
    (Semantic::Name, &["name", "fullname"]),
];

fn from_type(kind: &str) -> Option<Semantic> {
    Some(match kind {
        "email" => Semantic::Email,
        "tel" => Semantic::Phone,
        "password" => Semantic::Password,
        "url" => Semantic::Url,
        "date" => Semantic::Date,
        "time" => Semantic::Time,
        "datetime-local" => Semantic::DateTime,
        "month" => Semantic::Month,
        "week" => Semantic::Week,
        _ => return None,
    })
}

fn from_autocomplete(token: &str) -> Option<Semantic> {
    Some(match token {
        "email" => Semantic::Email,
        "tel" | "tel-national" => Semantic::Phone,
        "current-password" | "new-password" => Semantic::Password,
        "url" => Semantic::Url,
        "bday" => Semantic::Date,
        "postal-code" => Semantic::Zip,
        "username" => Semantic::Username,
        "name" => Semantic::Name,
        "given-name" => Semantic::FirstName,
        "family-name" => Semantic::LastName,
        "street-address" | "address-line1" => Semantic::Address,
        "address-level2" => Semantic::City,
        "address-level1" => Semantic::State,
        "country" | "country-name" => Semantic::Country,
        "organization" => Semantic::Company,
        "cc-number" => Semantic::CardNumber,
        "cc-exp" => Semantic::CardExpiry,
        "cc-csc" => Semantic::Cvv,
        _ => return None,
    })
}

/// The family of `input`, `None` when no rule applies.
pub(crate) fn classify(input: &StaticInput) -> Option<Semantic> {
    if let Some(s) = from_type(&input.kind) {
        return Some(s);
    }
    if let Some(last) = input
        .autocomplete
        .as_deref()
        .and_then(|a| a.split_whitespace().next_back())
    {
        if let Some(s) = from_autocomplete(&last.to_ascii_lowercase()) {
            return Some(s);
        }
    }
    let words = field_words(&format!("{} {}", input.name, input.id.as_deref().unwrap_or("")));
    KEYWORDS
        .iter()
        .find(|(_, set)| set.iter().any(|w| words.contains(*w)))
        .map(|(s, _)| *s)
}

/// Split a name such as `user_firstName` into its lower-case words and every
/// pair of adjacent words, so `firstName` matches `firstname` while
/// `nickname` never matches `name`.
pub(crate) fn field_words(s: &str) -> BTreeSet<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if !c.is_alphanumeric() {
            if !current.is_empty() {
                parts.push(std::mem::take(&mut current).to_lowercase());
            }
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower {
            parts.push(std::mem::take(&mut current).to_lowercase());
        }
        prev_lower = c.is_lowercase();
        current.push(c);
    }
    if !current.is_empty() {
        parts.push(current.to_lowercase());
    }
    let mut words = BTreeSet::new();
    for (i, part) in parts.iter().enumerate() {
        words.insert(part.clone());
        if i > 0 {
            words.insert(format!("{}{part}", parts[i - 1]));
        }
    }
    words
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn input(name: &str, kind: &str) -> StaticInput {
        StaticInput {
            name: name.to_owned(),
            kind: kind.to_owned(),
            ..StaticInput::default()
        }
    }

    #[test]
    fn words_split_on_case_and_separators() {
        let w = field_words("user_firstName id-7");
        for expect in [
            "user",
            "first",
            "name",
            "userfirst",
            "firstname",
            "id",
            "7",
            "id7",
        ] {
            assert!(w.contains(expect), "{expect} in {w:?}");
        }
        assert!(!field_words("nickname").contains("name"));
        assert!(field_words("fullname").contains("fullname"));
    }

    #[test]
    fn type_beats_autocomplete_beats_keyword() {
        assert_eq!(classify(&input("x", "email")), Some(Semantic::Email));
        let mut i = input("login", "text");
        i.autocomplete = Some("section-a shipping postal-code".to_owned());
        assert_eq!(classify(&i), Some(Semantic::Zip));
        i.autocomplete = None;
        assert_eq!(classify(&i), Some(Semantic::Username));
        assert_eq!(classify(&input("nickname", "text")), None);
    }

    #[test]
    fn compound_names_win_over_contained_words() {
        assert_eq!(classify(&input("username", "text")), Some(Semantic::Username));
        assert_eq!(classify(&input("user_email", "text")), Some(Semantic::Email));
        assert_eq!(classify(&input("firstName", "text")), Some(Semantic::FirstName));
        assert_eq!(classify(&input("name", "text")), Some(Semantic::Name));
        assert_eq!(classify(&input("zip_code", "text")), Some(Semantic::Zip));
        assert_eq!(classify(&input("zipcode", "text")), Some(Semantic::Zip));
    }

    #[test]
    fn id_attribute_contributes_words() {
        let mut i = input("f1", "text");
        i.id = Some("billing-city".to_owned());
        assert_eq!(classify(&i), Some(Semantic::City));
    }
}
