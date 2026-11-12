//! Realm-scoped HTTP credentials (`fetch.realmCredentials`): `Basic` and `Digest`.
//!
//! A credential belongs to one origin and one realm. It is offered in exactly two cases:
//!
//! * the origin answered `401` with a `WWW-Authenticate` challenge naming that realm, and the
//!   request is repeated once with the credential;
//! * a protection space of that realm was learned on the same origin earlier, and the request
//!   path lies inside it (preemptive promotion, so a crawl does not pay one `401` per page;
//!   for `Digest` the learned nonce is reused with an increasing nonce count).
//!
//! The origin comparison is exact (scheme, host and port), so a redirect to another origin and
//! an `https` to `http` downgrade never match. The caller additionally stops asking after a
//! redirect left the origin of the request chain. Nothing here logs or returns a secret except
//! the `Authorization` header value, which is marked sensitive. `Digest` never sends the
//! password: only the keyed hash of the challenge leaves the process, and the client nonce is
//! derived from the crawl seed so a replayed run answers the same way.

use crawlx_core::seed::CrawlSeed;
use crawlx_core::transport_policy::{RealmCredential, RealmScheme};
use http::{header, HeaderMap, HeaderValue, Method};
use parking_lot::Mutex;
use rand::RngExt as _;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;
use zeroize::Zeroizing;

/// Parameters kept per challenge; a header with more is truncated, never an allocation sink.
const MAX_CHALLENGE_PARAMS: usize = 16;

/// One challenge of a `WWW-Authenticate` header.
#[derive(Debug, PartialEq, Eq)]
struct Challenge {
    /// Lower-case scheme token.
    scheme: String,
    /// Parameters by lower-case name, quoted strings unescaped.
    params: BTreeMap<String, String>,
}

impl Challenge {
    fn realm(&self) -> Option<&str> {
        self.params.get("realm").map(String::as_str)
    }

    fn flag(&self, name: &str) -> bool {
        self.params
            .get(name)
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    }
}

/// Every challenge of every `WWW-Authenticate` header of `headers`, in order.
fn challenges(headers: &HeaderMap) -> Vec<Challenge> {
    headers
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(parse_challenges)
        .collect()
}

/// Parse `scheme param=value, param="quoted", scheme2 ...`. Unknown shapes (a `token68` after
/// the scheme, stray separators) are skipped rather than guessed at.
fn parse_challenges(value: &str) -> Vec<Challenge> {
    let bytes = value.as_bytes();
    let mut out: Vec<Challenge> = Vec::new();
    let mut i = 0;
    let skip = |i: &mut usize, set: &[u8]| {
        while bytes.get(*i).is_some_and(|b| set.contains(b)) {
            *i += 1;
        }
    };
    while i < bytes.len() {
        skip(&mut i, b" \t,");
        let start = i;
        while bytes.get(i).is_some_and(|b| !b" \t,=".contains(b)) {
            i += 1;
        }
        if start == i {
            // A lone `=` or a separator run that made no progress.
            i += 1;
            continue;
        }
        let word = &value[start..i];
        skip(&mut i, b" \t");
        if bytes.get(i) == Some(&b'=') {
            i += 1;
            skip(&mut i, b" \t");
            // `token68=` padding: the word was an opaque token, not a parameter name.
            if matches!(bytes.get(i), None | Some(b'=' | b',')) {
                skip(&mut i, b"=");
                continue;
            }
            let param = if bytes.get(i) == Some(&b'"') {
                i += 1;
                let mut text = String::new();
                while let Some(&b) = bytes.get(i) {
                    i += 1;
                    match b {
                        b'"' => break,
                        b'\\' => {
                            if let Some(&escaped) = bytes.get(i) {
                                text.push(char::from(escaped));
                                i += 1;
                            }
                        }
                        _ => text.push(char::from(b)),
                    }
                }
                text
            } else {
                let begin = i;
                while bytes.get(i).is_some_and(|b| !b" \t,".contains(b)) {
                    i += 1;
                }
                value[begin..i].to_owned()
            };
            if let Some(last) = out.last_mut() {
                if last.params.len() < MAX_CHALLENGE_PARAMS {
                    last.params.entry(word.to_ascii_lowercase()).or_insert(param);
                }
            }
        } else {
            out.push(Challenge {
                scheme: word.to_ascii_lowercase(),
                params: BTreeMap::new(),
            });
        }
    }
    out
}

/// Directory of `url`'s path, including the trailing slash: `/a/b.html` is `/a/`.
fn directory(url: &Url) -> &str {
    let path = url.path();
    path.rfind('/').map_or("/", |end| &path[..=end])
}

/// The request target a `Digest` response covers: path and query.
fn request_target(url: &Url) -> String {
    let mut target = url.path().to_owned();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

fn sensitive(value: &str) -> Option<HeaderValue> {
    let mut value = HeaderValue::from_str(value).ok()?;
    value.set_sensitive(true);
    Some(value)
}

/// Hash algorithm of a `Digest` challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DigestAlgorithm {
    Md5,
    Sha256,
}

impl DigestAlgorithm {
    /// `None` for an algorithm this client does not implement (a `-sess` variant, `SHA-512-256`).
    fn parse(token: Option<&str>) -> Option<Self> {
        match token {
            None => Some(Self::Md5),
            Some(token) if token.eq_ignore_ascii_case("MD5") => Some(Self::Md5),
            Some(token) if token.eq_ignore_ascii_case("SHA-256") => Some(Self::Sha256),
            Some(_) => None,
        }
    }

    fn hex(self, data: &str) -> String {
        match self {
            Self::Md5 => hex::encode(md5::Md5::digest(data.as_bytes())),
            Self::Sha256 => hex::encode(sha2::Sha256::digest(data.as_bytes())),
        }
    }
}

/// What a `Digest` challenge fixed: the nonce and how the response is computed.
#[derive(Clone, Debug)]
struct DigestState {
    nonce: String,
    opaque: Option<String>,
    algorithm: DigestAlgorithm,
    /// The `algorithm` token as the server wrote it, echoed back; absent keeps the default.
    algorithm_token: Option<String>,
    /// `qop=auth` (client nonce and count); otherwise the legacy RFC 2069 form.
    qop_auth: bool,
    cnonce: String,
    /// Count of the last response built from this nonce.
    nc: u32,
}

impl DigestState {
    /// `None` for a challenge this client cannot answer exactly: no nonce, an unsupported
    /// algorithm, a `qop` without `auth`, or a hashed user name.
    fn from_challenge(challenge: &Challenge, seed: CrawlSeed, realm: &str) -> Option<Self> {
        let nonce = challenge.params.get("nonce").filter(|nonce| !nonce.is_empty())?;
        let token = challenge.params.get("algorithm").map(String::as_str);
        let algorithm = DigestAlgorithm::parse(token)?;
        if challenge.flag("userhash") {
            return None;
        }
        let qop_auth = match challenge.params.get("qop") {
            None => false,
            Some(offered) if offered.split(',').any(|q| q.trim().eq_ignore_ascii_case("auth")) => true,
            Some(_) => return None,
        };
        let mut rng = seed.rng("fetch/digest-cnonce", &[nonce.as_bytes(), realm.as_bytes()]);
        Some(Self {
            nonce: nonce.clone(),
            opaque: challenge.params.get("opaque").cloned(),
            algorithm,
            algorithm_token: token.map(str::to_owned),
            qop_auth,
            cnonce: format!("{:016x}", rng.random::<u64>()),
            nc: 1,
        })
    }

    /// RFC 7616 `response` for `method` and request target `uri` at the current count.
    fn response(&self, user: &str, password: &str, realm: &str, method: &str, uri: &str) -> String {
        let ha1 = self
            .algorithm
            .hex(&Zeroizing::new(format!("{user}:{realm}:{password}")));
        let ha2 = self.algorithm.hex(&format!("{method}:{uri}"));
        if self.qop_auth {
            self.algorithm.hex(&format!(
                "{ha1}:{}:{:08x}:{}:auth:{ha2}",
                self.nonce, self.nc, self.cnonce
            ))
        } else {
            self.algorithm.hex(&format!("{ha1}:{}:{ha2}", self.nonce))
        }
    }

    fn header(&self, credential: &RealmCredential, method: &Method, uri: &str) -> Option<HeaderValue> {
        let quote = |text: &str| text.replace('\\', "\\\\").replace('"', "\\\"");
        let (user, password) = credential.user_and_password();
        let realm = credential.realm();
        let response = self.response(user, password, realm, method.as_str(), uri);
        let mut value = Zeroizing::new(format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{response}\"",
            quote(user),
            quote(realm),
            quote(&self.nonce),
            quote(uri),
        ));
        if let Some(token) = &self.algorithm_token {
            value.push_str(", algorithm=");
            value.push_str(token);
        }
        if self.qop_auth {
            value.push_str(&format!(
                ", qop=auth, nc={:08x}, cnonce=\"{}\"",
                self.nc, self.cnonce
            ));
        }
        if let Some(opaque) = &self.opaque {
            value.push_str(&format!(", opaque=\"{}\"", quote(opaque)));
        }
        sensitive(&value)
    }
}

/// What one credential learned: the protection spaces and, for `Digest`, the live nonce.
#[derive(Debug, Default)]
struct Learned {
    spaces: BTreeSet<String>,
    digest: Option<DigestState>,
}

impl Learned {
    /// The next `Authorization` value for a request inside a learned space. `Digest` advances
    /// the nonce count so no response repeats.
    fn next_header(
        &mut self,
        credential: &RealmCredential,
        url: &Url,
        method: &Method,
    ) -> Option<HeaderValue> {
        match credential.scheme() {
            RealmScheme::Digest => {
                let state = self.digest.as_mut()?;
                state.nc = state.nc.checked_add(1)?;
                state.header(credential, method, &request_target(url))
            }
            _ => credential
                .basic_authorization()
                .and_then(|value| sensitive(value.expose())),
        }
    }
}

/// Learned protection spaces of one fetcher, aligned with its realm credentials by index.
#[derive(Debug)]
pub(crate) struct RealmAuth {
    learned: Mutex<Vec<Learned>>,
    seed: CrawlSeed,
}

impl RealmAuth {
    /// Nothing learned for any of `count` credentials; `seed` derives `Digest` client nonces.
    pub(crate) fn new(count: usize, seed: CrawlSeed) -> Self {
        Self {
            learned: Mutex::new((0..count).map(|_| Learned::default()).collect()),
            seed,
        }
    }

    /// The credential to send with the first attempt for `url`: the first one whose origin is
    /// `url`'s and whose learned protection space contains `url`'s path.
    pub(crate) fn preemptive(
        &self,
        credentials: &[RealmCredential],
        url: &Url,
        method: &Method,
    ) -> Option<(usize, HeaderValue)> {
        let mut learned = self.learned.lock();
        let path = url.path();
        credentials.iter().enumerate().find_map(|(index, credential)| {
            if !credential.matches_origin(url) {
                return None;
            }
            let entry = learned.get_mut(index)?;
            if !entry.spaces.iter().any(|space| path.starts_with(space.as_str())) {
                return None;
            }
            entry
                .next_header(credential, url, method)
                .map(|value| (index, value))
        })
    }

    /// The credential answering the challenges in `headers`, never `skip` (the one that was
    /// just refused) unless the server calls its nonce stale. The protection space is
    /// remembered for preemptive promotion.
    pub(crate) fn answer(
        &self,
        credentials: &[RealmCredential],
        url: &Url,
        method: &Method,
        headers: &HeaderMap,
        skip: Option<usize>,
    ) -> Option<(usize, HeaderValue)> {
        let offered = challenges(headers);
        for (index, credential) in credentials.iter().enumerate() {
            if !credential.matches_origin(url) {
                continue;
            }
            for challenge in offered.iter().filter(|challenge| {
                challenge.scheme == credential.scheme().token()
                    && challenge.realm() == Some(credential.realm())
            }) {
                if Some(index) == skip && !challenge.flag("stale") {
                    continue;
                }
                let (value, digest) = match credential.scheme() {
                    RealmScheme::Digest => {
                        let Some(state) =
                            DigestState::from_challenge(challenge, self.seed, credential.realm())
                        else {
                            continue;
                        };
                        let Some(value) = state.header(credential, method, &request_target(url)) else {
                            continue;
                        };
                        (value, Some(state))
                    }
                    _ => {
                        let Some(value) = credential
                            .basic_authorization()
                            .and_then(|value| sensitive(value.expose()))
                        else {
                            continue;
                        };
                        (value, None)
                    }
                };
                if let Some(entry) = self.learned.lock().get_mut(index) {
                    entry.spaces.insert(directory(url).to_owned());
                    entry.digest = digest;
                }
                return Some((index, value));
            }
        }
        None
    }

    /// The server refused credential `index` for `url`: stop sending it for that protection space.
    pub(crate) fn reject(&self, index: usize, url: &Url) {
        let path = url.path();
        if let Some(entry) = self.learned.lock().get_mut(index) {
            entry.spaces.retain(|space| !path.starts_with(space.as_str()));
            if entry.spaces.is_empty() {
                entry.digest = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(header::WWW_AUTHENTICATE, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn challenges_parse_schemes_quoted_realms_and_lists() {
        let parsed = challenges(&headers(&[
            r#"Basic realm="members only", charset="UTF-8""#,
            r#"Digest realm="a, b", nonce="xyz", qop="auth,auth-int", Bearer realm=api"#,
            "Negotiate abc==",
        ]));
        let summary: Vec<_> = parsed.iter().map(|c| (c.scheme.as_str(), c.realm())).collect();
        assert_eq!(
            summary,
            [
                ("basic", Some("members only")),
                ("digest", Some("a, b")),
                ("bearer", Some("api")),
                ("negotiate", None),
            ]
        );
        assert_eq!(parsed[0].params["charset"], "UTF-8");
        assert_eq!(parsed[1].params["nonce"], "xyz");
        assert_eq!(parsed[1].params["qop"], "auth,auth-int");
        assert_eq!(
            challenges(&headers(&[r#"Basic realm="a\"b\\c""#]))[0].realm(),
            Some(r#"a"b\c"#)
        );
        assert!(challenges(&headers(&["", ",,,", "=", "realm=x"])).is_empty());
    }

    #[test]
    fn directories_are_the_path_up_to_the_last_slash() {
        let dir = |u: &str| directory(&Url::parse(u).unwrap()).to_owned();
        assert_eq!(dir("https://a.test/"), "/");
        assert_eq!(dir("https://a.test/a/b.html"), "/a/");
        assert_eq!(dir("https://a.test/a/b/"), "/a/b/");
        assert_eq!(dir("https://a.test/a"), "/");
    }

    fn state(algorithm: DigestAlgorithm, qop_auth: bool) -> DigestState {
        DigestState {
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_owned(),
            opaque: None,
            algorithm,
            algorithm_token: None,
            qop_auth,
            cnonce: "0a4f113b".to_owned(),
            nc: 1,
        }
    }

    #[test]
    fn digest_response_matches_the_published_md5_vectors() {
        // The worked example of RFC 2617 section 3.5.
        let with_qop = state(DigestAlgorithm::Md5, true).response(
            "Mufasa",
            "Circle Of Life",
            "testrealm@host.com",
            "GET",
            "/dir/index.html",
        );
        assert_eq!(with_qop, "6629fae49393a05397450978507c4ef1");
        // Without `qop` the response drops the count and client nonce (RFC 2069 form).
        let legacy = state(DigestAlgorithm::Md5, false).response(
            "Mufasa",
            "Circle Of Life",
            "testrealm@host.com",
            "GET",
            "/dir/index.html",
        );
        let md5 = |text: &str| hex::encode(md5::Md5::digest(text.as_bytes()));
        let (ha1, ha2) = (
            md5("Mufasa:testrealm@host.com:Circle Of Life"),
            md5("GET:/dir/index.html"),
        );
        assert_eq!(
            legacy,
            md5(&format!("{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:{ha2}"))
        );
        assert_ne!(legacy, with_qop);
    }

    #[test]
    fn digest_sha256_is_the_same_construction_over_the_other_hash() {
        let state = state(DigestAlgorithm::Sha256, true);
        let sha = |text: &str| hex::encode(sha2::Sha256::digest(text.as_bytes()));
        let ha1 = sha("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = sha("GET:/dir/index.html");
        let expected = sha(&format!(
            "{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:{ha2}"
        ));
        assert_eq!(
            state.response(
                "Mufasa",
                "Circle Of Life",
                "testrealm@host.com",
                "GET",
                "/dir/index.html"
            ),
            expected
        );
        assert_eq!(expected.len(), 64);
    }

    #[test]
    fn unsupported_digest_challenges_are_not_answered() {
        let seed = CrawlSeed(1);
        let parse = |header: &str| {
            let challenge = &parse_challenges(header)[0];
            DigestState::from_challenge(challenge, seed, "r")
        };
        assert!(parse(r#"Digest realm="r", nonce="n", qop="auth""#).is_some());
        assert!(parse(r#"Digest realm="r", nonce="n""#).is_some());
        assert!(parse(r#"Digest realm="r", qop="auth""#).is_none(), "no nonce");
        assert!(parse(r#"Digest realm="r", nonce="n", algorithm=SHA-512-256"#).is_none());
        assert!(parse(r#"Digest realm="r", nonce="n", algorithm=MD5-sess"#).is_none());
        assert!(parse(r#"Digest realm="r", nonce="n", qop="auth-int""#).is_none());
        assert!(parse(r#"Digest realm="r", nonce="n", userhash=true"#).is_none());
    }

    #[test]
    fn the_client_nonce_is_derived_from_the_seed_and_the_challenge() {
        let challenge = &parse_challenges(r#"Digest realm="r", nonce="n1", qop="auth""#)[0];
        let first = DigestState::from_challenge(challenge, CrawlSeed(7), "r").unwrap();
        let again = DigestState::from_challenge(challenge, CrawlSeed(7), "r").unwrap();
        let other_seed = DigestState::from_challenge(challenge, CrawlSeed(8), "r").unwrap();
        assert_eq!(first.cnonce, again.cnonce);
        assert_ne!(first.cnonce, other_seed.cnonce);
        assert_eq!(first.cnonce.len(), 16);
    }
}
