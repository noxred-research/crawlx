//! Multilingual verb/noun lexicon for side-effect classification
//! ("Accessible name and visible text").
//!
//! Text is folded before matching: lower-cased, camelCase split, accents and
//! diacritics reduced to ASCII (`löschen → loschen`, `şifre → sifre`,
//! `ı → i`), every non-alphanumeric character becomes a word boundary. Terms
//! are ASCII-folded for Latin-script languages (en, de, fr, es, tr) and kept
//! verbatim for scripts without word boundaries (ja, zh, ko, ru; substring
//! match).
//!
//! Matching is only ever used to **raise** a risk class: page text is
//! attacker-controlled, so a match can add risk but absence of a match never
//! lowers it. Terms are marked `verb` when they name an action and `noun`
//! when they name a topic; navigation links only react to verbs, because a
//! link to a "Security" page is a plain GET while a "Delete" link is not.

use crawlx_core::safety::RiskClass;

/// How a term is matched against folded text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Match {
    /// A word of the text starts with the term (`delet` matches `deleted`).
    Prefix,
    /// A word (or word sequence) equals the term.
    Exact,
    /// The term occurs anywhere (scripts without word boundaries).
    Sub,
}

/// One lexicon entry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Term {
    pub text: &'static str,
    pub how: Match,
    pub verb: bool,
}

const fn pv(text: &'static str) -> Term {
    Term {
        text,
        how: Match::Prefix,
        verb: true,
    }
}
const fn pn(text: &'static str) -> Term {
    Term {
        text,
        how: Match::Prefix,
        verb: false,
    }
}
const fn xv(text: &'static str) -> Term {
    Term {
        text,
        how: Match::Exact,
        verb: true,
    }
}
const fn xn(text: &'static str) -> Term {
    Term {
        text,
        how: Match::Exact,
        verb: false,
    }
}
const fn sv(text: &'static str) -> Term {
    Term {
        text,
        how: Match::Sub,
        verb: true,
    }
}
const fn sn(text: &'static str) -> Term {
    Term {
        text,
        how: Match::Sub,
        verb: false,
    }
}

/// delete / remove / revoke / purge.
pub(crate) const DESTRUCTIVE: &[Term] = &[
    // en
    pv("delet"),
    pv("remov"),
    pv("revok"),
    pv("purg"),
    pv("wipe"),
    pv("destroy"),
    pv("erase"),
    pv("terminat"),
    pv("deactivat"),
    pv("uninstall"),
    pv("close account"),
    // de
    pv("losch"),
    pv("entfern"),
    pv("widerruf"),
    pv("vernicht"),
    pv("deaktivier"),
    // fr
    pv("supprim"),
    pv("effac"),
    pv("retir"),
    pv("revoqu"),
    pv("detru"),
    pv("desactiv"),
    pv("resili"),
    // es
    pv("elimin"),
    pv("borrar"),
    xv("borra"),
    pv("revoc"),
    pv("destru"),
    pv("suprim"),
    pv("quitar"),
    // tr
    xv("sil"),
    pv("silin"),
    pv("silme"),
    pv("kaldir"),
    pv("feshet"),
    pv("yok et"),
    pv("devre disi"),
    pv("sonlandir"),
    // ja, zh, ko, ru
    sv("削除"),
    sv("删除"),
    sv("刪除"),
    sv("삭제"),
    sv("удал"),
];

/// pay / checkout / purchase / subscribe.
pub(crate) const FINANCIAL: &[Term] = &[
    // en
    xv("pay"),
    pn("payment"),
    pv("purchas"),
    xv("buy"),
    pn("checkout"),
    pn("check out"),
    pv("subscri"),
    pv("place order"),
    pv("donat"),
    pv("transfer"),
    pv("top up"),
    // de
    pv("bezahl"),
    pv("zahl"),
    pv("kauf"),
    pn("bestell"),
    pv("abonnier"),
    pv("uberweis"),
    pv("spenden"),
    // fr
    pn("paiement"),
    pv("payer"),
    pn("commande"),
    pv("achet"),
    pv("abonn"),
    pn("virement"),
    // es
    pv("pagar"),
    pn("pago"),
    pv("comprar"),
    pn("compra"),
    pv("suscrib"),
    pv("donar"),
    pv("transferir"),
    // tr
    xv("ode"),
    pn("odeme"),
    pv("satin al"),
    pv("abone"),
    pn("bagis"),
    // ja, zh, ko, ru
    sv("支払"),
    sv("支付"),
    sv("购买"),
    sv("購入"),
    sv("결제"),
    sv("оплат"),
    sv("купи"),
];

/// password / mfa / api key / token / security.
pub(crate) const SECURITY: &[Term] = &[
    // en
    pn("password"),
    pn("passcode"),
    xn("2fa"),
    xn("mfa"),
    pn("two factor"),
    pn("multi factor"),
    pn("2 factor"),
    xn("otp"),
    pn("authenticator"),
    pn("api key"),
    pn("apikey"),
    pn("access key"),
    pn("secret key"),
    pn("private key"),
    pn("ssh key"),
    pn("token"),
    pn("credential"),
    pn("secret"),
    pn("security"),
    pn("permission"),
    pn("privilege"),
    pv("grant access"),
    pv("make admin"),
    // de
    pn("passwort"),
    pn("kennwort"),
    pn("sicherheit"),
    pn("schlussel"),
    pn("zugangsdaten"),
    pn("berechtigung"),
    pn("zwei faktor"),
    // fr
    pn("mot de passe"),
    pn("motdepasse"),
    pn("securite"),
    pn("cle api"),
    pn("jeton"),
    pn("identifiant"),
    pn("double facteur"),
    pn("authentification"),
    // es
    pn("contrasena"),
    pn("clave api"),
    pn("seguridad"),
    pn("permiso"),
    pn("credencial"),
    pn("doble factor"),
    pn("autenticacion"),
    // tr
    pn("sifre"),
    pn("parola"),
    pn("guvenlik"),
    pn("anahtar"),
    pn("yetki"),
    pn("iki faktor"),
    pn("dogrulama"),
    // ja, zh, ko, ru
    sn("パスワード"),
    sn("密码"),
    sn("密碼"),
    sn("비밀번호"),
    sn("парол"),
];

/// send / invite / share / email / sms / contact / support.
pub(crate) const EXTERNAL: &[Term] = &[
    // en
    pv("send"),
    pv("invit"),
    pv("share"),
    pn("email"),
    pn("mail"),
    xn("sms"),
    pn("text message"),
    pn("contact"),
    pn("support"),
    pn("notif"),
    pn("message"),
    xv("forward"),
    xv("reply"),
    pv("broadcast"),
    pn("webhook"),
    pn("newsletter"),
    // de
    pv("einlad"),
    xv("teilen"),
    pv("freigeb"),
    pn("kontakt"),
    pn("unterstutz"),
    pn("benachricht"),
    pn("nachricht"),
    pv("absenden"),
    // fr
    pv("envoy"),
    pv("partag"),
    pn("assistance"),
    pn("courriel"),
    pn("soutien"),
    // es
    pv("envia"),
    pv("envio"),
    pv("compart"),
    pn("soporte"),
    pn("correo"),
    pn("mensaje"),
    pn("notific"),
    // tr
    pv("gonder"),
    pv("davet"),
    pv("paylas"),
    pn("iletisim"),
    pn("destek"),
    xn("posta"),
    pn("mesaj"),
    pn("bildir"),
    // ja, zh, ko, ru
    sv("送信"),
    sv("发送"),
    sv("發送"),
    sv("전송"),
    sv("отправ"),
    sv("招待"),
    sv("邀请"),
];

/// save / create / update / submit / post (own persistent writes).
pub(crate) const OWN_WRITE: &[Term] = &[
    // en
    pv("save"),
    pv("creat"),
    pv("updat"),
    pv("submit"),
    xv("post"),
    pv("publish"),
    xv("add"),
    pv("edit"),
    pv("renam"),
    xv("apply"),
    pv("confirm"),
    pv("sign up"),
    pv("signup"),
    pv("register"),
    pv("log out"),
    pv("logout"),
    pv("sign out"),
    pv("signout"),
    pv("unsubscribe"),
    pv("accept"),
    pv("approve"),
    pv("reject"),
    pv("archive"),
    pv("restore"),
    xv("move"),
    pv("import"),
    // de
    pv("speicher"),
    pv("erstell"),
    pv("aktualisier"),
    pv("veroffentlich"),
    pv("hinzufug"),
    pv("bearbeit"),
    pv("ubernehm"),
    pv("abmeld"),
    pv("registrier"),
    pv("einreich"),
    pv("ubermittl"),
    pv("bestatig"),
    pv("anlegen"),
    pv("andern"),
    // fr
    pv("enregistr"),
    pv("creer"),
    pv("creez"),
    pv("modifi"),
    pv("valider"),
    pv("soumettre"),
    pv("publier"),
    pv("ajouter"),
    pv("deconnexion"),
    pv("inscri"),
    pv("confirmer"),
    pv("mettre a jour"),
    // es
    pv("guardar"),
    pv("crear"),
    pv("actualiz"),
    pv("publicar"),
    pv("agregar"),
    pv("anadir"),
    pv("editar"),
    pv("registr"),
    pv("cerrar sesion"),
    pv("confirmar"),
    pv("modificar"),
    // tr
    pv("kaydet"),
    pv("kaydol"),
    pv("olustur"),
    pv("guncelle"),
    pv("yayinla"),
    xv("ekle"),
    pv("duzenle"),
    pv("uye ol"),
    pv("cikis"),
    pv("onayla"),
    pv("degistir"),
    // ja, zh, ko
    sv("保存"),
    sv("作成"),
    sv("创建"),
    sv("提交"),
    sv("登録"),
    sv("更新"),
    sv("저장"),
];

/// upload verbs (the control opens a file chooser).
pub(crate) const UPLOAD: &[Term] = &[
    pv("upload"),
    pv("hochlad"),
    pv("televers"),
    pv("yukle"),
    pv("attach"),
];

/// Reversible local-preference vocabulary (theme, sort, filter, pagination).
/// Never sufficient on its own for a button: see `classify` (needs a
/// structural control role).
pub(crate) const PREFERENCE: &[Term] = &[
    // en
    pv("sort"),
    pv("order by"),
    pv("filter"),
    pv("theme"),
    pv("dark mode"),
    pv("light mode"),
    pv("layout"),
    pv("density"),
    pv("per page"),
    pv("page size"),
    pv("language"),
    xv("next"),
    xv("previous"),
    xv("prev"),
    xv("page"),
    xv("rows"),
    // de
    pv("sortier"),
    pv("nachste"),
    pv("vorherige"),
    xv("seite"),
    pv("sprache"),
    // fr
    pv("trier"),
    pv("filtr"),
    pv("suivant"),
    pv("precedent"),
    pv("langue"),
    // es
    pv("ordenar"),
    pv("filtrar"),
    pv("siguiente"),
    pv("anterior"),
    pv("pagina"),
    pv("tema"),
    pv("idioma"),
    // tr
    pv("sirala"),
    pv("filtre"),
    pv("sonraki"),
    pv("onceki"),
    pv("sayfa"),
    xv("dil"),
];

/// Terms of `class`'s lexicon, if the class has one.
pub(crate) const fn lexicon_for(class: RiskClass) -> &'static [Term] {
    match class {
        RiskClass::Destructive => DESTRUCTIVE,
        RiskClass::FinancialTransaction => FINANCIAL,
        RiskClass::SecurityChange => SECURITY,
        RiskClass::ExternalCommunication => EXTERNAL,
        RiskClass::PersistentWriteOwn => OWN_WRITE,
        RiskClass::FileUpload => UPLOAD,
        RiskClass::ReversibleLocalPreference => PREFERENCE,
        RiskClass::NavigationReveal
        | RiskClass::PersistentWriteOtherPrincipal
        | RiskClass::OutOfScope
        | RiskClass::Unclassified => &[],
    }
}

/// Folded text: space-delimited lower-case words, padded with a leading and
/// trailing space so boundary checks are uniform.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Normalized(String);

impl Normalized {
    pub(crate) fn new(text: &str) -> Self {
        let mut out = String::with_capacity(text.len() + 2);
        out.push(' ');
        let mut prev_lower = false;
        for c in text.chars() {
            if c.is_uppercase() && prev_lower && !out.ends_with(' ') {
                out.push(' ');
            }
            prev_lower = c.is_lowercase();
            for lc in c.to_lowercase() {
                push_folded(&mut out, lc);
            }
        }
        if !out.ends_with(' ') {
            out.push(' ');
        }
        Self(out)
    }

    /// Does any term of `terms` match? With `verbs_only`, noun terms are skipped.
    pub(crate) fn matches_any(&self, terms: &[Term], verbs_only: bool) -> bool {
        terms.iter().any(|t| (!verbs_only || t.verb) && self.matches(t))
    }

    pub(crate) fn matches(&self, t: &Term) -> bool {
        match t.how {
            Match::Sub => self.0.contains(t.text),
            Match::Prefix => self.find_bounded(t.text, false),
            Match::Exact => self.find_bounded(t.text, true),
        }
    }

    /// Folded words with digits removed and whitespace collapsed: a stable
    /// rendering of a name that survives counters like `Inbox (5)`.
    pub(crate) fn without_digits(&self) -> String {
        let stripped: String = self.0.chars().filter(|c| !c.is_numeric()).collect();
        stripped.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn find_bounded(&self, needle: &str, whole: bool) -> bool {
        let hay = self.0.as_str();
        hay.match_indices(needle).any(|(i, _)| {
            let before = i.checked_sub(1).and_then(|j| hay.as_bytes().get(j));
            let after = hay.as_bytes().get(i + needle.len());
            before == Some(&b' ') && (!whole || after == Some(&b' '))
        })
    }
}

fn push_folded(out: &mut String, c: char) {
    let mapped = match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => 'a',
        'ç' | 'ć' | 'č' => 'c',
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ę' | 'ě' => 'e',
        'ì' | 'í' | 'î' | 'ï' | 'ı' | 'ī' => 'i',
        'ñ' | 'ń' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' => 'o',
        'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' => 'u',
        'ý' | 'ÿ' => 'y',
        'ş' | 'ś' | 'š' => 's',
        'ğ' => 'g',
        'ž' | 'ź' | 'ż' => 'z',
        'ł' => 'l',
        'ß' => {
            out.push_str("ss");
            return;
        }
        'æ' => {
            out.push_str("ae");
            return;
        }
        'œ' => {
            out.push_str("oe");
            return;
        }
        // combining marks (e.g. the dot of a decomposed İ)
        '\u{300}'..='\u{36f}' => return,
        other => other,
    };
    if mapped.is_alphanumeric() {
        out.push(mapped);
    } else if !out.ends_with(' ') {
        out.push(' ');
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn hit(text: &str, terms: &[Term]) -> bool {
        Normalized::new(text).matches_any(terms, false)
    }

    #[test]
    fn folding_handles_accents_case_and_camel() {
        assert!(hit("Löschen", DESTRUCTIVE));
        assert!(hit("LÖSCHEN", DESTRUCTIVE));
        assert!(hit("deleteProject", DESTRUCTIVE));
        assert!(hit("delete_project", DESTRUCTIVE));
        assert!(hit("Şifre değiştir", SECURITY));
        assert!(hit("Contraseña", SECURITY));
        assert!(hit("SİL", DESTRUCTIVE));
    }

    #[test]
    fn exact_terms_do_not_match_inside_other_words() {
        assert!(hit("Sil", DESTRUCTIVE));
        assert!(!hit("Silver plan", DESTRUCTIVE));
        assert!(!hit("Silent mode", DESTRUCTIVE));
        assert!(hit("Pay now", FINANCIAL));
        assert!(!hit("Payload", FINANCIAL));
        assert!(!hit("Pagination", FINANCIAL));
        assert!(!hit("Environment", EXTERNAL));
    }

    #[test]
    fn verb_filter_skips_nouns() {
        let n = Normalized::new("Security settings");
        assert!(n.matches_any(SECURITY, false));
        assert!(!n.matches_any(SECURITY, true));
        let d = Normalized::new("Delete project");
        assert!(d.matches_any(DESTRUCTIVE, true));
    }

    #[test]
    fn cjk_and_cyrillic_substrings() {
        assert!(hit("プロジェクトを削除", DESTRUCTIVE));
        assert!(hit("删除项目", DESTRUCTIVE));
        assert!(hit("Удалить проект", DESTRUCTIVE));
        assert!(hit("パスワードを変更", SECURITY));
    }

    #[test]
    fn multi_word_phrases() {
        assert!(hit("Create API key", SECURITY));
        assert!(hit("Mot de passe oublié", SECURITY));
        assert!(hit("Satın al", FINANCIAL));
        assert!(hit("Two-factor authentication", SECURITY));
    }
    #[test]
    fn without_digits_keeps_words_only() {
        assert_eq!(
            Normalized::new("Inbox (12) — 3 new").without_digits(),
            "inbox new"
        );
    }
}
