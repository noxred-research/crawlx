//! Keyword classification in en / de / fr / es / tr.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{class_of, Case};
use crawlx_core::safety::RiskClass;
use RiskClass::{
    Destructive as D, ExternalCommunication as E, FinancialTransaction as F, PersistentWriteOwn as W,
    ReversibleLocalPreference as R, SecurityChange as S,
};

fn button(name: &str) -> RiskClass {
    class_of(&Case::click("button", name))
}

fn check(lang: &str, cases: &[(&str, RiskClass)]) {
    for (name, expected) in cases {
        assert_eq!(button(name), *expected, "[{lang}] button {name:?}");
    }
}

#[test]
fn english() {
    check(
        "en",
        &[
            ("Delete account", D),
            ("Remove user", D),
            ("Purge cache", D),
            ("Wipe workspace", D),
            ("Revoke access", D),
            ("Pay invoice", F),
            ("Checkout", F),
            ("Purchase", F),
            ("Subscribe now", F),
            ("Change password", S),
            ("Enable 2FA", S),
            ("Create API key", S),
            ("Security settings", S),
            ("Send message", E),
            ("Share link", E),
            ("Invite teammate", E),
            ("Email report", E),
            ("Send SMS", E),
            ("Contact support", E),
            ("Save changes", W),
            ("Create project", W),
            ("Update profile", W),
            ("Submit", W),
            ("Post comment", W),
        ],
    );
}

#[test]
fn german() {
    check(
        "de",
        &[
            ("Projekt löschen", D),
            ("Benutzer entfernen", D),
            ("Zugriff widerrufen", D),
            ("Jetzt bezahlen", F),
            ("Kaufen", F),
            ("Abonnieren", F),
            ("Passwort ändern", S),
            ("Sicherheitseinstellungen", S),
            ("Nachricht senden", E),
            ("Einladen", E),
            ("Teilen", E),
            ("Kontakt", E),
            ("Speichern", W),
            ("Erstellen", W),
            ("Aktualisieren", W),
        ],
    );
}

#[test]
fn french() {
    check(
        "fr",
        &[
            ("Supprimer le projet", D),
            ("Retirer", D),
            ("Révoquer l'accès", D),
            ("Payer maintenant", F),
            ("Acheter", F),
            ("S'abonner", F),
            ("Mot de passe", S),
            ("Envoyer", E),
            ("Inviter", E),
            ("Partager", E),
            ("Contacter le support", E),
            ("Enregistrer", W),
            ("Créer", W),
            ("Modifier", W),
        ],
    );
}

#[test]
fn spanish() {
    check(
        "es",
        &[
            ("Eliminar proyecto", D),
            ("Borrar", D),
            ("Revocar acceso", D),
            ("Pagar ahora", F),
            ("Comprar", F),
            ("Suscribirse", F),
            ("Cambiar contraseña", S),
            ("Enviar mensaje", E),
            ("Invitar", E),
            ("Compartir", E),
            ("Contacto", E),
            ("Guardar", W),
            ("Crear", W),
            ("Actualizar", W),
        ],
    );
}

#[test]
fn turkish() {
    check(
        "tr",
        &[
            ("Projeyi sil", D),
            ("Kaldır", D),
            ("Ödeme yap", F),
            ("Satın al", F),
            ("Abone ol", F),
            ("Şifre değiştir", S),
            ("Mesaj gönder", E),
            ("Davet et", E),
            ("Paylaş", E),
            ("İletişim", E),
            ("Kaydet", W),
            ("Oluştur", W),
            ("Güncelle", W),
        ],
    );
}

#[test]
fn other_scripts() {
    check(
        "ja",
        &[
            ("プロジェクトを削除", D),
            ("パスワードを変更", S),
            ("送信", E),
            ("保存", W),
        ],
    );
    check("zh", &[("删除项目", D), ("支付", F)]);
    check("ru", &[("Удалить проект", D), ("Оплатить", F)]);
}

#[test]
fn preference_toggles_in_five_languages_need_a_control_role() {
    for name in [
        "Sort by",
        "Sortieren nach",
        "Trier par",
        "Ordenar por",
        "Sırala",
        "Filter",
        "Filtrer",
        "Theme",
        "Tema",
    ] {
        assert_eq!(class_of(&Case::click("combobox", name)), R, "{name}");
        // the same words on a plain button give no structural evidence
        assert_eq!(button(name), RiskClass::Unclassified, "plain button {name}");
    }
    assert_eq!(
        class_of(&Case::click("button", "Dark mode").attr("aria-pressed", "false")),
        R
    );
}

#[test]
fn ordinary_words_do_not_match_by_accident() {
    for name in [
        "Silver plan",
        "Silent",
        "Payload viewer",
        "Pagination",
        "Environment",
        "Postal code",
        "Address book",
    ] {
        assert_eq!(button(name), RiskClass::Unclassified, "{name}");
    }
}

#[test]
fn stronger_verb_wins_over_weaker_noun() {
    // "Revoke token": destructive verb and security noun; the max is the more severe class.
    assert_eq!(button("Revoke token"), S);
    assert_eq!(button("Delete project and send email"), D);
}

#[test]
fn camel_case_and_separators_are_split() {
    assert_eq!(button("deleteProject"), D);
    assert_eq!(button("delete_project"), D);
    assert_eq!(button("DELETE-PROJECT"), D);
}

#[test]
fn value_entry_ignores_field_labels_but_catches_secrets() {
    use crawlx_core::action::BrowserAction;
    use crawlx_core::secret::SecretOr;
    let typed = |name: &str, kind: &str| {
        let a = BrowserAction::Type {
            target: common::locator(),
            value: SecretOr::secret("x".to_owned()),
            clear_first: true,
        };
        Case::click("textbox", name).action(a).input(kind, "valid")
    };
    // a field labelled "Email" is data entry, not a send
    assert_eq!(class_of(&typed("Email", "email")), RiskClass::Unclassified);
    assert_eq!(class_of(&typed("Anything", "password")), S);
    assert_eq!(class_of(&typed("Card number", "card")), F);
    assert_eq!(class_of(&typed("Password", "text")), S);
}
