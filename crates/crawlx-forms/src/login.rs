//! `builtin:form` and `recorded:` login plans.
//!
//! The plan is **data**: a declarative `Vec<LoginStep>` that `crawlx-worker`
//! executes through the normal proposal/safety path, resolving the secret with
//! `SecretResolver::resolve` immediately before the `Type` / placeholder `FillSelector`
//! steps. This module never sees a credential value. Field detection runs the same
//! classifier and grouper as everything else; recorded flows ([`recorded`]) target
//! controls by selector instead.

pub mod recorded;

use crate::classify::{FieldRole, FormSemantics, InputKind};
use crate::group::{FormGroup, FormGroupId, FormGrouper, FormInput};
use crawlx_core::observation::{ObservedDescriptor, RuntimeLocator};
use recorded::{FillValue, PressKey, RecordedFlow, RecordedFlowError, Selector};
use serde::{Deserialize, Serialize};

/// Which login control a step refers to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LoginField {
    /// The username (or e-mail / phone) input.
    Username,
    /// The password input.
    Password,
}

/// Which half of the resolved credential a `Type` step types.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPart {
    /// The login name; typed as plain text.
    Username,
    /// Always typed as `SecretOr::Secret`.
    Password,
}

/// How the form is submitted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SubmitMethod {
    /// Click the form's submit control; fall back to Enter in the password field
    /// when no submit control was found.
    ClickSubmit,
    /// Press Enter in the password field.
    PressEnter,
}

/// Evidence that the session is logged in.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LoggedInIndicator {
    /// The password field is no longer present.
    PasswordFieldGone,
    /// A control named like log out / sign out / abmelden / déconnexion / cerrar sesión / çıkış.
    LogoutControl,
}

/// One acceptable post-submit outcome.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LoginExpectation {
    /// A main-frame navigation away from the login route.
    Navigation,
    /// The session shows the given logged-in indicator.
    LoggedIn(LoggedInIndicator),
}

/// One declarative login step.
///
/// The first four variants form the `builtin:form` plan (controls found by the
/// classifier); the selector-targeted variants come from recorded flows
/// and name their control by [`Selector`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum LoginStep {
    /// Locate the control (via [`detect_login_form`]) in the current observation.
    FindField {
        /// Control to locate.
        field: LoginField,
    },
    /// Type the credential part into the located field. The value is a
    /// `SecretOr<String>` resolved from `credentialRef` right before use.
    Type {
        /// Control receiving the text.
        field: LoginField,
        /// Half of the resolved credential to type.
        source: CredentialPart,
    },
    /// Submit the form.
    Submit {
        /// How the form is submitted.
        method: SubmitMethod,
    },
    /// Succeed when **any** expectation holds before `timeout_ms`.
    Expect {
        /// Acceptable outcomes; any one suffices.
        any_of: Vec<LoginExpectation>,
        /// Deadline for the outcome, in milliseconds.
        timeout_ms: u64,
    },
    /// Navigate the tab to `url` (`http`/`https` only).
    NavigateTo {
        /// Absolute URL to load.
        url: url::Url,
    },
    /// Type `value` into the control `selector` names. A placeholder is resolved with
    /// [`FillValue::resolve`] right before the native-input action; the executor must
    /// check that a `Placeholder(Password)` targets a password input.
    FillSelector {
        /// Control receiving the text.
        selector: Selector,
        /// Literal or credential placeholder.
        value: FillValue,
    },
    /// Click the control `selector` names (native input).
    ClickSelector {
        /// Control to click.
        selector: Selector,
    },
    /// Double-click the control `selector` names.
    DoubleClickSelector {
        /// Control to double-click.
        selector: Selector,
    },
    /// Wait until the control `selector` names is visible, at most `timeout_ms`.
    WaitVisible {
        /// Control that must become visible.
        selector: Selector,
        /// Deadline in milliseconds.
        timeout_ms: u64,
    },
    /// Wait `duration_ms` (then settle); `0` means settle only.
    Wait {
        /// Fixed wait in milliseconds before the settle.
        duration_ms: u64,
    },
    /// Press `key` on the focused element.
    Press {
        /// Key to press.
        key: PressKey,
    },
    /// Submit: click the control `selector` names, or without one the form's submit
    /// control, falling back to Enter in the focused password field.
    SubmitSelector {
        /// Optional explicit submit control.
        selector: Option<Selector>,
    },
}

/// A resolved control.
#[derive(Clone, PartialEq, Debug)]
pub struct LoginTarget {
    /// Index into the candidate slice.
    pub index: usize,
    /// Locator of the control.
    pub locator: RuntimeLocator,
}

/// The login controls found in an observation.
#[derive(Clone, PartialEq, Debug)]
pub struct LoginTargets {
    /// Group the controls belong to.
    pub group: FormGroupId,
    /// Absent on password-only (re-authentication) forms.
    pub username: Option<LoginTarget>,
    /// The password input.
    pub password: LoginTarget,
    /// Absent when the form has no submit control (use Enter).
    pub submit: Option<LoginTarget>,
}

impl LoginTargets {
    /// The target for `field`, if the form has one.
    #[must_use]
    pub const fn field(&self, field: LoginField) -> Option<&LoginTarget> {
        match field {
            LoginField::Username => self.username.as_ref(),
            LoginField::Password => Some(&self.password),
        }
    }
}

/// Login detection failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoginError {
    /// No fillable current-password field inside a login group.
    #[error("no login form with a current-password field was found")]
    NoLoginForm,
}

/// Where a plan came from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LoginPlanSource {
    /// `builtin:form`: controls found by the classifier.
    #[default]
    BuiltinForm,
    /// `recorded:<json>`: a compiled [`RecordedFlow`].
    Recorded,
}

/// A declarative login plan.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct LoginPlan {
    /// Steps executed in order.
    pub steps: Vec<LoginStep>,
    /// `builtin:form` or a recorded flow.
    #[serde(default)]
    pub source: LoginPlanSource,
}

/// `roles[].loginPlan` prefix of a recorded flow; the rest is the flow JSON.
pub const RECORDED_PLAN_PREFIX: &str = "recorded:";
/// `roles[].loginPlan` value of the built-in form plan.
pub const BUILTIN_FORM_PLAN: &str = "builtin:form";

/// Default post-submit wait (the quiescence hard timeout of `QuiescencePolicy`).
pub const DEFAULT_EXPECT_TIMEOUT_MS: u64 = 8_000;

impl LoginPlan {
    /// The `builtin:form` plan: find username, find password, type both, submit,
    /// expect navigation or a logged-in indicator.
    #[must_use]
    pub fn builtin_form() -> Self {
        Self {
            steps: vec![
                LoginStep::FindField {
                    field: LoginField::Username,
                },
                LoginStep::FindField {
                    field: LoginField::Password,
                },
                LoginStep::Type {
                    field: LoginField::Username,
                    source: CredentialPart::Username,
                },
                LoginStep::Type {
                    field: LoginField::Password,
                    source: CredentialPart::Password,
                },
                LoginStep::Submit {
                    method: SubmitMethod::ClickSubmit,
                },
                LoginStep::Expect {
                    any_of: vec![
                        LoginExpectation::Navigation,
                        LoginExpectation::LoggedIn(LoggedInIndicator::PasswordFieldGone),
                        LoginExpectation::LoggedIn(LoggedInIndicator::LogoutControl),
                    ],
                    timeout_ms: DEFAULT_EXPECT_TIMEOUT_MS,
                },
            ],
            source: LoginPlanSource::BuiltinForm,
        }
    }

    /// A plan replaying `flow` (already validated by [`RecordedFlow::parse`]).
    #[must_use]
    pub fn recorded(flow: RecordedFlow) -> Self {
        Self {
            steps: flow.steps,
            source: LoginPlanSource::Recorded,
        }
    }

    /// Parse a `roles[].loginPlan` value: `builtin:form`, or `recorded:` followed by a
    /// Chrome DevTools Recorder export or an explicit step list. Artifact
    /// references must be fetched by the caller before parsing.
    ///
    /// # Errors
    /// [`RecordedFlowError::NotRecorded`] for any other value, and the [`RecordedFlow::parse`]
    /// errors for a bad flow.
    pub fn parse(spec: &str) -> Result<Self, RecordedFlowError> {
        let spec = spec.trim();
        if spec == BUILTIN_FORM_PLAN {
            return Ok(Self::builtin_form());
        }
        match spec.strip_prefix(RECORDED_PLAN_PREFIX) {
            Some(json) => RecordedFlow::parse(json).map(Self::recorded),
            None => Err(RecordedFlowError::NotRecorded(spec.to_owned())),
        }
    }

    /// Is this a recorded flow?
    #[must_use]
    pub const fn is_recorded(&self) -> bool {
        matches!(self.source, LoginPlanSource::Recorded)
    }

    /// Does the plan type a credential: a `Type` step or a placeholder `FillSelector`?
    #[must_use]
    pub fn needs_credentials(&self) -> bool {
        self.steps.iter().any(|s| {
            matches!(
                s,
                LoginStep::Type { .. }
                    | LoginStep::FillSelector {
                        value: FillValue::Placeholder(_),
                        ..
                    }
            )
        })
    }

    /// Locate the plan's controls in `candidates`.
    ///
    /// # Errors
    /// Returns [`LoginError::NoLoginForm`] when no login form is found.
    pub fn resolve(&self, candidates: &[ObservedDescriptor]) -> Result<LoginTargets, LoginError> {
        detect_login_form(candidates)
    }

    /// Every `Type` step with a password source targets the password field and
    /// nothing else (guards hand-written plans).
    #[must_use]
    pub fn types_password_only_into_password_field(&self) -> bool {
        self.steps.iter().all(|s| match s {
            LoginStep::Type {
                field,
                source: CredentialPart::Password,
            } => *field == LoginField::Password,
            _ => true,
        })
    }
}

/// Find the login form in `candidates` with the shared classifier/grouper.
///
/// A login form is a group with a fillable password input that is not a
/// new/confirm-password field and whose semantics are `Login`. Several login
/// forms (e.g. header and page): the one with the largest password box, then
/// the earliest. The username is the nearest preceding fillable email/phone/text
/// input (a field classified `Username` wins), the submit is the group's
/// primary submit control.
///
/// # Errors
/// Returns [`LoginError::NoLoginForm`] when no group has a fillable
/// current-password input with login semantics.
pub fn detect_login_form(candidates: &[ObservedDescriptor]) -> Result<LoginTargets, LoginError> {
    let groups = FormGrouper::new().group(candidates);
    let mut best: Option<(f64, usize, &FormGroup, &FormInput)> = None;
    for (order, g) in groups.iter().enumerate() {
        if g.semantics != FormSemantics::Login {
            continue;
        }
        let Some(pw) = g.inputs.iter().find(|i| {
            i.fillable()
                && i.class.kind == InputKind::Password
                && !matches!(
                    i.class.role,
                    Some(FieldRole::NewPassword | FieldRole::ConfirmPassword)
                )
        }) else {
            continue;
        };
        let area = candidates[pw.index].bbox.map_or(0.0, |b| b.area());
        let better = match &best {
            None => true,
            Some((a, o, _, _)) => area > *a || (area == *a && order < *o),
        };
        if better {
            best = Some((area, order, g, pw));
        }
    }
    let (_, _, group, pw) = best.ok_or(LoginError::NoLoginForm)?;
    let username = pick_username(group, pw);
    let target = |index: usize| LoginTarget {
        index,
        locator: candidates[index].locator.clone(),
    };
    Ok(LoginTargets {
        group: group.id.clone(),
        username: username.map(|i| target(i.index)),
        password: target(pw.index),
        submit: group.submit_index.map(target),
    })
}

fn pick_username<'a>(group: &'a FormGroup, pw: &FormInput) -> Option<&'a FormInput> {
    let usable = |i: &&FormInput| {
        i.fillable()
            && matches!(
                i.class.kind,
                InputKind::Email | InputKind::Phone | InputKind::Text | InputKind::Unknown
            )
    };
    let named = group
        .inputs
        .iter()
        .filter(usable)
        .find(|i| i.class.role == Some(FieldRole::Username));
    named.or_else(|| {
        // nearest preceding field, else the nearest following one
        group
            .inputs
            .iter()
            .filter(usable)
            .rfind(|i| i.index < pw.index)
            .or_else(|| group.inputs.iter().filter(usable).find(|i| i.index > pw.index))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::classify::testutil::{desc, input};
    use crawlx_core::observation::BoundingBox;

    fn owned(mut d: ObservedDescriptor, form: &str) -> ObservedDescriptor {
        d.attributes.insert("crawlx:form".into(), form.into());
        d
    }

    fn login_form(form: &str, base: i64) -> Vec<ObservedDescriptor> {
        let mut submit = desc(base + 3, "button", "button", &[("type", "submit")]);
        submit.accessible_name = Some("Sign in".into());
        vec![
            desc(
                base,
                "form",
                "form",
                &[
                    ("id", form),
                    ("crawlx:form", form),
                    ("method", "post"),
                    ("action", "/session"),
                ],
            ),
            owned(
                input(
                    base + 1,
                    &[
                        ("type", "text"),
                        ("name", "username"),
                        ("autocomplete", "username"),
                    ],
                ),
                form,
            ),
            owned(
                input(
                    base + 2,
                    &[("type", "password"), ("autocomplete", "current-password")],
                ),
                form,
            ),
            owned(submit, form),
        ]
    }

    #[test]
    fn builtin_plan_shape() {
        let p = LoginPlan::builtin_form();
        assert_eq!(p.steps.len(), 6);
        assert!(matches!(
            p.steps[0],
            LoginStep::FindField {
                field: LoginField::Username
            }
        ));
        assert!(matches!(
            p.steps[1],
            LoginStep::FindField {
                field: LoginField::Password
            }
        ));
        assert!(matches!(
            p.steps[3],
            LoginStep::Type {
                field: LoginField::Password,
                source: CredentialPart::Password
            }
        ));
        assert!(matches!(
            p.steps[4],
            LoginStep::Submit {
                method: SubmitMethod::ClickSubmit
            }
        ));
        match &p.steps[5] {
            LoginStep::Expect { any_of, timeout_ms } => {
                assert!(any_of.contains(&LoginExpectation::Navigation));
                assert!(any_of.contains(&LoginExpectation::LoggedIn(LoggedInIndicator::PasswordFieldGone)));
                assert_eq!(*timeout_ms, DEFAULT_EXPECT_TIMEOUT_MS);
            }
            other => panic!("{other:?}"),
        }
        assert!(p.types_password_only_into_password_field());
        // plan is plain data: JSON round trip, and carries no secret values
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<LoginPlan>(&json).unwrap(), p);
        assert!(json.contains("\"op\":\"find_field\""));
    }

    #[test]
    fn detects_fields_on_synthetic_login_form() {
        let c = login_form("login", 0);
        let t = LoginPlan::builtin_form().resolve(&c).unwrap();
        assert_eq!(t.username.as_ref().unwrap().index, 1);
        assert_eq!(t.password.index, 2);
        assert_eq!(t.submit.as_ref().unwrap().index, 3);
        assert_eq!(t.field(LoginField::Password).unwrap().index, 2);
        assert_eq!(t.field(LoginField::Username).unwrap().locator, c[1].locator);
    }

    #[test]
    fn email_username_and_localized_labels() {
        // German login without form element: grouped by proximity, no autocomplete hints
        let mk = |mut d: ObservedDescriptor| {
            d.ancestor_roles = vec!["main".into()];
            d
        };
        let mut email = input(1, &[("name", "mail")]);
        email.accessible_name = Some("E-Mail-Adresse".into());
        let mut pw = input(2, &[("type", "password")]);
        pw.accessible_name = Some("Passwort".into());
        let mut btn = desc(3, "button", "button", &[("type", "submit")]);
        btn.accessible_name = Some("Anmelden".into());
        let t = detect_login_form(&[mk(email), mk(pw), mk(btn)]).unwrap();
        assert_eq!(t.username.unwrap().index, 0);
        assert_eq!(t.password.index, 1);
        assert_eq!(t.submit.unwrap().index, 2);
    }

    #[test]
    fn password_only_form_has_no_username() {
        let mut c = login_form("f", 0);
        c.remove(1);
        let t = detect_login_form(&c).unwrap();
        assert!(t.username.is_none());
    }

    #[test]
    fn registration_and_search_forms_are_not_login() {
        let mut reg = vec![desc(0, "form", "form", &[("id", "r"), ("crawlx:form", "r")])];
        reg.push(owned(input(1, &[("type", "email")]), "r"));
        reg.push(owned(
            input(2, &[("type", "password"), ("autocomplete", "new-password")]),
            "r",
        ));
        reg.push(owned(
            input(3, &[("type", "password"), ("autocomplete", "new-password")]),
            "r",
        ));
        assert_eq!(detect_login_form(&reg), Err(LoginError::NoLoginForm));
        let search = vec![input(1, &[("type", "search")])];
        assert_eq!(detect_login_form(&search), Err(LoginError::NoLoginForm));
        assert_eq!(detect_login_form(&[]), Err(LoginError::NoLoginForm));
    }

    #[test]
    fn prefers_the_larger_login_form() {
        let mut c = login_form("header", 0);
        let mut page = login_form("page", 10);
        c[2].bbox = Some(BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 80.0,
            height: 20.0,
        });
        page[2].bbox = Some(BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 300.0,
            height: 40.0,
        });
        c.extend(page);
        let t = detect_login_form(&c).unwrap();
        assert_eq!(t.password.index, 6);
    }

    #[test]
    fn invisible_password_fields_are_skipped() {
        let mut c = login_form("a", 0);
        c[2].visible = false;
        assert_eq!(detect_login_form(&c), Err(LoginError::NoLoginForm));
    }
}
