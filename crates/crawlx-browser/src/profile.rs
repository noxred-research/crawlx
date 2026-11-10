//! Launch profiles: which flags and which CDP domains each profile uses.

use crawlx_core::config::LaunchProfile;

/// Flags both profiles pass (before profile-specific and egress flags).
///
/// `--password-store=basic` keeps Chromium's cookie/credential store off the desktop
/// keyring: with a locked session keyring (for example after a reboot without a password
/// login) the cookie store blocks, which stalls `Storage.getCookies` and every navigation.
///
/// Do not create Chromium's default New Tab page: its account/promo services
/// can request vendor URLs before crawlx creates the first managed target. This
/// suppresses only the browser-owned startup window, not target-page networking.
pub const COMMON_FLAGS: [&str; 7] = [
    "--no-first-run",
    "--no-default-browser-check",
    "--no-startup-window",
    "--disable-extensions",
    "--disable-sync",
    "--disable-background-networking",
    "--password-store=basic",
];

/// Flags only `Standard` passes (Chromium automation defaults).
pub const STANDARD_FLAGS: [&str; 4] = [
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-popup-blocking",
    "--enable-automation",
];

/// Flags only `Stealth` passes.
pub const STEALTH_FLAGS: [&str; 1] = ["--disable-blink-features=AutomationControlled"];

/// Window, rendering and locale flags (both profiles; fixed viewport keeps geometry reproducible).
pub const RENDER_FLAGS: [&str; 5] = [
    "--window-size=1280,800",
    "--force-device-scale-factor=1",
    "--lang=en-US",
    "--force-color-profile=srgb",
    "--mute-audio",
];

/// Keep certificate-error network-time checks, but do not query the vendor's time
/// service merely because an owned browser started with a fresh profile.
///
/// Chromium 155's `NetworkTimeTracker::Initialize` queues an immediate background
/// check independently of `--disable-background-networking`. Its `FetchBehavior`
/// parameter retains on-demand checks without changing certificate verification,
/// the host clock, or page content/transport features.
/// See `components/network_time/network_time_tracker.cc` at the pinned revision.
pub(crate) const ON_DEMAND_BROWSER_SERVICES: &str = "NetworkTimeServiceQuerying:FetchBehavior/on-demand-only";

/// Skip only the omnibox AI Mode service's automatic startup eligibility request.
/// That request also consults Gaia's account cookie jar (`ListAccounts`); webpage
/// logins, ordinary cookies, and user-triggered AI eligibility remain available.
/// See pinned `components/omnibox/browser/aim_eligibility_service.cc`.
pub(crate) const NO_STARTUP_AI_ELIGIBILITY: &str = "AimServerRequestOnStartupEnabled";

/// Profile-specific launch flags.
#[must_use]
pub fn profile_flags(profile: LaunchProfile) -> Vec<String> {
    let src: &[&str] = match profile {
        LaunchProfile::Standard => &STANDARD_FLAGS,
        LaunchProfile::Stealth => &STEALTH_FLAGS,
    };
    src.iter().map(|s| (*s).to_owned()).collect()
}

/// What the adapter may do over CDP under a profile.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProfileBehavior {
    /// Launch profile this behavior was derived for.
    pub profile: LaunchProfile,
    /// `Runtime.enable` is sent for each tab (`Standard` with console capture only).
    pub enable_runtime: bool,
    /// Console messages are captured (`Stealth` never captures).
    pub console_capture: bool,
}

impl ProfileBehavior {
    /// Behavior of `profile` given the requested `console_capture`.
    #[must_use]
    pub const fn of(profile: LaunchProfile, console_capture_requested: bool) -> Self {
        let console_capture = matches!(profile, LaunchProfile::Standard) && console_capture_requested;
        Self {
            profile,
            enable_runtime: console_capture,
            console_capture,
        }
    }

    /// Is this the stealth profile?
    #[must_use]
    pub const fn is_stealth(&self) -> bool {
        matches!(self.profile, LaunchProfile::Stealth)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn stealth_never_captures_console_or_enables_runtime() {
        let b = ProfileBehavior::of(LaunchProfile::Stealth, true);
        assert!(!b.console_capture && !b.enable_runtime && b.is_stealth());
        let s = ProfileBehavior::of(LaunchProfile::Standard, true);
        assert!(s.console_capture && s.enable_runtime);
        let off = ProfileBehavior::of(LaunchProfile::Standard, false);
        assert!(!off.console_capture && !off.enable_runtime);
    }
}
