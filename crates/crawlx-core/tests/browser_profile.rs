//! Device, geolocation, block-list and flattening types of the browser plane: ranges, the
//! coherence check of the device matrix, option validation and serialized identity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::page_op::{
    BlockClass, DeviceBuildV1, DeviceMatrixEntryV1, DeviceMatrixV1, DeviceMeasurement, DevicePreset,
    Emulation, FlattenSpec, GeoPosition, DEVICE_SCALE_MAX_MILLI, DEVICE_SCALE_MIN_MILLI,
};
use crawlx_core::scrape::{Location, ResourceBlocking, ScrapeOptions};

#[test]
fn geo_positions_are_range_checked_and_report_the_member() {
    assert!(GeoPosition::new(90_000_000, 180_000_000, 1).is_ok());
    assert!(GeoPosition::new(-90_000_000, -180_000_000, GeoPosition::MAX_ACCURACY_M).is_ok());
    assert_eq!(GeoPosition::new(90_000_001, 0, 10), Err("latitude"));
    assert_eq!(GeoPosition::new(0, -180_000_001, 10), Err("longitude"));
    assert_eq!(GeoPosition::new(0, 0, 0), Err("accuracy"));
    assert_eq!(
        GeoPosition::new(0, 0, GeoPosition::MAX_ACCURACY_M + 1),
        Err("accuracy")
    );
    let munich = GeoPosition::new(48_137_154, 11_576_124, 25).unwrap();
    assert!((munich.latitude() - 48.137_154).abs() < 1e-9);
    assert!((munich.longitude() - 11.576_124).abs() < 1e-9);
}

#[test]
fn an_emulation_without_the_new_members_serializes_as_before() {
    let em = Emulation {
        viewport: Some((390, 844)),
        mobile: true,
        ..Emulation::default()
    };
    let value = serde_json::to_value(&em).unwrap();
    assert!(
        value.get("device_scale_milli").is_none() && value.get("geolocation").is_none(),
        "{value}"
    );
    let old: Emulation = serde_json::from_value(serde_json::json!({
        "viewport": [390, 844], "mobile": true, "user_agent": null, "accept_language": null,
        "locale": null, "timezone": null
    }))
    .unwrap();
    assert_eq!(old, em);
}

#[test]
fn presets_are_declared_emulations_of_the_running_major() {
    let phone = DevicePreset::Phone.emulation("155.0.8059.84", "en-US");
    assert_eq!(phone.viewport, Some((412, 915)));
    assert_eq!(phone.device_scale_milli, Some(2_625));
    assert!(phone.mobile);
    let ua = phone.user_agent.unwrap();
    assert!(ua.contains("Chrome/155.0.0.0 Mobile Safari/537.36"), "{ua}");
    assert!(
        !ua.contains("iPhone") && !ua.contains("Safari/604"),
        "no other browser is imitated: {ua}"
    );
    let tablet = DevicePreset::Tablet.emulation("155.0.8059.84", "de-DE");
    assert!(!tablet.user_agent.unwrap().contains(" Mobile"));
    assert_eq!(tablet.locale.as_deref(), Some("de-DE"));
    let desktop = DevicePreset::Desktop.emulation("155.0.8059.84", "en-US");
    assert!(!desktop.mobile && desktop.user_agent.is_none());
    assert_eq!(
        DevicePreset::ALL.map(DevicePreset::as_str),
        ["desktop", "phone", "tablet"]
    );
    const { assert!(DEVICE_SCALE_MIN_MILLI < 1_000 && DEVICE_SCALE_MAX_MILLI > 3_000) };
}

const DESKTOP_UA_PREFIX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "; // wire-compat: standard user-agent token

fn measured_for(preset: DevicePreset, version: &str) -> (Emulation, DeviceMeasurement) {
    let requested = preset.emulation(version, "en-US");
    let mobile = requested.mobile;
    let measured = DeviceMeasurement {
        viewport: requested.viewport.unwrap(),
        screen: requested.viewport.unwrap(),
        device_pixel_ratio_milli: requested.device_scale_milli.unwrap(),
        user_agent: requested
            .user_agent
            .clone()
            .unwrap_or_else(|| format!("{DESKTOP_UA_PREFIX}HeadlessChrome/{version} Safari/537.36")),
        language: "en-US".to_owned(),
        time_zone: "UTC".to_owned(),
        max_touch_points: if mobile { 5 } else { 0 },
        pointer_coarse: mobile,
        geolocation: None,
        geolocation_error: None,
    };
    (requested, measured)
}

#[test]
fn a_matching_measurement_is_coherent_and_every_disagreement_has_its_own_code() {
    let version = "155.0.8059.84";
    for preset in DevicePreset::ALL {
        let (requested, measured) = measured_for(preset, version);
        let entry = DeviceMatrixEntryV1::check(preset, requested, measured, version);
        assert!(entry.coherent, "{preset:?}: {:?}", entry.violations);
        assert!(entry.violations.is_empty());
    }
    let (requested, good) = measured_for(DevicePreset::Phone, version);
    type Change = Box<dyn Fn(&mut DeviceMeasurement)>;
    let cases: [(&str, Change); 8] = [
        ("viewport_mismatch", Box::new(|m| m.screen = (390, 844))),
        ("scale_mismatch", Box::new(|m| m.device_pixel_ratio_milli = 1_000)),
        ("user_agent_mismatch", Box::new(|m| m.user_agent.push('x'))),
        (
            "user_agent_build_mismatch",
            Box::new(|m| m.user_agent = m.user_agent.replace("Chrome/155", "Chrome/120")),
        ),
        ("touch_mismatch", Box::new(|m| m.max_touch_points = 0)),
        ("language_mismatch", Box::new(|m| m.language = "fr-FR".to_owned())),
        (
            "time_zone_mismatch",
            Box::new(|m| m.time_zone = "Asia/Tokyo".to_owned()),
        ),
        (
            "mobile_token_mismatch",
            Box::new(|m| m.user_agent = m.user_agent.replace(" Mobile", "")),
        ),
    ];
    for (code, change) in cases {
        let mut measured = good.clone();
        change(&mut measured);
        let entry = DeviceMatrixEntryV1::check(DevicePreset::Phone, requested.clone(), measured, version);
        assert!(!entry.coherent, "{code}");
        assert!(
            entry.violations.iter().any(|v| v == code),
            "{code} not in {:?}",
            entry.violations
        );
    }
}

#[test]
fn a_desktop_that_reports_touch_is_incoherent_and_the_matrix_never_claims_stealth() {
    let version = "155.0.8059.84";
    let (requested, mut measured) = measured_for(DevicePreset::Desktop, version);
    measured.max_touch_points = 3;
    let bad = DeviceMatrixEntryV1::check(DevicePreset::Desktop, requested, measured, version);
    assert_eq!(bad.violations, ["touch_mismatch"]);
    let (requested, measured) = measured_for(DevicePreset::Phone, version);
    let good = DeviceMatrixEntryV1::check(DevicePreset::Phone, requested, measured, version);
    let build = DeviceBuildV1 {
        chromium_version: version.to_owned(),
        pinned: true,
    };
    let matrix = DeviceMatrixV1::new(build.clone(), vec![good.clone()]);
    assert!(matrix.coherent() && !matrix.stealth_claim);
    let matrix = DeviceMatrixV1::new(build, vec![good, bad]);
    assert!(!matrix.coherent());
    let value = serde_json::to_value(&matrix).unwrap();
    assert_eq!(value["stealthClaim"], serde_json::json!(false));
    assert_eq!(value["schemaVersion"], serde_json::json!(1));
    assert_eq!(value["entries"][0]["preset"], serde_json::json!("phone"));
    let again: DeviceMatrixV1 = serde_json::from_value(value).unwrap();
    assert_eq!(again, matrix);
}

/// Default options changed by `change`.
fn with(change: impl FnOnce(&mut ScrapeOptions)) -> ScrapeOptions {
    let mut options = ScrapeOptions::default();
    change(&mut options);
    options
}

#[test]
fn the_new_scrape_options_are_validated_and_stay_out_of_old_identities() {
    let plain = ScrapeOptions::default();
    plain.validate().unwrap();
    let before = plain.cache_digest();
    let value = serde_json::to_value(&plain).unwrap();
    for key in ["deviceScaleMilli", "resourceBlocking", "flatten"] {
        assert!(value.get(key).is_none(), "{key}");
    }
    assert!(plain.location.is_none());

    let mut o = with(|o| o.device_scale_milli = Some(DEVICE_SCALE_MIN_MILLI - 1));
    assert!(o.validate().unwrap_err().contains("deviceScaleFactor"));
    o.device_scale_milli = Some(DEVICE_SCALE_MAX_MILLI + 1);
    assert!(o.validate().is_err());
    o.device_scale_milli = Some(2_000);
    o.validate().unwrap();
    assert_ne!(o.cache_digest(), before, "the page shape depends on the ratio");

    let mut o = with(|o| {
        o.resource_blocking = Some(ResourceBlocking {
            resource_types: vec![BlockClass::Ads],
            domains: Vec::new(),
        });
    });
    assert!(o.validate().unwrap_err().contains("font, media and image"));
    o.resource_blocking = Some(ResourceBlocking {
        resource_types: vec![BlockClass::Font],
        domains: vec!["Upper.example".to_owned()],
    });
    assert!(o.validate().unwrap_err().contains("domains"));
    o.resource_blocking = Some(ResourceBlocking {
        resource_types: vec![BlockClass::Font],
        domains: vec!["a.example".to_owned()],
    });
    o.validate().unwrap();

    let mut o = with(|o| {
        o.flatten = Some(FlattenSpec {
            shadow_dom: false,
            frames: false,
            max_frames: 4,
        });
    });
    assert!(o.validate().unwrap_err().contains("flatten"));
    o.flatten = Some(FlattenSpec {
        max_frames: FlattenSpec::MAX_FRAMES_LIMIT + 1,
        ..FlattenSpec::default()
    });
    assert!(o.validate().is_err());
    o.flatten = Some(FlattenSpec::default());
    o.validate().unwrap();
    assert!(o.needs_browser());
}

#[test]
fn geolocation_in_stored_options_is_range_checked_again() {
    // deserialization can build a position the constructor would refuse
    let location: Location = serde_json::from_value(serde_json::json!({
        "geolocation": { "latitudeE6": 91_000_000, "longitudeE6": 0, "accuracyM": 10 }
    }))
    .unwrap();
    let o = with(|o| o.location = Some(location));
    assert!(o.validate().unwrap_err().contains("latitude"));
}

#[test]
fn domain_names_are_lower_case_labels() {
    for ok in [
        "a.example",
        "xn--bcher-kva.example",
        "localhost",
        "a-b.c1.example",
    ] {
        assert!(ResourceBlocking::is_valid_domain(ok), "{ok}");
    }
    for bad in [
        "",
        "A.example",
        "a..example",
        ".a",
        "a.",
        "a:80",
        "a/b",
        "*.a",
        "a b",
        &"x".repeat(254),
    ] {
        assert!(!ResourceBlocking::is_valid_domain(bad), "{bad}");
    }
}

#[test]
fn a_published_device_matrix_is_bounded_browser_evidence_that_survives_serialization() {
    use crawlx_core::acquisition::BackendCapabilitiesV1;
    use crawlx_core::observation::BrowserBuildInfo;
    let version = "155.0.8059.84";
    let entries = DevicePreset::ALL
        .map(|preset| {
            let (requested, measured) = measured_for(preset, version);
            DeviceMatrixEntryV1::check(preset, requested, measured, version)
        })
        .to_vec();
    let matrix = DeviceMatrixV1::new(
        DeviceBuildV1 {
            chromium_version: version.to_owned(),
            pinned: true,
        },
        entries,
    );
    assert!(matrix.within_bounds());
    let mut browser = BackendCapabilitiesV1::native_browser(BrowserBuildInfo {
        chromium_version: version.to_owned(),
        cdp_revision: "1.3".to_owned(),
        user_agent: "fixture".to_owned(),
        pinned: true,
        launch_profile: crawlx_core::LaunchProfile::Standard,
        console_capture: false,
        attached: false,
    });
    assert!(browser.device_matrix.is_none());
    assert!(serde_json::to_value(&browser)
        .unwrap()
        .get("deviceMatrix")
        .is_none());
    browser.device_matrix = Some(matrix.clone());
    browser.validate_evidence().unwrap();
    let value = serde_json::to_value(&browser).unwrap();
    assert_eq!(value["deviceMatrix"]["stealthClaim"], serde_json::json!(false));
    let again: BackendCapabilitiesV1 = serde_json::from_value(value).unwrap();
    assert_eq!(again.device_matrix, Some(matrix.clone()));

    // a matrix belongs to an available browser backend, and stays small
    let mut http = BackendCapabilitiesV1::native_http("fixture", "1");
    http.device_matrix = Some(matrix.clone());
    assert!(http.validate_evidence().is_err());
    let mut unavailable = BackendCapabilitiesV1::native_browser_unavailable("probe_failed");
    unavailable.device_matrix = Some(matrix.clone());
    assert!(unavailable.validate_evidence().is_err());
    let mut oversized = matrix.clone();
    oversized.entries[0].violations = vec!["x".repeat(65)];
    assert!(!oversized.within_bounds());
    let mut crowded = matrix;
    crowded.entries.push(crowded.entries[0].clone());
    assert!(!crowded.within_bounds());
    browser.device_matrix = Some(crowded);
    assert!(browser.validate_evidence().is_err());
}
