//! Compile-fail gates:
//! the sealed `AdmittedAction`, the `Display`-less `SecretOr` and the `SecretFree`
//! bound of `ArtifactSink::put`. `TRYBUILD=overwrite cargo test -p crawlx-safety --test ui`
//! refreshes the expected diagnostics after a compiler upgrade.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn compile_fail_cases() {
    // The runner already applied its stack limit to this test thread. Do not pass
    // that runtime-only limit to the compiler processes the fixture starts below.
    // This integration target contains only this test, so no sibling reads it.
    std::env::remove_var("RUST_MIN_STACK");
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
