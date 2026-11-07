//! Compile-fail gates:
//! the sealed `AdmittedAction`, the `Display`-less `SecretOr` and the `SecretFree`
//! bound of `ArtifactSink::put`. `TRYBUILD=overwrite cargo test -p crawlx-safety --test ui`
//! refreshes the expected diagnostics after a compiler upgrade.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn compile_fail_cases() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
