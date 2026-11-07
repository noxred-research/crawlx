//! `scope_pattern_compile` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `crawlx_fuzz::scope_pattern_compile`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| crawlx_fuzz::scope_pattern_compile(data));

#[cfg(not(fuzzing))]
fn main() {
    crawlx_fuzz::run_stdin(crawlx_fuzz::scope_pattern_compile);
}
