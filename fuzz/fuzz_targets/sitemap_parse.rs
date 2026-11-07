//! `sitemap_parse` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `crawlx_fuzz::sitemap_parse`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| crawlx_fuzz::sitemap_parse(data));

#[cfg(not(fuzzing))]
fn main() {
    crawlx_fuzz::run_stdin(crawlx_fuzz::sitemap_parse);
}
