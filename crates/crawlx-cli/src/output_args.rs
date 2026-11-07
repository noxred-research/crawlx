//! Output, filter and verbosity flags of `crawlx crawl` (katana's Output and Filter groups).

use crate::crawl::PageTypeArg;
use crate::merge::fill_fields;
use anyhow::{anyhow, bail, Context as _};
use clap::Args;
use crawlx_worker::output::{
    expand_patterns, field_names, Dsl, ExportFormat, Exporter, Field, OutputFilters, StoredResponses,
    Template,
};
use crawlx_worker::StoreFields;
use std::path::{Path, PathBuf};

/// Result-stream and verbosity flags.
#[derive(Args, Debug, Clone, Default)]
pub struct OutputArgs {
    /// File the result stream is written to: JSONL records with `--jsonl`, else one line per
    /// `--field`/`--output-template` value (the URL by default). Without it text goes to
    /// standard output and JSONL to `DIR/results.jsonl`.
    #[arg(short = 'o', long, value_name = "FILE", help_heading = "Output")]
    pub output_file: Option<PathBuf>,
    /// Never overwrite an existing non-empty output file, response directory or error log:
    /// the next free numbered name (`out1.txt`, `out2.txt`) is used.
    #[arg(long, help_heading = "Output")]
    pub no_clobber: bool,
    /// Store every emitted page's raw request and response under the response directory with
    /// an `index.txt` (implies `--capture-raw`).
    #[arg(long, help_heading = "Output")]
    pub store_response: bool,
    /// Directory for `--store-response` (default `DIR/crawlx_response`); implies it.
    #[arg(long, value_name = "DIR", help_heading = "Output")]
    pub store_response_dir: Option<PathBuf>,
    /// Keep the raw request and response HTTP text of every page (`request.raw`,
    /// `response.raw`). `--jsonl` captures it unless `--omit-raw`.
    #[arg(long, help_heading = "Output")]
    pub capture_raw: bool,
    /// Leave `request.raw` and `response.raw` out of the JSONL records.
    #[arg(long, help_heading = "Output")]
    pub omit_raw: bool,
    /// Leave the response body out of the JSONL records (they carry it by default).
    #[arg(long, help_heading = "Output")]
    pub omit_body: bool,
    /// Print the JSONL fields `--exclude-output-fields` accepts, one per line, and exit.
    #[arg(long, help_heading = "Output")]
    pub list_output_fields: bool,
    /// JSONL fields to drop (comma separated; see `--list-output-fields`).
    #[arg(long, value_name = "LIST", value_delimiter = ',', help_heading = "Output")]
    pub exclude_output_fields: Vec<String>,
    /// Write the error log: one JSON line per URL that failed or was unreachable.
    #[arg(long, value_name = "FILE", help_heading = "Output")]
    pub error_log: Option<PathBuf>,
    /// No ANSI colour (also `NO_COLOR`); colour appears on a terminal or with `CLICOLOR_FORCE=1`.
    #[arg(long, help_heading = "Output")]
    pub no_color: bool,
    /// Print results only: no counter block, no diagnostics, only errors are logged.
    #[arg(long, conflicts_with_all = ["verbose", "debug"], help_heading = "Output")]
    pub silent: bool,
    /// Log at `info` level.
    #[arg(short = 'v', long, help_heading = "Output")]
    pub verbose: bool,
    /// Log at `debug` level (`DEBUG=true` in the environment does the same).
    #[arg(long, help_heading = "Output")]
    pub debug: bool,
    /// Keep only results whose URL (or printed value) matches one of these regexes; comma
    /// separated, repeatable, or a file with one regex per line.
    #[arg(long, value_name = "REGEX", help_heading = "Filters")]
    pub match_regex: Vec<String>,
    /// Drop results whose URL (or printed value) matches one of these regexes; same forms.
    #[arg(long, value_name = "REGEX", help_heading = "Filters")]
    pub filter_regex: Vec<String>,
    /// Keep only results for which this condition holds, e.g. `status_code == 200 &&
    /// contains(response.headers.content-type, "html")`.
    #[arg(long, value_name = "DSL", help_heading = "Filters")]
    pub match_condition: Option<String>,
    /// Drop results for which this condition holds.
    #[arg(long, value_name = "DSL", help_heading = "Filters")]
    pub filter_condition: Option<String>,
    /// Page types left out of the output (comma separated). Pages are still crawled and
    /// their links followed; `--no-expand-page-type` stops that.
    #[arg(
        long,
        value_enum,
        value_name = "TYPES",
        value_delimiter = ',',
        help_heading = "Filters"
    )]
    pub filter_page_type: Vec<PageTypeArg>,
    /// Print one line per value of these fields for every page (comma separated: `url`,
    /// `path`, `fqdn`, `rdn`, `rurl`, `qurl`, `qpath`, `file`, `ufile`, `key`, `value`, `kv`,
    /// `dir`, `udir` or a custom field).
    #[arg(
        short = 'f',
        long,
        value_name = "FIELDS",
        value_delimiter = ',',
        conflicts_with = "output_template",
        help_heading = "Output"
    )]
    pub field: Vec<String>,
    /// Print one line per page rendered from a `{{field}}` template.
    #[arg(long, value_name = "TEMPLATE", help_heading = "Output")]
    pub output_template: Option<String>,
    /// Append each page's field values to per-host wordlists in this directory.
    #[arg(
        long,
        visible_alias = "store-field-dir",
        value_name = "DIR",
        help_heading = "Output"
    )]
    pub store_fields: Option<PathBuf>,
    /// Store only these fields (comma separated, repeatable), independently of `--field`
    /// and `--output-template`. Defaults to `DIR/katana_field` without `--store-fields`.
    #[arg(long, value_name = "FIELDS", value_delimiter = ',', help_heading = "Output")]
    pub store_field: Vec<String>,
    /// Also write one request/response record per page as JSON lines.
    #[arg(short = 'j', long, help_heading = "Output")]
    pub jsonl: bool,
}

/// The exporters and files a crawl's result streams use.
#[derive(Debug)]
pub(crate) struct OutputPlan {
    /// JSONL exporter, when `--jsonl` is set.
    pub jsonl: Option<Exporter>,
    /// Text exporter: set when a field, template, wordlist directory or `-o` asks for text.
    pub text: Option<Exporter>,
    /// Where the JSONL stream goes: `-o FILE`, else `DIR/results.jsonl`.
    pub jsonl_file: Option<PathBuf>,
    /// Where the text stream goes: `-o FILE` (without `--jsonl`), else standard output.
    pub text_file: Option<PathBuf>,
    /// Never overwrite an existing non-empty `-o` file (the default `results.jsonl` is replaced).
    pub no_clobber: bool,
    /// `--jsonl` writes to the user's `-o FILE`, so `--no-clobber` applies to it.
    pub jsonl_to_user_file: bool,
}

impl OutputArgs {
    /// Fill unset fields from `lower`.
    pub(crate) fn fill_from(&mut self, lower: Self) {
        fill_fields!(
            self,
            lower,
            OutputArgs {
                output_file,
                no_clobber,
                store_response,
                store_response_dir,
                capture_raw,
                omit_raw,
                omit_body,
                list_output_fields,
                exclude_output_fields,
                error_log,
                no_color,
                silent,
                verbose,
                debug,
                match_regex,
                filter_regex,
                match_condition,
                filter_condition,
                filter_page_type,
                field,
                output_template,
                store_fields,
                store_field,
                jsonl,
            }
        );
    }

    /// `true` when the raw request/response text must be captured: asked for, stored, or
    /// carried by the JSONL records.
    pub(crate) fn wants_raw(&self) -> bool {
        self.capture_raw || self.stores_responses() || (self.jsonl && !self.omit_raw)
    }

    /// `true` when response bodies are read back: JSONL records carry them (unless
    /// `--omit-body`) and `--store-response` writes them. The page's HTML is then stored.
    pub(crate) fn wants_body(&self) -> bool {
        (self.jsonl && !self.omit_body) || self.stores_responses()
    }

    fn stores_responses(&self) -> bool {
        self.store_response || self.store_response_dir.is_some()
    }

    /// The default log filter these flags ask for, `None` when they ask for nothing.
    pub(crate) fn log_filter(&self, env_debug: bool) -> Option<&'static str> {
        if self.debug || env_debug {
            Some("debug")
        } else if self.verbose {
            Some("info")
        } else if self.silent {
            Some("error")
        } else {
            None
        }
    }

    /// The names `--list-output-fields` prints.
    pub(crate) fn listed_fields() -> Vec<&'static str> {
        field_names()
    }

    /// Parse every selector now so a bad field, template, regex or condition fails before the
    /// crawl starts, and open the files the streams share.
    ///
    /// `technologies_off` leaves the `technologies` field out of the JSONL records
    /// (`--katana-defaults` without `--tech-detect`); `knowledge_base` adds the
    /// `response.knowledgebase` object (`--knowledge-base`).
    ///
    /// # Errors
    /// The first selector that does not parse, an unknown `--exclude-output-fields` name, or a
    /// directory that cannot be created.
    pub(crate) fn plan(
        &self,
        output_dir: &Path,
        technologies_off: bool,
        knowledge_base: bool,
    ) -> anyhow::Result<OutputPlan> {
        let fields = if self.field.is_empty() {
            Vec::new()
        } else {
            Field::parse_list(&self.field.join(",")).map_err(|e| anyhow!("--field: {e}"))?
        };
        let stored_field_selection = if self.store_field.is_empty() {
            None
        } else {
            Some(Field::parse_list(&self.store_field.join(",")).map_err(|e| anyhow!("--store-field: {e}"))?)
        };
        let template = self
            .output_template
            .as_deref()
            .map(|t| Template::parse(t).map_err(|e| anyhow!("--output-template: {e}")))
            .transpose()?;
        let match_regex = expand_patterns(&self.match_regex).context("--match-regex")?;
        let filter_regex = expand_patterns(&self.filter_regex).context("--filter-regex")?;
        let filters = OutputFilters::new(&match_regex, &filter_regex, &[], &[])
            .context("--match-regex/--filter-regex")?;
        let match_condition = self
            .match_condition
            .as_deref()
            .map(|c| Dsl::parse(c).map_err(|e| anyhow!("--match-condition: {e}")))
            .transpose()?;
        let filter_condition = self
            .filter_condition
            .as_deref()
            .map(|c| Dsl::parse(c).map_err(|e| anyhow!("--filter-condition: {e}")))
            .transpose()?;
        let known: std::collections::BTreeSet<&str> = field_names().into_iter().collect();
        let mut exclude_fields = Vec::with_capacity(self.exclude_output_fields.len().saturating_add(1));
        for name in self
            .exclude_output_fields
            .iter()
            .map(|n| n.trim())
            .filter(|n| !n.is_empty())
        {
            if !known.contains(name) {
                bail!("--exclude-output-fields: unknown field `{name}` (see --list-output-fields)");
            }
            exclude_fields.push(name.to_owned());
        }
        if technologies_off {
            exclude_fields.push("technologies".to_owned());
        }
        let stored_responses = if self.stores_responses() {
            let dir = self
                .store_response_dir
                .clone()
                .unwrap_or_else(|| output_dir.join(crawlx_worker::output::stored::DEFAULT_DIR));
            Some(
                StoredResponses::new(&dir, self.no_clobber)
                    .with_context(|| format!("creating {}", dir.display()))?,
            )
        } else {
            None
        };
        let store_fields = self
            .store_fields
            .clone()
            .or_else(|| {
                stored_field_selection
                    .as_ref()
                    .map(|_| output_dir.join(crawlx_worker::output::store_fields::DEFAULT_DIR))
            })
            .map(StoreFields::new);
        let shared = Exporter {
            filters,
            match_condition,
            filter_condition,
            filter_page_types: self
                .filter_page_type
                .iter()
                .map(|t| crawlx_core::config::PageType::from(*t).as_str().to_owned())
                .collect(),
            stored_responses,
            exclude_fields,
            omit_raw: self.omit_raw,
            omit_body: self.omit_body,
            knowledge_base,
            ..Exporter::default()
        };
        let jsonl = self.jsonl.then(|| Exporter {
            format: ExportFormat::Jsonl,
            include_body: true,
            ..shared.clone()
        });
        let wants_text = !fields.is_empty()
            || template.is_some()
            || store_fields.is_some()
            || (self.stores_responses() && !self.jsonl)
            || (self.output_file.is_some() && !self.jsonl);
        let text = wants_text.then(|| Exporter {
            format: ExportFormat::Text,
            fields,
            template,
            store_fields,
            stored_field_selection,
            // the raw response is stored once: by the JSONL exporter when both streams run
            stored_responses: if self.jsonl {
                None
            } else {
                shared.stored_responses.clone()
            },
            ..shared
        });
        Ok(OutputPlan {
            jsonl,
            text,
            jsonl_file: if self.jsonl {
                Some(
                    self.output_file
                        .clone()
                        .unwrap_or_else(|| output_dir.join("results.jsonl")),
                )
            } else {
                None
            },
            text_file: if self.jsonl {
                None
            } else {
                self.output_file.clone()
            },
            no_clobber: self.no_clobber,
            jsonl_to_user_file: self.output_file.is_some(),
        })
    }
}
