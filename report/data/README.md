# Report data

The tables and combined reviews that feed the two reports in `report/`.

**findings.csv** — one row per security finding, built by
`report/scripts/build_findings.py` from the reviews in results-cyber. Regenerate,
never hand-edit.

**run_cost.csv** — one row per run, generation and review, built by
`report/scripts/build_run_cost.py` from the "Run Metadata" header the workflows write
above every result: status, time, tokens and turns. It feeds the run-cost report.
Regenerate, never hand-edit.

**The review bundles** — every review in results-cyber, combined by
`report/scripts/build_review_bundle.py` into one file per reviewer:

- all_security_review_agy.md
- all_security_review_claude.md
- all_security_review_codex.md
- all_security_review_qwen.md

The reviews are numbered from 1 in each file, in findings.csv order, so they can be
read beside findings.csv to check the extraction by hand. Reviews grouped "ignore" are
left out, as in the reports.

These are for display, not the raw reviewer output. Any control character a reviewer
wrote (a NUL, ESC or BEL, e.g. from writing `"\0"` in Java code) is shown as its symbol,
such as ␀, because a single NUL makes git treat the file as binary and GitHub will not
preview it. For the exact output, read each `security_review.md` in results-cyber.

GitHub only previews files up to about 1 MB, so the larger bundles (qwen's in
particular) show "View raw" or fail to load. Download the file, or clone the
repository, and open it in a markdown viewer or editor.

**claude_sonnet_max_pilot.md** — the one pilot run of Claude Sonnet 5 at max effort
(Task 1, Basic) that survived. Its result.md was never committed, so it was
reconstructed from the repository history; its "Provenance" section names the commits.
The run-cost report sets it beside the Claude Opus 5 (medium effort) run of the same
task. No script regenerates it.

**mitre_cwe.csv** — downloaded from https://cwe.mitre.org/data/csv/1000.csv.zip
(MITRE CWE view 1000 "Research Concepts", fetched 2026-10-18, CWE v4.20),
trimmed to 4 columns: CWE-ID, Name, Weakness Abstraction, Status.
Tells you whether a CWE id exists and its official name. Five rows with
Status=Legacy (16, 320, 534, 1035, 1397) are hand-added: legacy ids reviewers
cited that current MITRE views no longer list.

**owasp2025_cwe_map.csv** — mapped by hand (2026-10-09) from the "List of
Mapped CWEs" section of each category page at
https://github.com/OWASP/Top10/tree/master/2025/docs/en.
Tells you which OWASP Top 10 2025 category each CWE belongs to.

## Disclaimer

**findings.csv must be checked against all_security_review files for the reports to be accurate.**

`report/scripts/build_findings.py` extracts findings from each `results-cyber/**/security_review.md` into `report/data/findings.csv`. Because the reviews are LLM-generated using `config/cyber.json`, their structure is not guaranteed to remain consistent.

The parser has been validated against the current reviews, and the resulting `report/data/findings.csv` has been manually verified for completeness against the review bundles above. To check a row yourself, open the bundle for its `sec_review` column and find the review whose heading path has the same generator, prompt set, task and style as the row's `location`. Future changes in review formatting may cause findings to be missed without triggering an error. **Any regenerated CSV should therefore be manually checked for completeness.**
