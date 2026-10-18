# Report data

The tables and combined reviews that feed the security report in `report/`.

**findings.csv** — one row per security finding, built by
`report/scripts/build_findings.py` from the reviews in results-cyber. Regenerate,
never hand-edit.

**all_security_review.md** — every review in results-cyber in one file, built by
`report/scripts/build_review_bundle.py`, numbered in findings.csv order. For
reading beside findings.csv to check the extraction by hand.

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

`report/scripts/build_findings.py` extracts findings from each `results-cyber/**/security_review.md` into `report/data/findings.csv`. Because the reviews are LLM-generated using `config/cyber.json`, their structure is not guaranteed to remain consistent.

The parser has been validated against the current reviews, and the resulting `report/data/findings.csv` has been manually verified for completeness. Future changes in review formatting may cause findings to be missed without triggering an error. **Any regenerated CSV should therefore be manually checked for completeness.**
