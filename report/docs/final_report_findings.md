# Security findings data report


- [Executive summary](#executive-summary)
- [The eight Security-informed rules and the CWEs assigned to
  them](#the-eight-security-informed-rules-and-the-cwes-assigned-to-them)
- [Programs, reviews and findings](#programs-reviews-and-findings)
- [Completed reviews per task and
  generator](#completed-reviews-per-task-and-generator)
- [Paired difference in findings per review, overall and by
  generator](#paired-difference-in-findings-per-review-overall-and-by-generator)
- [Paired difference in findings per review by
  generator](#paired-difference-in-findings-per-review-by-generator)
- [Findings per review, median and High/Critical
  share](#findings-per-review-median-and-highcritical-share)
- [Findings per review](#findings-per-review)
- [Findings per review by generator](#findings-per-review-by-generator)
- [Findings per review by task](#findings-per-review-by-task)
- [Severity of findings](#severity-of-findings)
- [Reviews naming the task’s anchor
  CWE](#reviews-naming-the-tasks-anchor-cwe)
- [The 14 most-reported CWEs](#the-14-most-reported-cwes)
- [Findings per review by CWE](#findings-per-review-by-cwe)
- [Findings per review by CWE, per
  condition](#findings-per-review-by-cwe-per-condition)
- [Findings per review by OWASP
  category](#findings-per-review-by-owasp-category)
- [Findings per review by OWASP category, per
  condition](#findings-per-review-by-owasp-category-per-condition)
- [CWE make-up of findings](#cwe-make-up-of-findings)
- [OWASP category make-up of
  findings](#owasp-category-make-up-of-findings)
- [CWE make-up of findings by
  generator](#cwe-make-up-of-findings-by-generator)
- [OWASP category make-up of findings by
  generator](#owasp-category-make-up-of-findings-by-generator)
- [Findings per review by Security-informed
  rule](#findings-per-review-by-security-informed-rule)
- [Findings per review by Security-informed rule, per
  condition](#findings-per-review-by-security-informed-rule-per-condition)
- [Rule make-up of findings](#rule-make-up-of-findings)
- [Findings per review by reviewer and
  generator](#findings-per-review-by-reviewer-and-generator)
- [Reviewer volume, severity and own-code
  contrast](#reviewer-volume-severity-and-own-code-contrast)
- [Reviewer volume against severity, and own code against other
  generators’
  code](#reviewer-volume-against-severity-and-own-code-against-other-generators-code)
- [Severity of findings by reviewer](#severity-of-findings-by-reviewer)
- [Reviewers naming the same CWE, and the same OWASP category, on a
  program](#reviewers-naming-the-same-cwe-and-the-same-owasp-category-on-a-program)
- [Share of (program, category) pairs named by 1, 2, 3 or 4
  reviewers](#share-of-program-category-pairs-named-by-1-2-3-or-4-reviewers)
- [Mean Jaccard overlap of each reviewer pair’s labels on the same
  program](#mean-jaccard-overlap-of-each-reviewer-pairs-labels-on-the-same-program)
- [CWE make-up of findings by
  generator](#cwe-make-up-of-findings-by-generator-1)
- [OWASP category make-up of findings by
  generator](#owasp-category-make-up-of-findings-by-generator-1)
- [Findings per review by CWE and
  task](#findings-per-review-by-cwe-and-task)
- [Findings per review by OWASP category and
  task](#findings-per-review-by-owasp-category-and-task)
- [Data checks](#data-checks)
- [About this report](#about-this-report)

<!-- The report template. The cyber workflow renders it as-is (markdown, blank TEXT
     placeholders) for the writer AI to read, then copies it to final_report_findings.qmd with
     html/docx output, the writer fills the placeholders in that copy, and the copy is rendered. -->

## Executive summary

- Reviewers reported 1217 findings across 192 reviews of 120 generated
  programs; these are reviewer-reported findings, not confirmed
  vulnerabilities.
- Basic and Security-aware self-reviews produced 300 and 315 findings,
  while Security-informed self-reviews produced 139 findings across 24
  reviews; the corresponding findings per review were 6.25, 6.56, and
  5.79.
- In 48 matched Basic and Security-aware self-review pairs, the mean
  delta was 0.31 findings and the median delta was 0.0; 18 pairs had
  fewer findings, 23 had more, and 7 were ties.
- Sensitive data was the largest Security-informed rule grouping with
  339 findings (27.9%), followed by Authentication and access with 207
  (17.0%).
- CWE-307 was the most-reported CWE with 90 findings (7.4%); the 14
  most-reported CWEs together accounted for 51.9% of all findings.
- Reviewer agreement was higher at the OWASP-category level than at the
  CWE-label level: 32.1% of OWASP pairs versus 64.3% of CWE pairs were
  named by only one reviewer.

## The eight Security-informed rules and the CWEs assigned to them

<div id="tbl-rules">

Table 1: The eight Security-informed rules and the CWEs assigned to them
· All findings

<div class="cell-output cell-output-display cell-output-markdown">

| rule | CWEs | findings | % of all findings |
|:---|:---|---:|---:|
| 1 Trust boundaries | CWE-15, CWE-20, CWE-22, CWE-59, CWE-89, CWE-116, CWE-117, CWE-178, CWE-290, CWE-345, CWE-807, CWE-1284 | 99 | 8.1 |
| 2 Secrets | CWE-214, CWE-256, CWE-321, CWE-323, CWE-522, CWE-526, CWE-798 | 86 | 7.1 |
| 3 Authentication and access | CWE-284, CWE-287, CWE-306, CWE-307, CWE-521, CWE-636, CWE-645, CWE-799, CWE-862 | 207 | 17.0 |
| 4 Identifiers and tokens | CWE-330, CWE-338, CWE-352, CWE-384, CWE-613, CWE-614, CWE-1004 | 60 | 4.9 |
| 5 Sensitive data | CWE-226, CWE-244, CWE-276, CWE-316, CWE-319, CWE-359, CWE-377, CWE-400, CWE-532, CWE-549, CWE-732, CWE-770, CWE-779 | 339 | 27.9 |
| 6 Failure behaviour | CWE-200, CWE-203, CWE-204, CWE-208, CWE-209, CWE-754, CWE-1188 | 121 | 9.9 |
| 7 Concurrency | CWE-362, CWE-367 | 67 | 5.5 |
| 8 Prefer the platform | CWE-326, CWE-327, CWE-494, CWE-759, CWE-829, CWE-916, CWE-1395 | 79 | 6.5 |
| No rule | every CWE not listed above | 159 | 13.1 |

</div>

</div>

The largest rule grouping in
<a href="#tbl-rules" class="quarto-xref">Table 1</a> is Sensitive data
with 339 reviewer-reported findings (27.9%), followed by Authentication
and access with 207 (17.0%). Findings assigned to no rule total 159
(13.1%), while Identifiers and tokens is the smallest named grouping
with 60 (4.9%).

## Programs, reviews and findings

<div id="tbl-accounting">

Table 2: Programs, reviews and findings · All conditions, all reviews

<div class="cell-output cell-output-display cell-output-markdown">

| condition | programs | self-reviews | external reviews | reviews with no findings | findings |
|:---|---:|---:|---:|---:|---:|
| Basic | 48 | 48 | 0 | 0 | 300 |
| Security-aware | 48 | 48 | 0 | 1 | 315 |
| Security-informed | 24 | 24 | 72 | 6 | 602 |

</div>

</div>

<a href="#tbl-accounting" class="quarto-xref">Table 2</a> contains 48
Basic programs and 48 Security-aware programs, each with 48
self-reviews, plus 24 Security-informed programs with 24 self-reviews
and 72 external reviews. The conditions yielded 300, 315, and 602
reviewer-reported findings respectively, and 7 reviews in total had no
findings.

## Completed reviews per task and generator

<div id="fig-completeness">

![](final_report_findings_files/figure-commonmark/fig-completeness-output-1.png)

Figure 1: Completed reviews per task and generator · All conditions, all
reviews

</div>

<a href="#fig-completeness" class="quarto-xref">Figure 1</a> shows
uniform review completion across every task and generator within each
condition. Basic and Security-aware have the same completion pattern,
while Security-informed has more completed reviews in every cell.

## Paired difference in findings per review, overall and by generator

<div id="tbl-paired">

Table 3: Paired difference in findings per review, overall and by
generator · Basic and Security-aware, matched pairs, self-review

<div class="cell-output cell-output-display cell-output-markdown">

| scope | pairs | Basic mean | Security-aware mean | mean delta | median delta | fewer | more | ties | CI low | CI high |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all | 48 | 6.25 | 6.56 | 0.31 | 0.0 | 18 | 23 | 7 | -0.29 | 0.94 |
| agy | 12 | 6.33 | 7.42 | 1.08 | 1.0 | 2 | 9 | 1 | 0.17 | 1.92 |
| claude | 12 | 5.5 | 5.75 | 0.25 | 0.0 | 3 | 5 | 4 | -0.83 | 1.25 |
| codex | 12 | 4.33 | 3.58 | -0.75 | -1.0 | 7 | 4 | 1 | -1.67 | 0.17 |
| qwen | 12 | 8.83 | 9.5 | 0.67 | -0.5 | 6 | 5 | 1 | -1.0 | 2.33 |

</div>

</div>

Across 48 matched pairs in
<a href="#tbl-paired" class="quarto-xref">Table 3</a>, Basic averaged
6.25 findings and Security-aware averaged 6.56, for a mean delta of 0.31
and median delta of 0.0; 18 pairs had fewer findings, 23 had more, and 7
were ties. The generator-specific mean deltas were 1.08 for agy, 0.25
for claude, -0.75 for codex, and 0.67 for qwen.

## Paired difference in findings per review by generator

<div id="fig-paired">

![](final_report_findings_files/figure-commonmark/fig-paired-output-1.png)

Figure 2: Paired difference in findings per review by generator · Basic
and Security-aware, matched pairs, self-review

</div>

<a href="#fig-paired" class="quarto-xref">Figure 2</a> shows
matched-pair differences on both sides of zero for every generator. The
mean marker is positive for agy, claude, and qwen, and negative for
codex, with qwen showing the widest visual spread.

## Findings per review, median and High/Critical share

<div id="tbl-conditions">

Table 4: Findings per review, median and High/Critical share · All
conditions, self-review

<div class="cell-output cell-output-display cell-output-markdown">

| condition | self-reviews | findings | findings per review | median | High/Critical % |
|:---|---:|---:|---:|---:|---:|
| Basic | 48 | 300 | 6.25 | 6.0 | 16.67 |
| Security-aware | 48 | 315 | 6.56 | 7.0 | 17.78 |
| Security-informed | 24 | 139 | 5.79 | 7.0 | 14.39 |

</div>

</div>

In <a href="#tbl-conditions" class="quarto-xref">Table 4</a>,
Security-aware has the highest findings per review at 6.56, compared
with 6.25 for Basic and 5.79 for Security-informed. The median is 6.0
for Basic and 7.0 for both other conditions, while the High/Critical
share is 16.67%, 17.78%, and 14.39%, respectively.

## Findings per review

<div id="fig-distribution">

![](final_report_findings_files/figure-commonmark/fig-distribution-output-1.png)

Figure 3: Findings per review · All conditions, self-review

</div>

<a href="#fig-distribution" class="quarto-xref">Figure 3</a> shows
broadly overlapping findings-per-review distributions across the three
conditions. Security-aware has the broadest upper range, while
Security-informed has a wider central box than Basic.

## Findings per review by generator

<div id="fig-generator">

![](final_report_findings_files/figure-commonmark/fig-generator-output-1.png)

Figure 4: Findings per review by generator · All conditions, self-review

</div>

<a href="#fig-generator" class="quarto-xref">Figure 4</a> shows distinct
condition patterns by generator: Security-aware is highest for agy and
qwen, Security-informed is highest for claude, and Basic is highest for
codex. Codex declines across the conditions, whereas claude rises most
strongly under Security-informed.

## Findings per review by task

<div id="fig-task">

![](final_report_findings_files/figure-commonmark/fig-task-output-1.png)

Figure 5: Findings per review by task · All conditions, self-review

</div>

<a href="#fig-task" class="quarto-xref">Figure 5</a> shows that
task-level findings per self-review differ by condition. Basic and
Security-aware are highest on Task 6, while Security-informed is highest
on Task 3 and lower on Tasks 1, 5, and 6 than the other conditions.

## Severity of findings

<div id="fig-severity">

![](final_report_findings_files/figure-commonmark/fig-severity-output-1.png)

Figure 6: Severity of findings · All conditions, self-review

</div>

<a href="#fig-severity" class="quarto-xref">Figure 6</a> shows that
Medium and Low findings make up most reviewer-reported findings in every
condition. Security-aware has the largest High share, while
Security-informed has the largest Low share and is the only condition
with a visible Other segment.

## Reviews naming the task’s anchor CWE

<div id="fig-anchor">

![](final_report_findings_files/figure-commonmark/fig-anchor-output-1.png)

Figure 7: Reviews naming the task’s anchor CWE · All conditions,
self-review

</div>

<a href="#fig-anchor" class="quarto-xref">Figure 7</a> shows that the
task’s anchor CWE was named only for Tasks 5 and 6. Task 5 has the
highest anchor-CWE naming rate in every condition, while the conditions
are closer together on Task 6.

## The 14 most-reported CWEs

<div id="tbl-top-cwes">

Table 5: The 14 most-reported CWEs · All findings

<div class="cell-output cell-output-display cell-output-markdown">

| rank | CWE | title | findings | cumulative % |
|---:|:---|:---|---:|---:|
| 1 | CWE-307 | Improper Restriction of Excessive Authentication Attempts | 90 | 7.4 |
| 2 | CWE-400 | Uncontrolled Resource Consumption | 82 | 14.1 |
| 3 | CWE-916 | Use of Password Hash With Insufficient Computational Effort | 58 | 18.9 |
| 4 | CWE-316 | Cleartext Storage of Sensitive Information in Memory | 52 | 23.2 |
| 5 | CWE-732 | Incorrect Permission Assignment for Critical Resource | 50 | 27.3 |
| 6 | CWE-521 | Weak Password Requirements | 49 | 31.3 |
| 7 | CWE-770 | Allocation of Resources Without Limits or Throttling | 40 | 34.6 |
| 8 | CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | 35 | 37.5 |
| 9 | CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization (‘Race Condition’) | 32 | 40.1 |
| 10 | CWE-208 | Observable Timing Discrepancy | 31 | 42.6 |
| 11 | CWE-532 | Insertion of Sensitive Information into Log File | 31 | 45.2 |
| 12 | CWE-798 | Use of Hard-coded Credentials | 31 | 47.7 |
| 13 | CWE-204 | Observable Response Discrepancy | 26 | 49.9 |
| 14 | CWE-209 | Generation of Error Message Containing Sensitive Information | 25 | 51.9 |

</div>

</div>

<a href="#tbl-top-cwes" class="quarto-xref">Table 5</a> ranks CWE-307
first with 90 reviewer-reported findings (7.4%), followed by CWE-400
with 82; CWE-916 is third with 58. The listed 14 CWEs account
cumulatively for 51.9% of all findings.

## Findings per review by CWE

<div id="fig-cwe-rates">

![](final_report_findings_files/figure-commonmark/fig-cwe-rates-output-1.png)

Figure 8: Findings per review by CWE · All conditions, self-review

</div>

<a href="#fig-cwe-rates" class="quarto-xref">Figure 8</a> shows that the
leading CWE rates vary across conditions. CWE-307 is consistently
prominent; Security-informed is comparatively higher for CWE-400,
CWE-770, and CWE-367, but has no visible bars for CWE-798 or CWE-204.

## Findings per review by CWE, per condition

<div id="tbl-cwe-rates">

Table 6: Findings per review by CWE, per condition · All conditions,
self-review

<div class="cell-output cell-output-display cell-output-markdown">

| category | Basic | Security-aware | Security-informed |
|:---|---:|---:|---:|
| CWE-307 Improper Restriction of Excessive… | 0.48 | 0.48 | 0.5 |
| CWE-400 Uncontrolled Resource Consumption | 0.35 | 0.31 | 0.5 |
| CWE-916 Use of Password Hash With Insufficient… | 0.38 | 0.38 | 0.25 |
| CWE-316 Cleartext Storage of Sensitive Information… | 0.29 | 0.31 | 0.21 |
| CWE-732 Incorrect Permission Assignment for Critical… | 0.31 | 0.25 | 0.29 |
| CWE-521 Weak Password Requirements | 0.44 | 0.29 | 0.08 |
| CWE-770 Allocation of Resources Without Limits or… | 0.06 | 0.08 | 0.21 |
| CWE-367 Time-of-check Time-of-use (TOCTOU) Race… | 0.04 | 0.1 | 0.29 |
| CWE-362 Concurrent Execution using Shared Resource… | 0.19 | 0.15 | 0.04 |
| CWE-208 Observable Timing Discrepancy | 0.1 | 0.17 | 0.08 |
| CWE-532 Insertion of Sensitive Information into Log… | 0.15 | 0.23 | 0.08 |
| CWE-798 Use of Hard-coded Credentials | 0.31 | 0.29 | 0.0 |
| CWE-204 Observable Response Discrepancy | 0.23 | 0.25 | 0.0 |
| CWE-209 Generation of Error Message Containing… | 0.15 | 0.21 | 0.12 |
| Other | 2.77 | 3.06 | 3.12 |

</div>

</div>

In <a href="#tbl-cwe-rates" class="quarto-xref">Table 6</a>, CWE-307 is
similar across conditions at 0.48, 0.48, and 0.5 findings per review,
while CWE-400 rises from 0.35 and 0.31 to 0.5 in Security-informed.
Security-informed is also highest for CWE-770 at 0.21 and CWE-367 at
0.29, whereas CWE-798 and CWE-204 are both 0.0.

## Findings per review by OWASP category

<div id="fig-owasp-rates">

![](final_report_findings_files/figure-commonmark/fig-owasp-rates-output-1.png)

Figure 9: Findings per review by OWASP category · All conditions,
self-review

</div>

<a href="#fig-owasp-rates" class="quarto-xref">Figure 9</a> shows A07 as
the largest mapped OWASP category in each condition, though its rate
declines from Basic through Security-informed. Unmapped CWEs form the
largest overall bar for Security-aware and Security-informed, and A04
increases across the three conditions.

## Findings per review by OWASP category, per condition

<div id="tbl-owasp-rates">

Table 7: Findings per review by OWASP category, per condition · All
conditions, self-review

<div class="cell-output cell-output-display cell-output-markdown">

| category | Basic | Security-aware | Security-informed |
|:---|---:|---:|---:|
| A01 Broken Access Control | 0.77 | 0.83 | 0.54 |
| A02 Security Misconfiguration | 0.17 | 0.12 | 0.08 |
| A03 Software Supply Chain Failures | 0.02 | 0.0 | 0.0 |
| A04 Cryptographic Failures | 0.52 | 0.69 | 0.79 |
| A05 Injection | 0.17 | 0.21 | 0.25 |
| A06 Insecure Design | 0.73 | 0.58 | 0.5 |
| A07 Authentication Failures | 1.75 | 1.38 | 1.04 |
| A08 Software or Data Integrity Failures | 0.15 | 0.12 | 0.08 |
| A09 Security Logging and Alerting Failures | 0.29 | 0.44 | 0.33 |
| A10 Mishandling of Exceptional Conditions | 0.21 | 0.27 | 0.25 |
| Unmapped CWE outside the OWASP Top 10:2025 list | 1.48 | 1.92 | 1.92 |

</div>

</div>

<a href="#tbl-owasp-rates" class="quarto-xref">Table 7</a> shows A07 at
1.75, 1.38, and 1.04 findings per review across Basic, Security-aware,
and Security-informed, respectively. A04 rises from 0.52 to 0.69 to
0.79, while unmapped CWEs rise from 1.48 to 1.92 and remain at 1.92.

## CWE make-up of findings

<div id="fig-cwe-mix">

![](final_report_findings_files/figure-commonmark/fig-cwe-mix-output-1.png)

Figure 10: CWE make-up of findings · All conditions, self-review

</div>

<a href="#fig-cwe-mix" class="quarto-xref">Figure 10</a> shows that the
aggregated Other group is the largest share of findings in all three
conditions and is largest in Security-informed. Among individually
displayed CWEs, Security-informed places more emphasis on CWE-400, while
Basic and Security-aware have more similar mixes.

## OWASP category make-up of findings

<div id="fig-owasp-mix">

![](final_report_findings_files/figure-commonmark/fig-owasp-mix-output-1.png)

Figure 11: OWASP category make-up of findings · All conditions,
self-review

</div>

<a href="#fig-owasp-mix" class="quarto-xref">Figure 11</a> shows that
A07 and unmapped CWEs occupy the largest portions of each condition’s
findings. The A07 share decreases across the conditions, while the
unmapped and A04 shares are larger in Security-informed than in Basic.

## CWE make-up of findings by generator

<div id="fig-cwe-pies">

![](final_report_findings_files/figure-commonmark/fig-cwe-pies-output-1.png)

Figure 12: CWE make-up of findings by generator · All conditions,
self-review

</div>

<a href="#fig-cwe-pies" class="quarto-xref">Figure 12</a> shows
substantial variation in CWE mix by generator and condition. Codex’s
Security-informed self-review is concentrated in CWE-307 and a small set
of other displayed CWEs, whereas most other panels are dominated by the
aggregated Other segment.

## OWASP category make-up of findings by generator

<div id="fig-owasp-pies">

![](final_report_findings_files/figure-commonmark/fig-owasp-pies-output-1.png)

Figure 13: OWASP category make-up of findings by generator · All
conditions, self-review

</div>

<a href="#fig-owasp-pies" class="quarto-xref">Figure 13</a> shows that
A07 is prominent for most generator-condition combinations, while
unmapped CWEs dominate several Security-aware and Security-informed
panels. The Security-informed codex panel is especially concentrated in
A07, whereas qwen’s Security-informed panel is more broadly distributed
across mapped categories and unmapped CWEs.

## Findings per review by Security-informed rule

<div id="fig-rule-rates">

![](final_report_findings_files/figure-commonmark/fig-rule-rates-output-1.png)

Figure 14: Findings per review by Security-informed rule · All
conditions, self-review

</div>

<a href="#fig-rule-rates" class="quarto-xref">Figure 14</a> shows
Sensitive data as the highest-rate rule grouping for all three
conditions. Security-informed is comparatively lower for Secrets,
Authentication and access, and Failure behaviour, but higher for Trust
boundaries, Concurrency, and No rule.

## Findings per review by Security-informed rule, per condition

<div id="tbl-rule-rates">

Table 8: Findings per review by Security-informed rule, per condition ·
All conditions, self-review

<div class="cell-output cell-output-display cell-output-markdown">

| category                    | Basic | Security-aware | Security-informed |
|:----------------------------|------:|---------------:|------------------:|
| 1 Trust boundaries          |  0.48 |           0.48 |              0.58 |
| 2 Secrets                   |  0.73 |           0.73 |              0.17 |
| 3 Authentication and access |  1.25 |            1.1 |              0.88 |
| 4 Identifiers and tokens    |  0.35 |           0.21 |              0.38 |
| 5 Sensitive data            |  1.58 |           1.77 |              1.75 |
| 6 Failure behaviour         |  0.65 |           0.81 |              0.42 |
| 7 Concurrency               |  0.23 |           0.25 |              0.33 |
| 8 Prefer the platform       |  0.44 |           0.48 |              0.38 |
| No rule                     |  0.54 |           0.73 |              0.92 |

</div>

</div>

In <a href="#tbl-rule-rates" class="quarto-xref">Table 8</a>, Sensitive
data has the highest findings-per-review value in all three conditions
at 1.58, 1.77, and 1.75. Security-informed has the lowest Secrets value
at 0.17 and the highest No rule value at 0.92, while Authentication and
access declines from 1.25 to 1.1 to 0.88.

## Rule make-up of findings

<div id="fig-rule-mix">

![](final_report_findings_files/figure-commonmark/fig-rule-mix-output-1.png)

Figure 15: Rule make-up of findings · All conditions, self-review

</div>

<a href="#fig-rule-mix" class="quarto-xref">Figure 15</a> shows
Sensitive data as the largest rule share in every condition.
Security-informed has visibly larger shares for Trust boundaries,
Concurrency, and No rule, and a much smaller Secrets share than Basic or
Security-aware.

## Findings per review by reviewer and generator

<div id="fig-matrix">

![](final_report_findings_files/figure-commonmark/fig-matrix-output-1.png)

Figure 16: Findings per review by reviewer and generator ·
Security-informed, all four reviewers

</div>

<a href="#fig-matrix" class="quarto-xref">Figure 16</a> shows that all
four reviewers report more findings on agy-generated programs than on
codex-generated programs. Agy, claude, and qwen report fewer findings on
their own code than their row maximum, while codex’s own-code cell is
the lowest value in the matrix.

## Reviewer volume, severity and own-code contrast

<div id="tbl-behaviour">

Table 9: Reviewer volume, severity and own-code contrast ·
Security-informed, all four reviewers

<div class="cell-output cell-output-display cell-output-markdown">

| reviewer | reviews | findings per review | High/Critical % | distinct CWEs | own code | other code | other minus own |
|:---|---:|---:|---:|---:|---:|---:|---:|
| agy | 24 | 4.83 | 29.31 | 50 | 6.67 | 4.22 | -2.44 |
| claude | 24 | 7.83 | 7.98 | 60 | 8.0 | 7.78 | -0.22 |
| codex | 24 | 5.29 | 14.96 | 46 | 2.0 | 6.39 | 4.39 |
| qwen | 24 | 7.12 | 15.79 | 68 | 6.5 | 7.33 | 0.83 |

</div>

</div>

<a href="#tbl-behaviour" class="quarto-xref">Table 9</a> shows claude
with the highest findings per review at 7.83 and the most distinct CWEs
at 60, while qwen names 68 distinct CWEs and averages 7.12 findings. Agy
has the highest High/Critical share at 29.31%; codex shows the largest
positive other-minus-own contrast at 4.39, while agy’s contrast is
-2.44.

## Reviewer volume against severity, and own code against other generators’ code

<div id="fig-behaviour">

![](final_report_findings_files/figure-commonmark/fig-behaviour-output-1.png)

Figure 17: Reviewer volume against severity, and own code against other
generators’ code · Security-informed, all four reviewers

</div>

<a href="#fig-behaviour" class="quarto-xref">Figure 17</a> separates
reviewer volume from severity: claude has the highest findings volume
but the lowest High/Critical share, while agy has the lowest volume and
highest High/Critical share. Codex reports substantially more findings
on other generators’ code than on its own, whereas agy shows the
opposite pattern.

## Severity of findings by reviewer

<div id="fig-severity-reviewer">

![](final_report_findings_files/figure-commonmark/fig-severity-reviewer-output-1.png)

Figure 18: Severity of findings by reviewer · Security-informed, all
four reviewers

</div>

<a href="#fig-severity-reviewer" class="quarto-xref">Figure 18</a> shows
distinct severity mixes across reviewers. Agy has the largest High
share, codex is dominated by Medium findings, and claude has the largest
Low share; only qwen has a clearly visible Other segment.

## Reviewers naming the same CWE, and the same OWASP category, on a program

<div id="fig-agreement">

![](final_report_findings_files/figure-commonmark/fig-agreement-output-1.png)

Figure 19: Reviewers naming the same CWE, and the same OWASP category,
on a program · Security-informed, all four reviewers

</div>

<a href="#fig-agreement" class="quarto-xref">Figure 19</a> shows that
most CWE-label pairs are named by only one reviewer, with rapidly fewer
pairs as the number of agreeing reviewers increases. OWASP-category
agreement is more distributed across multiple reviewers, and its largest
group is categories named by two reviewers.

## Share of (program, category) pairs named by 1, 2, 3 or 4 reviewers

<div id="tbl-agreement">

Table 10: Share of (program, category) pairs named by 1, 2, 3 or 4
reviewers · Security-informed, all four reviewers

<div class="cell-output cell-output-display cell-output-markdown">

| level          | pairs | named by 1 % | named by 2 % | named by 3 % | named by 4 % |
|:---------------|------:|-------------:|-------------:|-------------:|-------------:|
| CWE label      |   387 |         64.3 |         27.1 |          7.2 |          1.3 |
| OWASP category |   137 |         32.1 |         35.8 |         21.2 |         10.9 |

</div>

</div>

In <a href="#tbl-agreement" class="quarto-xref">Table 10</a>, 64.3% of
387 CWE-label pairs were named by one reviewer, compared with 32.1% of
137 OWASP-category pairs. Agreement by all four reviewers occurred for
1.3% of CWE-label pairs and 10.9% of OWASP-category pairs.

## Mean Jaccard overlap of each reviewer pair’s labels on the same program

<div id="tbl-jaccard">

Table 11: Mean Jaccard overlap of each reviewer pair’s labels on the
same program · Security-informed, all four reviewers

<div class="cell-output cell-output-display cell-output-markdown">

| reviewer pair  | CWE Jaccard | OWASP Jaccard |
|:---------------|------------:|--------------:|
| agy / claude   |        0.12 |          0.29 |
| agy / codex    |        0.12 |          0.26 |
| agy / qwen     |         0.1 |          0.31 |
| claude / codex |        0.22 |          0.31 |
| claude / qwen  |        0.19 |          0.54 |
| codex / qwen   |        0.13 |          0.34 |

</div>

</div>

<a href="#tbl-jaccard" class="quarto-xref">Table 11</a> shows low mean
CWE overlap for every reviewer pair, ranging from 0.1 for agy / qwen to
0.22 for claude / codex. OWASP overlap is higher for every pair, led by
claude / qwen at 0.54 and lowest for agy / codex at 0.26.

## CWE make-up of findings by generator

<div id="fig-cwe-pies-2">

![](final_report_findings_files/figure-commonmark/fig-cwe-pies-2-output-1.png)

Figure 20: CWE make-up of findings by generator · Security-informed,
self-review and external review

</div>

<a href="#fig-cwe-pies-2" class="quarto-xref">Figure 20</a> shows
different CWE mixes between Security-informed self-review and external
review for each generator. External reviews are generally more dispersed
across the displayed CWEs, although codex external reviews have a
particularly large aggregated Other segment.

## OWASP category make-up of findings by generator

<div id="fig-owasp-pies-2">

![](final_report_findings_files/figure-commonmark/fig-owasp-pies-2-output-1.png)

Figure 21: OWASP category make-up of findings by generator ·
Security-informed, self-review and external review

</div>

<a href="#fig-owasp-pies-2" class="quarto-xref">Figure 21</a> shows
unmapped CWEs as the largest category in most Security-informed
self-review and external-review panels. Codex self-review is the
exception, where A07 dominates, while the external-review mix is led by
unmapped CWEs for every generator.

## Findings per review by CWE and task

<div id="fig-cwe-task">

![](final_report_findings_files/figure-commonmark/fig-cwe-task-output-1.png)

Figure 22: Findings per review by CWE and task · All conditions,
self-review

</div>

<a href="#fig-cwe-task" class="quarto-xref">Figure 22</a> shows that CWE
profiles vary by task, with the aggregated Other group largest for every
task. Among the displayed CWEs, CWE-307 is most prominent in later
tasks, while CWE-732 and CWE-798 are especially prominent on Task 6.

## Findings per review by OWASP category and task

<div id="fig-owasp-task">

![](final_report_findings_files/figure-commonmark/fig-owasp-task-output-1.png)

Figure 23: Findings per review by OWASP category and task · All
conditions, self-review

</div>

<a href="#fig-owasp-task" class="quarto-xref">Figure 23</a> shows
unmapped CWEs as the highest-rate grouping for Tasks 2 through 6, while
A07 is highest on Task 1. A07 is also prominent on Tasks 4 through 6,
and A03 is nearly absent across all tasks.

## Data checks

<div id="tbl-checks">

Table 12: Data checks · All reviews

<div class="cell-output cell-output-display cell-output-markdown">

| check                               | value |
|:------------------------------------|------:|
| CSV rows                            |  1224 |
| Recorded findings                   |  1217 |
| Reviews                             |   192 |
| Reviews with no findings            |     7 |
| Generated programs                  |   120 |
| Rows missing reviewer or generator  |     0 |
| Programs read by all 4 reviewers    |    24 |
| Duplicate CSV rows                  |     0 |
| Findings with no CWE                |     0 |
| Findings with non-standard severity |     8 |
| Repeated sec_id within one review   |     0 |

</div>

</div>

<a href="#tbl-checks" class="quarto-xref">Table 12</a> records 1224 CSV
rows comprising 1217 reviewer-reported findings across 192 reviews and
120 generated programs, with 7 reviews having no findings. It reports 0
rows missing reviewer or generator, 0 duplicate rows, 0 findings with no
CWE, 8 findings with non-standard severity, and 0 repeated sec_id values
within a review.

## About this report

Every table and figure is computed from `findings.csv` when the report
is rendered. The text was written by an AI from the rendered tables and
figures. All counts are reviewer-reported findings, not confirmed
vulnerabilities.
