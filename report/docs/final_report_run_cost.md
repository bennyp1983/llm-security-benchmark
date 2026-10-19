# Run cost data report


- [Summary](#summary)
- [What was measured](#what-was-measured)
  - [Source of the numbers](#source-of-the-numbers)
  - [Two token measures, one rule for every
    assistant](#two-token-measures-one-rule-for-every-assistant)
  - [Gaps in the data](#gaps-in-the-data)
- [How the runs finished](#sec-run-completion)
- [Overall cost per assistant](#sec-run-overall)
- [Generation](#sec-run-generation)
- [Review](#sec-run-review)
- [Claude at maximum effort in the pilot](#sec-run-sonnet)
- [Qwen review effort](#sec-run-qwen)
- [Reading these numbers](#sec-run-reading)

<!-- The report template. The cyber workflow renders it as-is (markdown, blank TEXT
     placeholders) for the writer AI to read, then copies it to final_report_run_cost.qmd with
     html/docx output, the writer fills the placeholders in that copy, and the copy is rendered. -->

## Summary

- All 30 generation runs succeeded for Claude, Codex and Qwen;
  Antigravity had 29 successes and 1 error, with 7 empty replies. All 48
  review runs for each assistant succeeded with no empty replies.
- Qwen had the largest reported generation cost, totaling 50.98 hours
  and 709.11 million tokens processed across 30 runs; Codex processed
  8.28 million tokens, while its run time was not reported.
- Across 48 review runs, Qwen reported 34.53 total hours and 402.96
  million tokens processed. Antigravity, Claude and Codex processed
  141.09 million, 56.78 million and 65.42 million review tokens,
  respectively, and Codex review time was not reported.
- The generation figures show that Qwen’s security-informed runs stand
  apart from the other conditions in both time and processed tokens,
  while the other assistants show smaller condition-to-condition shifts.
- In the recovered pilot, Claude Sonnet 5 at max effort used 30.24
  minutes, 1.24 million processed tokens and 21.0 turns for Task 1
  Basic, compared with 4.38 minutes, 0.24 million processed tokens and
  12.0 turns for Claude Opus 5 at medium on the same task.
- Qwen’s security-informed setting combined xhigh generation with medium
  review: generation averaged 358.46 minutes and self-review 46.38
  minutes, and the 24-review panel totaled 14.4 actual hours at medium
  versus 190.5 estimated hours at xhigh.

> **Reader’s rule:** time and tokens describe the coding assistant as
> configured (model, effort setting, scaffolding and hardware), not the
> model alone. Codex records no run time, so it is absent from every
> time figure.

## What was measured

### Source of the numbers

This section distinguishes generation runs, whose reported cost is
assigned to the generator, from review runs, whose reported cost is
assigned to the reviewer. The report covers 30 generation runs and 48
review runs for each assistant, as summarized in the later completion
and cost tables.

- A **generation run** is one assistant writing one program. Its cost
  belongs to the generator.
- A **review run** is one reviewer reading one program. Its cost belongs
  to the reviewer.

### Two token measures, one rule for every assistant

The table sets out what each assistant includes in input, cached and
total token counts. It also defines tokens processed consistently as all
reported input, cache-related and output tokens available for each
assistant.

| Assistant | What “input” counts | Cached tokens | Tool’s own total | Tokens processed, as used here |
|:---|:---|:---|:---|:---|
| Antigravity | input not read from cache | reported separately | input + output | input + cached read + output |
| Claude Code | input not read from or written to cache | reported separately, plus cache creation | input + output | input + cache creation + cached read + output |
| Codex | all input, cached included | already inside input | input + output | input + output |
| Qwen Code | the whole prompt, re-sent on every request | not reported | input + output | input + output |

How each assistant reports tokens, and the measure this report derives
from them

### Gaps in the data

Codex did not report run time, so its time values are missing from the
overall table and it does not appear in the time figures. The completion
tables also distinguish an ERROR from successful runs that returned an
empty reply, preserving both kinds of gaps in the run record.

## How the runs finished

<div id="tbl-run-completion">

Table 1: Run status and empty replies by assistant · All generation and
review runs

<div class="cell-output cell-output-display cell-output-markdown">

| assistant | stage      | runs | status SUCCESS | status ERROR | empty reply |
|:----------|:-----------|-----:|---------------:|-------------:|------------:|
| agy       | generation |   30 |             29 |            1 |           7 |
| agy       | review     |   48 |             48 |            0 |           0 |
| claude    | generation |   30 |             30 |            0 |           0 |
| claude    | review     |   48 |             48 |            0 |           0 |
| codex     | generation |   30 |             30 |            0 |           0 |
| codex     | review     |   48 |             48 |            0 |           0 |
| qwen      | generation |   30 |             30 |            0 |           0 |
| qwen      | review     |   48 |             48 |            0 |           0 |

</div>

</div>

<a href="#tbl-run-completion" class="quarto-xref">Table 1</a> shows that
Claude, Codex and Qwen each completed all 30 generation runs
successfully, while Antigravity recorded 29 successes, 1 error and 7
empty replies. All four assistants completed their 48 review runs
successfully with 0 empty replies.

<div id="tbl-run-problems">

Table 2: Runs that ended in ERROR or returned no reply · All generation
and review runs

<div class="cell-output cell-output-display cell-output-markdown">

| run                           | stage      | status  | empty reply | minutes |
|:------------------------------|:-----------|:--------|:------------|--------:|
| agy/post_research/1/security/ | generation | ERROR   | yes         |     5.0 |
| agy/ruth/3/basic/             | generation | SUCCESS | yes         |     4.9 |
| agy/ruth/5/basic/             | generation | SUCCESS | yes         |     5.0 |
| agy/ruth/5/security/          | generation | SUCCESS | yes         |     4.9 |
| agy/sallie/1/security/        | generation | SUCCESS | yes         |     4.8 |
| agy/sallie/3/basic/           | generation | SUCCESS | yes         |     4.9 |
| agy/sallie/3/security/        | generation | SUCCESS | yes         |     4.9 |

</div>

</div>

All seven problem entries in
<a href="#tbl-run-problems" class="quarto-xref">Table 2</a> are
Antigravity generation runs: 1 ended in ERROR and 6 had SUCCESS status
with an empty reply. Their reported times range from 4.8 to 5.0 minutes.

## Overall cost per assistant

<div id="tbl-run-headline">

Table 3: Time and tokens per assistant · All generation runs (by
generator) and all review runs (by reviewer); Codex records no time

<div class="cell-output cell-output-display cell-output-markdown">

| assistant | stage | runs | total hours | mean minutes per run | total tokens processed (M) | mean tokens processed per run (M) | mean tokens generated per run (k) |
|:---|:---|---:|---:|---:|---:|---:|---:|
| agy | generation | 30 | 2.47 | 4.95 | 68.09 | 2.27 | 45.8 |
| agy | review | 48 | 3.73 | 4.66 | 141.09 | 2.94 | 51.45 |
| claude | generation | 30 | 2.84 | 5.68 | 15.81 | 0.53 | 27.11 |
| claude | review | 48 | 5.3 | 6.63 | 56.78 | 1.18 | 28.25 |
| codex | generation | 30 |  |  | 8.28 | 0.28 | 8.13 |
| codex | review | 48 |  |  | 65.42 | 1.36 | 13.28 |
| qwen | generation | 30 | 50.98 | 101.96 | 709.11 | 23.64 | 233.91 |
| qwen | review | 48 | 34.53 | 43.17 | 402.96 | 8.39 | 98.67 |

</div>

</div>

<a href="#tbl-run-headline" class="quarto-xref">Table 3</a> shows that
Qwen generation had the largest reported totals at 50.98 hours and
709.11 million tokens processed, with means of 101.96 minutes and 23.64
million processed tokens per run. For review, Qwen reported 34.53 hours
and 402.96 million processed tokens, while Codex review time was not
reported and its 48 reviews processed 65.42 million tokens.

## Generation

<div id="fig-run-gen-time">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-time-output-1.png)

Figure 1: Mean minutes per program by generator and condition · All
generation runs; Codex records no time

</div>

<a href="#fig-run-gen-time" class="quarto-xref">Figure 1</a> shows Qwen
taking much longer per generated program than Antigravity or Claude,
especially in the security-informed condition. Antigravity and Claude
also take longer in the security-informed condition than in their other
two conditions; Codex is absent because its time was not reported.

<div id="fig-run-gen-tokens">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-tokens-output-1.png)

Figure 2: Mean tokens processed per program by generator and condition ·
All generation runs

</div>

<a href="#fig-run-gen-tokens" class="quarto-xref">Figure 2</a> shows
Qwen processing the most tokens per generated program in every
condition, with a particularly large increase for security-informed
generation. Antigravity is next highest across the conditions, while
Claude and Codex remain lower.

<div id="fig-run-gen-task-time">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-task-time-output-1.png)

Figure 3: Mean minutes per program by task and generator · All
generation runs; Codex records no time

</div>

Across the task panels in
<a href="#fig-run-gen-task-time" class="quarto-xref">Figure 3</a>, Qwen
takes the most reported time for every task and condition, with the
strongest contrast in the security-informed panel. Antigravity and
Claude are closer to one another, although their task patterns vary;
Codex is absent because its time was not reported.

<div id="fig-run-gen-task-tokens">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-task-tokens-output-1.png)

Figure 4: Mean tokens processed per program by task and generator · All
generation runs

</div>

<a href="#fig-run-gen-task-tokens" class="quarto-xref">Figure 4</a>
shows Qwen processing the most tokens for every task in each condition,
with the security-informed task cells standing far above its Basic and
Security-aware cells. Antigravity, Claude and Codex have smaller values
and less pronounced condition shifts.

## Review

<div id="fig-run-review-time">

![](final_report_run_cost_files/figure-commonmark/fig-run-review-time-output-1.png)

Figure 5: Mean minutes per self-review by reviewer and condition · All
conditions, self-review; Codex records no time

</div>

<a href="#fig-run-review-time" class="quarto-xref">Figure 5</a> shows
Qwen self-reviews taking substantially longer than Antigravity or Claude
in all three conditions. Antigravity and Claude take their longest
self-review time in the security-informed condition, whereas Qwen’s bars
decline across the displayed conditions; Codex is absent because its
time was not reported.

<div id="fig-run-review-tokens">

![](final_report_run_cost_files/figure-commonmark/fig-run-review-tokens-output-1.png)

Figure 6: Mean tokens processed per self-review by reviewer and
condition · All conditions, self-review

</div>

<a href="#fig-run-review-tokens" class="quarto-xref">Figure 6</a> shows
Qwen processing the most tokens per self-review in every condition. For
Antigravity, Claude and Codex, security-informed self-review is also the
highest of their three conditions.

<div id="fig-run-review-matrix">

![](final_report_run_cost_files/figure-commonmark/fig-run-review-matrix-output-1.png)

Figure 7: Mean tokens per review, reviewer × generator ·
Security-informed, all four reviewers

</div>

In <a href="#fig-run-review-matrix" class="quarto-xref">Figure 7</a>,
the Qwen reviewer generally occupies the high end of both processed and
generated tokens, while the Codex reviewer generates the fewest tokens
across all generator columns. Within each reviewer row, reviews of
Qwen-generated programs tend to require the most processed tokens, while
reviews of Codex-generated programs tend to require the least.

## Claude at maximum effort in the pilot

This section compares one recovered Claude Sonnet 5 pilot generation run
at max effort with Claude Opus 5 at medium effort. It covers the same
Task 1 Basic run and also provides the Opus mean across its 12 Basic
generation runs, using time, output and thinking tokens, processed
tokens and turns.

<div id="tbl-run-sonnet">

Table 4: Claude Sonnet 5 at max effort (recovered pilot run) against
Claude Opus 5 at medium · Task 1 Basic, generation; Opus mean over its
12 Basic runs

<div class="cell-output cell-output-display cell-output-markdown">

| measure | Sonnet 5 max, pilot | Opus 5 medium, same task | Sonnet / Opus | Opus 5 medium, mean of 12 Basic runs |
|:---|---:|---:|---:|---:|
| minutes | 30.24 | 4.38 | 6.91 | 2.81 |
| output tokens | 166076.0 | 23639.0 | 7.03 | 13680.0 |
| thinking tokens | 139895.0 | 7475.0 | 18.72 | 3234.25 |
| thinking share of output % | 84.24 | 31.62 | 2.66 | 23.64 |
| tokens processed (M) | 1.24 | 0.24 | 5.12 | 0.16 |
| turns | 21.0 | 12.0 | 1.75 | 9.08 |

</div>

</div>

In <a href="#tbl-run-sonnet" class="quarto-xref">Table 4</a>, the Sonnet
5 max pilot used 30.24 minutes, 166076.0 output tokens, 139895.0
thinking tokens, 1.24 million processed tokens and 21.0 turns. Relative
to Opus 5 medium on the same task, the table reports ratios of 6.91 for
minutes, 7.03 for output tokens, 18.72 for thinking tokens, 5.12 for
processed tokens and 1.75 for turns.

## Qwen review effort

This section separates Qwen generation and self-review time by condition
and effort setting. It also reports actual medium-effort review hours
for the security-informed panel and the corresponding estimated hours at
xhigh effort.

<div id="fig-run-qwen-effort">

![](final_report_run_cost_files/figure-commonmark/fig-run-qwen-effort-output-1.png)

Figure 8: Qwen mean minutes to generate a program and to self-review it,
with effort settings · All conditions, Qwen generation and self-review

</div>

<a href="#fig-run-qwen-effort" class="quarto-xref">Figure 8</a> shows
self-review taking longer than generation in the Basic and
Security-aware conditions, where both stages used xhigh effort. In the
security-informed condition, xhigh generation takes much longer than
medium-effort self-review.

<div id="tbl-run-qwen-effort">

Table 5: Qwen generation and self-review time per program, with effort
settings · All conditions, Qwen generation and self-review

<div class="cell-output cell-output-display cell-output-markdown">

| condition | programs | generation effort | review effort | generation minutes | self-review minutes | review / generation |
|:---|---:|:---|:---|---:|---:|---:|
| Basic | 12 | xhigh | xhigh | 36.11 | 51.75 | 1.43 |
| Security-aware | 12 | xhigh | xhigh | 39.56 | 48.76 | 1.23 |
| Security-informed | 6 | xhigh | medium | 358.46 | 46.38 | 0.13 |

</div>

</div>

<a href="#tbl-run-qwen-effort" class="quarto-xref">Table 5</a> reports
generation and self-review means of 36.11 and 51.75 minutes for Basic,
39.56 and 48.76 minutes for Security-aware, and 358.46 and 46.38 minutes
for Security-informed. The corresponding review-to-generation ratios are
1.43, 1.23 and 0.13.

<div id="tbl-run-qwen-estimate">

Table 6: Qwen panel review hours at medium, and estimated at xhigh ·
Security-informed, Qwen as reviewer

<div class="cell-output cell-output-display cell-output-markdown">

| Qwen panel reviews | actual hours at medium | estimated hours at xhigh |
|:---|---:|---:|
| 6 self-reviews | 4.6 | 47.6 |
| 24 reviews (all four generators) | 14.4 | 190.5 |

</div>

</div>

For the 6 Qwen self-reviews,
<a href="#tbl-run-qwen-estimate" class="quarto-xref">Table 6</a> reports
4.6 actual hours at medium and 47.6 estimated hours at xhigh. Across all
24 panel reviews, the corresponding totals are 14.4 actual hours and
190.5 estimated hours.

<div id="fig-run-qwen">

![](final_report_run_cost_files/figure-commonmark/fig-run-qwen-output-1.png)

Figure 9: Qwen panel review hours: actual at medium and estimated at
xhigh · Security-informed, Qwen as reviewer

</div>

<a href="#fig-run-qwen" class="quarto-xref">Figure 9</a> shows the
estimated xhigh review time standing well above the actual medium-effort
time for both the self-review subset and the full four-generator panel.
The separation is larger for the full panel.

## Reading these numbers

Time, token and turn values are the values reported by each assistant’s
CLI under its configured model, effort setting, scaffolding and
hardware. Generation costs belong to the generator and review costs to
the reviewer, while the token-processed measure follows the
assistant-specific accounting described above. Where a value is missing,
including all Codex run times, it was not reported.
