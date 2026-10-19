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

- Across 30 generation runs and 48 review runs per assistant,
  Antigravity had 1 generation ERROR and 7 empty generation replies;
  every Claude, Codex and Qwen run was successful and non-empty.
- Qwen had the largest reported totals: generation used 50.98 hours and
  709.11 million tokens processed, while review used 34.53 hours and
  402.96 million tokens processed.
- Antigravity generation used 2.47 hours and 68.09 million tokens
  processed, and Claude generation used 2.84 hours and 15.81 million;
  Codex processed 8.28 million generation tokens but did not report run
  time.
- Security-informed generation was the highest-time and highest-token
  condition for every assistant shown, with the largest visual increase
  for Qwen.
- In the recovered Claude pilot, Sonnet 5 at max effort took 30.24
  minutes and 21.0 turns, compared with 4.38 minutes and 12.0 turns for
  Opus 5 at medium on the same task.
- For Qwen’s security-informed panel, 6 self-reviews took 4.6 actual
  hours at medium and were estimated at 47.6 hours at xhigh; all 24
  reviews took 14.4 actual hours and were estimated at 190.5 hours.

> **Reader’s rule:** time and tokens describe the coding assistant as
> configured (model, effort setting, scaffolding and hardware), not the
> model alone. Codex records no run time, so it is absent from every
> time figure.

## What was measured

### Source of the numbers

This section distinguishes generation runs, whose cost is assigned to
the generator, from review runs, whose cost is assigned to the reviewer.
The tables and figures summarize completion, elapsed time, token use
and, where shown, turns from the assistants’ CLI records.

- A **generation run** is one assistant writing one program. Its cost
  belongs to the generator.
- A **review run** is one reviewer reading one program. Its cost belongs
  to the reviewer.

### Two token measures, one rule for every assistant

The table aligns each assistant’s reported input, cache and output
fields with a common “tokens processed” measure. It also shows whether
cached tokens are separate from input or already included in it.

| Assistant | What “input” counts | Cached tokens | Tool’s own total | Tokens processed, as used here |
|:---|:---|:---|:---|:---|
| Antigravity | input not read from cache | reported separately | input + output | input + cached read + output |
| Claude Code | input not read from or written to cache | reported separately, plus cache creation | input + output | input + cache creation + cached read + output |
| Codex | all input, cached included | already inside input | input + output | input + output |
| Qwen Code | the whole prompt, re-sent on every request | not reported | input + output | input + output |

How each assistant reports tokens, and the measure this report derives
from them

### Gaps in the data

Codex did not report run time, so its time values and time-figure
entries are absent. Antigravity had 1 generation run with ERROR status
and 7 generation runs with empty replies, including 6 marked SUCCESS;
the corresponding rows are listed below rather than estimated.

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

<a href="#tbl-run-completion" class="quarto-xref">Table 1</a> shows 30
generation runs and 48 review runs for each assistant. Antigravity
recorded 29 generation successes, 1 generation error and 7 empty
generation replies, while all other assistant-stage combinations show
only successes and no empty replies.

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

All 7 runs in
<a href="#tbl-run-problems" class="quarto-xref">Table 2</a> are
Antigravity generation runs. 1 ended in ERROR and the other 6 were
marked SUCCESS, but every listed run returned an empty reply and had a
reported time.

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

<a href="#tbl-run-headline" class="quarto-xref">Table 3</a> shows Qwen
with the largest reported totals for both stages: 50.98 generation hours
and 709.11 million processed tokens, then 34.53 review hours and 402.96
million processed tokens. Codex reported 8.28 million processed tokens
for generation and 65.42 million for review, but its total hours and
mean minutes were not reported.

## Generation

<div id="fig-run-gen-time">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-time-output-1.png)

Figure 1: Mean minutes per program by generator and condition · All
generation runs; Codex records no time

</div>

<a href="#fig-run-gen-time" class="quarto-xref">Figure 1</a> shows Qwen
taking much longer per program than Antigravity or Claude in every
plotted condition. Mean time rises from Basic through Security-aware to
Security-informed for each timed generator, with the Security-informed
increase especially pronounced for Qwen; Codex is absent because it did
not report time.

<div id="fig-run-gen-tokens">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-tokens-output-1.png)

Figure 2: Mean tokens processed per program by generator and condition ·
All generation runs

</div>

<a href="#fig-run-gen-tokens" class="quarto-xref">Figure 2</a> shows
Qwen processing the most tokens per program in every condition, followed
by Antigravity, Claude and Codex. For every generator, Security-informed
is the highest-token condition and Basic is the lowest.

<div id="fig-run-gen-task-time">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-task-time-output-1.png)

Figure 3: Mean minutes per program by task and generator · All
generation runs; Codex records no time

</div>

Across the task panels in
<a href="#fig-run-gen-task-time" class="quarto-xref">Figure 3</a>, Qwen
takes longer than Antigravity and Claude for every task and condition.
The largest times cluster in Qwen’s Security-informed panel,
particularly for Tasks 4 and 5, while Antigravity and Claude remain much
lower across tasks; Codex is absent because it did not report time.

<div id="fig-run-gen-task-tokens">

![](final_report_run_cost_files/figure-commonmark/fig-run-gen-task-tokens-output-1.png)

Figure 4: Mean tokens processed per program by task and generator · All
generation runs

</div>

<a href="#fig-run-gen-task-tokens" class="quarto-xref">Figure 4</a>
shows Qwen as the highest-token generator for every task and condition.
Its Security-informed task values dominate the grid, while Antigravity,
Claude and Codex also generally rise in that condition but remain well
below Qwen.

## Review

<div id="fig-run-review-time">

![](final_report_run_cost_files/figure-commonmark/fig-run-review-time-output-1.png)

Figure 5: Mean minutes per self-review by reviewer and condition · All
conditions, self-review; Codex records no time

</div>

<a href="#fig-run-review-time" class="quarto-xref">Figure 5</a> shows
Qwen self-reviews taking substantially longer than Antigravity or Claude
self-reviews in all three conditions. Antigravity and Claude are highest
in Security-informed, whereas Qwen decreases from Basic to
Security-aware to Security-informed; Codex is absent because it did not
report time.

<div id="fig-run-review-tokens">

![](final_report_run_cost_files/figure-commonmark/fig-run-review-tokens-output-1.png)

Figure 6: Mean tokens processed per self-review by reviewer and
condition · All conditions, self-review

</div>

<a href="#fig-run-review-tokens" class="quarto-xref">Figure 6</a> shows
Qwen processing the most tokens per self-review in each condition.
Security-informed is the highest condition for Antigravity, Claude and
Codex, while Qwen is highest in Security-aware and lowest in
Security-informed.

<div id="fig-run-review-matrix">

![](final_report_run_cost_files/figure-commonmark/fig-run-review-matrix-output-1.png)

Figure 7: Mean tokens per review, reviewer × generator ·
Security-informed, all four reviewers

</div>

In <a href="#fig-run-review-matrix" class="quarto-xref">Figure 7</a>,
Qwen is the highest-token processor for programs from every generator,
and Qwen-generated programs require the most processed tokens within
every reviewer row. Generated-token levels vary separately: Qwen’s
reviews have the broadest spread across generators, while Antigravity’s
are comparatively even.

## Claude at maximum effort in the pilot

This section isolates the recovered Claude Sonnet 5 pilot generation run
at max effort. The table compares it with Claude Opus 5 at medium on the
same task and with Opus’s mean across 12 Basic runs, covering minutes,
output and thinking tokens, processed tokens and turns.

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
5 max pilot took 30.24 minutes and processed 1.24 million tokens, versus
4.38 minutes and 0.24 million for Opus 5 medium on the same task, ratios
of 6.91 and 5.12. Sonnet produced 166076.0 output tokens, including
139895.0 thinking tokens, and used 21.0 turns; the same-task Opus run
produced 23639.0 output tokens, including 7475.0 thinking tokens, and
used 12.0 turns.

## Qwen review effort

This section compares Qwen generation and self-review time across
conditions and their displayed effort settings. It also reports the
actual Security-informed review hours at medium and the corresponding
estimates at xhigh for 6 self-reviews and the full 24-review panel.

<div id="fig-run-qwen-effort">

![](final_report_run_cost_files/figure-commonmark/fig-run-qwen-effort-output-1.png)

Figure 8: Qwen mean minutes to generate a program and to self-review it,
with effort settings · All conditions, Qwen generation and self-review

</div>

<a href="#fig-run-qwen-effort" class="quarto-xref">Figure 8</a> shows
self-review taking longer than generation in Basic and Security-aware
when both use xhigh effort. In Security-informed, generation at xhigh is
far longer than self-review at medium, reversing that relationship.

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

In <a href="#tbl-run-qwen-effort" class="quarto-xref">Table 5</a>,
Qwen’s Basic generation and self-review means are 36.11 and 51.75
minutes, and its Security-aware means are 39.56 and 48.76 minutes, with
review/generation ratios of 1.43 and 1.23. For Security-informed,
generation at xhigh averages 358.46 minutes and self-review at medium
averages 46.38 minutes, for a ratio of 0.13.

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

<a href="#tbl-run-qwen-estimate" class="quarto-xref">Table 6</a> reports
4.6 actual hours at medium for 6 Qwen self-reviews and 14.4 hours for
all 24 reviews. The corresponding xhigh estimates are 47.6 hours and
190.5 hours.

<div id="fig-run-qwen">

![](final_report_run_cost_files/figure-commonmark/fig-run-qwen-output-1.png)

Figure 9: Qwen panel review hours: actual at medium and estimated at
xhigh · Security-informed, Qwen as reviewer

</div>

<a href="#fig-run-qwen" class="quarto-xref">Figure 9</a> shows the
estimated xhigh review time far above the actual medium time for both
the 6 self-reviews and the full 24-review panel. The gap is visibly
larger for the full panel.

## Reading these numbers

The headline table aggregates all generation runs by generator and all
review runs by reviewer, while the condition and task figures show mean
cost per run. Time is omitted wherever the CLI did not report it, and
the token measures follow the assistant-specific accounting summarized
above. The recovered Claude pilot and Qwen xhigh projections are
presented separately from the main run totals.
