# Workflow data-flow contract — bwqKVV0abQefK272 (n8n-cyber "My workflow")

Empirical per-node I/O contract, extracted from execution #52 (last successful run,
2026-10-04) on n8n-cyber. This is the cross-reference table for safe workflow edits:
the workflow JSON in this folder stores *expressions*, but NOT the per-node *output
contracts* recorded here — which are what determine whether an upstream change breaks
a downstream reader ("some nodes don't passthrough").

Regenerate by fetching a recent successful execution:
`GET :5688/api/v1/executions/<id>?includeData=true` → `data.resultData.runData`.

## Critical mechanics (verified, not assumed)

1. **Downstream nodes read the JOB from `$('Loop Jobs')`, not from their
   predecessor.** The item-pairing chain guarantees `$('Loop Jobs').item` resolves
   back to the loop item for the row being processed. So the loop item (job) must
   carry every field these references name.
2. **Dead-end extractors destroy fields:** `Read benchmark_cyber_hash.txt` → `Parse benchmark_cyber_hash.txt`
   output ONLY `existing_benchmark_cyber_hash` (file metadata/`existing_*` key) —
   `cli_settings`/`benchmark_cyber_hash` are GONE on that branch.
3. **`Attach Job Context` (Edit Fields, raw JSON) re-attaches the job** to
   `return_txt`: `Object.assign({}, $('Loop Jobs').item.json, {return_txt})`. It
   replaced the old `Merge` (combineAll). It has a single input (`Extract Cyber CLI
   Return`), so it only runs when the return file was actually read. A failed
   `Run CLI: Review Code` (e.g. exit 78 when the benchmark output has no `prompt_hash.txt`)
   leaves no `cyber_return.txt`, `Read cyber_return.txt` takes its error output
   back to `Loop Jobs`, and Parse/Write are never reached (the old Merge released
   with only its job input and wrote into a never-created folder -> ENOENT).
4. **Error-output lifecycle:** `Read benchmark_cyber_hash.txt`, `Read cyber_return.txt`,
   `Check security_review.md Exists` = `onError: continueErrorOutput` (missing file → out1,
   which carries the *input* item, i.e. full job fields). `Run CLI: Review Code` =
   `continueRegularOutput` (failure → normal out0 with `{error}` only — NOT the job;
   rescued by Merge's pairing). `If Already Reviewed` out0(match)/out1(mismatch)
   pass through whatever arrived (branch-2 items = job; branch-1 items = extract
   output only, which is why the Run CLI: Review Code path always enters via out1 with the
   item paired to Loop Jobs).
5. **`Convert cyber_result.md to File` empties `json`** → `{binary.result_md_data}`;
   everything after it reads via `$('Build cyber_result.md')` refs + the binary.
6. **Legacy merge conflict:** both Extract nodes wrote `destinationKey: prompts_json`
   and Merge combineAll deep-unioned two `cli_settings` lists **by list index**
   (order-dependent coupling between cyber.json and benchmark.json (then prompts_cyber.json / prompts_2.json)). Fixed in
   the all-vs-all redesign by distinct keys `main_json` / `cyber_json` + explicit
   join-by-name in Build Jobs.

## Node contracts (pre-redesign baseline, execution #52 counts)

| # | Node | Reads (expr → upstream) | Output contract | Counts (#52) |
|---|------|-------------------------|-----------------|--------------|
| 1 | manualTrigger | — | `{}` | 1 |
| 2 | Read cyber.json → `/data/config/cyber.json` | literal | file meta json + `binary.data` | 1 |
| 3 | Parse cyber.json | binary | `{prompts_json}` (cyber cfg) — **binary consumed** | 1 |
| 4 | Read benchmark.json → `/data/config/benchmark.json` | literal | file meta + `binary.data` | 1 |
| 5 | Parse benchmark.json | binary | `{prompts_json}` (main cfg) | 1 |
| 6 | Combine Configs (merge combineAll) | — | 1 item, union of both `prompts_json` (see note 6) | 1 |
| 7 | Build Jobs (python) | `_items[0].json.prompts_json` | 5 items `{name, task[]}` (nested) | 5 |
| 8 | Split Out Tasks (`task`) | — | `{task_number, prompts[]}` — `name` **dropped** | 25 |
| 9 | Split Out Prompts (`prompts`) | — | job: `{style, prompt, hash, cyber_prompt, cyber_hash, benchmark_cyber_hash, cli_settings[]}` | 63 |
| 10 | If string not empty (`$json.prompt`) | inline | job passthrough out0 / empties out1 | 42 / 21 |
| 11 | Split models (`cli_settings`, includeAllOther) | — | job with `cli_settings` **flattened dict** per model | 168 |
| 12 | Loop Jobs (splitInBatches) | — | out1: job (per item); out0 when done | 1/iter |
| 13 | Read benchmark_cyber_hash.txt | `cli_settings.cyber_container_path` (inline=$json from loop) + `benchmark_cyber_hash.txt` | out0: file meta + binary (fields DESTROYED, note 2); out1 on missing file: **job** | 144 / 24 |
| 14 | Parse benchmark_cyber_hash.txt | binary → `existing_benchmark_cyber_hash` | `{existing_benchmark_cyber_hash}` only | 144 |
| 15 | If Already Reviewed | `$('Loop Jobs')…benchmark_cyber_hash` == `$json.existing_benchmark_cyber_hash` | pass-through in; out0=skip→loop, out1=review→Run CLI: Review Code | 144 / 0* |
| 16 | Run CLI: Review Code (exec) | `$('Loop Jobs')`: cyber_container_path ×4, container_path, skill_path, cyber_prompt, headless_execute, prompt_prefix, prompt_suffix, benchmark_cyber_hash ×2 | `{exitCode,stderr,stdout}`; onError→`{error}` | 24 (1 err) |
| 17 | Read cyber_return.txt | `$('Loop Jobs')…cyber_container_path` + `cyber_return.txt` | out0 file meta+binary; out1: job | |
| 18 | Parse cyber_return.txt | binary → `return_txt` | `{return_txt}` only | |
| 19 | Attach Job Context (Edit Fields) | `$('Loop Jobs').item.json` + `$json.return_txt` | job ∪ `return_txt` | 24 |
| 20 | Build cyber_result.md (python) | `_items[0].json` → `return_txt`, `cli_settings`, + passthrough | merged job ∪ `{parse_success, parse_error, parse_mode, result_md, response, status, conversation_id, input/output/thinking/total/cached_read/cache_creation_tokens, num_turns, duration_*}` | |
| 21 | Convert cyber_result.md to File (`result_md`→`result_md_data`) | `$json.result_md` | json EMPTY, `binary.result_md_data` | |
| 22 | Write cyber_result.md | `$('Build cyber_result.md')…cli_settings.cyber_container_path` + `cyber_result.md`; `dataPropertyName=result_md_data` | `{fileName}` + binary kept | |
| 23 | If Review Succeeded | `$('Build cyber_result.md')…parse_success && output_tokens>0` | pass `{fileName}`+binary; out1→loop | |
| 24 | Check security_review.md Exists | `$('Build cyber_result.md')…cyber_container_path` + `security_review.md` | out0: file meta (success→Mark Done: Write benchmark_cyber_hash.txt); out1: input item (→loop, gates hash write) | 17 / 1 |
| 25 | Mark Done: Write benchmark_cyber_hash.txt | `$('Build cyber_result.md')`: benchmark_cyber_hash, cyber_container_path | `{exitCode,stderr,stdout}` → loop | 17 |

\* #52 ran fully-cached cells + fresh reviews; out1 count shown for Run CLI: Review Code entries.

## Job item key contract (what `$('Loop Jobs').item.json` MUST provide)

```
hash, cyber_prompt, cyber_hash, benchmark_cyber_hash, style, prompt,
cli_settings: { name, set_id, skill_path, container_path, cyber_container_path,
                headless_execute, prompt_prefix, prompt_suffix, continue_conversation,
                resume_conversation, json_output_* (10 keys) }
```

All-RvR redesign adds ONLY: `reviewer_id, target_id, prompt_set, task_number` (debug), and
redefines `container_path` = TARGET's code path and `cyber_container_path` =
`<reviewer parent>/<target_id>/…` — same key names ⇒ the 19 downstream references
(#13, #15–#18, #20–#25 expressions above) need zero edits.

## Run knobs ? run_config in config/cyber.json (v1174, 2026-10-05)

| Key | Selects | Tokens |
|---|---|---|
| `reviewers` | which models RUN the review | empty or `["all"]` = all; ids: agy/claude/codex/qwen |
| `target_prompt_sets` | which prompt set is read (ben/pilot/post_research/ruth/sallie) | empty or `["all"]` = all |
| `target_prompt_tasks_num` | task numbers within a prompt set | empty or `["all"]` = all; int or string |
| `target_prompt_style` | prompt style | empty or `["all"]` = all |
| `target_models` | WHOSE code gets reviewed | empty or `["all"]` = all; **`self` = the reviewer's own code** (per-job, mixable with ids) |

Diagonal-only run (each model reviews only its own code): `reviewers:["all"], target_models:["self"]`.
Grid = reviewers x folders x tasks x styles x models; hash markers still decide actual work.

## Report nodes (added 2026-10-18)

`Loop Jobs` out0 (done) → **Build Findings** → **Render Report**, both Execute Command with
`executeOnce: true` (out0 emits every processed item; without it the report would build once per item).

| Node | Command | Notes |
|---|---|---|
| Build Findings | `cd /data/report && python3 scripts/build_findings.py` | stdlib-only; a non-zero exit stops the chain, so render never reads a stale CSV |
| Render Report | `cd /data/report && quarto render report.qmd` | Quarto + Python deps baked into the n8n-cyber image (`QUARTO_PYTHON=/opt/report-venv/bin/python`) |

## Node names (renamed 2026-10-18)

Executions before this date show the old names. Benchmark and cyber use the same name where a node does the same job.

| Old name | New name | Workflow |
|---|---|---|
| Extract Prompts JSON | Parse benchmark.json | both |
| Hash Prompts | Build Jobs | both |
| Loop Models | Loop Jobs | both |
| When clicking ‘Execute workflow’ | Start | both |
| Attach Cyber Prompts | Combine Configs | cyber |
| Check Security Review | Check security_review.md Exists | cyber |
| Convert Cyber Result to File | Convert cyber_result.md to File | cyber |
| Convert Result to File | Convert result.md to File | benchmark |
| Extract CLI Return | Parse return.txt | benchmark |
| Extract Cyber CLI Return | Parse cyber_return.txt | cyber |
| Extract Cyber Hash | Parse benchmark_cyber_hash.txt | cyber |
| Extract Cyber Prompts JSON | Parse cyber.json | cyber |
| Extract Prompt Hash | Parse prompt_hash.txt | benchmark |
| Generate Code | Run CLI: Generate Code | benchmark |
| If Cyber Generation Succeeded | If Review Succeeded | cyber |
| If Cyber Hash Matches | If Already Reviewed | cyber |
| If Prompt Hash Matches | If Already Generated | benchmark |
| If string not empty | Skip Empty Prompts | benchmark |
| Parse CLI Output | Build result.md | benchmark |
| Parse Cyber CLI Output | Build cyber_result.md | cyber |
| Read CLI Return | Read return.txt | benchmark |
| Read Cyber CLI Return | Read cyber_return.txt | cyber |
| Read Cyber Hash | Read benchmark_cyber_hash.txt | cyber |
| Read Prompt Hash | Read prompt_hash.txt | benchmark |
| Review Code | Run CLI: Review Code | cyber |
| Split Out Prompts | Split Prompt Styles | benchmark |
| Split Out Tasks | Split Tasks | benchmark |
| Split models | Split Jobs per CLI | benchmark |
| Write Cyber Hash | Mark Done: Write benchmark_cyber_hash.txt | cyber |
| Write Cyber Result.md | Write cyber_result.md | cyber |
| Write Prompt Hash | Mark Done: Write prompt_hash.txt | benchmark |
| Write Result.md | Write result.md | benchmark |
