# Workflow data-flow contract — bwqKVV0abQefK272 (n8n-cyber "My workflow")

Empirical per-node I/O contract, extracted from execution #52 (last successful run,
2026-10-04) on n8n-cyber. This is the cross-reference table for safe workflow edits:
the workflow JSON in this folder stores *expressions*, but NOT the per-node *output
contracts* recorded here — which are what determine whether an upstream change breaks
a downstream reader ("some nodes don't passthrough").

Regenerate by fetching a recent successful execution:
`GET :5688/api/v1/executions/<id>?includeData=true` → `data.resultData.runData`.

## Critical mechanics (verified, not assumed)

1. **Downstream nodes read the JOB from `$('Loop Models')`, not from their
   predecessor.** The item-pairing chain guarantees `$('Loop Models').item` resolves
   back to the loop item for the row being processed. So the loop item (job) must
   carry every field these references name.
2. **Dead-end extractors destroy fields:** `Read Cyber Hash` → `Extract Cyber Hash`
   output ONLY `existing_benchmark_cyber_hash` (file metadata/`existing_*` key) —
   `cli_settings`/`benchmark_cyber_hash` are GONE on that branch.
3. **`Merge` (combineAll) re-attaches the job** to the `return_txt`/`error` branch
   via item-pairing; the branch surviving the dead end contributes its small key set,
   the job branch contributes the full job. Failed `Review Code` runs union an
   `error` key into the merged item (survives into Parse; harmless today).
4. **Error-output lifecycle:** `Read Cyber Hash`, `Read Cyber CLI Return`,
   `Check Security Review` = `onError: continueErrorOutput` (missing file → out1,
   which carries the *input* item, i.e. full job fields). `Review Code` =
   `continueRegularOutput` (failure → normal out0 with `{error}` only — NOT the job;
   rescued by Merge's pairing). `If Cyber Hash Matches` out0(match)/out1(mismatch)
   pass through whatever arrived (branch-2 items = job; branch-1 items = extract
   output only, which is why the Review Code path always enters via out1 with the
   item paired to Loop Models).
5. **`Convert Cyber Result to File` empties `json`** → `{binary.result_md_data}`;
   everything after it reads via `$('Parse Cyber CLI Output')` refs + the binary.
6. **Legacy merge conflict:** both Extract nodes wrote `destinationKey: prompts_json`
   and Merge combineAll deep-unioned two `cli_settings` lists **by list index**
   (order-dependent coupling between prompts_cyber.json and prompts_2.json). Fixed in
   the all-vs-all redesign by distinct keys `main_json` / `cyber_json` + explicit
   join-by-name in Hash Prompts.

## Node contracts (pre-redesign baseline, execution #52 counts)

| # | Node | Reads (expr → upstream) | Output contract | Counts (#52) |
|---|------|-------------------------|-----------------|--------------|
| 1 | manualTrigger | — | `{}` | 1 |
| 2 | Read prompts.json1 → `/data/prompts/prompts_cyber.json` | literal | file meta json + `binary.data` | 1 |
| 3 | Extract Cyber Prompts JSON | binary | `{prompts_json}` (cyber cfg) — **binary consumed** | 1 |
| 4 | Read prompts.json → `/data/prompts/prompts_2.json` | literal | file meta + `binary.data` | 1 |
| 5 | Extract Prompts JSON | binary | `{prompts_json}` (main cfg) | 1 |
| 6 | Attach Cyber Prompts (merge combineAll) | — | 1 item, union of both `prompts_json` (see note 6) | 1 |
| 7 | Hash Prompts (python) | `_items[0].json.prompts_json` | 5 items `{name, task[]}` (nested) | 5 |
| 8 | Split Out Tasks (`task`) | — | `{task_number, prompts[]}` — `name` **dropped** | 25 |
| 9 | Split Out Prompts (`prompts`) | — | job: `{style, prompt, hash, cyber_prompt, cyber_hash, benchmark_cyber_hash, cli_settings[]}` | 63 |
| 10 | If string not empty (`$json.prompt`) | inline | job passthrough out0 / empties out1 | 42 / 21 |
| 11 | Split models (`cli_settings`, includeAllOther) | — | job with `cli_settings` **flattened dict** per model | 168 |
| 12 | Loop Models (splitInBatches) | — | out1: job (per item); out0 when done | 1/iter |
| 13 | Read Cyber Hash | `cli_settings.cyber_container_path` (inline=$json from loop) + `benchmark_cyber_hash.txt` | out0: file meta + binary (fields DESTROYED, note 2); out1 on missing file: **job** | 144 / 24 |
| 14 | Extract Cyber Hash | binary → `existing_benchmark_cyber_hash` | `{existing_benchmark_cyber_hash}` only | 144 |
| 15 | If Cyber Hash Matches | `$('Loop Models')…benchmark_cyber_hash` == `$json.existing_benchmark_cyber_hash` | pass-through in; out0=skip→loop, out1=review→Review Code+Merge | 144 / 0* |
| 16 | Review Code (exec) | `$('Loop Models')`: cyber_container_path ×4, container_path, skill_path, cyber_prompt, headless_execute, prompt_prefix, prompt_suffix, benchmark_cyber_hash ×2 | `{exitCode,stderr,stdout}`; onError→`{error}` | 24 (1 err) |
| 17 | Read Cyber CLI Return | `$('Loop Models')…cyber_container_path` + `cyber_return.txt` | out0 file meta+binary; out1: job | |
| 18 | Extract Cyber CLI Return | binary → `return_txt` | `{return_txt}` only | |
| 19 | Merge (combineAll) | — | job ∪ branch (∪ `error` if failed run) | 24 |
| 20 | Parse Cyber CLI Output (python) | `_items[0].json` → `return_txt`, `cli_settings`, + passthrough | merged job ∪ `{parse_success, parse_error, parse_mode, result_md, response, status, conversation_id, input/output/thinking/total/cached_read/cache_creation_tokens, num_turns, duration_*}` | |
| 21 | Convert Cyber Result to File (`result_md`→`result_md_data`) | `$json.result_md` | json EMPTY, `binary.result_md_data` | |
| 22 | Write Cyber Result.md | `$('Parse Cyber CLI Output')…cli_settings.cyber_container_path` + `cyber_result.md`; `dataPropertyName=result_md_data` | `{fileName}` + binary kept | |
| 23 | If Cyber Generation Succeeded | `$('Parse Cyber CLI Output')…parse_success && output_tokens>0` | pass `{fileName}`+binary; out1→loop | |
| 24 | Check Security Review | `$('Parse Cyber CLI Output')…cyber_container_path` + `security_review.md` | out0: file meta (success→Write Cyber Hash); out1: input item (→loop, gates hash write) | 17 / 1 |
| 25 | Write Cyber Hash | `$('Parse Cyber CLI Output')`: benchmark_cyber_hash, cyber_container_path | `{exitCode,stderr,stdout}` → loop | 17 |

\* #52 ran fully-cached cells + fresh reviews; out1 count shown for Review Code entries.

## Job item key contract (what `$('Loop Models').item.json` MUST provide)

```
hash, cyber_prompt, cyber_hash, benchmark_cyber_hash, style, prompt,
cli_settings: { name, set_id, skill_path, container_path, cyber_container_path,
                headless_execute, prompt_prefix, prompt_suffix, continue_conversation,
                resume_conversation, json_output_* (10 keys) }
```

All-RvR redesign adds ONLY: `reviewer_id, target_id, folder, task_number` (debug), and
redefines `container_path` = TARGET's code path and `cyber_container_path` =
`<reviewer parent>/<target_id>/…` — same key names ⇒ the 19 downstream references
(#13, #15–#18, #20–#25 expressions above) need zero edits.
