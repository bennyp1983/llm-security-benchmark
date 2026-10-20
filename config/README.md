# Configuration Guide
The benchmark is built around four coding CLIs, which both write the code and review it:

- Google Antigravity (`agy`) 
- Claude Code (`claude`) 
- ChatGPT Codex (`codex`) 
- Qwen Code (`qwen`) 

## Config files

> **Before editing the files below,** read the [main README](../README.md). It explains the
> benchmark and how finished runs are skipped.

Everything the pipeline does is set in two JSON files:

- **[benchmark.json](benchmark.json)**: the coding CLIs, the prompts, and how the reports group them.
- **[cyber.json](cyber.json)**: which reviews run, the review prompt, and the AI that writes the report text.

### Dependencies

Everything that reads these two files:

| Dependent | Location | Reads |
|---|---|---|
| benchmark workflow | [`n8n-workflows/benchmark/bwqKVV0abQefK272.json`](../n8n-workflows/benchmark/bwqKVV0abQefK272.json) | benchmark.json |
| cyber workflow | [`n8n-workflows/cyber/bwqKVV0abQefK272.json`](../n8n-workflows/cyber/bwqKVV0abQefK272.json) | benchmark.json, cyber.json |
| setup script | [`setup.sh`](../setup.sh) | benchmark.json |
| findings builder | [`report/scripts/build_findings.py`](../report/scripts/build_findings.py) | benchmark.json |
| run-cost builder | [`report/scripts/build_run_cost.py`](../report/scripts/build_run_cost.py) | benchmark.json |
| report analysis | [`report/scripts/analysis_findings.py`](../report/scripts/analysis_findings.py) | benchmark.json |


### Why JSON files?

- **One source of truth.** Every part of the pipeline reads the same two files, so nothing
  can disagree about which CLIs, prompts or report groups exist.
- **Versioned with the results.** The configuration is committed next to the results it
  produced, so the prompts, models and settings behind any result can be read from the
  repository, and a git diff shows exactly what changed between runs.
- **Works headless.** Editing a text file works over SSH on a machine with no browser,
  which suits a benchmark run on a server or VM.
- **Ready for an interface.** A web interface would only need to read and write these two
  files; the workflows would not change. It is left as future work.

The cost of this is that the files are edited by hand. A JSON syntax error stops a
workflow, and only `report_group` is checked against `report_order`.

<br>
<br>
<br>

## [benchmark.json](benchmark.json) explained

The file has three parts, in this order:

```json
{
    "cli_settings": [...],
    "report_order": [...],
    "prompt_sets": [...]
}
```

### cli_settings

One entry per coding CLI, each with this shape:

```json
"cli_settings": [
    {
        "name": ...,
        "container_path": ...,
        "login": ...,
        "input": {
            "headless_execute": ...,
            "set": [
                {
                    "id": ...,
                    "prompt_prefix": ...,
                    "prompt_suffix": ...
                }
            ],
            "continue_conversation": ...,
            "resume_conversation": ...
        },
        "json_output": {
            ...
        }
    }
]
```

| Key | What it is |
|---|---|
| `name` | The CLI's name: `Google Antigravity`, `Claude Code`, `ChatGPT Codex`, `Qwen`. <br><br> **cyber.json** joins its own settings to these by this name. |
| `container_path` | Where the CLI's results go inside the container, e.g. `/data/results/claude`. |
| `login` | The command `./setup.sh` runs to sign the CLI in, e.g. `claude` or `codex login --device-auth`. |
| `headless_execute` | The command that runs the CLI without its interactive screen, e.g. `agy -p` or `codex exec`. |
| `set` | Two sets of options, `a` and `b`, whose `prompt_prefix` and `prompt_suffix` hold the model, effort and output flags. The workflows use set `a`: `gemini-3.7-flash-high`, `claude-opus-5`, `gpt-5.6-sol` and `vllm-general`. Set `b` holds alternative models and efforts that are not used. |
| `continue_conversation`, `resume_conversation` | The CLI's flags for continuing a conversation, e.g. `--continue` and `--resume`, kept for multi-turn prompts. No node uses them yet. |
| `json_output` | Where each value is in the CLI's output: the reply, status, token counts, duration and turns, e.g. `"input_tokens": "usage.input_tokens"`. |

> Names in bold italics and quotes, like ***'Build Jobs'***, are nodes in the n8n workflows.

For every prompt, the benchmark workflow's ***'Run CLI: Generate Code'*** node puts these pieces
together, with the prompt between the prefix and suffix:

```
headless_execute  prompt_prefix  "<prompt>"  prompt_suffix
```

Each CLI has its own flags for the model, thinking level and folder permissions, and some
must go before the prompt and some after, which is why both a prefix and a suffix exist.

Each CLI also prints its output in its own format. `json_output` says where each value is in
that output, so ***'Build result.md'*** can parse it.

Apart from the model and thinking level, these settings are best left as they are. Check the
CLI's own documentation before changing any of them.

### report_order

```json
"report_order": ["Basic", "Security-aware", "Security-informed"],
```

The report groups, in the order every table and figure shows them. Each prompt in
`prompt_sets` names its group in `report_group`, and results with the same group are pooled,
whatever prompt set they come from. A `report_group` that is neither in `report_order` nor
`ignore` stops the report build with an error, so a typo cannot silently drop results.

The reports are designed around these three groups. More can be listed, but figures with one
panel per group get crowded, group colours repeat after six, every pair of groups is compared,
and a few sections are written for these three groups by name.

### prompt_sets

The prompts, grouped into named sets. Each set has the benchmark's six Java tasks, each built
around one security weakness (listed in the [main README](../README.md#the-tasks-and-prompts)),
and each task has its prompts, with this shape:

```json
"prompt_sets": [
    {
        "name": ...,
        "task": [
            {
                "task_number": ...,
                "prompts": [
                    {
                        "report_group": ...,
                        "style": ...,
                        "turn": ...,
                        "prompt": ...
                    }
                ]
            }
        ]
    }
]
```

| Key | What it is |
|---|---|
| `name` | The set's name, also its results folder: `ben`, `ruth`, `sallie`, `pilot`, `post_research`. |
| `task_number` | The task, `1` to `6`, also a folder. |
| `report_group` | Which group in `report_order` the prompt's results count towards: `Basic`, `Security-aware`, `Security-informed`, or `ignore`. |
| `style` | The prompting style, also a folder: `basic`, `security`, `multi-turn`. |
| `turn` | Only on the `multi-turn` placeholders: the turn number, e.g. `1`, also a folder. |
| `prompt` | The prompt text, e.g. "Develop Java code for a web application that…". An empty prompt is skipped. |

A prompt's results go in `<container_path>/set_a/<name>/<task_number>/<style>/`, so the code
Claude wrote for ruth's task 1, basic, is in `results/claude/set_a/ruth/1/basic/`.


<br>
<br>
<br>

## [cyber.json](cyber.json) explained

The file has five parts, in this order:

```json
{
    "run_config": {...},
    "cli_settings": [...],
    "analyst": [...],
    "reviewer_cli": {...},
    "report_writer": {...}
}
```

The reviewers are the same four CLIs, run with their benchmark.json settings: the same
command, set `a` model and `json_output`. cyber.json adds only what a review needs on top.

### run_config

Which generated-code folders a cyber run reviews, and which CLIs review them, with this shape:

```json
"run_config": {
    "reviewers": [...],
    "target_prompt_sets": [...],
    "target_prompt_tasks_num": [...],
    "target_prompt_style": [...],
    "target_models": [...]
}
```

Each list picks from the configuration; an empty list or `["all"]` picks everything.

| Key | What it picks |
|---|---|
| `reviewers` | The CLIs that review, by their `id`, e.g. `["codex", "qwen"]`. |
| `target_prompt_sets` | The prompt-set folders to review, e.g. `["post_research"]`. |
| `target_prompt_tasks_num` | The task folders, e.g. `[1, 3]`. |
| `target_prompt_style` | The style folders, e.g. `["security"]`. |
| `target_models` | Whose code each reviewer reviews, by `id`, e.g. `["agy", "claude"]`. `"self"` means the reviewer's own code; listing other CLIs is a cross-review. |

`run_config` targets which benchmark results get a security review. For example:

- `"reviewers": ["qwen"]` has only Qwen review.
- `"target_prompt_sets": ["post_research"]` reviews only the Security-informed prompts.
- `"target_prompt_tasks_num": [1]` reviews only task 1.
- `"target_prompt_style": ["security"]` reviews only the security-style prompts.
- `"target_models": ["self"]` reviews each CLI's own code only (the current setting).
- `"target_models": ["all"]` reviews every CLI's code, a cross-review.
- `"target_models": ["codex"]` reviews only Codex's code.

`run_config` does not decide what the reports show. The reports always pick up every review on disk,
grouped by the `report_group` and `report_order` in benchmark.json.

### cli_settings

One entry per reviewer, each with this shape:

```json
"cli_settings": [
    {
        "id": ...,
        "name": ...,
        "cyber_container_path": ...,
        "skill_path": ...
    }
]
```

| Key | What it is |
|---|---|
| `id` | The reviewer's short name, used in `run_config` and as its folder: `agy`, `claude`, `codex`, `qwen`. |
| `name` | Must match the CLI's `name` in benchmark.json, e.g. `Claude Code`. This is how the two files are joined. |
| `cyber_container_path` | Where its reviews go inside the cyber container, e.g. `/data/results-cyber/codex`. |
| `skill_path` | Where the security-review skill is installed for this CLI in the cyber image, e.g. `/root/.claude/skills/review-code-for-security-vulnerabilities/SKILL.md`. |

A review goes in `<cyber_container_path>/<generator>/set_a/<name>/<task_number>/<style>/`, so
Codex's review of its own code for ruth's task 1, basic, is in
`results-cyber/codex/codex/set_a/ruth/1/basic/security_review.md`.

### analyst

The review prompt, the same for every review, with the same shape as a prompt set:

```json
"analyst": [
    {
        "name": ...,
        "task": [
            {
                "task_number": ...,
                "prompts": [
                    {
                        "style": ...,
                        "prompt": ...
                    }
                ]
            }
        ]
    }
]
```

| Key | What it is |
|---|---|
| `name` | `llm_analyst`. |
| `task_number`, `style` | `1` and `review`; only one prompt is used. |
| `prompt` | The review instructions, e.g. "Review all the code in the source folder named in these instructions for security vulnerabilities…". |

The prompt sets the fixed report structure every review is written to, which
`build_findings.py` reads the findings from.

### reviewer_cli

The flag that lets each reviewer read the code it reviews, with this shape:

```json
"reviewer_cli": {
    "<id>": {
        "flag": ...,
        "placement": ...
    }
}
```

| Key | What it is |
|---|---|
| `<id>` | One entry per reviewer, by `id`: `agy`, `claude`, `codex`, `qwen`. |
| `flag` | The flag that grants read access to the code's folder: `--add-dir` for all four. |
| `placement` | Whether the flag goes before the prompt (`prefix`, Codex) or after it (`suffix`, the other three). |

The cyber workflow's ***'Run CLI: Review Code'*** node builds each review command from the
reviewer's benchmark.json settings, with this flag next to the prompt:

```
headless_execute  prompt_prefix  [flag]  "<review prompt>"  [flag]  prompt_suffix
```

The review prompt is the `analyst` prompt with a short opening that names the skill and the
folder to review. The generated code is mounted read-only, so a review can never change what it
reviews.

### report_writer

The AI that writes the report text at the end of the cyber workflow, with this shape:

```json
"report_writer": {
    "command_before_prompt": ...,
    "command_after_prompt": ...,
    "prompt_findings": ...,
    "prompt_run_cost": ...
}
```

| Key | What it is |
|---|---|
| `command_before_prompt` | The command, up to where the prompt goes, e.g. `codex exec --model gpt-5.6-sol -c model_reasoning_effort=medium …`. |
| `command_after_prompt` | Anything after the prompt; empty for Codex. |
| `prompt_findings` | The instructions for writing the findings report, e.g. "You are writing the text of an automatically generated data report about security findings…". |
| `prompt_run_cost` | The instructions for writing the run-cost report. |

***'Run CLI: Write Findings Report'*** and ***'Run CLI: Write Run Cost Report'*** each run
`command_before_prompt "<prompt>" command_after_prompt`. The report writer has its own full
command, separate from `cli_settings`, so the report can use a different model or effort from
the runs it reports on.

Keys named `_doc` in either file are notes for the reader; nothing reads them.
