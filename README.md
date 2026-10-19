# llm-security-benchmark

## Executive summary

> **TODO (Ben):** a few lines on what this study found, for someone landing on the repository.


## Reports

- **[Security findings report](report/docs/final_report_findings.md)**: what the reviewers found, by prompting style, task, CWE and OWASP category, and how the LLMs compare, as code generators and as security reviewers.
- **[Run cost report](report/docs/final_report_run_cost.md)**: how the runs finished, and the time, tokens and turns each assistant used.

Every table and figure in the reports is computed from the data. The text is written by an AI from the rendered tables and figures, and checked to contain no unfilled placeholders.


## About this project

A reproducible benchmark for the security of code written by AI coding assistants. It asks four coding CLIs to write Java for six security-sensitive tasks under different prompting styles, has every program reviewed for vulnerabilities by LLM security reviewers, and turns the reviews into a findings report and a run-cost report.

Everything runs in two [n8n](https://n8n.io/) workflows, each in its own Docker container:

| | benchmark (code generation) | cyber (security review and reports) |
|---|---|---|
| What it does | sends each prompt to each coding CLI and saves the program it writes | has each reviewer CLI review the generated code, then builds both reports |
| Container | `n8n-benchmark` at http://localhost:5678 | `n8n-cyber` at http://localhost:5688 |
| Writes | `results/` | `results-cyber/` and `report/` |

The two are kept apart on purpose. The security-review skills are installed only in the cyber container, so the generators never see them, and the reviewers get the generated code read-only, so a review can never change what it is reviewing.

The coding assistants are Google Antigravity (`agy`), Claude Code (`claude`), ChatGPT Codex (`codex`) and Qwen Code (`qwen`). The same four act as the security reviewers.


## The data

Everything the reports are built from is in the repository:

| What | Where |
|---|---|
| Every generated program, with the prompt, the CLI's output and a summary | `results/<cli>/set_a/<prompt_set>/<task>/<style>/` |
| Every security review (`security_review.md`) of every program | `results-cyber/<reviewer>/<target>/set_a/<prompt_set>/<task>/<style>/` |
| One row per finding (CWE, OWASP category, severity) | [`report/data/findings.csv`](report/data/findings.csv) |
| One row per run (time, tokens, turns) | [`report/data/run_cost.csv`](report/data/run_cost.csv) |
| Every review in one file, in `findings.csv` order, for checking by hand | [`report/data/all_security_review.md`](report/data/all_security_review.md) |

### The tasks and prompts

Six Java tasks, each built around one security weakness:

| Task | Scenario | Anchor weakness |
|---|---|---|
| 1 | Session cookie after authentication (Jakarta Servlet) | CWE-1004 |
| 2 | Symmetric encryption and decryption of sensitive data | CWE-321 |
| 3 | User account lookup through JDBC | CWE-89 |
| 4 | User registration and credential storage | CWE-256 |
| 5 | Login attempts and credential verification | CWE-307 |
| 6 | Authentication with activity logging | CWE-778 |

The prompts live in [`config/benchmark.json`](config/benchmark.json), grouped into prompt sets. Each prompt has a `style`, which is also its results folder name, and a `report_group`, which decides how the reports label it. `report_order` sets the order the groups appear in the reports; `ignore` keeps a run on disk but out of the reports.

| Prompt set | Style (folder) | `report_group` |
|---|---|---|
| ruth, sallie | `basic` | Basic |
| ruth, sallie | `security` | Security-aware (the same task with a short security hint) |
| post_research | `security` | Security-informed (eight security rules written from what the first prompts revealed) |
| pilot, ben | `basic`, `security` | ignore (early trial and demo runs) |
| every set | `multi-turn` | ignore (empty prompts, never run) |

The reports read `report_group` from the config, never the folder names, so a new prompt set only needs the right `report_group` to appear in the reports.


## Run it yourself

### What you need

- Linux, macOS, or Windows with WSL2.
- [Docker Engine with the Compose plugin](https://docs.docker.com/engine/install/), plus `bash` and `curl`.
- About 25 GB of free disk for the two images.
- Access to the coding CLIs you want to use: a subscription or account for each. Qwen is configured for an OpenAI-compatible server (this study used a self-hosted one). If you have no access to a CLI, remove it (see [Configuration](#configuration)).

### Set up

```bash
git clone https://github.com/bennyp1983/llm-security-benchmark.git
cd llm-security-benchmark
./setup.sh
```

`./setup.sh` shows a menu. Choose **[i]nstall** first. It:

1. creates the folders Docker mounts, owned by you;
2. builds both images and starts both n8n instances;
3. imports the benchmark and cyber workflows into their n8n;
4. asks once for an email and password, and creates your account on both n8n instances.

Then choose **[l]ogin**. Every container keeps its own CLI logins, so it signs each CLI in on both containers, one after the other. Follow each CLI's own sign-in steps, and exit the CLI when it says you are signed in.

If your user is not in the `docker` group, run it as `sudo ./setup.sh`. You can also skip the menu with `./setup.sh install`, `./setup.sh login` or `./setup.sh reset`.

### Run the benchmark

1. Open http://localhost:5678, open the **benchmark** workflow and click **Execute workflow**. Each CLI writes a program for every prompt into `results/`.
2. Open http://localhost:5688, open the **cyber** workflow and click **Execute workflow**. Every program is reviewed into `results-cyber/`, then both reports are rebuilt into `report/docs/`.

Both workflows skip any program or review that already exists for the same prompt, so a clone of this repository only runs what is new. Re-running costs nothing for work that is already done.

### Configuration

Choosing what runs is done in the two config files, not in `setup.sh`. Edit them, then run the workflows again.

**[`config/benchmark.json`](config/benchmark.json)**
- `cli_settings`: one entry per coding CLI. Its command, **model and thinking effort** are in `input.set` (the workflows use set `a`), `login` is what `./setup.sh` login runs, and `json_output` says where its output keeps the reply and token counts.
- **Fewer CLIs:** delete the entries for CLIs you have no access to. Generation, reviews, logins and reports all follow this list, so with Codex alone you need one account and two logins. A CLI that is listed but not signed in fails within seconds; the run carries on and retries it next time.
- `prompt_sets`: the prompts. To add your own, add a prompt set:
  ```json
  {
      "name": "my_prompts",
      "task": [
          {
              "task_number": 1,
              "prompts": [
                  { "report_group": "Basic", "style": "basic", "prompt": "Develop Java code that ..." }
              ]
          }
      ]
  }
  ```
  Only the new prompts run; everything already in `results/` is kept and skipped.
- `report_order` and `report_group`: the reports compare **groups**, not prompt sets.
  ```json
  "report_order": ["Basic", "Security-aware", "Security-informed"]
  ```
  `report_order` lists the groups every report table and figure is calculated for, in the order they appear. Each prompt's `report_group` decides which group its results count towards, and it must match one of these names exactly, or be `ignore` to keep the results out of the reports. All prompts with the same `report_group` are pooled together, whatever prompt set they belong to: a new prompt set with `"report_group": "Basic"` adds to the Basic group alongside ruth and sallie. For a new kind of prompt, add its group name to `report_order` and use that name as the prompts' `report_group`. A `report_group` that isn't in `report_order` (and isn't `ignore`) stops the report build with an error, so a typo can't silently drop results.
- **Changing a model:** a run is skipped when its prompt text is unchanged, whatever the model. A new model therefore does not redo finished work, and its new results would sit beside the old model's. To compare models, copy the prompt set under a new name after changing the model, so each model's results get their own folders.

**[`config/cyber.json`](config/cyber.json)**
- `run_config`: which reviews run. It picks the reviewers, prompt sets, tasks and styles, and whose code each reviewer reads: `"self"` means each reviewer reviews only its own code, `"all"` means every reviewer reviews every assistant's code. Leave a CLI out here and it does no reviews.
- `report_writer`: the AI that writes the report text, and its two prompts. It has its **own full command** (now Codex), separate from `cli_settings` on purpose, so the report can be written with a different model or a higher thinking level than the generation runs use. To change it, write the command in two parts: everything before the prompt in `command_before_prompt`, everything after it in `command_after_prompt`. A CLI's `headless_execute`, `prompt_prefix` and `prompt_suffix` in `cli_settings` are a good starting point.

To undo config changes, `git checkout config/`.

### Start from nothing

To keep the setup but delete every generated program and review, choose **[r]eset** in `./setup.sh` (you type `reset` to confirm). The results folders stay in place, and the next benchmark and cyber runs fill them again. A fresh clone brings the original results back.


## Repository layout

| Path | What it is |
|---|---|
| `setup.sh` | install, CLI logins, reset |
| `docker-compose.yml` | the two n8n instances and their task runners |
| `Dockerfile.benchmark`, `Dockerfile.cyber` | the images; cyber builds on top of benchmark and adds the review skills, Quarto and the report's Python packages |
| `config/` | the prompts and CLI settings (`benchmark.json`), and the review and report-writer settings (`cyber.json`) |
| `n8n-workflows/` | exports of the benchmark and cyber workflows |
| `custom-skills/` | the security-review skill given to the reviewers |
| `results/`, `results-cyber/` | generated programs, and their reviews |
| `report/` | report templates (`report_findings.qmd`, `report_run_cost.qmd`), the scripts that build their data, the data, and the final reports in `report/docs/` |

Each results folder is mounted at the same path inside its container (`results/` at `/data/results/`, `results-cyber/` at `/data/results-cyber/`), so absolute paths recorded in generated files and logs are valid inside the containers.


## Notes on the committed results

### File permissions

Git does not keep POSIX file permissions (only the executable bit), so every file here is stored as `644` however it was created. The containers run as root, so generated files are root-owned, and some tools wrote owner-only files. Where that stopped a file from being committed, read permission was added; the contents are unchanged. When judging security controls, use the source code and README of each program, not the file modes in this repository. The individual cases are listed in [README_old.md](README_old.md#file-permissions-in-committed-results).

### Files a tool asked to ignore

Some generated files match ignore rules, either this repository's `*.log` or `.gitignore` files the tools wrote themselves (e.g. `target/`, `out/`, `build-logs/`). They are part of the generated output, so they were committed anyway (`git add -f`).

### Pilot reviews

The 48 pilot reviews were made with an earlier review prompt that had no fixed report structure, and were not re-run. Their hash files were updated to the current prompt's hash so the workflow skips them, so those hashes do not match the prompt the reviews were made with. The pilot is excluded from the reports (`report_group: ignore`).
