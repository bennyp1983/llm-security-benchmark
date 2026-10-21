# llm-security-benchmark

A benchmark of how prompting changes the security of Java code written by four AI coding assistants: Google Antigravity (Gemini), Claude Code, ChatGPT Codex and Qwen Code. The same four review every program for vulnerabilities, using the open-source [Anthropic Cybersecurity Skills](https://github.com/mukul975/anthropic-cybersecurity-skills) library.

**Research paper** (PDF / DOCX): 
- *coming soon*.

**Automated data reports**, rebuilt by the pipeline on every run:

- **[Security findings report](report/docs/final_report_findings.md)**: what the reviewers found, by prompting style, task, CWE and OWASP category, and how the LLMs compare as code generators and as security reviewers.
- **[Run cost report](report/docs/final_report_run_cost.md)**: how the runs finished, and the time, tokens and turns each assistant used.

Report tables and figures are computed directly from the data; the text describing them is AI-written.


## Summary

Across 120 programs, 192 reviews and 1,217 findings:

- **A short security hint made no measurable difference.** Findings per review went from 6.25 (Basic) to 6.56 (Security-aware); the matched-pair difference of +0.31 has a 95% interval of −0.29 to +0.94.
- **Eight security rules cut findings where they apply directly**, such as secrets, from 0.73 to 0.17 per review. Overall they cut findings only modestly, to 5.79 per review, and findings outside every rule rose.
- **Reviewers agree on the category more than the exact weakness.** 64.3% of program–CWE pairs were named by only one of the four reviewers, against 32.1% of program–OWASP-category pairs.

All counts are reviewer-reported findings, not confirmed vulnerabilities; a sample was [checked by hand](#human-verification).


## About the benchmark

It answers three questions:

1. **Prompting:** how do Basic, Security-aware and Security-informed prompts affect the security findings in the generated code?
2. **Coding assistant:** how do the findings differ between the four assistants?
3. **Reviewer:** how consistently do four LLM security reviewers report weaknesses in the same program?

The assistants run through their own command-line tools, not raw model APIs. Everything runs in two [n8n](https://n8n.io/) workflows, each in its own Docker container:

| | benchmark (code generation) | cyber (security review and reports) |
|---|---|---|
| What it does | sends each prompt to each coding CLI and saves the program it writes | has each reviewer CLI review the generated code, then builds both reports |
| Container | `n8n-benchmark` at http://localhost:5678 | `n8n-cyber` at http://localhost:5688 |
| Writes | `results/` | `results-cyber/` and `report/` |

The two are kept apart on purpose. The security-review skills are installed only in the cyber container, so the generators never see them, and the reviewers get the generated code read-only, so a review can never change what it is reviewing.


## Methodology

### The tasks

Six Java tasks, each built around one security weakness:

| Task | Scenario | OWASP Top 10:2025 | Anchor CWE |
|---|---|---|---|
| 1 | Session cookie after authentication (Jakarta Servlet) | A02 Security Misconfiguration | CWE-1004 |
| 2 | Symmetric encryption and decryption of sensitive data | A04 Cryptographic Failures | CWE-321 |
| 3 | User account lookup through JDBC | A05 Injection | CWE-89 |
| 4 | User registration and credential storage | A06 Insecure Design | CWE-256 |
| 5 | Login attempts and credential verification | A07 Authentication Failures | CWE-307 |
| 6 | Authentication with activity logging | A09 Security Logging and Alerting Failures | CWE-778 |

### Stage 1: Basic and Security-aware

Two team members each wrote a prompt set. For every task there is a **Basic** prompt, the task with no security guidance, and a **Security-aware** prompt, the same task with a short hint about its anchor weakness. 2 authors × 6 tasks × 2 prompts × 4 assistants = 96 programs, each reviewed by the assistant that wrote it.

### The eight rules

The team read the Stage 1 reviews and distilled the recurring problems into eight task-independent rules: trust boundaries, secrets, authentication and access, identifiers and tokens, sensitive data, failure behaviour, concurrency, and prefer the platform. Appended to a task as a fixed block, they form the **Security-informed** prompt.

### Stage 2: Security-informed and cross-review

One author wrote the six Security-informed prompts: 6 tasks × 4 assistants = 24 programs. Every program was reviewed by all four reviewers, 96 reviews, so the same code can be compared across reviewers.

### Models

| Assistant | Model |
|---|---|
| Google Antigravity | Gemini 3.7 Flash, high |
| Claude Code | Claude Opus 5, medium effort |
| ChatGPT Codex | GPT-5.6 Sol, medium reasoning effort |
| Qwen Code | Qwen3.8-Flash-Next, self-hosted |

### Security review

The reviewers work with [Anthropic Cybersecurity Skills](https://github.com/mukul975/anthropic-cybersecurity-skills), a community library of security skills by mukul975 (not an Anthropic project). The full library was too large for Codex to load, and the reviewers did not reliably pick the right skills from it on their own, so the reviewers call one skill written for this project, [review-code-for-security-vulnerabilities](custom-skills/review-code-for-security-vulnerabilities/SKILL.md). It works out what the code does, then finds and applies the matching skills from the library.

Every review uses that skill and one fixed review prompt, which asks for each finding with a CWE id and file:line evidence.

### Human verification
**needs work: *percentage checked and task 1 to match taks 5 style***

Two team members checked a sample of the Stage 1 code and reviews by hand, matching findings by the code's behaviour rather than the CWE label:

- **Task 1 (CWE-1004):** the AI reviews agreed with most of the manual findings, but missed some (a CSRF gap, compilation errors) and made some unsupported claims, including seven findings for a run that produced no Java code.
- **Task 5 (CWE-307):** of 128 AI-reported findings, 16 matched a weakness the human audits confirmed and only 1 was shown to be wrong. The other 111 were neither confirmed nor rejected, mostly because the audits did not rule on each AI claim, so the sample gives no AI error rate. The human audits also found 10 weaknesses the AI did not report.

Both checks were static source-code reviews; exploitability was not tested.

### Prompt sets and report groups

The prompts are in [`config/benchmark.json`](config/benchmark.json), and each prompt's `report_group` decides which group of the reports it counts towards:

| Prompt set | Style (folder) | `report_group` |
|---|---|---|
| ruth, sallie | `basic` | `Basic` |
| ruth, sallie | `security` | `Security-aware` |
| post_research | `security` | `Security-informed` |
| ben, pilot | `basic`, `security` | `ignore` (a demo and an early trial) |
| every set | `multi-turn` | `ignore` (empty placeholders, never run) |

### How runs are skipped

Both n8n workflows skip any prompt they have already run, unless its text has changed, so executing the benchmark or cyber workflow again only does new work:

- **Generation:** the SHA-256 of the prompt text is saved as `prompt_hash.txt` beside the program. A prompt whose hash matches is skipped.
- **Review:** the hash covers both the generation prompt and the review prompt, saved as `benchmark_cyber_hash.txt`. Changing either prompt runs the review again.

Models, efforts and every other setting are not part of the hash, so changing a model alone does not run finished work again. That is why each CLI has two option sets, `a` and `b`: a new model configuration goes in the other set, and because each set's results are stored in different folders (`set_a/`, `set_b/`), it runs fresh instead of being skipped. The study ran set `a`, which both workflows' Build Jobs nodes select, and the reports are built for set `a`; set `b` was only used in early pilot runs (see [Pilot reviews](#pilot-reviews)).

Prompt sets, task numbers and styles are also the results' folder names, so renaming one in the configuration leaves its committed results without a matching prompt, and the report build stops.


## The data

Everything the reports are built from is in the repository:

| What | Where |
|---|---|
| Every generated program, with the prompt, the CLI's output and a summary | `results/<cli>/set_a/<prompt_set>/<task>/<style>/` |
| Every security review (`security_review.md`) of every program | `results-cyber/<reviewer>/<target>/set_a/<prompt_set>/<task>/<style>/` |
| One row per finding (CWE, OWASP category, severity) | [`report/data/findings.csv`](report/data/findings.csv) |
| One row per run (time, tokens, turns) | [`report/data/run_cost.csv`](report/data/run_cost.csv) |
| Every review, one file per reviewer, in `findings.csv` order for checking by hand | [agy](report/data/all_security_review_agy.md), [claude](report/data/all_security_review_claude.md), [codex](report/data/all_security_review_codex.md), [qwen](report/data/all_security_review_qwen.md) |

[`report/data/README.md`](report/data/README.md) describes every data file.

<br>
<br>
<br>

# Run it yourself

## What you need

- Linux, macOS, or Windows with WSL2.
- [Docker Engine with the Compose plugin](https://docs.docker.com/engine/install/), plus `bash` and `curl`.
- About 25 GB of free disk for the two images.
- A subscription or account for each of the four coding CLIs. Qwen is configured for an OpenAI-compatible server (this study used a self-hosted one).

## Set up

```bash
git clone https://github.com/bennyp1983/llm-security-benchmark.git
cd llm-security-benchmark
./setup.sh
```

`./setup.sh` shows a menu. Choose **[i]nstall** first. It:

1. creates the folders Docker mounts, owned by you
2. builds both images and starts both n8n instances
3. imports the benchmark and cyber workflows into their n8n
4. asks once for an email and password, and creates your account on both n8n instances

Then choose **[l]ogin**. Every container keeps its own CLI logins, so it signs each CLI in on both containers, one after the other. Follow each CLI's own sign-in steps, and exit the CLI when it says you are signed in.

If your user is not in the `docker` group, run it as `sudo ./setup.sh`. You can also skip the menu with `./setup.sh install`, `./setup.sh login` or `./setup.sh reset`.

## Run the benchmark

1. Open http://localhost:5678, open the **benchmark** workflow and click **Execute workflow**. Each CLI writes a program for every prompt into `results/`.
2. Open http://localhost:5688, open the **cyber** workflow and click **Execute workflow**. Every program is reviewed into `results-cyber/`, then both reports are rebuilt into `report/docs/`.

A clone of this repository already holds every result, so both runs skip all finished work (see [How runs are skipped](#how-runs-are-skipped)).

## Configuration

Both workflows are configured through two files in [`config/`](config/):

- [`benchmark.json`](config/benchmark.json): the coding CLIs, the prompts and the report groups
- [`cyber.json`](config/cyber.json): which reviews run, the review prompt and the AI that writes the report text

The [configuration guide](config/README.md) explains every setting.

## Start from nothing

To keep the setup but delete every generated program and review, choose **[r]eset** in `./setup.sh` (you type `reset` to confirm). The results folders stay in place, and the next benchmark and cyber runs fill them again. A fresh clone brings the original results back.

Reset does not touch the configuration. The next runs use the prompts and settings already in `config/`, so for a new study, change them first (see the [configuration guide](config/README.md)).


## Repository layout

| Path | What it is |
|---|---|
| `setup.sh` | install, CLI logins, reset |
| `docker-compose.yml` | the two n8n instances and their task runners |
| `Dockerfile.benchmark`, `Dockerfile.cyber` | the images; cyber builds on top of benchmark and adds the review skills, Quarto and the report's Python packages |
| `config/` | the prompts and CLI settings (`benchmark.json`), the review and report-writer settings (`cyber.json`), and the [configuration guide](config/README.md) |
| `n8n-workflows/` | exports of the benchmark and cyber workflows |
| `custom-skills/` | the security-review skill given to the reviewers |
| `results/`, `results-cyber/` | generated programs, and their reviews |
| `report/` | report templates (`report_findings.qmd`, `report_run_cost.qmd`), the scripts that build their data, the data, and the final reports in `report/docs/` |

Each results folder is mounted at the same path inside its container (`results/` at `/data/results/`, `results-cyber/` at `/data/results-cyber/`), so absolute paths recorded in generated files and logs are valid inside the containers.


## Notes on the committed results

### File permissions

Git does not keep file permissions (only the executable bit), so every file here is stored as `644`. The containers ran as root, and some tools wrote owner-only files; read access was added so they could be committed, with contents unchanged. Judge security controls from each program's source code and README, not from file modes here. The [known cases](results/README.md#file-permissions) are listed with the results.

### Files hidden by the assistants' own .gitignore

Some coding assistants wrote a `.gitignore` for their project. Files those `.gitignore` files exclude were committed anyway, so everything the assistants produced can be reviewed.

### Pilot reviews

The 48 pilot reviews were made with an earlier review prompt that had no fixed report structure, and were not re-run. Their hash files were updated to the current prompt's hash so the workflow skips them, so those hashes do not match the prompt the reviews were made with. The pilot is excluded from the reports (`report_group: ignore`).

The first pilot runs used option set `b` and were deleted before the study; one Claude Sonnet 5 run was recovered from the git history for the run-cost report ([`report/data/claude_sonnet_max_pilot.md`](report/data/claude_sonnet_max_pilot.md)).
