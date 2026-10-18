# llm-security-benchmark

> Placeholder. A full README will be written once the benchmark is complete.

## Layout and naming

The project has two stages, each with its own n8n container, Dockerfile, workflow and results tree:

| | benchmark (code generation) | cyber (security review) |
|---|---|---|
| Container | `n8n-benchmark` (:5678) | `n8n-cyber` (:5688) |
| Dockerfile | `Dockerfile.benchmark` | `Dockerfile.cyber` (builds `FROM n8n-benchmark`) |
| Workflow | `n8n-workflows/benchmark/` | `n8n-workflows/cyber/` |
| Config | `config/benchmark.json` | `config/cyber.json` |
| Results | `results/<cli>/set_a/<prompt_set>/<task>/<style>/` | `results-cyber/<reviewer>/<target>/set_a/<prompt_set>/<task>/<style>/` |

Each results folder is mounted at the same path inside its container (`results/` at `/data/results/`, `results-cyber/` at `/data/results-cyber/`), so the absolute paths recorded in generated files and logs are valid in-container. `config/` is mounted read-only into both containers. The cyber container reads `results/` read-only and writes `results-cyber/`. Reviewer skills are installed only in the cyber image, so the generators never see them.

### Prompt styles

The `style` of each prompt in `config/benchmark.json` is also its folder name. The existing prompts use `basic` and `security`:

| Prompt sets | Style folder | Reported as |
|---|---|---|
| pilot, ruth, sallie, ben | `basic` | Basic |
| pilot, ruth, sallie, ben | `security` | Security-aware |
| post_research | `security` | Security-informed |

The report maps post_research's `security` folders to `security_informed` (`ARM_RELABEL` in `report/scripts/build_findings.py`). New prompts can use `"style": "security_informed"` directly; those folders are reported as Security-informed without any mapping.

### Renamed on 2026-10-18

| Before | After |
|---|---|
| `prompts/prompts_2.json` | `config/benchmark.json` |
| `prompts/prompts_cyber.json` | `config/cyber.json` |
| `Dockerfile` | `Dockerfile.benchmark` |
| JSON key `student` | `prompt_sets` |
| `run_config.target_folders` | `run_config.target_prompt_sets` |

Result folders and their contents were not renamed or changed. Hash files are unaffected: hashes cover the prompt text only.

## Notes

### File permissions in committed results

Git does not preserve POSIX file permissions (only the executable bit), so every file in this repository is stored as `644` regardless of how it was created. File modes in this repository therefore do not reflect the permissions a tool or generated program applied at generation time.

The n8n container runs as root, so generated files are root-owned. Any file created without read access for other users is unreadable to the user committing it. In the instances below, read permission was added solely so the files could be committed; file contents are unchanged.

**Known instance:** `results/agy/set_a/sallie/5/basic` and `results/agy/set_a/sallie/5/security`

- After generation, `employee_records.txt` was found with `rw-------` / `600` permissions. The generated `EmployeePortalAuth.java` contains code to set these permissions, and each folder's README describes this behaviour ("File Permission Hardening" in basic, "File System Hardening" in security).
- Read permission was added (`644`).

**Known instance:** `results/qwen/set_a/sallie/1/basic/build/tomcat`

- qwen started a local Tomcat 10.1 server to test its generated code, and the server's runtime files were left in the result folder.
- After generation, the logs, `tomcat.pid`, the unpacked web application (`webapps/app`) and the work directories were found as `640` files and `750` directories. This matches Tomcat's default `UMASK` of `0027` set in `catalina.sh`.
- `conf/web.xml` and `conf/logging.properties` were found as `600`. Both are byte-identical to the Tomcat distribution's own copies, which ship as `600`.
- Read permission was added (`a+rX`).

**Known instance:** `results/agy/set_a/post_research/4/security`

- After generation, `data/`, `data/secure_store/`, `target/test-data-config/` and `target/test-data-service/` (including their per-run UUID subdirectories) were found as `700` directories, and `data/secure_store/user_auth_db.mv.db` as a `600` file.
- An empty `data;INJECTION/` directory (`700`) was also left behind. Git does not track empty directories, so it is not in the repository.
- Read permission was added (`a+rX`).

**Known instance:** `results/codex/set_a/post_research/5/security`

- After generation, `build.sh` was found as `700`, the `build/` directory tree as `700` directories, and the compiled `.class` files under `build/classes` and `build/test-classes` as `600`.
- Read permission was added (`a+rX`).

**Known instance:** `results/qwen/set_a/post_research/1/security/build`

- qwen downloaded Apache Tomcat 10.1.60 and started local Tomcat servers (`catalina-default`, `catalina-limited`, `catalina-noverifier`) to test its generated code. The distribution, the three server base directories and their logs were left in the result folder.
- After generation, the Tomcat files were found as `640` files and `750` directories, matching Tomcat's default `UMASK` of `0027`. The `bin` scripts were `750`, and the `conf` directory of the distribution was `700`.
- The `conf/*` files in each server directory (`catalina.policy`, `server.xml`, `web.xml` and others) were found as `600`; those in the distribution are copies of Tomcat's own `600` files.
- Read permission was added (`a+rX`).

**Known instance:** `results/qwen/set_a/post_research/4/security/identity.properties.example` (`600`) and `results/qwen/set_a/post_research/5/security/portal.sh`, `tools/gen-cert.sh` (`700`)

- These were generated by qwen with owner-only permissions. Read permission was added (`a+rX`).

### Files excluded by .gitignore

Some generated files match ignore rules (`*.log` in the repository `.gitignore`, and `.gitignore` files written by the tools themselves, such as `/target/` for codex post_research tasks 3 and 4 and `out/` for qwen post_research task 5). They are part of the generated output, so they were added with `git add -f`.

The same applies in `results-cyber/`: `target/` for codex post_research tasks 3 and 4, `build/*.log` (and `build/logs/`) for qwen post_research task 1, `out/` for qwen post_research task 5, and `build-logs/` for qwen post_research task 6. These were likewise added with `git add -f`.

When evaluating security controls, use the source code and README rather than the file modes in this repository.

### Security review report template

The n8n-cyber review prompt in `config/cyber.json` was updated to require a fixed structure for `security_review.md`.

- The 48 pilot reviews (`results-cyber/*/set_a/pilot`) were completed with the earlier prompt, which had no report template, and were not re-run.
- Their `benchmark_cyber_hash.txt` files were updated to the new prompt's hash so the workflow skips them. These hashes therefore do not match the prompt those reviews were run with.
- Reviews for ruth and sallie use the updated prompt, so their report structure differs from the pilot reviews.

### Cyber review status — post_research

- claude and codex: all six tasks (`1`–`6`) complete, `benchmark_cyber_hash.txt` present for each.
- agy: tasks `2`–`6` complete. Task `1` failed with a 293s API timeout (see `cyber_return.txt`); no `benchmark_cyber_hash.txt` was written, so the result is committed as a recorded failure, not a completed review.
- qwen: no task completed. The vLLM backend was taken offline while these reviews were running; all six attempts failed with a 45s request timeout (0 tokens processed, error recorded in `cyber_result.md`), and no `benchmark_cyber_hash.txt` was written for any task.
