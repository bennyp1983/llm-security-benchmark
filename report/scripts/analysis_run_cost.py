# Run time and token use, for the run cost report
#
# Where the numbers come from:
#   "Run Metadata" header of every result.md and cyber_result.md
#   ->  scripts/build_run_cost.py  ->  run_cost.csv  ->  this file  ->  report tables and figures
#
# run_cost.csv holds one row per run; rows the config groups "ignore" are dropped on load.
#
# Review selections follow the findings report:
#   self-review  - each assistant reviewing its own code
#   panel        - every review of the conditions that contain external reviews

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from analysis_findings import (CODERS, REPORT_ORDER, markdown_table, panel, external_groups,
                      show_table_if_possible, show_figure_if_possible, keep_present_groups_and_coders,
                      grouped_bars, matrix_heatmap, show_figure, legend_above)


# Step 1 - Constants

RUNS_PATH = "data/run_cost.csv"

# Codex's output has no duration, so every time figure and table leaves it out
TIMED_CODERS = ["agy", "claude", "qwen"]

# What each CLI counts as input. Claude and Antigravity report cached reads apart from input,
# so they are added back; Codex counts cached reads inside input already, and Qwen re-sends the
# whole prompt every request (the vLLM prefix cache is not reported), so both are input + output
CACHE_ADDED = {"agy": ["cached_read_tokens"],
               "claude": ["cached_read_tokens", "cache_creation_tokens"],
               "codex": [],
               "qwen": []}

# The one pilot run of Claude Sonnet 5 at max effort that survived, rebuilt from the repository history,
# and the main-study Claude Opus 5 (medium) run of the same task, author and prompt
SONNET_PILOT_PATH = "data/claude_sonnet_max_pilot.md"
SONNET_COMPARISON = "claude/sallie/1/basic/"

# Qwen's review effort per condition, as the runs were actually configured
QWEN_REVIEW_EFFORT = {"Basic": "xhigh", "Security-aware": "xhigh", "Security-informed": "medium"}
QWEN_PANEL_REVIEWS = 24    # 4 generators x 6 tasks


# Step 2 - Load the data

# Returns run_cost.csv as one table, with minutes and the two token measures added
def load_runs(path=RUNS_PATH):
    runs = pd.read_csv(path, encoding="utf-8-sig")

    # report_group "ignore" is the config's mark for runs no report covers
    runs = runs[runs["report_group"] != "ignore"].copy()
    runs["status"] = runs["status"].str.upper()    # Claude and Qwen write "success", the others "SUCCESS"
    runs["minutes"] = runs["duration_seconds"] / 60

    # Tokens processed = every input token the model read, cached or not, plus its output
    processed = []
    for _, run in runs.iterrows():
        cli = run["sec_review"] if run["stage"] == "review" else run["dev_llm"]
        total = run["input_tokens"] + run["output_tokens"]
        for column in CACHE_ADDED[cli]:
            if not pd.isna(run[column]):
                total += run[column]
        processed.append(total)
    runs["tokens_processed"] = processed

    # Tokens generated = output, which already includes thinking for all four CLIs
    runs["tokens_generated"] = runs["output_tokens"]

    # The assistant that did the work: the generator for generation, the reviewer for review
    runs["assistant"] = runs["sec_review"].fillna(runs["dev_llm"])
    runs["self_review"] = (runs["stage"] == "review") & (runs["sec_review"] == runs["dev_llm"])

    # Draw only the groups and assistants this run's data has
    keep_present_groups_and_coders(runs)
    TIMED_CODERS[:] = [coder for coder in TIMED_CODERS if coder in CODERS]
    return runs


# Returns only the generation runs (one per program)
def generation(runs):
    return runs[runs["stage"] == "generation"]


# Returns only the self-reviews
def self_reviews(runs):
    return runs[runs["self_review"]]


# Returns only the review runs of the panel conditions, decided by which conditions hold
# external reviews - the same rule the findings report uses
def panel_review_runs(runs):
    return panel(runs[runs["stage"] == "review"])


# Step 3 - Tables

# Returns one row per assistant and stage: runs, total and mean time, total and mean tokens
def headline_table(runs):
    summary = []
    for coder in CODERS:
        for stage in ["generation", "review"]:
            part = runs[(runs["assistant"] == coder) & (runs["stage"] == stage)]
            summary.append({
                "assistant": coder,
                "stage": stage,
                "runs": len(part),
                "total hours": part["minutes"].sum(min_count=1) / 60,
                "mean minutes per run": part["minutes"].mean(),
                "total tokens processed (M)": part["tokens_processed"].sum() / 1e6,
                "mean tokens processed per run (M)": part["tokens_processed"].mean() / 1e6,
                "mean tokens generated per run (k)": part["tokens_generated"].mean() / 1e3
            })
    return pd.DataFrame(summary)


# Returns one row per assistant and stage: how many runs finished cleanly and how many did not
def completion_table(runs):
    summary = []
    for coder in CODERS:
        for stage in ["generation", "review"]:
            part = runs[(runs["assistant"] == coder) & (runs["stage"] == stage)]
            summary.append({
                "assistant": coder,
                "stage": stage,
                "runs": len(part),
                "status SUCCESS": int((part["status"] == "SUCCESS").sum()),
                "status ERROR": int((part["status"] == "ERROR").sum()),
                "empty reply": int(part["body_empty"].sum())
            })
    return pd.DataFrame(summary)


# Returns every run that ended in ERROR or left an empty reply
def problem_runs_table(runs):
    problems = runs[(runs["status"] != "SUCCESS") | runs["body_empty"]]
    table = pd.DataFrame({"run": problems["location"],
                          "stage": problems["stage"],
                          "status": problems["status"],
                          "empty reply": problems["body_empty"].map({True: "yes", False: "no"}),
                          "minutes": problems["minutes"]})
    return table


# Returns the "Run Metadata" header of a result file as {field: value}
def read_run_header(path):
    with open(path, encoding="utf-8") as file:
        header = file.read().split("\n---\n")[0]
    fields = {}
    for line in header.splitlines():
        if line.startswith("- **") and ":** " in line:
            name, value = line[4:].split(":** ", 1)
            fields[name] = value.strip()
    return fields


# Returns the Sonnet max pilot run beside the Opus medium run of the same task, and Opus's Basic mean
def sonnet_pilot_table(runs):
    fields = read_run_header(SONNET_PILOT_PATH)
    output = float(fields["Output tokens"])
    thinking = float(fields["Thinking tokens"])
    processed = (float(fields["Input tokens"]) + output + float(fields["Cached read tokens"])
                 + float(fields["Cache creation tokens"]))
    sonnet = {"minutes": float(fields["Duration"].rstrip("s")) / 60,    # Written as seconds, e.g. "1814.582s"
              "output tokens": output,
              "thinking tokens": thinking,
              "thinking share of output %": 100 * thinking / output,
              "tokens processed (M)": processed / 1e6,
              "turns": float(fields["Turns"])}

    opus_runs = generation(runs)
    opus_runs = opus_runs[(opus_runs["dev_llm"] == "claude") & (opus_runs["report_group"] == REPORT_ORDER[0])]
    same_task = opus_runs[opus_runs["location"] == SONNET_COMPARISON].iloc[0]

    summary = []
    for measure in sonnet:
        if measure == "thinking share of output %":
            opus = 100 * same_task["thinking_tokens"] / same_task["output_tokens"]
            opus_mean = 100 * opus_runs["thinking_tokens"].sum() / opus_runs["output_tokens"].sum()
        else:
            column = {"minutes": "minutes", "output tokens": "output_tokens",
                      "thinking tokens": "thinking_tokens", "tokens processed (M)": "tokens_processed",
                      "turns": "turns"}[measure]
            divide_by = 1e6 if measure == "tokens processed (M)" else 1
            opus = same_task[column] / divide_by
            opus_mean = opus_runs[column].mean() / divide_by
        summary.append({"measure": measure,
                        "Sonnet 5 max, pilot": sonnet[measure],
                        "Opus 5 medium, same task": opus,
                        "Sonnet / Opus": sonnet[measure] / opus,
                        "Opus 5 medium, mean of 12 Basic runs": opus_mean})
    return pd.DataFrame(summary)


# Returns, for each condition, Qwen's mean minutes to generate a program and to self-review it.
# Generation was always xhigh; review effort is in QWEN_REVIEW_EFFORT
def qwen_effort_table(runs):
    summary = []
    for group in REPORT_ORDER:
        made = generation(runs)
        made = made[(made["dev_llm"] == "qwen") & (made["report_group"] == group)]
        read = self_reviews(runs)
        read = read[(read["dev_llm"] == "qwen") & (read["report_group"] == group)]
        summary.append({
            "condition": group,
            "programs": len(made),
            "generation effort": "xhigh",
            "review effort": QWEN_REVIEW_EFFORT[group],
            "generation minutes": made["minutes"].mean(),
            "self-review minutes": read["minutes"].mean(),
            "review / generation": read["minutes"].sum() / made["minutes"].sum()
        })
    return pd.DataFrame(summary)


# Returns the conditions where Qwen reviewed at xhigh, the like-for-like ratio basis
def qwen_xhigh_groups():
    groups = []
    for group in REPORT_ORDER:
        if QWEN_REVIEW_EFFORT[group] == "xhigh":
            groups.append(group)
    return groups


# Returns Qwen's review/generation ratio across the xhigh review conditions together
def qwen_xhigh_ratio(runs):
    xhigh = qwen_xhigh_groups()

    made = generation(runs)
    made = made[(made["dev_llm"] == "qwen") & made["report_group"].isin(xhigh)]
    read = self_reviews(runs)
    read = read[(read["dev_llm"] == "qwen") & read["report_group"].isin(xhigh)]
    return read["minutes"].sum() / made["minutes"].sum()


# Returns the panel Qwen review time actually taken at medium, against an xhigh estimate.
# The estimate scales Qwen's panel-condition generation time by its xhigh review/generation ratio;
# for all reviews it assumes the other generators' code takes as long to review as Qwen's own
def qwen_projection_table(runs):
    ratio = qwen_xhigh_ratio(runs)
    panel_group = external_groups(runs[runs["stage"] == "review"])[0]

    made = generation(runs)
    made = made[(made["dev_llm"] == "qwen") & (made["report_group"] == panel_group)]
    generation_hours = made["minutes"].sum() / 60

    read = panel_review_runs(runs)
    read = read[read["sec_review"] == "qwen"]
    own = read[read["dev_llm"] == "qwen"]

    reviews_per_generator = QWEN_PANEL_REVIEWS // len(CODERS)
    summary = [
        {"Qwen panel reviews": f"{len(own)} self-reviews",
         "actual hours at medium": own["minutes"].sum() / 60,
         "estimated hours at xhigh": generation_hours * ratio},
        {"Qwen panel reviews": f"{len(read)} reviews (all four generators)",
         "actual hours at medium": read["minutes"].sum() / 60,
         "estimated hours at xhigh": generation_hours * ratio * len(read) / reviews_per_generator}
    ]
    return pd.DataFrame(summary)


# Step 4 - Figures. Titles live in the report's figure captions, so the plots carry panel titles only

# Mean of one measure for each assistant (rows) and condition (bars), drawn with the findings report's grouped bars
def plot_condition_bars(part, column, ylabel, divide_by=1, coders=CODERS, value_format="{:.1f}"):
    means = part.pivot_table(index="assistant", columns="report_group", values=column) / divide_by
    means = means.reindex(index=coders, columns=REPORT_ORDER)

    plt.figure(figsize=(8, 4))
    grouped_bars(means, ylabel, value_format)
    show_figure()


# Mean of one measure for each task (rows) and assistant (columns), one panel per condition
def plot_task_grid(part, column, label, divide_by=1, coders=CODERS, value_format="{:.1f}"):
    plt.figure(figsize=(11, 3.8))
    for slot, group in enumerate(REPORT_ORDER, 1):
        in_group = part[part["report_group"] == group]
        grid = in_group.pivot_table(index="task", columns="assistant", values=column) / divide_by
        grid = grid.reindex(columns=coders)

        plt.subplot(1, len(REPORT_ORDER), slot)
        plt.imshow(grid.to_numpy(), cmap="YlOrRd", aspect="auto")
        darkest = grid.to_numpy().max()
        for i in range(grid.shape[0]):
            for j in range(grid.shape[1]):
                value = grid.iat[i, j]
                colour = "white" if value > 0.6 * darkest else "black"    # Light text on the dark cells
                plt.text(j, i, value_format.format(value), ha="center", va="center", fontsize=8, color=colour)
        plt.xticks(range(len(coders)), coders)
        plt.yticks(range(len(grid.index)), [f"Task {t}" for t in grid.index])
        plt.title(group)
    plt.suptitle(label, fontsize=9)
    show_figure()


# Panel reviewer x generator: mean tokens processed and generated per review
def plot_review_matrix(runs):
    part = panel_review_runs(runs)
    processed = part.pivot_table(index="sec_review", columns="dev_llm", values="tokens_processed") / 1e6
    generated = part.pivot_table(index="sec_review", columns="dev_llm", values="tokens_generated") / 1e3

    plt.figure(figsize=(11, 4.25))
    plt.subplot(1, 2, 1)
    matrix_heatmap(processed.reindex(index=CODERS, columns=CODERS), "YlOrRd", "Tokens processed (millions)")
    plt.subplot(1, 2, 2)
    matrix_heatmap(generated.reindex(index=CODERS, columns=CODERS), "YlGnBu", "Tokens generated (thousands)")
    show_figure()


# Qwen's mean minutes to generate and to self-review a program in each condition, with the effort
# settings under each group and the review/generation ratio above it
def plot_qwen_effort(runs):
    table = qwen_effort_table(runs)
    x = np.arange(len(table))
    width = 0.36

    plt.figure(figsize=(8, 4.4))
    bars = [("generation minutes", "#6482AD", -0.5, "generation"),
            ("self-review minutes", "#C44E52", 0.5, "self-review")]
    for column, colour, shift, name in bars:
        positions = x + shift * width
        plt.bar(positions, table[column], width, label=name, color=colour)
        for position, value in zip(positions, table[column]):
            plt.text(position, value, f"{value:.0f}", ha="center", va="bottom", fontsize=8)

    # The ratio sits above the taller bar of each group
    for i, row in table.iterrows():
        top = max(row["generation minutes"], row["self-review minutes"])
        plt.text(x[i], top * 1.08 + 10, f"review / generation = {row['review / generation']:.2f}",
                 ha="center", va="bottom", fontsize=8.5, fontweight="bold")

    labels = []
    for _, row in table.iterrows():
        labels.append(f"{row['condition']}\ngenerate {row['generation effort']}, review {row['review effort']}")
    plt.xticks(x, labels)
    plt.ylabel("Mean minutes per program")
    plt.ylim(0, table["generation minutes"].max() * 1.25)
    legend_above(columns=2)
    show_figure()


# Qwen's panel review hours: what medium took, beside the xhigh estimate
def plot_qwen_projection(runs):
    table = qwen_projection_table(runs)
    x = np.arange(len(table))
    width = 0.36

    plt.figure(figsize=(7.5, 4))
    bars = [("actual hours at medium", "#408C87", -0.5), ("estimated hours at xhigh", "#C44E52", 0.5)]
    for column, colour, shift in bars:
        positions = x + shift * width
        plt.bar(positions, table[column], width, label=column, color=colour)
        for position, value in zip(positions, table[column]):
            plt.text(position, value, f"{value:.0f} h", ha="center", va="bottom", fontsize=8)
    plt.xticks(x, table["Qwen panel reviews"])
    plt.ylabel("Hours of review")
    plt.ylim(0, table["estimated hours at xhigh"].max() * 1.15)
    legend_above(columns=2)
    show_figure()
