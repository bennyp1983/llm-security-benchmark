# Build run_cost.csv from the run headers the n8n workflow wrote into every result file
#
# Run:  python report/scripts/build_run_cost.py
#
# Every number is copied from the "Run Metadata" header above the assistant's reply;
# nothing is read from return.txt. A generation run belongs to its generator, a
# review run to its reviewer. Pilot is skipped here - its pre-prompt format is a
# parse constraint; whether a run shows in reports is its config report_group.


#-----------------------------------------#    imports    #-----------------------------------------#

import json
import re
import pandas as pd
from pathlib import Path


#-------------------------------------#    Define constants    #-------------------------------------#

REPO = Path(__file__).resolve().parents[2]                           # Repo root, the folder holding results and results-cyber
OUT_FILE = REPO / "report" / "data" / "run_cost.csv"
GENERATIONS_DIR = REPO / "results"
REVIEWS_DIR = REPO / "results-cyber"
CONFIG_FILE = REPO / "config" / "benchmark.json"
SKIP_FOLDERS = ("pilot",)                                           # Pilot predates the proper prompts and result headers

# The header field names, and the CSV column each one is written to
NUMBER_FIELDS = {"Input tokens": "input_tokens",
                 "Output tokens": "output_tokens",
                 "Thinking tokens": "thinking_tokens",
                 "Cached read tokens": "cached_read_tokens",
                 "Cache creation tokens": "cache_creation_tokens",
                 "Total tokens": "total_tokens_reported",
                 "Turns": "turns"}


#--------------------------------#    Read one result file    #--------------------------------#


# Returns the config lookup {(set, task, style): report_group} and the report's print order
def load_report_groups():
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

    groups = {}
    for prompt_set in config["prompt_sets"]:
        for task_entry in prompt_set["task"]:
            for prompt in task_entry["prompts"]:
                key = (prompt_set["name"], int(task_entry["task_number"]), prompt["style"])
                groups[key] = prompt["report_group"]
    return groups, config["report_order"]


GROUPS, REPORT_ORDER = load_report_groups()
IGNORE = "ignore"                                                   # The reserved report_group meaning "not part of any report"


# Returns "ignore" or one of report_order's display names, for a disk run's set, task and style.
# Stops the build, naming the prompt, when config says nothing about the run or the group
# is outside report_order - a made-up column value is worse than no build
def report_group_for(set_name, task, style):
    key = (set_name, int(task), style)
    if key not in GROUPS:
        raise SystemExit(f"config/benchmark.json has no prompt for set {key[0]} task {key[1]} style {key[2]}")

    group = GROUPS[key]
    if group != IGNORE and group not in REPORT_ORDER:
        raise SystemExit(f"report_group '{group}' for set {key[0]} task {key[1]} style {key[2]} is neither 'ignore' nor in report_order")
    return group



# Returns the header as {field: value} and the text below it (the assistant's reply)
def read_result(path):
    text = path.read_text(encoding="utf-8")
    header, _, body = text.partition("\n---\n")

    fields = {}
    for line in header.splitlines():
        match = re.match(r"- \*\*(.+?):\*\*[ \t]*(.*)$", line)
        if match:
            fields[match.group(1)] = match.group(2).strip()
    return fields, body


# Returns a duration such as "1h 2m 3.5s" or "4m 59.624s" in seconds, or None when blank (Codex)
def duration_seconds(text):
    seconds = 0
    for value, unit in re.findall(r"([\d.]+)\s*(h|m|s)\b", text):
        if unit == "h":
            seconds += float(value) * 3600
        elif unit == "m":
            seconds += float(value) * 60
        else:
            seconds += float(value)
    if seconds == 0:
        return None
    return seconds


# Returns a header number as a float, or None when the field is blank
def to_number(text):
    if text == "":
        return None
    return float(text)


# Returns one CSV row for a run
def make_row(stage, generator, reviewer, folder, task, style_on_disk, path):
    fields, body = read_result(path)

    if stage == "generation":
        location = f"{generator}/{folder}/{task}/{style_on_disk}/"
    else:
        location = f"{reviewer}/{generator}/{folder}/{task}/{style_on_disk}/"

    row = {"stage": stage, "location": location, "dev_llm": generator, "sec_review": reviewer,
           "folder": folder, "task": int(task), "report_group": report_group_for(folder, task, style_on_disk),
           "cli": fields["CLI"], "status": fields["Status"],
           "body_empty": body.strip() == "",
           "duration_seconds": duration_seconds(fields.get("Duration", ""))}
    for field, column in NUMBER_FIELDS.items():
        row[column] = to_number(fields.get(field, ""))
    return row


#---------------------------------------#    Walk both trees    #---------------------------------------#

# Returns one row per generation run: results/<generator>/set_a/<folder>/<task>/<style>/result.md
def generation_rows():
    rows = []
    for generator in sorted(p.name for p in GENERATIONS_DIR.iterdir()):
        for folder in sorted(p.name for p in (GENERATIONS_DIR / generator / "set_a").iterdir()):
            if folder in SKIP_FOLDERS:
                continue
            folder_path = GENERATIONS_DIR / generator / "set_a" / folder
            for task in sorted(p.name for p in folder_path.iterdir()):
                for style in sorted(p.name for p in (folder_path / task).iterdir()):
                    path = folder_path / task / style / "result.md"
                    rows.append(make_row("generation", generator, None, folder, task, style, path))
    return rows


# Returns one row per review run: results-cyber/<reviewer>/<generator>/set_a/<folder>/<task>/<style>/cyber_result.md
def review_rows():
    rows = []
    for reviewer in sorted(p.name for p in REVIEWS_DIR.iterdir()):
        for generator in sorted(p.name for p in (REVIEWS_DIR / reviewer).iterdir()):
            for folder in sorted(p.name for p in (REVIEWS_DIR / reviewer / generator / "set_a").iterdir()):
                if folder in SKIP_FOLDERS:
                    continue
                folder_path = REVIEWS_DIR / reviewer / generator / "set_a" / folder
                for task in sorted(p.name for p in folder_path.iterdir()):
                    for style in sorted(p.name for p in (folder_path / task).iterdir()):
                        path = folder_path / task / style / "cyber_result.md"
                        rows.append(make_row("review", generator, reviewer, folder, task, style, path))
    return rows


#----------------------------------------#    main    #----------------------------------------#

def main():
    # One row per run: the study as built by n8n, report_group saying what each row means to a report
    runs = pd.DataFrame(generation_rows() + review_rows())
    runs.to_csv(OUT_FILE, index=False, encoding="utf-8-sig")

    print(f"Wrote {len(runs)} rows to {OUT_FILE}")
    print(runs.groupby(["stage", "report_group"]).size())
    print("Status values:", runs["status"].value_counts().to_dict())
    print("Empty replies:", int(runs["body_empty"].sum()))


if __name__ == "__main__":
    main()
