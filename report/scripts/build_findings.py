# Build findings.csv from the security reviews in results-cyber
#
# Run:  python report/scripts/build_findings.py
#
# A finding is a heading like "### SEC-01: Title" and owns the lines under it. The
# first CWE line under the heading gives the cwe and the reviewer's own name for it,
# kept as written - an old or wrong name is evidence of stale training data.


#-----------------------------------------#    imports    #-----------------------------------------#

import csv
import json
import re
from pathlib import Path


#-------------------------------------#    Define constants    #-------------------------------------#

# Define repo layout
REPO = Path(__file__).resolve().parents[2]                           # Repo root, the folder holding results-cyber
REVIEWS_DIR = REPO / "results-cyber"
DATA_DIR = REPO / "report" / "data"
CONFIG_FILE = REPO / "config" / "benchmark.json"
OUT_FILE = DATA_DIR / "findings.csv"
MITRE_FILE = DATA_DIR / "mitre_cwe.csv"                              # Official CWE names, the fallback for a nameless finding
OWASP_FILE = DATA_DIR / "owasp2025_cwe_map.csv"                      # Which OWASP Top 10 2025 category each CWE sits in

# Define review path constants
# Path shape: results-cyber/<reviewer>/<dev_llm>/set_a/<folder>/<task>/<prompt_arm>/security_review.md
REVIEW_GLOB = "*/*/*/*/*/*/security_review.md"
SKIP_FOLDERS = ("pilot",)                                           # Pilot predates the proper review prompt, its format is unparseable here

# Define review reading patterns
FINDING_HEAD_RE = re.compile(                                        # Group 1 is the finding id, group 2 its title
    r"^#{2,4}\s+(SEC-\d+|VULN-\d+|FIND-\d+|ISSUE-\d+|SR-\d+|F-\d+|V-\d+|Finding \d+)"
    r"[\s:—\-]+(.+)$", re.I)
CWE_NUMBER_RE = re.compile(r"CWE[\s*\":.\-]*(\d+)", re.I)            # Group 1 is the bare CWE number
CWE_LABEL_RE = re.compile(r"CWE[\s*\":.\-]*\d*", re.I)               # A CWE label with no number kept, for cutting labels out
BRACKET_PAIR_RE = re.compile(r"\([^()]*\)")                          # A complete pair means real words are inside
ASIDE_RE = re.compile(r"\s*\((also|with|same as|see)[^)]*", re.I)    # Refers to another id, names nothing

# Define CSV values
CWE_PREFIX = "CWE-"
CWE_MARK = "CWE-"                                                    # A blank row whose review still mentions CWEs needs an eye
UNMAPPED = "Unmapped"                                                # A cited CWE OWASP does not map
SEVERITY_WORDS = ("Critical", "High", "Medium", "Low")               # Only when the review writes no Severity label
EDGE_PUNCT = " /:;-\u2014.*"                                         # What a cut CWE label leaves on the line

# The columns of findings.csv, in order
COLUMNS = [
    "location", "sec_review", "dev_llm", "folder", "task", "report_group",
    "sec_id", "sec_title", "cwe", "cwe_title", "owasp", "owasp_title", "severity"
]


#-------------------------------------#    Define functions    #-------------------------------------#


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


# Returns the review's text, unreadable bytes replaced rather than raising
def read_text(file_path):
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return text


# Returns every review in the corpus in a stable order, pilot left out
def review_files():
    found = REVIEWS_DIR.glob(REVIEW_GLOB)
    ordered = sorted(found)

    paths = []
    for path in ordered:
        relative_path = path.relative_to(REVIEWS_DIR)
        reviewer, dev_llm, set_name, folder, task, prompt_arm, file_name = relative_path.parts

        if folder not in SKIP_FOLDERS:
            paths.append(path)

    return paths


# Returns the six columns saying which review a finding came from
def review_key_columns(path):
    relative_path = path.relative_to(REVIEWS_DIR)
    reviewer, dev_llm, set_name, folder, task, prompt_arm, file_name = relative_path.parts

    report_group = report_group_for(folder, task, prompt_arm)

    location_parts = [reviewer, dev_llm, folder, task, prompt_arm]
    location = "/".join(location_parts)
    location = location + "/"

    key_columns = {"location": location,
                   "sec_review": reviewer,
                   "dev_llm": dev_llm,
                   "folder": folder,
                   "task": task,
                   "report_group": report_group}
    return key_columns


# Returns (line number, match) for every finding heading in the review
def find_headings(lines):
    headings = []
    for line_number, line in enumerate(lines):
        match = FINDING_HEAD_RE.match(line)

        if match:
            headings.append((line_number, match))

    return headings


# Returns the lines one finding owns, its heading up to the next one
def finding_block(lines, headings, position):
    heading = headings[position]
    block_start = heading[0]
    next_position = position + 1

    # The last finding runs to the end of the review
    if next_position < len(headings):
        block_end = headings[next_position][0]
    else:
        block_end = len(lines)

    block = lines[block_start:block_end]
    return block


# Returns the finding id in CSV form, "Finding 1" and "sec-01" both upper cased
def clean_id(raw_id):
    sec_id = raw_id.upper()
    sec_id = sec_id.replace(" ", "-")
    return sec_id


# Returns the finding title in CSV form, markdown markers off, "__Host-" untouched
def clean_title(raw_title):
    sec_title = raw_title.strip()
    sec_title = sec_title.replace("`", "")
    sec_title = sec_title.replace("**", "")
    return sec_title


# Returns the CWE number and the reviewer's own name for it, from the first CWE line in the block
def find_cwe(block):
    cwe = ""
    cwe_words = ""

    for line in block:
        match = CWE_NUMBER_RE.search(line)
        if match is None:
            continue

        cwe_number = match.group(1)
        cwe = CWE_PREFIX + cwe_number

        words = line
        words = words.replace("`", "")
        words = words.replace("**", "")
        words = CWE_LABEL_RE.sub(" ", words)
        words = ASIDE_RE.sub("", words)
        words = words.strip(EDGE_PUNCT)

        # A name written wholly in brackets is the name itself
        name_is_wrapped = words.startswith("(") and words.endswith(")")
        while name_is_wrapped:
            words = words[1:-1]
            words = words.strip()
            name_is_wrapped = words.startswith("(") and words.endswith(")")

        # Lines carrying several CWEs leave lone brackets behind
        bracket_pair = BRACKET_PAIR_RE.search(words)
        if bracket_pair is None:
            words = words.replace("(", " ")
            words = words.replace(")", " ")

        word_parts = words.split()
        cwe_words = " ".join(word_parts)

        return cwe, cwe_words

    return cwe, cwe_words


# Returns the severity as the review wrote it, "Low-Medium" and notes kept whole
def find_severity(block):
    heading_line = block[0]
    body_lines = block[1:]

    for line in body_lines:
        stripped_line = line.lstrip("-*> `")
        has_label = stripped_line.lower().startswith("severity")

        if has_label:
            label_parts = stripped_line.partition(":")
            severity_value = label_parts[2]
            severity_value = severity_value.strip()
            severity_value = severity_value.strip("*` ")
            severity_value = severity_value.rstrip(".*")
            return severity_value

    # Reviews without a Severity label state it in the heading instead
    for word in SEVERITY_WORDS:
        if word in heading_line:
            return word

    return ""


# Returns one finding's row, the review's columns plus the finding's own
def finding_row(key_columns, sec_id, sec_title, cwe, cwe_words, severity, mitre_table, owasp_table):
    cwe_number = cwe.replace(CWE_PREFIX, "")

    # MITRE's official name only when the reviewer wrote none of their own
    if cwe_words != "":
        cwe_title = cwe_words
    else:
        mitre_row = mitre_table.get(cwe_number, {})
        cwe_title = mitre_row.get("Name", "")

    owasp_row = owasp_table.get(cwe_number, {})
    owasp_code = owasp_row.get("owasp", UNMAPPED)
    owasp_title = owasp_row.get("owasp_title", UNMAPPED)

    row = dict(key_columns)
    row["sec_id"] = sec_id
    row["sec_title"] = sec_title
    row["cwe"] = cwe
    row["cwe_title"] = cwe_title
    row["owasp"] = owasp_code
    row["owasp_title"] = owasp_title
    row["severity"] = severity
    return row


# Returns a clean review's row: which review, nothing found
def blank_row(key_columns):
    row = dict(key_columns)

    for column in COLUMNS:
        if column not in row:
            row[column] = ""

    return row


# Returns a reference table keyed by bare CWE number, both tables are pure lookups
def load_table(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        found = list(reader)

    table = {}
    for row in found:
        cwe_number = row["CWE-ID"]
        table[cwe_number] = row

    return table


# Writes findings.csv, utf-8-sig so Excel reads the accents and arrows
def write_csv(rows):
    with open(OUT_FILE, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {OUT_FILE.name}: {len(rows)} rows")


# Prints the blank rows that may be missed findings rather than clean reviews
def report_blank_reviews(blank_reviews):
    if len(blank_reviews) == 0:
        return

    print("blank rows - clean review, or findings we missed? check by hand:")
    for path in blank_reviews:
        relative_path = path.relative_to(REPO)
        print("  ", relative_path.as_posix())


#-------------------------------------#    Main execution of program    #-------------------------------------#

# Wrapped so build_review_bundle.py can import this file without rebuilding the CSV
def main():

    # The two reference tables every finding is looked up against
    mitre_table = load_table(MITRE_FILE)
    owasp_table = load_table(OWASP_FILE)

    # Every review in the corpus, in the order the CSV is written
    review_paths = review_files()

    rows = []
    blank_reviews = []

    for path in review_paths:

        # The review's own columns come off the path, its findings off the text
        key_columns = review_key_columns(path)
        text = read_text(path)
        lines = text.split("\n")
        headings = find_headings(lines)

        # A clean review still gets a row, so it counts in the report
        if len(headings) == 0:
            row = blank_row(key_columns)
            rows.append(row)

            # CWEs named with no finding heading is what a missed finding looks like
            if CWE_MARK in text:
                blank_reviews.append(path)

            continue

        for position, heading in enumerate(headings):
            heading_match = heading[1]

            # Everything up to the next heading, so text never falls into the finding after it
            block = finding_block(lines, headings, position)

            raw_id = heading_match.group(1)
            raw_title = heading_match.group(2)
            sec_id = clean_id(raw_id)
            sec_title = clean_title(raw_title)

            cwe, cwe_words = find_cwe(block)
            severity = find_severity(block)

            # The reviewer's wording wins the cwe_title, even when MITRE names it differently
            row = finding_row(key_columns, sec_id, sec_title, cwe, cwe_words, severity, mitre_table, owasp_table)
            rows.append(row)

    write_csv(rows)
    report_blank_reviews(blank_reviews)


if __name__ == "__main__":
    main()
