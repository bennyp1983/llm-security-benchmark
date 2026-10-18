# Shared analysis code for the report, report/report.qmd
#
# Where the numbers come from:
#   security_review.md files -> scripts/build_findings.py -> data/findings.csv
#   -> this file -> every table and figure in the report
#
# findings.csv holds one row per finding, plus one empty row per review that found
# nothing. Every table and figure here is computed from that one file.
#
# Scope: only the folders listed in STAGE_OF_FOLDER are part of the study, so demo
# folders (ben) are dropped when the CSV loads.
#
# Two ways of selecting reviews are used, and every figure says which one it uses:
#   self-review  - each generator reviewing its own code. The only reviews all three
#                  conditions share, so every three-condition comparison uses these.
#   Stage 2      - every Security-informed review, self and external (the four-reviewer panel).


#-----------------------------------------#    imports    #-----------------------------------------#

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from pathlib import Path


#-------------------------------------#    Define constants    #-------------------------------------#

# Define the data file
REPO = Path(__file__).resolve().parents[2]              # Repo root, so the CSV is found from any folder
CSV_PATH = REPO / "report" / "data" / "findings.csv"

# Define the study shape
CODERS = ["agy", "claude", "codex", "qwen"]             # The four coding assistants, also the four reviewers
CODER_COLOURS = {"agy": "#4C72B0", "claude": "#DD8452", "codex": "#55A868", "qwen": "#C44E52"}
STAGE_OF_FOLDER = {"ruth": "Stage 1", "sallie": "Stage 1", "post_research": "Stage 2"}
ANCHORS = {1: "CWE-1004", 2: "CWE-321", 3: "CWE-89", 4: "CWE-256", 5: "CWE-307", 6: "CWE-778"}

# Define the prompt conditions, in the order they were run
STYLES = ["basic", "security", "security_informed"]
STYLE_NAMES = {"basic": "Basic", "security": "Security-aware", "security_informed": "Security-informed"}
STYLE_COLOURS = {"basic": "#6482AD", "security": "#C48C54", "security_informed": "#408C87"}

# Define severity and OWASP categories
SEVERITIES = ["Critical", "High", "Medium", "Low", "Other"]   # Anything the reviewers wrote outside the four words
SEVERITY_COLOURS = {"Critical": "#7A2A34", "High": "#BA5A4B", "Medium": "#D2A568",
                    "Low": "#A9B8C7", "Other": "#CDD1D6"}
OWASP_ORDER = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "Unmapped"]
OWASP_NAMES = {"A01": "Broken Access Control", "A02": "Security Misconfiguration",
               "A03": "Software Supply Chain Failures", "A04": "Cryptographic Failures",
               "A05": "Injection", "A06": "Insecure Design", "A07": "Authentication Failures",
               "A08": "Software or Data Integrity Failures",
               "A09": "Security Logging and Alerting Failures",
               "A10": "Mishandling of Exceptional Conditions",
               "Unmapped": "CWE outside the OWASP Top 10:2025 list"}

# Define the Security-informed rules. Each CWE sits under the one rule that most
# directly forbids it - the team confirmed the placement, a CWE not listed is No rule
RULES = ["1 Trust boundaries", "2 Secrets", "3 Authentication and access", "4 Identifiers and tokens",
         "5 Sensitive data", "6 Failure behaviour", "7 Concurrency", "8 Prefer the platform"]
RULE_CWES = {
    "1 Trust boundaries": [20, 807, 290, 117, 116, 22, 1284, 345, 15, 178, 89, 59],
    "2 Secrets": [798, 214, 526, 522, 256, 321, 323],
    "3 Authentication and access": [307, 645, 287, 306, 862, 284, 521, 799, 636],
    "4 Identifiers and tokens": [384, 613, 614, 1004, 352, 330, 338],
    "5 Sensitive data": [532, 316, 226, 244, 732, 276, 400, 770, 359, 319, 549, 779, 377],
    "6 Failure behaviour": [209, 204, 208, 203, 200, 754, 1188],
    "7 Concurrency": [362, 367],
    "8 Prefer the platform": [916, 759, 326, 327, 494, 1395, 829],
}
NO_RULE = "No rule"

TOP_CWES = 14                                           # How many CWEs get their own bar, row, segment or slice

# Define colours and plot defaults
CATEGORY_COLOURS = ["#1F77B4", "#E6A800", "#DE9ED6", "#843C39", "#2CA02C", "#E7298A", "#B5DF6B",
                    "#E41A1C", "#66C2A5", "#6A3D9A", "#9EDAE5", "#17BECF", "#8C9D4F", "#D95F02"]
REST_COLOUR = "#7F7F7F"                                 # Always the colour of "the rest" group

plt.rcParams.update({"figure.dpi": 150, "font.size": 9,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "axes.titleweight": "bold"})


#-------------------------------------#    Define table functions    #-------------------------------------#


# Returns findings.csv as one table, with the columns every later step groups on
def load_findings(path=CSV_PATH):
    df = pd.read_csv(path, encoding="utf-8-sig")

    # Demo runs are not part of the study, only ruth, sallie and post_research folders
    df = df[df["folder"].isin(STAGE_OF_FOLDER)]

    df["stage"] = df["folder"].map(STAGE_OF_FOLDER)

    # A clean review has no sec_id, so only rows with one are findings
    df["has_finding"] = df["sec_id"].notna()

    df["severity_group"] = df["severity"].where(df["severity"].isin(SEVERITIES), "Other")
    df["high_plus"] = df["severity"].isin(["Critical", "High"])

    rule_of = {}
    for rule, cwes in RULE_CWES.items():
        for cwe in cwes:
            rule_of[f"CWE-{cwe}"] = rule
    df["rule"] = df["cwe"].map(rule_of).fillna(NO_RULE)

    # One generated program = generator + folder + task + prompt; a review adds the reviewer
    programs = []
    for dev, folder, task, style in zip(df["dev_llm"], df["folder"], df["task"], df["prompt_style"]):
        programs.append(f"{dev}/{folder}/{task}/{style}")
    df["program"] = programs
    return df


# Returns only the rows that are findings, dropping the clean-review rows
def findings_only(df):
    return df[df["has_finding"]]


# Returns one row per review: findings, High/Critical count, and whether the task's anchor CWE was named
def review_table(df):
    keys = ["location", "program", "stage", "sec_review", "dev_llm", "folder", "task", "prompt_style"]
    df = df.copy()
    df["anchor_hit"] = df["cwe"] == df["task"].map(ANCHORS)
    reviews = df.groupby(keys).agg(findings=("has_finding", "sum"),
                                   high_plus=("high_plus", "sum"),
                                   anchor_reported=("anchor_hit", "any")).reset_index()
    return reviews


# Returns only the self-reviews (a generator reviewing its own code) from a review or finding table
def self_review(table):
    return table[table["sec_review"] == table["dev_llm"]]


# Returns only the Stage 2 rows (all four reviewers of the Security-informed code)
def stage_2(table):
    return table[table["stage"] == "Stage 2"]


# Returns a table as Markdown text, so Quarto numbers it and Word gets a real table
def markdown_table(table, decimals=2):
    table = table.round(decimals)

    # Numbers line up on the right, text on the left
    alignment = []
    for column in table.columns:
        alignment.append("---:" if pd.api.types.is_numeric_dtype(table[column]) else ":---")

    lines = ["| " + " | ".join(str(c) for c in table.columns) + " |",
             "|" + "|".join(alignment) + "|"]
    for _, row in table.iterrows():
        cells = []
        for value in row:
            cells.append("" if pd.isna(value) else str(value))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


# Returns the counts the method section quotes, one row per check
def quality_checks(df):
    reviews = review_table(df)
    found = findings_only(df)
    reviewers_per_program = stage_2(reviews).groupby("program")["sec_review"].nunique()
    checks = {
        "CSV rows": len(df),
        "Recorded findings": len(found),
        "Reviews": len(reviews),
        "Reviews with no findings": int((reviews["findings"] == 0).sum()),
        "Generated programs": reviews["program"].nunique(),
        "Rows missing reviewer or generator": int(df[["sec_review", "dev_llm"]].isna().any(axis=1).sum()),
        "Stage 2 programs with all 4 reviewers": int((reviewers_per_program == 4).sum()),
        "Duplicate CSV rows": int(df.duplicated().sum()),
        "Findings with no CWE": int(found["cwe"].isna().sum()),
        "Findings with non-standard severity": int((found["severity_group"] == "Other").sum()),
        "Repeated sec_id within one review": int(found.duplicated(["location", "sec_id"]).sum()),
    }
    return pd.DataFrame({"check": list(checks), "value": list(checks.values())})


# Returns one row per condition: programs, reviews (self and external), clean reviews and findings
def stage_summary(df):
    reviews = review_table(df)
    summary = []
    for style in STYLES:
        subset = reviews[reviews["prompt_style"] == style]
        own_reviews = self_review(subset)
        summary.append({
            "condition": STYLE_NAMES[style],
            "stage": subset["stage"].iloc[0],
            "programs": subset["program"].nunique(),
            "self-reviews": len(own_reviews),
            "external reviews": len(subset) - len(own_reviews),
            "reviews with no findings": int((subset["findings"] == 0).sum()),
            "findings": int(subset["findings"].sum())
        })
    return pd.DataFrame(summary)


# Returns the 48 Stage 1 pairs: same author folder, task and generator, Basic vs Security-aware
def paired_table(reviews):
    stage_1 = reviews[reviews["stage"] == "Stage 1"]
    pairs = stage_1.pivot_table(index=["folder", "task", "dev_llm"], columns="prompt_style",
                                values="findings").reset_index()
    pairs["delta"] = pairs["security"] - pairs["basic"]    # Positive = more findings under Security-aware
    return pairs


# Returns the paired effect overall and per generator, with a 10,000-draw bootstrap 95% interval.
# One seeded generator is shared across the rows, so the intervals repeat exactly
def paired_effect_table(pairs, draws=10000, seed=6224):
    rng = np.random.default_rng(seed)
    groups = [("all", pairs)]
    for coder in CODERS:
        groups.append((coder, pairs[pairs["dev_llm"] == coder]))

    summary = []
    for scope, group in groups:
        deltas = group["delta"].to_numpy(float)
        # Each draw resamples the pairs with replacement and keeps the mean
        resampled = deltas[rng.integers(0, len(deltas), size=(draws, len(deltas)))].mean(axis=1)
        low, high = np.quantile(resampled, [0.025, 0.975])
        summary.append({
            "scope": scope,
            "pairs": len(deltas),
            "basic mean": group["basic"].mean(),
            "aware mean": group["security"].mean(),
            "mean delta": deltas.mean(),
            "median delta": np.median(deltas),
            "fewer": int((deltas < 0).sum()),
            "more": int((deltas > 0).sum()),
            "ties": int((deltas == 0).sum()),
            "CI low": low,
            "CI high": high
        })
    return pd.DataFrame(summary)


# Returns findings per self-review, median and High/Critical share for each condition
def self_review_table(reviews):
    own_reviews = self_review(reviews)
    summary = []
    for style in STYLES:
        subset = own_reviews[own_reviews["prompt_style"] == style]
        summary.append({
            "condition": STYLE_NAMES[style],
            "self-reviews": len(subset),
            "findings": int(subset["findings"].sum()),
            "findings per review": subset["findings"].mean(),
            "median": subset["findings"].median(),
            "High/Critical %": 100 * subset["high_plus"].sum() / subset["findings"].sum()
        })
    return pd.DataFrame(summary)


# Returns the top CWEs by count, ties broken by CWE id so the list never changes
def top_cwes(found, top_count=TOP_CWES):
    counts = found["cwe"].value_counts()
    ranked = sorted(counts.index, key=lambda cwe: (-counts[cwe], cwe))
    return ranked[:top_count]


# Returns the top CWEs with their count and running share of all findings
def top_cwe_table(found):
    counts = found["cwe"].value_counts()
    titles = found.groupby("cwe")["cwe_title"].agg(lambda s: s.value_counts().index[0])
    summary = []
    running = 0
    for rank, cwe in enumerate(top_cwes(found), 1):
        running += counts[cwe]
        summary.append({"rank": rank, "CWE": cwe, "title": titles[cwe], "findings": counts[cwe],
                        "cumulative %": round(100 * running / len(found), 1)})
    return pd.DataFrame(summary)


# Returns the categories of one kind in display order, rest group last.
# kind is "cwe" (top CWEs + Other), "owasp" (A01-A10 + Unmapped) or "rule" (eight rules + No rule)
def category_order(found, kind):
    if kind == "cwe":
        return top_cwes(found) + ["Other"]
    if kind == "owasp":
        return OWASP_ORDER
    return RULES + [NO_RULE]


# Returns each finding's category of the given kind
def category_of(found, kind, vocabulary=None):
    if kind == "cwe":
        return found["cwe"].where(found["cwe"].isin(vocabulary), "Other")
    return found[kind]


# Returns {category: colour}, grey for the rest group
def category_colours(found, kind):
    order = category_order(found, kind)
    colours = {}
    for i, category in enumerate(order[:-1]):
        colours[category] = CATEGORY_COLOURS[i % len(CATEGORY_COLOURS)]
    colours[order[-1]] = REST_COLOUR
    return colours


# Returns the long label for a category, used in legends and tables
def category_label(found, kind, category):
    if kind == "owasp":
        return f"{category} {OWASP_NAMES[category]}"
    if kind == "cwe" and category != "Other":
        title = found[found["cwe"] == category]["cwe_title"].value_counts().index[0]
        if len(title) > 45:
            title = title[:45].rsplit(" ", 1)[0] + "..."    # Cut at a word, not mid-word
        return f"{category} {title}"
    return category


# Returns findings per self-review for every category of a kind, one column per condition
def category_rates(found, reviews, kind):
    own_findings = self_review(found)
    reviews_per_style = self_review(reviews).groupby("prompt_style").size()
    counts = pd.crosstab(category_of(own_findings, kind, top_cwes(found)), own_findings["prompt_style"])
    counts = counts.reindex(index=category_order(found, kind), columns=STYLES, fill_value=0)
    return counts / reviews_per_style[STYLES]


# Returns category_rates as a display table, with the change from the Stage 1 average
def category_rate_table(found, reviews, kind):
    rates = category_rates(found, reviews, kind)
    table = pd.DataFrame({"category": [category_label(found, kind, c) for c in rates.index]})
    for style in STYLES:
        table[STYLE_NAMES[style]] = rates[style].to_numpy()
    stage_1_average = (rates["basic"] + rates["security"]) / 2
    change = 100 * (rates["security_informed"] / stage_1_average - 1)
    table["change vs Stage 1 average %"] = change.round(0).to_numpy()
    return table


# Returns the rule mapping as a table: each rule, its CWEs, and how many findings fall under it
def rule_table(found):
    rows = []
    for rule in RULES + [NO_RULE]:
        rule_findings = found[found["rule"] == rule]
        if rule == NO_RULE:
            listed = "every CWE not listed above"
        else:
            listed = ", ".join(f"CWE-{cwe_number}" for cwe_number in sorted(RULE_CWES[rule]))
        rows.append({"rule": rule, "CWEs": listed, "findings": len(rule_findings),
                     "% of all findings": round(100 * len(rule_findings) / len(found), 1)})
    return pd.DataFrame(rows)


# Returns the Stage 2 findings of one review context: "self-review", "external review" or the whole panel
def context_findings(found, context):
    subset = stage_2(found)
    is_own = subset["sec_review"] == subset["dev_llm"]
    if context == "self-review":
        return subset[is_own]
    if context == "external review":
        return subset[~is_own]
    return subset


# Returns mean findings per review: one row per reviewer, one column per generator (Stage 2)
def reviewer_matrix(reviews):
    matrix = stage_2(reviews).pivot_table(index="sec_review", columns="dev_llm", values="findings",
                                          aggfunc="mean")
    return matrix.reindex(index=CODERS, columns=CODERS)


# Returns one row per Stage 2 reviewer: volume, High/Critical share, own-code vs other-code means
def reviewer_behaviour_table(reviews, found):
    panel_reviews = stage_2(reviews)
    panel_found = stage_2(found)
    summary = []
    for reviewer in CODERS:
        subset = panel_reviews[panel_reviews["sec_review"] == reviewer]
        own_code = subset[subset["dev_llm"] == reviewer]["findings"].mean()
        other_code = subset[subset["dev_llm"] != reviewer]["findings"].mean()
        issues = panel_found[panel_found["sec_review"] == reviewer]
        summary.append({
            "reviewer": reviewer,
            "reviews": len(subset),
            "findings per review": subset["findings"].mean(),
            "High/Critical %": 100 * issues["high_plus"].mean(),
            "distinct CWEs": issues["cwe"].nunique(),
            "own code": own_code,
            "other code": other_code,
            "other minus own": other_code - own_code
        })
    return pd.DataFrame(summary)


# Returns, for each Stage 2 program and category, how many of the four reviewers named it.
# For OWASP, Unmapped is left out: two different off-list CWEs are not an agreement
def support_table(found, kind="cwe"):
    subset = stage_2(found)
    if kind == "owasp":
        subset = subset[subset["owasp"] != "Unmapped"]
    support = subset.groupby(["program", kind])["sec_review"].nunique()
    return support.rename("reviewer_support").reset_index()


# Returns the share of (program, category) pairs named by exactly 1, 2, 3 and 4 reviewers
def support_share_table(found):
    rows = []
    for kind, name in [("cwe", "CWE label"), ("owasp", "OWASP category")]:
        support = support_table(found, kind)["reviewer_support"]
        row = {"level": name, "pairs": len(support)}
        for reviewer_count in [1, 2, 3, 4]:
            row[f"named by {reviewer_count} %"] = round(100 * (support == reviewer_count).mean(), 1)
        rows.append(row)
    return pd.DataFrame(rows)


# Returns the Jaccard overlap of CWE (or OWASP) sets for every reviewer pair on every Stage 2 program.
# When both reviewers named nothing the overlap is undefined (NaN), not 1
def reviewer_pair_jaccard(reviews, found, kind="cwe"):
    subset = stage_2(found)
    if kind == "owasp":
        subset = subset[subset["owasp"] != "Unmapped"]
    rows = []
    for program in stage_2(reviews)["program"].unique():
        named = {}
        for reviewer in CODERS:
            picked = subset[(subset["program"] == program) & (subset["sec_review"] == reviewer)]
            named[reviewer] = set(picked[kind])

        for i, first in enumerate(CODERS):
            for second in CODERS[i + 1:]:
                both = named[first] & named[second]
                either = named[first] | named[second]
                rows.append({"program": program, "reviewer_A": first, "reviewer_B": second,
                             "shared": len(both), "union": len(either),
                             "jaccard": len(both) / len(either) if either else np.nan})
    return pd.DataFrame(rows)


# Returns mean Jaccard per reviewer pair, for CWE labels and OWASP categories side by side
def jaccard_pair_table(reviews, found):
    cwe = reviewer_pair_jaccard(reviews, found, "cwe").groupby(["reviewer_A", "reviewer_B"])["jaccard"].mean()
    owasp = reviewer_pair_jaccard(reviews, found, "owasp").groupby(["reviewer_A", "reviewer_B"])["jaccard"].mean()
    table = pd.DataFrame({"CWE Jaccard": cwe, "OWASP Jaccard": owasp}).reset_index()
    table.insert(0, "reviewer pair", table["reviewer_A"] + " / " + table["reviewer_B"])
    return table.drop(columns=["reviewer_A", "reviewer_B"])


#-------------------------------------#    Define figure functions    #-------------------------------------#

# Titles live in the report's figure captions, so the plots carry panel titles only


# Lays out the current figure and shows it in the notebook or report
def show_figure():
    plt.tight_layout()
    plt.show()
    plt.close()


# Puts the legend in a row above the plot area, where it cannot cover any bars
def legend_above(columns=3):
    plt.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=columns, frameon=False)


# Puts the legend to the right of the plot area
def legend_right():
    plt.legend(loc="upper left", bbox_to_anchor=(1.01, 1), frameon=False, fontsize=8)


# Draws the study design: the two stages, and the reading of Stage 1 that produced the rules
def plot_study_design():
    box = {"boxstyle": "round,pad=.5", "facecolor": "#EAF0F4", "edgecolor": "#9BAFBD"}
    middle = {"boxstyle": "round,pad=.5", "facecolor": "#FFF4E0", "edgecolor": "#C48C54"}
    stage_1_steps = ["Stage 1", "2 prompt authors × 6 tasks", "Basic and Security-aware prompts",
                     "4 coding assistants: 96 programs", "Each program self-reviewed: 96 reviews"]
    stage_2_steps = ["Stage 2", "6 tasks", "Security-informed prompt (8 rules)",
                     "4 coding assistants: 24 programs",
                     "Each program read by all 4 reviewers:\n96 reviews (24 self, 72 external)"]

    plt.figure(figsize=(11.5, 4))
    plt.axis("off")
    plt.xlim(0, 1)
    plt.ylim(0, 1)
    for x, steps in [(0.17, stage_1_steps), (0.83, stage_2_steps)]:
        for i, step in enumerate(steps):
            y = 0.92 - i * 0.2
            weight = "bold" if i == 0 else "normal"
            plt.text(x, y, step, ha="center", va="center", fontsize=9.5, fontweight=weight, bbox=box)
    plt.text(0.5, 0.5, "Stage 1 reviews read\nby the team\n\nfindings distilled into\n8 security rules",
             ha="center", va="center", fontsize=9.5, bbox=middle)
    plt.annotate("", xy=(0.4, 0.5), xytext=(0.33, 0.5), arrowprops={"arrowstyle": "->", "color": "#4D6979"})
    plt.annotate("", xy=(0.67, 0.5), xytext=(0.6, 0.5), arrowprops={"arrowstyle": "->", "color": "#4D6979"})
    show_figure()


# Draws completed reviews per task × generator cell, one panel per condition (0 would mark a missing review)
def plot_completeness(reviews):
    plt.figure(figsize=(11, 3.6))
    for slot, style in enumerate(STYLES, 1):
        subset = reviews[reviews["prompt_style"] == style]
        grid = subset.pivot_table(index="task", columns="dev_llm", values="location",
                                  aggfunc="count", fill_value=0).reindex(columns=CODERS, fill_value=0)

        plt.subplot(1, 3, slot)
        plt.imshow(grid.to_numpy(), cmap="Blues", vmin=0, vmax=4)
        for i in range(grid.shape[0]):
            for j in range(grid.shape[1]):
                plt.text(j, i, str(grid.iat[i, j]), ha="center", va="center", color="white")
        plt.xticks(range(len(CODERS)), CODERS)
        plt.yticks(range(len(grid.index)), [f"Task {t}" for t in grid.index])
        plt.title(STYLE_NAMES[style])
    show_figure()


# Draws the Stage 1 paired differences: one dot per pair, the generator's mean as a diamond
def plot_paired_effect(pairs):
    plt.figure(figsize=(8, 4.2))
    for row, coder in enumerate(CODERS):
        deltas = pairs[pairs["dev_llm"] == coder]["delta"]
        colour = CODER_COLOURS[coder]

        # Pairs with the same difference are stacked slightly apart so none is hidden
        for value, count in deltas.value_counts().items():
            offsets = (np.arange(count) - (count - 1) / 2) * 0.09
            plt.scatter([value] * count, row + offsets, s=30, color=colour, alpha=0.6)
        plt.scatter(deltas.mean(), row, s=130, marker="D", color=colour, edgecolors="black", zorder=3)

    plt.axvline(0, color="#515151", ls="--", lw=1)
    plt.yticks(range(len(CODERS)), CODERS)
    plt.gca().invert_yaxis()
    plt.xlabel("Security-aware minus Basic findings, per matched pair")
    show_figure()


# Draws a box per condition with every self-review as a dot
def plot_findings_distribution(reviews):
    own_reviews = self_review(reviews)
    groups = []
    labels = []
    for style in STYLES:
        values = own_reviews[own_reviews["prompt_style"] == style]["findings"]
        groups.append(values)
        labels.append(f"{STYLE_NAMES[style]}\n(n={len(values)})")

    plt.figure(figsize=(7.5, 4))
    plt.boxplot(groups, tick_labels=labels, showmeans=True)
    for position, (style, values) in enumerate(zip(STYLES, groups), 1):
        spread = position + np.linspace(-0.13, 0.13, len(values))    # Spreads the dots so they do not overlap
        plt.scatter(spread, values, alpha=0.5, s=16, color=STYLE_COLOURS[style])
    plt.ylabel("Findings per self-review")
    show_figure()


# Draws grouped vertical bars: one group per row of the table, one bar per condition, values on top
def grouped_bars(table, ylabel, value_format="{:.1f}"):
    centres = np.arange(len(table))
    width = 0.26
    for offset, style in enumerate(STYLES):
        positions = centres + (offset - 1) * width
        plt.bar(positions, table[style], width, label=STYLE_NAMES[style], color=STYLE_COLOURS[style])
        for position, value in zip(positions, table[style]):
            plt.text(position, value, value_format.format(value), ha="center", va="bottom", fontsize=7.5)
    plt.xticks(centres, table.index)
    plt.ylabel(ylabel)
    plt.ylim(0, table[STYLES].to_numpy().max() * 1.15)
    legend_above()


# Draws mean findings per self-review for each generator and condition
def plot_findings_by_generator(reviews):
    own_reviews = self_review(reviews)
    means = own_reviews.pivot_table(index="dev_llm", columns="prompt_style", values="findings").reindex(CODERS)

    plt.figure(figsize=(8, 4))
    grouped_bars(means, "Findings per self-review")
    show_figure()


# Draws mean findings per self-review for each task (rows) and condition (columns)
def plot_findings_by_task(reviews):
    own_reviews = self_review(reviews)
    grid = own_reviews.pivot_table(index="task", columns="prompt_style", values="findings").reindex(columns=STYLES)

    plt.figure(figsize=(7.5, 4.2))
    plt.imshow(grid.to_numpy(), cmap="YlGnBu", aspect="auto")
    for i in range(grid.shape[0]):
        for j in range(grid.shape[1]):
            plt.text(j, i, f"{grid.iat[i, j]:.2f}", ha="center", va="center")
    plt.xticks(range(len(STYLES)), [STYLE_NAMES[s] for s in STYLES])
    plt.yticks(range(len(grid.index)), [f"Task {t} ({ANCHORS[t]})" for t in grid.index])
    plt.colorbar(label="Findings per self-review")
    show_figure()


# Draws the share of self-reviews that named the task's own anchor CWE, every bar labelled including 0%
def plot_anchor_reporting(reviews):
    own_reviews = self_review(reviews)
    rates = own_reviews.pivot_table(index="task", columns="prompt_style", values="anchor_reported") * 100
    rates.index = [f"Task {t}\n{ANCHORS[t]}" for t in rates.index]

    plt.figure(figsize=(9, 4))
    grouped_bars(rates, "Self-reviews naming the anchor CWE (%)", "{:g}%")
    plt.ylim(0, 100)
    show_figure()


# Draws 100% stacked horizontal bars, one per condition, from a table of shares (rows = conditions)
def stacked_shares(shares, colours, labels, findings_per_style):
    left = np.zeros(len(shares))
    for column in shares.columns:
        widths = shares[column].to_numpy()
        plt.barh(range(len(shares)), widths, left=left, height=0.62, color=colours[column],
                 edgecolor="white", label=labels[column])
        for row in range(len(shares)):
            if widths[row] >= 5:    # Segments under 5% are too thin for a number
                plt.text(left[row] + widths[row] / 2, row, f"{widths[row]:.0f}", ha="center",
                         va="center", fontsize=7.5, color="white")
        left += widths
    plt.yticks(range(len(STYLES)), [f"{STYLE_NAMES[s]}\n{findings_per_style[s]} findings" for s in STYLES])
    plt.gca().invert_yaxis()    # Basic on top, the order the conditions were run
    plt.xlim(0, 100)
    plt.xlabel("Share of the condition's findings (%)")


# Draws the severity mix of each condition's self-review findings
def plot_severity_by_condition(found):
    own_findings = self_review(found)
    shares = pd.crosstab(own_findings["prompt_style"], own_findings["severity_group"], normalize="index") * 100
    shares = shares.reindex(index=STYLES, columns=SEVERITIES, fill_value=0)
    findings_per_style = own_findings["prompt_style"].value_counts()

    plt.figure(figsize=(9, 3.2))
    stacked_shares(shares, SEVERITY_COLOURS, {s: s for s in SEVERITIES}, findings_per_style)
    legend_above(columns=5)
    show_figure()


# Draws findings per self-review for each category (CWE, OWASP or rule), one bar per condition.
# For CWEs the Other row (over 100 CWEs combined) is left off, as it would flatten every other bar
def plot_category_rates(found, reviews, kind):
    rates = category_rates(found, reviews, kind)
    if kind == "cwe":
        rates = rates.drop(index="Other")
    rows = np.arange(len(rates))
    height = 0.26

    plt.figure(figsize=(9, 0.42 * len(rates) + 1.4))
    for offset, style in enumerate(STYLES):
        plt.barh(rows + (offset - 1) * height, rates[style], height, label=STYLE_NAMES[style],
                 color=STYLE_COLOURS[style])
    plt.yticks(rows, [category_label(found, kind, c) for c in rates.index])
    plt.gca().invert_yaxis()
    plt.xlabel("Findings per self-review")
    legend_above()
    show_figure()


# Draws the make-up of each condition's self-review findings by category (CWE, OWASP or rule)
def plot_category_mix(found, kind):
    own_findings = self_review(found)
    categories = category_of(own_findings, kind, top_cwes(found))
    order = category_order(found, kind)
    shares = pd.crosstab(own_findings["prompt_style"], categories, normalize="index") * 100
    shares = shares.reindex(index=STYLES, columns=order, fill_value=0)
    findings_per_style = own_findings["prompt_style"].value_counts()

    labels = {}
    for category in order:
        labels[category] = category_label(found, kind, category)

    plt.figure(figsize=(11, 3.6))
    stacked_shares(shares, category_colours(found, kind), labels, findings_per_style)
    legend_right()
    show_figure()


# Draws findings per self-review for each category (rows) and task (columns), all three conditions together
def plot_category_by_task(found, reviews, kind):
    own_findings = self_review(found)
    reviews_per_task = self_review(reviews).groupby("task").size()
    counts = pd.crosstab(category_of(own_findings, kind, top_cwes(found)), own_findings["task"])
    counts = counts.reindex(index=category_order(found, kind), fill_value=0)
    rates = counts / reviews_per_task    # Each column divided by that task's self-review count

    plt.figure(figsize=(9, 0.4 * len(rates) + 1.5))
    plt.imshow(rates.to_numpy(), cmap="YlOrBr", aspect="auto")
    for i in range(rates.shape[0]):
        for j in range(rates.shape[1]):
            plt.text(j, i, f"{rates.iat[i, j]:.2f}", ha="center", va="center", fontsize=7)
    plt.xticks(range(rates.shape[1]), [f"Task {t}\n{ANCHORS[t]}" for t in rates.columns])
    plt.yticks(range(len(rates)), [category_label(found, kind, c) for c in rates.index])
    plt.colorbar(label="Findings per self-review")
    show_figure()


# Draws one pie per generator (rows) and column; columns are the three conditions (self-review)
# or Stage 2 self-review against external review. Slices of 5% or more are labelled
def plot_category_pies(found, kind, columns="conditions"):
    order = category_order(found, kind)
    colours = category_colours(found, kind)
    vocabulary = top_cwes(found)

    # Each panel is a column heading and the findings it covers
    panels = []
    if columns == "conditions":
        own_findings = self_review(found)
        for style in STYLES:
            panels.append((f"{STYLE_NAMES[style]}\nself-review", own_findings[own_findings["prompt_style"] == style]))
    else:
        panels.append(("Security-informed\nself-review", context_findings(found, "self-review")))
        panels.append(("Security-informed\nexternal review", context_findings(found, "external review")))

    plt.figure(figsize=(4.6 * len(panels) + 1, 18.5))
    slot = 1
    for coder in CODERS:
        for heading, subset in panels:
            mine = subset[subset["dev_llm"] == coder]
            counts = category_of(mine, kind, vocabulary).value_counts()

            sizes, slice_colours, labels = [], [], []
            for category in order:
                if counts.get(category, 0) > 0:
                    sizes.append(counts[category])
                    slice_colours.append(colours[category])
                    share = 100 * counts[category] / len(mine)
                    labels.append(f"{category} {share:.0f}%" if share >= 5 else "")

            plt.subplot(len(CODERS), len(panels), slot)
            plt.pie(sizes, labels=labels, colors=slice_colours, startangle=90, counterclock=False,
                    labeldistance=1.08, textprops={"fontsize": 8.5},
                    wedgeprops={"edgecolor": "white", "linewidth": 1})

            # The most-reported single value is named because, for CWEs, it can sit inside Other
            values = mine[kind].value_counts()
            most = sorted(values.index, key=lambda v: (-values[v], v))[0]
            plt.text(0, -1.4, f"n={len(mine)}, most reported {most} ({values[most]})",
                     ha="center", fontsize=9.5, color="#444444")
            if coder == CODERS[0]:
                plt.title(heading, fontsize=11.5, pad=16)
            if slot % len(panels) == 1:
                plt.text(-2.1, 0, coder.upper(), ha="right", va="center", fontsize=15, fontweight="bold")
            slot += 1

    handles = []
    names = []
    for category in order:
        handles.append(Patch(color=colours[category]))
        names.append(category_label(found, kind, category))
    columns = 2 if len(panels) == 2 else 3
    plt.figlegend(handles, names, loc="lower center", ncol=columns, frameon=False, fontsize=9.5)

    # Leave a band at the bottom tall enough for every legend row, so it never covers a pie caption
    legend_rows = -(-len(order) // columns)    # Rounds up
    plt.tight_layout(rect=(0, 0.016 * legend_rows, 1, 1))
    plt.show()
    plt.close()


# Draws one annotated reviewer × generator heatmap on the current subplot
def matrix_heatmap(matrix, cmap, title):
    plt.imshow(matrix.to_numpy(), cmap=cmap)
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            plt.text(j, i, f"{matrix.iat[i, j]:.2f}", ha="center", va="center", fontsize=9)
    plt.xticks(range(len(CODERS)), CODERS)
    plt.yticks(range(len(CODERS)), CODERS)
    plt.xlabel("Generator")
    plt.ylabel("Reviewer")
    plt.title(title)
    plt.colorbar(shrink=0.75)


# Draws Stage 2 reviewer × generator: raw findings per review, and each row divided by its own mean
def plot_reviewer_matrix(reviews):
    matrix = reviewer_matrix(reviews)
    ratio = matrix.div(matrix.mean(axis=1), axis=0)    # 1.0 = that reviewer's average

    plt.figure(figsize=(11, 4.25))
    plt.subplot(1, 2, 1)
    matrix_heatmap(matrix, "YlOrRd", "Findings per review")
    plt.subplot(1, 2, 2)
    matrix_heatmap(ratio, "RdBu_r", "Ratio to the reviewer's own mean")
    show_figure()


# Draws Stage 2 reviewers: volume against High/Critical share, and own-code against other-code means
def plot_reviewer_behaviour(reviews, found):
    behaviour = reviewer_behaviour_table(reviews, found)

    plt.figure(figsize=(11, 4.2))
    plt.subplot(1, 2, 1)
    for _, behaviour_row in behaviour.iterrows():
        plt.scatter(behaviour_row["findings per review"], behaviour_row["High/Critical %"], s=70,
                    color=CODER_COLOURS[behaviour_row["reviewer"]])
        plt.annotate(behaviour_row["reviewer"], (behaviour_row["findings per review"], behaviour_row["High/Critical %"]),
                     xytext=(6, 4), textcoords="offset points")
    plt.xlabel("Findings per review")
    plt.ylabel("High/Critical share of findings (%)")
    plt.title("Volume and severity")

    plt.subplot(1, 2, 2)
    for row, (_, behaviour_row) in enumerate(behaviour.iterrows()):
        plt.plot([behaviour_row["own code"], behaviour_row["other code"]], [row, row], "-", color="#8A9EAA", lw=2)
        plt.scatter(behaviour_row["own code"], row, s=70, color="#C48C54", label="own code" if row == 0 else None)
        plt.scatter(behaviour_row["other code"], row, s=70, color="#408C87",
                    label="other generators' code" if row == 0 else None)
    plt.yticks(range(len(CODERS)), CODERS)
    plt.gca().invert_yaxis()
    plt.xlabel("Findings per review")
    plt.title("Own code and other code", pad=24)
    legend_above(columns=2)
    show_figure()


# Draws the severity mix of each reviewer's Stage 2 findings
def plot_severity_by_reviewer(found):
    panel_found = stage_2(found)
    shares = pd.crosstab(panel_found["sec_review"], panel_found["severity_group"], normalize="index") * 100
    shares = shares.reindex(index=CODERS, columns=SEVERITIES, fill_value=0)
    counts = panel_found["sec_review"].value_counts()

    plt.figure(figsize=(9, 3.4))
    left = np.zeros(len(shares))
    for severity in SEVERITIES:
        widths = shares[severity].to_numpy()
        plt.barh(range(len(shares)), widths, left=left, height=0.62, label=severity,
                 color=SEVERITY_COLOURS[severity], edgecolor="white")
        for row in range(len(shares)):
            if widths[row] >= 5:
                plt.text(left[row] + widths[row] / 2, row, f"{widths[row]:.0f}", ha="center",
                         va="center", fontsize=7.5, color="white")
        left += widths
    plt.yticks(range(len(CODERS)), [f"{c}\n{counts[c]} findings" for c in CODERS])
    plt.gca().invert_yaxis()
    plt.xlim(0, 100)
    plt.xlabel("Share of the reviewer's findings (%)")
    legend_above(columns=5)
    show_figure()


# Draws how many (program, category) pairs were named by exactly 1, 2, 3 or 4 reviewers, CWE and OWASP side by side
def plot_agreement(found):
    plt.figure(figsize=(10, 3.8))
    for slot, (kind, title) in enumerate([("cwe", "CWE label"), ("owasp", "OWASP category")], 1):
        support = support_table(found, kind)
        counts = support["reviewer_support"].value_counts().reindex([1, 2, 3, 4], fill_value=0)

        plt.subplot(1, 2, slot)
        plt.bar(counts.index, counts.values, color=["#BACBD3", "#7DAEB9", "#538C93", "#397175"])
        for x, y in counts.items():
            plt.text(x, y, f"{y}\n({100 * y / counts.sum():.0f}%)", ha="center", va="bottom", fontsize=8)
        plt.xticks([1, 2, 3, 4])
        plt.ylim(0, counts.max() * 1.3)
        plt.xlabel("Reviewers naming it on the same program")
        plt.ylabel("(program, category) pairs")
        plt.title(title)
    show_figure()
