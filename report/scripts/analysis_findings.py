# Tables and figures for the generated report
#
# Imported by report/report_findings.qmd, never run on its own.
#
# Every table and figure is computed from data/findings.csv, which
# scripts/build_findings.py builds from the security reviews: one row per finding,
# plus one empty row per review that found nothing.
#
# Scope: config/benchmark.json decides what prints. report_group on every CSV row is the
# condition it prints under; rows grouped "ignore" are dropped when the CSV loads.
#
# Two selections of reviews are used, and every caption says which:
#   self-review  - each generator reviewing its own code
#   panel        - every review of the conditions that contain external reviews, self and
#                  external alike (the reviewer comparison set)


#-----------------------------------------#    imports    #-----------------------------------------#

import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from pathlib import Path


#-------------------------------------#    Define constants    #-------------------------------------#

# Define the data file
REPO = Path(__file__).resolve().parents[2]                           # Repo root, so the CSV is found from any folder
CSV_PATH = REPO / "report" / "data" / "findings.csv"
CONFIG_PATH = REPO / "config" / "benchmark.json"

# Define the study shape
CODERS = ["agy", "claude", "codex", "qwen"]                          # The four coding assistants, also the reviewers
CODER_COLOURS = {"agy": "#4C72B0", "claude": "#DD8452", "codex": "#55A868", "qwen": "#C44E52"}
ANCHORS = {1: "CWE-1004", 2: "CWE-321", 3: "CWE-89", 4: "CWE-256", 5: "CWE-307", 6: "CWE-778"}

# Define the report conditions: config/benchmark.json holds the names, in print order.
# Colours cycle a palette, so any number of conditions draws
REPORT_ORDER = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["report_order"]
CONDITION_PALETTE = ["#6482AD", "#C48C54", "#408C87", "#8172B2", "#A5694F", "#5F9EA0"]
GROUP_COLOURS = {}
for position, group in enumerate(REPORT_ORDER):
    GROUP_COLOURS[group] = CONDITION_PALETTE[position % len(CONDITION_PALETTE)]

# Define severity and OWASP categories
SEVERITIES = ["Critical", "High", "Medium", "Low", "Other"]          # Other is anything outside the four words
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

TOP_CWES = 14                                                        # CWEs that get their own bar, row or slice
LABEL_MIN_SHARE = 5                                                  # Thinner segments and slices go unlabelled
TITLE_MAX_LENGTH = 45                                                # Longer CWE titles are cut at a word

# Define colours and plot defaults
CATEGORY_COLOURS = ["#1F77B4", "#E6A800", "#DE9ED6", "#843C39", "#2CA02C", "#E7298A", "#B5DF6B",
                    "#E41A1C", "#66C2A5", "#6A3D9A", "#9EDAE5", "#17BECF", "#8C9D4F", "#D95F02"]
REST_COLOUR = "#7F7F7F"                                              # Always the colour of "the rest" group

plt.rcParams.update({"figure.dpi": 150, "font.size": 9,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "axes.titleweight": "bold"})


#-------------------------------------#    Define table functions    #-------------------------------------#


# Returns findings.csv as one table, with the columns every later step groups on
def load_findings(path=CSV_PATH):
    df = pd.read_csv(path, encoding="utf-8-sig")

    # report_group "ignore" is the config's mark for runs no report covers
    df = df[df["report_group"] != "ignore"].copy()

    # A clean review has no sec_id, so only rows with one are findings
    df["has_finding"] = df["sec_id"].notna()

    df["severity_group"] = df["severity"].where(df["severity"].isin(SEVERITIES), "Other")
    df["high_plus"] = df["severity"].isin(["Critical", "High"])

    rule_of = {}
    for rule, cwes in RULE_CWES.items():
        for cwe in cwes:
            rule_of[f"CWE-{cwe}"] = rule
    df["rule"] = df["cwe"].map(rule_of).fillna(NO_RULE)

    # One generated program = generator + folder + task + condition; a review adds the reviewer
    programs = []
    for dev, folder, task, group in zip(df["dev_llm"], df["folder"], df["task"], df["report_group"]):
        programs.append(f"{dev}/{folder}/{task}/{group}")
    df["program"] = programs

    return df


# Returns only the rows that are findings, dropping the clean-review rows
def findings_only(df):
    found = df[df["has_finding"]]
    return found


# Returns one row per review: findings, High/Critical count, and whether the task's anchor CWE was named
def review_table(df):
    review_keys = ["location", "program", "sec_review", "dev_llm", "folder", "task", "report_group"]

    df = df.copy()
    df["anchor_hit"] = df["cwe"] == df["task"].map(ANCHORS)

    grouped = df.groupby(review_keys)
    reviews = grouped.agg(findings=("has_finding", "sum"),
                          high_plus=("high_plus", "sum"),
                          anchor_reported=("anchor_hit", "any"))
    reviews = reviews.reset_index()
    return reviews


# Returns only the self-reviews (a generator reviewing its own code) from a review or finding table
def self_review(table):
    own = table[table["sec_review"] == table["dev_llm"]]
    return own


# Returns the conditions that contain external reviews (a reviewer reading another
# generator's code). The reviewer-panel figures draw exactly these, so which conditions
# they are follows what n8n ran, not a hard-coded folder or name
def external_groups(table):
    external = table["sec_review"] != table["dev_llm"]

    groups = []
    for group in REPORT_ORDER:
        if external[table["report_group"] == group].any():
            groups.append(group)
    return groups


# Returns every row of the panel conditions: the whole reviewer comparison set, self and external
def panel(table):
    return table[table["report_group"].isin(external_groups(table))]


# Returns a table as Markdown text, so Quarto numbers it and Word gets a real table
def markdown_table(table, decimals=2):
    table = table.round(decimals)

    # Numbers line up on the right, text on the left
    headings = []
    alignment = []
    for column in table.columns:
        headings.append(str(column))
        if pd.api.types.is_numeric_dtype(table[column]):
            alignment.append("---:")
        else:
            alignment.append(":---")

    lines = []
    lines.append("| " + " | ".join(headings) + " |")
    lines.append("|" + "|".join(alignment) + "|")

    for _, row in table.iterrows():
        cells = []
        for value in row:
            if pd.isna(value):
                cells.append("")
            else:
                cells.append(str(value))
        lines.append("| " + " | ".join(cells) + " |")

    markdown = "\n".join(lines)
    return markdown


# Returns the counts the data checks quote, one row per check
def quality_checks(df):
    reviews = review_table(df)
    found = findings_only(df)

    reviewers_per_program = panel(reviews).groupby("program")["sec_review"].nunique()
    clean_reviews = reviews["findings"] == 0
    missing_names = df[["sec_review", "dev_llm"]].isna().any(axis=1)
    panel_reviewers = panel(reviews)["sec_review"].nunique()
    full_panels = reviewers_per_program == panel_reviewers
    other_severity = found["severity_group"] == "Other"
    repeated_ids = found.duplicated(["location", "sec_id"])

    checks = {
        "CSV rows": len(df),
        "Recorded findings": len(found),
        "Reviews": len(reviews),
        "Reviews with no findings": int(clean_reviews.sum()),
        "Generated programs": reviews["program"].nunique(),
        "Rows missing reviewer or generator": int(missing_names.sum()),
        f"Programs read by all {panel_reviewers} reviewers": int(full_panels.sum()),
        "Duplicate CSV rows": int(df.duplicated().sum()),
        "Findings with no CWE": int(found["cwe"].isna().sum()),
        "Findings with non-standard severity": int(other_severity.sum()),
        "Repeated sec_id within one review": int(repeated_ids.sum()),
    }

    table = pd.DataFrame({"check": list(checks), "value": list(checks.values())})
    return table


# Returns one row per condition: programs, reviews (self and external), clean reviews and findings
def condition_summary(df):
    reviews = review_table(df)

    summary = []
    for group in REPORT_ORDER:
        subset = reviews[reviews["report_group"] == group]
        own_reviews = self_review(subset)
        clean_reviews = subset["findings"] == 0

        summary.append({
            "condition": group,
            "programs": subset["program"].nunique(),
            "self-reviews": len(own_reviews),
            "external reviews": len(subset) - len(own_reviews),
            "reviews with no findings": int(clean_reviews.sum()),
            "findings": int(subset["findings"].sum())
        })

    table = pd.DataFrame(summary)
    return table


# Returns the paired comparison: the first two conditions in print order whose programs
# overlap, matched on author set, task and generator. The pair names ride in pairs.attrs,
# so the table and the figure label themselves from the data rather than from names in code
def paired_table(reviews):
    keys = ["folder", "task", "dev_llm"]
    pair = None

    for first_position, first in enumerate(REPORT_ORDER):
        for second in REPORT_ORDER[first_position + 1:]:
            first_keys = set(map(tuple, reviews[reviews["report_group"] == first][keys].to_numpy()))
            second_keys = set(map(tuple, reviews[reviews["report_group"] == second][keys].to_numpy()))
            if len(first_keys & second_keys) > 0:
                pair = (first, second)
                break
        if pair is not None:
            break

    first, second = pair
    both = reviews[reviews["report_group"].isin([first, second])]
    pairs = both.pivot_table(index=keys, columns="report_group", values="findings")
    pairs = pairs.reset_index()

    # Positive = more findings under the second condition
    pairs["delta"] = pairs[second] - pairs[first]
    pairs.attrs["pair"] = (first, second)
    return pairs


# Returns the paired effect overall and per generator, with a 10,000-draw bootstrap 95% interval.
# One seeded generator is shared across the rows, so the intervals repeat exactly
def paired_effect_table(pairs, draws=10000, seed=6224):
    rng = np.random.default_rng(seed)
    first, second = pairs.attrs["pair"]

    groups = [("all", pairs)]
    for coder in CODERS:
        groups.append((coder, pairs[pairs["dev_llm"] == coder]))

    summary = []
    for scope, group in groups:
        deltas = group["delta"].to_numpy(float)

        # Each draw resamples the pairs with replacement and keeps the mean
        picks = rng.integers(0, len(deltas), size=(draws, len(deltas)))
        resampled_means = deltas[picks].mean(axis=1)
        low, high = np.quantile(resampled_means, [0.025, 0.975])

        summary.append({
            "scope": scope,
            "pairs": len(deltas),
            f"{first} mean": group[first].mean(),
            f"{second} mean": group[second].mean(),
            "mean delta": deltas.mean(),
            "median delta": np.median(deltas),
            "fewer": int((deltas < 0).sum()),
            "more": int((deltas > 0).sum()),
            "ties": int((deltas == 0).sum()),
            "CI low": low,
            "CI high": high
        })

    table = pd.DataFrame(summary)
    return table


# Returns findings per self-review, median and High/Critical share for each condition
def self_review_table(reviews):
    own_reviews = self_review(reviews)

    summary = []
    for group in REPORT_ORDER:
        subset = own_reviews[own_reviews["report_group"] == group]
        findings = subset["findings"].sum()
        high_plus = subset["high_plus"].sum()

        summary.append({
            "condition": group,
            "self-reviews": len(subset),
            "findings": int(findings),
            "findings per review": subset["findings"].mean(),
            "median": subset["findings"].median(),
            "High/Critical %": 100 * high_plus / findings
        })

    table = pd.DataFrame(summary)
    return table


# Returns the values of a value_counts() result, most counted first, ties broken by the value itself
def ranked_by_count(counts):
    ranking = []
    for value, count in counts.items():
        ranking.append((-count, value))
    ranking.sort()

    ranked = []
    for negative_count, value in ranking:
        ranked.append(value)
    return ranked


# Returns the top CWEs by count, ties broken by CWE id so the list never changes
def top_cwes(found, top_count=TOP_CWES):
    counts = found["cwe"].value_counts()
    ranked = ranked_by_count(counts)
    return ranked[:top_count]


# Returns the title the reviewers most often gave a CWE
def cwe_title(found, cwe):
    titles = found[found["cwe"] == cwe]["cwe_title"]
    title = titles.value_counts().index[0]
    return title


# Returns the top CWEs with their count and running share of all findings
def top_cwe_table(found):
    counts = found["cwe"].value_counts()

    summary = []
    running = 0
    for rank, cwe in enumerate(top_cwes(found), 1):
        running += counts[cwe]
        cumulative_share = round(100 * running / len(found), 1)
        summary.append({"rank": rank, "CWE": cwe, "title": cwe_title(found, cwe), "findings": counts[cwe],
                        "cumulative %": cumulative_share})

    table = pd.DataFrame(summary)
    return table


# Returns the categories of one kind in display order, rest group last.
# kind is "cwe" (top CWEs + Other), "owasp" (A01-A10 + Unmapped) or "rule" (eight rules + No rule)
def category_order(found, kind):
    if kind == "cwe":
        order = top_cwes(found) + ["Other"]
    elif kind == "owasp":
        order = OWASP_ORDER
    else:
        order = RULES + [NO_RULE]
    return order


# Returns each finding's category of the given kind
def category_of(found, kind, vocabulary=None):
    if kind == "cwe":
        categories = found["cwe"].where(found["cwe"].isin(vocabulary), "Other")
    else:
        categories = found[kind]
    return categories


# Returns {category: colour}, grey for the rest group
def category_colours(found, kind):
    order = category_order(found, kind)

    colours = {}
    for position, category in enumerate(order[:-1]):
        colours[category] = CATEGORY_COLOURS[position % len(CATEGORY_COLOURS)]
    colours[order[-1]] = REST_COLOUR
    return colours


# Returns the long label for a category, used in legends and tables
def category_label(found, kind, category):
    if kind == "owasp":
        return f"{category} {OWASP_NAMES[category]}"

    if kind == "cwe" and category != "Other":
        title = cwe_title(found, category)

        # Cut at a word, not mid-word
        if len(title) > TITLE_MAX_LENGTH:
            title = title[:TITLE_MAX_LENGTH].rsplit(" ", 1)[0] + "..."
        return f"{category} {title}"

    return category


# Returns the long label of every category in a list
def category_labels(found, kind, categories):
    labels = []
    for category in categories:
        labels.append(category_label(found, kind, category))
    return labels


# Returns findings per self-review for every category of a kind, one column per condition
def category_rates(found, reviews, kind):
    own_findings = self_review(found)
    reviews_per_group = self_review(reviews).groupby("report_group").size()

    categories = category_of(own_findings, kind, top_cwes(found))
    counts = pd.crosstab(categories, own_findings["report_group"])
    counts = counts.reindex(index=category_order(found, kind), columns=REPORT_ORDER, fill_value=0)

    rates = counts / reviews_per_group[REPORT_ORDER]
    return rates


# Returns category_rates as a display table, one column per condition in print order
def category_rate_table(found, reviews, kind):
    rates = category_rates(found, reviews, kind)

    table = pd.DataFrame({"category": category_labels(found, kind, rates.index)})
    for group in REPORT_ORDER:
        table[group] = rates[group].to_numpy()
    return table


# Returns the rule mapping as a table: each rule, its CWEs, and how many findings fall under it
def rule_table(found):
    rows = []
    for rule in RULES + [NO_RULE]:
        rule_findings = found[found["rule"] == rule]

        if rule == NO_RULE:
            listed = "every CWE not listed above"
        else:
            cwe_names = []
            for cwe_number in sorted(RULE_CWES[rule]):
                cwe_names.append(f"CWE-{cwe_number}")
            listed = ", ".join(cwe_names)

        share = round(100 * len(rule_findings) / len(found), 1)
        rows.append({"rule": rule, "CWEs": listed, "findings": len(rule_findings), "% of all findings": share})

    table = pd.DataFrame(rows)
    return table


# Returns the panel findings of one review context: "self-review", "external review" or the whole panel
def context_findings(found, context):
    subset = panel(found)
    is_own = subset["sec_review"] == subset["dev_llm"]

    if context == "self-review":
        return subset[is_own]
    if context == "external review":
        return subset[~is_own]
    return subset


# Returns mean findings per review: one row per reviewer, one column per generator (the panel)
def reviewer_matrix(reviews):
    panel_reviews = panel(reviews)
    matrix = panel_reviews.pivot_table(index="sec_review", columns="dev_llm", values="findings", aggfunc="mean")
    matrix = matrix.reindex(index=CODERS, columns=CODERS)
    return matrix


# Returns one row per panel reviewer: volume, High/Critical share, own-code vs other-code means
def reviewer_behaviour_table(reviews, found):
    panel_reviews = panel(reviews)
    panel_found = panel(found)

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

    table = pd.DataFrame(summary)
    return table


# Returns, for each panel program and category, how many reviewers named it.
# For OWASP, Unmapped is left out: two different off-list CWEs are not an agreement
def support_table(found, kind="cwe"):
    subset = panel(found)
    if kind == "owasp":
        subset = subset[subset["owasp"] != "Unmapped"]

    support = subset.groupby(["program", kind])["sec_review"].nunique()
    support = support.rename("reviewer_support")
    support = support.reset_index()
    return support


# Returns the share of (program, category) pairs named by exactly 1, 2, 3 and 4 reviewers
def support_share_table(found):
    rows = []
    for kind, name in [("cwe", "CWE label"), ("owasp", "OWASP category")]:
        support = support_table(found, kind)["reviewer_support"]

        row = {"level": name, "pairs": len(support)}
        for reviewer_count in [1, 2, 3, 4]:
            share = 100 * (support == reviewer_count).mean()
            row[f"named by {reviewer_count} %"] = round(share, 1)
        rows.append(row)

    table = pd.DataFrame(rows)
    return table


# Returns the Jaccard overlap of CWE (or OWASP) sets for every reviewer pair on every panel program.
# When both reviewers named nothing the overlap is undefined (NaN), not 1
def reviewer_pair_jaccard(reviews, found, kind="cwe"):
    subset = panel(found)
    if kind == "owasp":
        subset = subset[subset["owasp"] != "Unmapped"]

    rows = []
    for program in panel(reviews)["program"].unique():
        named = {}
        for reviewer in CODERS:
            picked = subset[(subset["program"] == program) & (subset["sec_review"] == reviewer)]
            named[reviewer] = set(picked[kind])

        for position, first in enumerate(CODERS):
            for second in CODERS[position + 1:]:
                both = named[first] & named[second]
                either = named[first] | named[second]

                if either:
                    jaccard = len(both) / len(either)
                else:
                    jaccard = np.nan

                rows.append({"program": program, "reviewer_A": first, "reviewer_B": second,
                             "shared": len(both), "union": len(either), "jaccard": jaccard})

    table = pd.DataFrame(rows)
    return table


# Returns mean Jaccard per reviewer pair, for CWE labels and OWASP categories side by side
def jaccard_pair_table(reviews, found):
    pair_keys = ["reviewer_A", "reviewer_B"]
    cwe_pairs = reviewer_pair_jaccard(reviews, found, "cwe")
    owasp_pairs = reviewer_pair_jaccard(reviews, found, "owasp")
    cwe_means = cwe_pairs.groupby(pair_keys)["jaccard"].mean()
    owasp_means = owasp_pairs.groupby(pair_keys)["jaccard"].mean()

    table = pd.DataFrame({"CWE Jaccard": cwe_means, "OWASP Jaccard": owasp_means})
    table = table.reset_index()
    table.insert(0, "reviewer pair", table["reviewer_A"] + " / " + table["reviewer_B"])
    table = table.drop(columns=pair_keys)
    return table


#-------------------------------------#    Define figure functions    #-------------------------------------#

# Titles live in the report's figure captions, so the plots carry panel titles only


# Lays out the current figure and shows it in the report
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


# Writes each cell's value in the middle of an image grid (a heatmap)
def label_cells(grid, value_format, fontsize=None):
    for row in range(grid.shape[0]):
        for column in range(grid.shape[1]):
            text = value_format.format(grid.iat[row, column])
            plt.text(column, row, text, ha="center", va="center", fontsize=fontsize)


# Returns one label per task from a format with {task} and, optionally, its {anchor} CWE
def task_labels(tasks, label_format="Task {task}"):
    labels = []
    for task in tasks:
        labels.append(label_format.format(task=task, anchor=ANCHORS[task]))
    return labels


# Draws completed reviews per task × generator cell, one panel per condition (0 would mark a missing review)
def plot_completeness(reviews):
    plt.figure(figsize=(11, 3.6))

    for slot, group in enumerate(REPORT_ORDER, 1):
        subset = reviews[reviews["report_group"] == group]
        grid = subset.pivot_table(index="task", columns="dev_llm", values="location", aggfunc="count", fill_value=0)
        grid = grid.reindex(columns=CODERS, fill_value=0)

        plt.subplot(1, len(REPORT_ORDER), slot)
        plt.imshow(grid.to_numpy(), cmap="Blues", vmin=0, vmax=4)
        for row in range(grid.shape[0]):
            for column in range(grid.shape[1]):
                plt.text(column, row, str(grid.iat[row, column]), ha="center", va="center", color="white")
        plt.xticks(range(len(CODERS)), CODERS)
        plt.yticks(range(len(grid.index)), task_labels(grid.index))
        plt.title(group)

    show_figure()


# Draws the paired differences: one dot per pair, the generator's mean as a diamond
def plot_paired_effect(pairs):
    first, second = pairs.attrs["pair"]

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
    plt.xlabel(f"{second} minus {first} findings, per matched pair")
    show_figure()


# Draws a box per condition with every self-review as a dot
def plot_findings_distribution(reviews):
    own_reviews = self_review(reviews)

    groups = []
    labels = []
    for group in REPORT_ORDER:
        values = own_reviews[own_reviews["report_group"] == group]["findings"]
        groups.append(values)
        labels.append(f"{group}\n(n={len(values)})")

    plt.figure(figsize=(7.5, 4))
    plt.boxplot(groups, tick_labels=labels, showmeans=True)

    for position, (group, values) in enumerate(zip(REPORT_ORDER, groups), 1):
        # Spreads the dots across the box so they do not overlap
        spread = position + np.linspace(-0.13, 0.13, len(values))
        plt.scatter(spread, values, alpha=0.5, s=16, color=GROUP_COLOURS[group])

    plt.ylabel("Findings per self-review")
    show_figure()


# Draws grouped vertical bars: one group per row of the table, one bar per condition, values on top
def grouped_bars(table, ylabel, value_format="{:.1f}"):
    centres = np.arange(len(table))
    width = 0.78 / len(REPORT_ORDER)

    for offset, group in enumerate(REPORT_ORDER):
        positions = centres + (offset - (len(REPORT_ORDER) - 1) / 2) * width
        plt.bar(positions, table[group], width, label=group, color=GROUP_COLOURS[group])
        for position, value in zip(positions, table[group]):
            plt.text(position, value, value_format.format(value), ha="center", va="bottom", fontsize=7.5)

    plt.xticks(centres, table.index)
    plt.ylabel(ylabel)
    plt.ylim(0, table[REPORT_ORDER].to_numpy().max() * 1.15)
    legend_above()


# Draws mean findings per self-review for each generator and condition
def plot_findings_by_generator(reviews):
    own_reviews = self_review(reviews)
    means = own_reviews.pivot_table(index="dev_llm", columns="report_group", values="findings")
    means = means.reindex(CODERS)

    plt.figure(figsize=(8, 4))
    grouped_bars(means, "Findings per self-review")
    show_figure()


# Draws mean findings per self-review for each task (rows) and condition (columns)
def plot_findings_by_task(reviews):
    own_reviews = self_review(reviews)
    grid = own_reviews.pivot_table(index="task", columns="report_group", values="findings")
    grid = grid.reindex(columns=REPORT_ORDER)

    plt.figure(figsize=(7.5, 4.2))
    plt.imshow(grid.to_numpy(), cmap="YlGnBu", aspect="auto")
    label_cells(grid, "{:.2f}")
    plt.xticks(range(len(REPORT_ORDER)), REPORT_ORDER)
    plt.yticks(range(len(grid.index)), task_labels(grid.index, "Task {task} ({anchor})"))
    plt.colorbar(label="Findings per self-review")
    show_figure()


# Draws the share of self-reviews that named the task's own anchor CWE, every bar labelled including 0%
def plot_anchor_reporting(reviews):
    own_reviews = self_review(reviews)
    rates = own_reviews.pivot_table(index="task", columns="report_group", values="anchor_reported") * 100
    rates.index = task_labels(rates.index, "Task {task}\n{anchor}")

    plt.figure(figsize=(9, 4))
    grouped_bars(rates, "Self-reviews naming the anchor CWE (%)", "{:g}%")
    plt.ylim(0, 100)
    show_figure()


# Draws 100% stacked horizontal bars from a table of shares, one bar per row, first row on top
def stacked_shares(shares, colours, labels, row_labels, xlabel):
    rows = range(len(shares))
    left = np.zeros(len(shares))

    for column in shares.columns:
        widths = shares[column].to_numpy()
        plt.barh(rows, widths, left=left, height=0.62, color=colours[column], edgecolor="white",
                 label=labels[column])

        # Segments too thin for a number are left unlabelled
        for row in rows:
            if widths[row] >= LABEL_MIN_SHARE:
                plt.text(left[row] + widths[row] / 2, row, f"{widths[row]:.0f}", ha="center",
                         va="center", fontsize=7.5, color="white")
        left += widths

    plt.yticks(rows, row_labels)
    plt.gca().invert_yaxis()
    plt.xlim(0, 100)
    plt.xlabel(xlabel)


# Returns one bar label per condition: its name and how many findings the bar covers
def condition_labels(findings_per_group):
    labels = []
    for group in REPORT_ORDER:
        labels.append(f"{group}\n{findings_per_group[group]} findings")
    return labels


# Draws the severity mix of each condition's self-review findings
def plot_severity_by_condition(found):
    own_findings = self_review(found)
    shares = pd.crosstab(own_findings["report_group"], own_findings["severity_group"], normalize="index") * 100
    shares = shares.reindex(index=REPORT_ORDER, columns=SEVERITIES, fill_value=0)
    findings_per_group = own_findings["report_group"].value_counts()

    severity_labels = {}
    for severity in SEVERITIES:
        severity_labels[severity] = severity

    plt.figure(figsize=(9, 3.2))
    stacked_shares(shares, SEVERITY_COLOURS, severity_labels, condition_labels(findings_per_group),
                   "Share of the condition's findings (%)")
    legend_above(columns=5)
    show_figure()


# Draws findings per self-review for each category (CWE, OWASP or rule), one bar per condition.
# For CWEs the Other row (over 100 CWEs combined) is left off, as it would flatten every other bar
def plot_category_rates(found, reviews, kind):
    rates = category_rates(found, reviews, kind)
    if kind == "cwe":
        rates = rates.drop(index="Other")

    rows = np.arange(len(rates))
    height = 0.78 / len(REPORT_ORDER)

    plt.figure(figsize=(9, 0.42 * len(rates) + 1.4))
    for offset, group in enumerate(REPORT_ORDER):
        plt.barh(rows + (offset - (len(REPORT_ORDER) - 1) / 2) * height, rates[group], height, label=group,
                 color=GROUP_COLOURS[group])
    plt.yticks(rows, category_labels(found, kind, rates.index))
    plt.gca().invert_yaxis()
    plt.xlabel("Findings per self-review")
    legend_above()
    show_figure()


# Draws the make-up of each condition's self-review findings by category (CWE, OWASP or rule)
def plot_category_mix(found, kind):
    own_findings = self_review(found)
    categories = category_of(own_findings, kind, top_cwes(found))
    order = category_order(found, kind)

    shares = pd.crosstab(own_findings["report_group"], categories, normalize="index") * 100
    shares = shares.reindex(index=REPORT_ORDER, columns=order, fill_value=0)
    findings_per_group = own_findings["report_group"].value_counts()

    labels = {}
    for category in order:
        labels[category] = category_label(found, kind, category)

    plt.figure(figsize=(11, 3.6))
    stacked_shares(shares, category_colours(found, kind), labels, condition_labels(findings_per_group),
                   "Share of the condition's findings (%)")
    legend_right()
    show_figure()


# Draws findings per self-review for each category (rows) and task (columns), all three conditions together
def plot_category_by_task(found, reviews, kind):
    own_findings = self_review(found)
    reviews_per_task = self_review(reviews).groupby("task").size()

    categories = category_of(own_findings, kind, top_cwes(found))
    counts = pd.crosstab(categories, own_findings["task"])
    counts = counts.reindex(index=category_order(found, kind), fill_value=0)

    # Each column divided by that task's self-review count
    rates = counts / reviews_per_task

    plt.figure(figsize=(9, 0.4 * len(rates) + 1.5))
    plt.imshow(rates.to_numpy(), cmap="YlOrBr", aspect="auto")
    label_cells(rates, "{:.2f}", fontsize=7)
    plt.xticks(range(rates.shape[1]), task_labels(rates.columns, "Task {task}\n{anchor}"))
    plt.yticks(range(len(rates)), category_labels(found, kind, rates.index))
    plt.colorbar(label="Findings per self-review")
    show_figure()


# Returns the pie panels: one per condition (self-review), or panel self-review against external
# review. Each panel is its column heading and the findings it covers
def pie_panels(found, panel_set):
    panels = []

    if panel_set == "conditions":
        own_findings = self_review(found)
        for group in REPORT_ORDER:
            heading = f"{group}\nself-review"
            panels.append((heading, own_findings[own_findings["report_group"] == group]))
    else:
        panel_group = external_groups(found)[0]
        panels.append((f"{panel_group}\nself-review", context_findings(found, "self-review")))
        panels.append((f"{panel_group}\nexternal review", context_findings(found, "external review")))

    return panels


# Draws one pie per generator (rows) and panel (columns). Slices of 5% or more are labelled
def plot_category_pies(found, kind, panel_set="conditions"):
    order = category_order(found, kind)
    colours = category_colours(found, kind)
    vocabulary = top_cwes(found)
    panels = pie_panels(found, panel_set)

    plt.figure(figsize=(4.6 * len(panels) + 1, 18.5))
    slot = 1
    for coder in CODERS:
        for heading, subset in panels:
            mine = subset[subset["dev_llm"] == coder]
            counts = category_of(mine, kind, vocabulary).value_counts()

            sizes = []
            slice_colours = []
            labels = []
            for category in order:
                if counts.get(category, 0) == 0:
                    continue
                sizes.append(counts[category])
                slice_colours.append(colours[category])

                share = 100 * counts[category] / len(mine)
                if share >= LABEL_MIN_SHARE:
                    labels.append(f"{category} {share:.0f}%")
                else:
                    labels.append("")

            plt.subplot(len(CODERS), len(panels), slot)
            plt.pie(sizes, labels=labels, colors=slice_colours, startangle=90, counterclock=False,
                    labeldistance=1.08, textprops={"fontsize": 8.5},
                    wedgeprops={"edgecolor": "white", "linewidth": 1})

            # The most-reported single value is named because, for CWEs, it can sit inside Other
            values = mine[kind].value_counts()
            most = ranked_by_count(values)[0]
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

    if len(panels) == 2:
        legend_columns = 2
    else:
        legend_columns = 3
    plt.figlegend(handles, names, loc="lower center", ncol=legend_columns, frameon=False, fontsize=9.5)

    # Leave a band at the bottom tall enough for every legend row, so it never covers a pie caption
    legend_rows = int(np.ceil(len(order) / legend_columns))
    plt.tight_layout(rect=(0, 0.016 * legend_rows, 1, 1))
    plt.show()
    plt.close()


# Draws one annotated reviewer × generator heatmap on the current subplot
def matrix_heatmap(matrix, cmap, title):
    plt.imshow(matrix.to_numpy(), cmap=cmap)
    label_cells(matrix, "{:.2f}", fontsize=9)
    plt.xticks(range(len(CODERS)), CODERS)
    plt.yticks(range(len(CODERS)), CODERS)
    plt.xlabel("Generator")
    plt.ylabel("Reviewer")
    plt.title(title)
    plt.colorbar(shrink=0.75)


# Draws the panel reviewer × generator: raw findings per review, and each row divided by its own mean
def plot_reviewer_matrix(reviews):
    matrix = reviewer_matrix(reviews)

    # 1.0 = that reviewer's average
    ratio = matrix.div(matrix.mean(axis=1), axis=0)

    plt.figure(figsize=(11, 4.25))
    plt.subplot(1, 2, 1)
    matrix_heatmap(matrix, "YlOrRd", "Findings per review")
    plt.subplot(1, 2, 2)
    matrix_heatmap(ratio, "RdBu_r", "Ratio to the reviewer's own mean")
    show_figure()


# Draws panel reviewers: volume against High/Critical share, and own-code against other-code means
def plot_reviewer_behaviour(reviews, found):
    behaviour = reviewer_behaviour_table(reviews, found)

    plt.figure(figsize=(11, 4.2))
    plt.subplot(1, 2, 1)
    for _, reviewer_row in behaviour.iterrows():
        reviewer = reviewer_row["reviewer"]
        volume = reviewer_row["findings per review"]
        severe_share = reviewer_row["High/Critical %"]

        plt.scatter(volume, severe_share, s=70, color=CODER_COLOURS[reviewer])
        plt.annotate(reviewer, (volume, severe_share), xytext=(6, 4), textcoords="offset points")
    plt.xlabel("Findings per review")
    plt.ylabel("High/Critical share of findings (%)")
    plt.title("Volume and severity")

    plt.subplot(1, 2, 2)
    for row, (_, reviewer_row) in enumerate(behaviour.iterrows()):
        own_code = reviewer_row["own code"]
        other_code = reviewer_row["other code"]

        # Only the first row's dots go in the legend
        if row == 0:
            own_label = "own code"
            other_label = "other generators' code"
        else:
            own_label = None
            other_label = None

        plt.plot([own_code, other_code], [row, row], "-", color="#8A9EAA", lw=2)
        plt.scatter(own_code, row, s=70, color="#C48C54", label=own_label)
        plt.scatter(other_code, row, s=70, color="#408C87", label=other_label)
    plt.yticks(range(len(CODERS)), CODERS)
    plt.gca().invert_yaxis()
    plt.xlabel("Findings per review")
    plt.title("Own code and other code", pad=24)
    legend_above(columns=2)
    show_figure()


# Draws the severity mix of each panel reviewer's findings
def plot_severity_by_reviewer(found):
    panel_found = panel(found)
    shares = pd.crosstab(panel_found["sec_review"], panel_found["severity_group"], normalize="index") * 100
    shares = shares.reindex(index=CODERS, columns=SEVERITIES, fill_value=0)
    counts = panel_found["sec_review"].value_counts()

    severity_labels = {}
    for severity in SEVERITIES:
        severity_labels[severity] = severity

    reviewer_labels = []
    for coder in CODERS:
        reviewer_labels.append(f"{coder}\n{counts[coder]} findings")

    plt.figure(figsize=(9, 3.4))
    stacked_shares(shares, SEVERITY_COLOURS, severity_labels, reviewer_labels,
                   "Share of the reviewer's findings (%)")
    legend_above(columns=5)
    show_figure()


# Draws how many (program, category) pairs were named by exactly 1, 2, 3 or 4 reviewers, CWE and OWASP side by side
def plot_agreement(found):
    bar_colours = ["#BACBD3", "#7DAEB9", "#538C93", "#397175"]

    plt.figure(figsize=(10, 3.8))
    for slot, (kind, title) in enumerate([("cwe", "CWE label"), ("owasp", "OWASP category")], 1):
        support = support_table(found, kind)
        counts = support["reviewer_support"].value_counts().reindex([1, 2, 3, 4], fill_value=0)

        plt.subplot(1, 2, slot)
        plt.bar(counts.index, counts.values, color=bar_colours)
        for reviewer_count, pairs in counts.items():
            share = 100 * pairs / counts.sum()
            plt.text(reviewer_count, pairs, f"{pairs}\n({share:.0f}%)", ha="center", va="bottom", fontsize=8)
        plt.xticks([1, 2, 3, 4])
        plt.ylim(0, counts.max() * 1.3)
        plt.xlabel("Reviewers naming it on the same program")
        plt.ylabel("(program, category) pairs")
        plt.title(title)
    show_figure()
