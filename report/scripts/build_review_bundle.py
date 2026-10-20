# Write data/all_security_review_<reviewer>.md, every review in one file per reviewer
#
# Run:  python report/scripts/build_review_bundle.py
#
# The extraction needs checking by hand against the reviews it read, so they are
# combined here in build order, each under its path. There is one file per reviewer
# that has reviews, so each stays small enough to open, and a reviewer with none is
# simply left out. Reviews are numbered from 1 in each file, in build order, the same
# order as findings.csv. Reviews grouped "ignore" are left out, as the reports leave them out.
# Control characters a reviewer wrote are shown as their symbol (NUL as ␀), because one
# NUL makes git treat the whole file as binary and GitHub will not preview it. The reviews
# themselves are not changed. People read these beside findings.csv; no script uses them.


#-----------------------------------------#    imports    #-----------------------------------------#

import sys
import datetime
from pathlib import Path

# Reused from the build, so the bundles can never cover another set than the CSV did
sys.path.insert(0, str(Path(__file__).parent))
from build_findings import REVIEWS_DIR, IGNORE, review_files, review_key_columns, read_text


#-------------------------------------#    Define constants    #-------------------------------------#

DATA_DIR = REVIEWS_DIR.parent / "report" / "data"
OUT_PREFIX = "all_security_review_"                                  # Followed by the reviewer, e.g. _codex.md
DIVIDER = "\n\n---\n\n"
KEPT_CONTROLS = "\n\t"                                                # Control characters left as they are
SYMBOL_START = 0x2400                                                # Unicode control pictures: ␀ is 0x2400 + 0
DELETE_SYMBOL = "\u2421"                                             # ␡, the symbol for DEL (0x7f)


#-------------------------------------#    Define functions    #-------------------------------------#


# Returns the bundle file for a reviewer, e.g. "codex" -> all_security_review_codex.md
def bundle_path(reviewer):
    file_name = OUT_PREFIX + reviewer + ".md"
    return DATA_DIR / file_name


# Deletes the bundles of an earlier build, so a reviewer that is gone leaves no old file behind
def remove_old_bundles():
    old_files = DATA_DIR.glob(OUT_PREFIX + "*.md")

    for old_file in old_files:
        old_file.unlink()


# Returns the title block that opens a bundle, with its reviewer, today's date and the review count
def header(reviewer, review_count):
    today = datetime.date.today()
    return f"# All Security Reviews by {reviewer}\n\n{review_count} reviews combined {today}. Read-only.\n"


# Returns the text with every control character but newline and tab swapped for its symbol
def show_control_characters(text):
    shown = []
    for character in text:
        code = ord(character)

        if character in KEPT_CONTROLS:
            shown.append(character)
        elif code < 0x20:
            shown.append(chr(SYMBOL_START + code))
        elif code == 0x7f:
            shown.append(DELETE_SYMBOL)
        else:
            shown.append(character)

    return "".join(shown)


# Returns one review's section: its number and path as a heading, then the review itself
def section(review_number, review_path, text):
    relative_path = review_path.relative_to(REVIEWS_DIR)
    source = relative_path.as_posix()
    body = show_control_characters(text.strip())

    title = f"### {review_number}) results-cyber/{source}"
    block = DIVIDER + title + "\n\n" + body + "\n"
    return block


# Writes one bundle: the opening line and every review section of its group
def write_bundle(out_file, opening, sections):
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write(opening)

        for block in sections:
            fh.write(block)


#-------------------------------------#    Main execution of program    #-------------------------------------#

def main():

    # The same list the CSV was built from, so the two can never cover different reviews
    review_paths = review_files()

    # Only reviewers found on disk get a list, so a missing reviewer can never break the build
    sections_by_reviewer = {}

    # Kept in build order, the same order as findings.csv
    for review_path in review_paths:
        key_columns = review_key_columns(review_path)

        # Runs the config marks "ignore" are left out, as the reports leave them out
        if key_columns["report_group"] == IGNORE:
            continue

        reviewer = key_columns["sec_review"]
        if reviewer not in sections_by_reviewer:
            sections_by_reviewer[reviewer] = []

        # Numbered from 1 within each reviewer's file
        review_number = len(sections_by_reviewer[reviewer]) + 1

        text = read_text(review_path)
        block = section(review_number, review_path, text)
        sections_by_reviewer[reviewer].append(block)

    remove_old_bundles()

    # One file per reviewer that has reviews, in build order
    for reviewer, sections in sections_by_reviewer.items():
        out_file = bundle_path(reviewer)
        write_bundle(out_file, header(reviewer, len(sections)), sections)
        print(f"wrote {out_file.name}: {len(sections)} reviews")


if __name__ == "__main__":
    main()
