# Name: Ben Pivetta
#
# Write data/all_security_review.md, every review in one file
#
# Run:  python report/scripts/build_review_bundle.py
#
# The extraction needs checking by hand against the reviews it read, so they are
# combined here in build order with each review's path and heading count. People
# read it beside findings.csv; no script uses it.


#-----------------------------------------#    imports    #-----------------------------------------#

import sys
import datetime
from pathlib import Path

# Reused from the build, so the bundle can never cover another set than the CSV did
sys.path.insert(0, str(Path(__file__).parent))
from build_findings import REVIEWS_DIR, FINDING_HEAD_RE, review_files, read_text


#-------------------------------------#    Define constants    #-------------------------------------#

DATA_DIR = REVIEWS_DIR.parent / "report" / "data"
OUT_FILE = DATA_DIR / "all_security_review.md"
DIVIDER = "\n\n---\n\n"


#-------------------------------------#    Define functions    #-------------------------------------#


# Returns how many finding headings the build would have seen in this review
def count_headings(text):
    lines = text.split("\n")

    count = 0
    for line in lines:
        match = FINDING_HEAD_RE.match(line)

        if match:
            count = count + 1

    return count


# Returns the title block that opens the bundle, with today's date and the review count
def header(review_count):
    today = datetime.date.today()
    return f"# All Security Reviews\n\n{review_count} reviews combined {today}. Read-only.\n"


# Returns one review's section: its path, what the build saw, the review itself
def section(review_number, review_path, text, heading_count):
    relative_path = review_path.relative_to(REVIEWS_DIR)
    source = relative_path.as_posix()
    body = text.strip()

    title = f"# [{review_number}] results-cyber/{source}"
    count_line = f"(finding headings: {heading_count})"
    block = DIVIDER + title + "\n" + count_line + "\n\n" + body + "\n"
    return block


# Writes the opening line and every review section
def write_bundle(opening, sections):
    with open(OUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(opening)

        for block in sections:
            fh.write(block)


#-------------------------------------#    Main execution of program    #-------------------------------------#

def main():

    # The same list the CSV was built from, so the two can never cover different reviews
    review_paths = review_files()
    review_count = len(review_paths)
    opening = header(review_count)

    sections = []

    # Numbered in build order, so a review named in findings.csv is one step to find
    for review_number, review_path in enumerate(review_paths, start=1):
        text = read_text(review_path)

        # Counted with the build's own pattern, so it is the count the build saw
        heading_count = count_headings(text)

        block = section(review_number, review_path, text, heading_count)
        sections.append(block)

    write_bundle(opening, sections)
    print(f"wrote {OUT_FILE.name}: {review_count} reviews")


if __name__ == "__main__":
    main()
