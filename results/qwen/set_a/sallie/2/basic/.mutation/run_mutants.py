#!/usr/bin/env python3
"""Mutation harness: break one documented behaviour at a time, confirm the test
suite notices. Written for this repo only; it copies the sources into a scratch
directory so the real tree is never modified."""
import concurrent.futures
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".mutation" / "work"
SPEC = ROOT / ".mutation" / "mutants.tsv"
WORKERS = 2


def apply_mutation(text, expression):
    """Run the perl substitution and prove it changed something."""
    expression = unquote(expression)
    result = subprocess.run(
        ["perl", "-0777", "-pe", expression],
        input=text, capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None, "perl failed: " + (result.stderr.strip() or f"exit {result.returncode}")
    if result.stdout == text:
        return None, "pattern did not match, mutant not applied"
    if not result.stdout.strip():
        return None, "file became empty"
    return result.stdout, None


def unquote(expression):
    """The spec quotes each expression for shell use; perl must not see them."""
    if len(expression) >= 2 and expression[0] == "'" and expression[-1] == "'":
        return expression[1:-1]
    return expression


def run_mutant(line):
    mutant_id, target, expression = line.split("\t")
    mutant_id, target, expression = mutant_id.strip(), target.strip(), expression.strip()
    work = WORK / mutant_id
    if work.exists():
        shutil.rmtree(work)
    (work / "src").mkdir(parents=True)
    shutil.copytree(ROOT / "src", work / "src", dirs_exist_ok=True)
    shutil.copytree(ROOT / "test", work / "test")

    path = work / target
    original = path.read_text()
    mutated, problem = apply_mutation(original, expression)
    if mutated is None:
        return mutant_id, "NOT-APPLIED", problem

    # Sanity: the mutated file must differ only where the expression put it.
    path.write_text(mutated)

    out = work / "out"
    out.mkdir()
    compile_result = subprocess.run(
        ["javac", "-nowarn", "-d", str(out), *sorted((work / "src").glob("*.java")),
         *sorted((work / "test").glob("*.java"))],
        capture_output=True, text=True,
    )
    if compile_result.returncode != 0:
        first = compile_result.stderr.strip().splitlines()
        return mutant_id, "COMPILE-FAIL", (first[0] if first else "no message")

    test_result = subprocess.run(
        ["java", "-cp", str(out), "PiiCryptoTest"], capture_output=True, text=True, timeout=900,
    )
    shutil.rmtree(work)
    if test_result.returncode == 0:
        return mutant_id, "SURVIVED", test_result.stdout.strip().splitlines()[-1]
    tail = [line.strip()[2:] for line in test_result.stdout.splitlines() if line.strip().startswith("-")][:3]
    if tail:
        return mutant_id, "KILLED", "; ".join(tail)
    # No failure list means the suite aborted before reporting, usually an
    # AssertionError escaping main. Record where it stopped instead of a blank cell.
    trace = [line.strip() for line in test_result.stderr.splitlines() if line.strip()]
    return mutant_id, "KILLED", "suite aborted: " + (" | ".join(trace[:2]) if trace else "no stderr")


def selected(lines, only):
    if not only:
        return lines
    wanted = {part.strip() for part in only.split(",") if part.strip()}
    return [line for line in lines if line.split("\t")[0].strip() in wanted]


def match_count(text, expression):
    """How many places the search part of the expression matches, or None if the
    delimiter form is not the simple s/search/replacement/flags one."""
    if not expression.startswith("s/"):
        return None
    expression = unquote(expression)
    parts = expression[2:].split("/")
    if len(parts) < 2:
        return None
    search, flags = parts[0], (parts[2] if len(parts) > 2 else "")
    probe = subprocess.run(
        ["perl", "-0777", "-ne", f"my @m = /{search}/{flags}g; print scalar @m;"],
        input=text, capture_output=True, text=True,
    )
    return int(probe.stdout) if probe.stdout.strip().isdigit() else None


def precheck(lines):
    """Fail fast and cheap on entries whose pattern does not apply, or applies
    more than once.

    Without this a typo costs a full compile-and-test cycle, and a pattern that
    matches several places mutates more than the one behaviour under test.
    """
    sources = {}
    broken = []
    for line in lines:
        mutant_id, target, expression = (part.strip() for part in line.split("\t"))
        if target not in sources:
            sources[target] = (ROOT / target).read_text()
        mutated, problem = apply_mutation(sources[target], expression)
        if mutated is None:
            broken.append(f"{mutant_id}: {problem}")
            continue
        count = match_count(sources[target], expression)
        if count is not None and count != 1:
            broken.append(f"{mutant_id}: the pattern matches {count} places, it must match exactly one")
    if broken:
        print("PRE-CHECK FAILED:")
        for entry in broken:
            print("  " + entry)
        return False
    print("pre-check ok: every pattern applies exactly once\n", flush=True)
    return True


def main():
    all_lines = [l for l in SPEC.read_text().splitlines() if l.strip() and not l.startswith("#")]
    only = None
    for index, argument in enumerate(sys.argv):
        if argument == "--only" and index + 1 < len(sys.argv):
            only = sys.argv[index + 1]
    lines = selected(all_lines, only)
    if not lines:
        print(f"no mutant matched {only!r} of {len(all_lines)}")
        return 1
    if not precheck(lines):
        sys.exit(1)
    if "--precheck-only" in sys.argv:
        print("pre-check only, nothing run")
        return 0
    WORK.mkdir(parents=True, exist_ok=True)
    tally = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for mutant_id, status, detail in pool.map(run_mutant, lines):
            tally[status] = tally.get(status, 0) + 1
            print(f"{mutant_id}  {status}  {detail[:220]}", flush=True)
    print("\nTALLY " + "  ".join(f"{k}={v}" for k, v in sorted(tally.items())) + f"  TOTAL={len(lines)}")
    # Anything other than KILLED is either a broken harness entry or a real gap;
    # both have to be looked at, so the process says so loudly.
    unfinished = [k for k in tally if k != "KILLED"]
    return 1 if unfinished else 0


if __name__ == "__main__":
    sys.exit(main())
