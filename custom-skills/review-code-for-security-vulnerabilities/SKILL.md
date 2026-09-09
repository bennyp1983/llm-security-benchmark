---
name: review-code-for-security-vulnerabilities
description: >-
  Reviews application source code for security vulnerabilities. First works out
  what the code actually does, then searches THIS skill library for the
  specialised skills that match the code's security-relevant behaviour, then
  applies those skills to audit the code and reports findings with CWE ids and
  fixes. Use this whenever asked to review, audit, or security-check source
  code, do a secure code review, find vulnerabilities, or check code against the
  OWASP Top 10 or CWE. Keywords: code review, secure code review, source code
  audit, find vulnerabilities, security assessment of code, OWASP, CWE, SQL
  injection, weak cryptography, hardcoded secrets, insecure deserialization,
  XSS, SSRF, authentication and session flaws, JWT verification, password
  storage.
domain: cybersecurity
subdomain: application-security
tags:
  - code-review
  - security-review
  - owasp
  - cwe
  - sast
  - dispatcher
version: "1.1"
license: Apache-2.0
---
# Reviewing Code for Security Vulnerabilities

## Overview

This is a router skill. On its own it holds no vulnerability rules; its job is
to understand the code under review, pull in the most relevant specialised
skills from this same library, and apply them. This library contains hundreds
of specialised skills (cryptographic audit, SQL injection, JWT verification,
secrets in source, deserialization, access control, and many more) whose
individual descriptions are often too narrow to self-trigger on a plain "review
this code" request. This skill is the entry point that finds and uses them.

## When to Use

- Any request to review, audit, or security-check source code
- Any request to find vulnerabilities or check code against OWASP Top 10 / CWE
- As the first step before the library's specialised application-security skills

## Workflow

### Step 1 - Understand the code
Read every source file in scope. For each file, note in one or two lines what it
does, and flag every security-relevant behaviour, e.g.:
- SQL / database query construction (string building vs parameterised)
- Cryptography: hashing, encryption, cipher mode, key/IV/salt handling, RNG
- Authentication, sessions, password storage, tokens / JWT
- Input handling, deserialization, file/path access, OS command execution
- Network calls, TLS settings, secrets / credentials in source
Turn these into a short list of keywords (e.g. "sql injection", "cryptography",
"jwt", "hardcoded secret", "deserialization", "xss").

### Step 2 - Find applicable skills (cheaply)
The other skills in this library are the sibling directories next to this
skill's own directory. Do NOT read them all. Instead:
1. Find this skill's directory, then its parent (the library root).
2. Grep skill NAMES first for your Step 1 keywords, e.g. from the library root:
   `ls | grep -iE 'crypto|sql|jwt|secret|deserial|xss|auth|password'`
3. For the closest name matches, read ONLY the `description` frontmatter of
   their SKILL.md (`sed -n '1,15p' <name>/SKILL.md`).

Select EVERY skill whose description clearly matches a security-relevant
behaviour you found in Step 1 - one or more per behaviour. Do NOT cap the count
artificially: code that touches several concerns should match several skills,
and that is expected. Order the selected skills by likely severity / relevance
so the most important are handled first.

### Step 3 - Apply each selected skill
Work through the selected skills in priority order. Read each skill's body (and
its `references/` files if present) only when you reach it - one at a time, not
all up front - so that a long list of matches never exhausts context. Apply each
skill's weakness table / checklist / verification criteria against the actual
code from Step 1, citing concrete `file:line` evidence for every check that
fires. Some skills ship Python helper scripts - apply their *knowledge* to
whatever language the code is in; do not run their scripts against non-Python
code.

### Step 4 - Report
Produce a findings report:
- One entry per issue: severity, CWE id, `file:line`, why it is a problem, and
  the fix.
- A "Skills applied" list naming the specialised skills you used.
- For any security-relevant behaviour that had no matching library skill, review
  it against general OWASP Top 10 / CWE knowledge and say you did so.
- If nothing is wrong, say so explicitly and list what you checked.

## Constraints

- Report only. Do not create or modify any files unless explicitly asked.
- Keep the library search cheap: grep names, skim descriptions, and fully read
  skill bodies only as you apply them, one at a time. Never load the whole
  library into context at once.

## Verification

- Every security-relevant behaviour from Step 1 is either matched to a skill and
  checked, or explicitly reviewed against general knowledge.
- Every finding carries a CWE id and a `file:line`.
- The "Skills applied" list is present.
