"""Replace literal control/non-ASCII char constants with numeric code-point casts.

Kept as a dev tool because the trap it fixes is recurring: a raw control character inside a
Java source file is invisible in a diff and still compiles, so assertions silently test the
wrong bytes. Run with no arguments to check every source file for such bytes.
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def scan(root):
    offenders = {}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('bin', 'build', 'lib', '.git', 'tools')]
        for f in files:
            if not f.endswith('.java'):
                continue
            p = os.path.join(base, f)
            raw = open(p, 'rb').read()
            bad = sorted({b for b in raw
                          if (b < 0x20 and b not in (0x09, 0x0a)) or b == 0x7f or b > 0x7e})
            if bad:
                offenders[os.path.relpath(p, root)] = [hex(b) for b in bad]
    return offenders


FIXES = [
    (rb"static final char NUL = '[^']*';", "static final char NUL = (char) 0x00;"),
    (rb"static final char TAB = '[^']*';", "static final char TAB = (char) 0x09;"),
    (rb"static final char CR = '[^']*';", "static final char CR = (char) 0x0D;"),
    (rb"static final char LF = '[^']*';", "static final char LF = (char) 0x0A;"),
    (rb"static final char DEL = '[^']*';", "static final char DEL = (char) 0x7F;"),
    (rb"static final char E_ACUTE = '[^']*';", "static final char E_ACUTE = (char) 0x00E9;"),
    (rb"static final char FULLWIDTH_A = '[^']*';", "static final char FULLWIDTH_A = (char) 0xFF41;"),
]


def fix(path):
    raw = open(path, 'rb').read()
    for pattern, replacement in FIXES:
        raw = re.sub(pattern, replacement.encode('ascii'), raw)
    open(path, 'wb').write(raw)
    return raw


if __name__ == '__main__':
    target = os.path.join(ROOT, 'src', 'test', 'java', 'com', 'example', 'identity',
                          'IdentityValidationTest.java')
    if len(sys.argv) > 1 and sys.argv[1] == 'fix':
        raw = fix(target)
    bad = scan(ROOT)
    if bad:
        print('FILES WITH CONTROL OR NON-ASCII BYTES:')
        for k, v in bad.items():
            print('  ', k, v)
        sys.exit(1)
    print('CLEAN: every .java source is ASCII with no raw control bytes')
