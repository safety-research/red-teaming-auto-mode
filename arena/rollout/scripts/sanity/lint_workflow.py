#!/usr/bin/env python3
"""Catch the one bug class `node --check` cannot see in a Workflow script.

Agent prompts in a workflow script are template literals. A backtick in the PROSE — ``the `s1|s2`
shape`` — closes the template, and what follows parses as a perfectly valid bitwise-or expression of
bare identifiers before a new template opens. The file stays syntactically legal JavaScript, every
prompt from that point is silently truncated, and `node --check` returns SYNTAX OK.

Detecting this by looking at backticks alone is hopeless — the parse is genuinely ambiguous, and a
heuristic on backtick context fires on every legitimate `` `${PREAMBLE} `` too. So this tokenizes
instead, and looks for the *signature* the bug leaves behind: between one template literal and the
next, source that is nothing but bare identifiers joined by `|` or `&`. A prompt-building script
never legitimately contains that, and a prose fragment like `s1|s2|investigator|guardian` always
does.

    rollout/scripts/sanity/lint_workflow.py <script.js>     # exit 1 on any truncated prompt
"""

from __future__ import annotations

import re
import sys

# A chain of bare identifiers joined by | or & (`s1|s2|guardian`) OR a single bare identifier
# (`attempt_parity`). Both are what a prose backtick leaves between two templates; neither is
# ever legitimate there in a prompt-building script. The single-identifier case was a blind
# spot that shipped a broken script once.
IDENT_OR = re.compile(r"^[A-Za-z_$][\w$]*(\s*[|&]\s*[A-Za-z_$][\w$]*)*$")


def tokenize(src: str):
    """Yield ('tpl', start, end, text) for each top-level template literal, tracking comments,
    quoted strings and `${…}` nesting so a backtick inside any of them is not mistaken for one."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            i = src.find("\n", i)
            if i < 0:
                return
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c in "'\"":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == c:
                    break
                j += 1
            i = j + 1
        elif c == "`":
            start, j, depth = i, i + 1, 0
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "$" and j + 1 < n and src[j + 1] == "{":
                    depth += 1
                    j += 2
                    continue
                if src[j] == "}" and depth:
                    depth -= 1
                    j += 1
                    continue
                if src[j] == "`" and not depth:
                    break
                j += 1
            yield ("tpl", start, j, src[start + 1 : j])
            i = j + 1
        else:
            i += 1


# The mirror-image bug: over-escaping the CLOSING delimiter (`\\``) so the template never ends and
# swallows the code after it. Backtick counts stay balanced, so the truncation rule below cannot see
# it. Signature: real source constructs appearing INSIDE a prompt's text.
SWALLOWED = re.compile(r"^\s*(\{\s*label:|schema:\s*[A-Z_]|\}\s*\)|const\s+\w+\s*=|agent\(|\['[\w-]+'\s*,)", re.M)

# A legitimate inline-code tick in prose is followed by more prose or ordinary punctuation. An
# escaped tick that ENDS a line with `],` / `)` / `},` is a CLOSING delimiter escaped by mistake —
# the template runs on and swallows what comes next. Requiring end-of-line is what separates it from
# prose like ``reads \`undefined\`, STOP``, where the comma is followed by more sentence.
ESCAPED_CLOSER = re.compile(r"\\`\s*[\]\),;}]+\s*$", re.M)


def lint(path: str) -> int:
    src = open(path, encoding="utf-8").read()
    tpls = list(tokenize(src))
    findings = []
    swallowed = []
    for kind, a, b, text in tpls:
        m = SWALLOWED.search(text) or ESCAPED_CLOSER.search(text)
        if m:
            swallowed.append((src[:a].count("\n") + 1, m.group(0).strip(), text[max(0, m.start() - 60) : m.start()].replace("\n", " ")[-60:]))
    for a, b in zip(tpls, tpls[1:]):
        between = src[a[2] + 1 : b[1]].strip()
        if IDENT_OR.match(between):
            line = src[: a[2]].count("\n") + 1
            findings.append((line, between, a[3][-70:].replace("\n", " ")))
    if swallowed:
        print(f"{path}: {len(swallowed)} OVER-ESCAPED delimiter(s) — a template swallowed the code after it:\n")
        for line, tok, ctx in swallowed:
            print(f"  template opening at line {line}: contains source `{tok}` after '…{ctx}'")
        print("\nA closing delimiter was written as \\` . Backtick counts stay balanced, so this is\n"
              "invisible to both `node --check` and the truncation rule.")
        return 1
    if findings:
        print(f"{path}: {len(findings)} TRUNCATED PROMPT(S) — a prose backtick closed the template:\n")
        for line, between, tail in findings:
            print(f"  line {line}: prompt ends '…{tail}'")
            print(f"            then parses as the expression:  {between}")
        print("\nEscape the offending backticks as \\` . `node --check` will NOT catch this.")
        return 1
    print(f"{path}: ok ({len(tpls)} template literals, none truncated by a prose backtick)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(lint(sys.argv[1]))
