"""Maven version ordering (a pragmatic subset of Maven's ComparableVersion).

Rules implemented:
  * tokens are runs of digits or letters; separators ('.', '-', '_', '+') are ignored
  * numbers compare numerically and rank above qualifiers  (1.0.1 > 1.0-rc1)
  * known qualifiers: alpha < beta < milestone < rc == cr < snapshot < release == ga == final < sp
  * unknown qualifiers rank after 'sp' and compare lexically (jre, android, ...)
  * missing tokens act as 0 against numbers and as 'release' against qualifiers,
    so 1.0 == 1 == 1.0.0 == 1.0.RELEASE
"""

from __future__ import annotations

import functools
import re

_QUALIFIERS = {
    "alpha": 0, "a": 0,
    "beta": 1, "b": 1,
    "milestone": 2, "m": 2,
    "rc": 3, "cr": 3,
    "snapshot": 4,
    "": 5, "ga": 5, "final": 5, "release": 5,
    "sp": 6,
}
_UNKNOWN_RANK = 7
_RELEASE = ("q", 5, "")


def _tokens(version: str) -> list[tuple]:
    out: list[tuple] = []
    for tok in re.findall(r"\d+|[a-z]+", version.strip().lower()):
        if tok.isdigit():
            out.append(("n", int(tok), ""))
        else:
            out.append(("q", _QUALIFIERS.get(tok, _UNKNOWN_RANK), tok))
    return out


def _cmp_item(x, y) -> int:
    if x is None and y is None:
        return 0
    if x is None:
        return -_cmp_item(y, None)
    if y is None:
        if x[0] == "n":
            return 1 if x[1] > 0 else 0
        y = _RELEASE
    if x[0] == "n" and y[0] == "n":
        return (x[1] > y[1]) - (x[1] < y[1])
    if x[0] == "n":
        return 1
    if y[0] == "n":
        return -1
    if x[1] != y[1]:
        return (x[1] > y[1]) - (x[1] < y[1])
    if x[1] == _UNKNOWN_RANK:
        return (x[2] > y[2]) - (x[2] < y[2])
    return 0


def compare(a: str, b: str) -> int:
    """Return -1, 0 or 1 like Java's compareTo."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        c = _cmp_item(ta[i] if i < len(ta) else None, tb[i] if i < len(tb) else None)
        if c:
            return c
    return 0


sort_key = functools.cmp_to_key(compare)


def numeric_prefix(version: str, n: int) -> tuple[int, ...]:
    """First n numeric components, zero padded: numeric_prefix('2.9.10.8', 2) == (2, 9)."""
    nums = [int(t) for t in re.findall(r"\d+", version.split("-")[0])][:n]
    return tuple(nums + [0] * (n - len(nums)))


def major(version: str) -> int:
    return numeric_prefix(version, 1)[0]


def same_line(a: str, b: str) -> bool:
    """Same major.minor release line."""
    return numeric_prefix(a, 2) == numeric_prefix(b, 2)


def is_prerelease(version: str) -> bool:
    return any(t[0] == "q" and t[1] < 5 for t in _tokens(version))


def fixes(candidate: str, fixed_versions: list[str]) -> bool:
    """Does `candidate` contain the fix for a CVE fixed in `fixed_versions`?

    Wiz (like most advisories) lists one fixed version per maintained release line,
    e.g. ["2.12.7.1", "2.13.4.2"]. A candidate is fixed when it is on the same
    major.minor line as a fix and not older than it, or not older than the highest fix.
    """
    if not fixed_versions:
        return False
    highest = max(fixed_versions, key=sort_key)
    if compare(candidate, highest) >= 0:
        return True
    return any(same_line(candidate, f) and compare(candidate, f) >= 0 for f in fixed_versions)


def flavor(version: str) -> str:
    """Trailing unknown qualifier that selects an artifact flavour, e.g. 'jre' / 'android' (Guava)."""
    toks = _tokens(version)
    return toks[-1][2] if toks and toks[-1][0] == "q" and toks[-1][1] == _UNKNOWN_RANK else ""


def minimal_safe_version(current: str, per_cve_fixes: list[list[str]]) -> str | None:
    """Smallest version from the advisories' fixed versions that fixes every CVE and is newer
    than `current`. Keeps the current flavour (31.1-jre -> 32.0.0-jre, never -android) when such a
    candidate exists. Pre-releases are only used when nothing else works. Returns None when
    no single listed version satisfies all CVEs."""
    candidates = sorted(
        {v for fx in per_cve_fixes for v in fx if compare(v, current) > 0},
        key=sort_key,
    )
    same = [c for c in candidates if flavor(c) == flavor(current)]
    if same:
        candidates = same
    for allow_pre in (False, True):
        for cand in candidates:
            if is_prerelease(cand) and not allow_pre:
                continue
            if all(fixes(cand, fx) for fx in per_cve_fixes):
                return cand
    return None
