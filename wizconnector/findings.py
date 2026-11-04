"""Normalise Wiz findings and keep only those fixable by bumping a DIRECT Maven dependency."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import mvnversion as mv
from .maventree import Inventory

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0, "INFO": 0, "NONE": 0, "UNKNOWN": 0}


def _first(d: dict, *keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return default


def parse_package(raw: str) -> tuple[str | None, str]:
    """Return (groupId or None, artifactId) from 'g:a', 'g:a:v', 'g/a', 'pkg:maven/g/a@v' or 'a'."""
    s = (raw or "").strip()
    if s.lower().startswith("pkg:maven/"):
        s = s[len("pkg:maven/"):].split("@", 1)[0].split("?", 1)[0]
        g, _, a = s.partition("/")
        return (g or None, a or g)
    for sep in (":", "/"):
        if sep in s:
            parts = s.split(sep)
            if len(parts) >= 2 and parts[0] and parts[1]:
                return parts[0], parts[1]
    return None, s


def split_versions(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        items = re.split(r"[,;|\s]+", str(raw))
    out = []
    for it in items:
        it = it.strip().strip("[]()").lstrip("=>v ").strip()
        if it and re.search(r"\d", it) and it not in out:
            out.append(it)
    return out


@dataclass
class Finding:
    cve: str
    group: str | None
    artifact: str
    version: str
    fixed_versions: list[str]
    severity: str
    cvss: float | None
    has_exploit: bool
    cisa_kev: bool
    url: str | None
    raw_package: str

    @property
    def ga(self) -> str | None:
        return f"{self.group}:{self.artifact}" if self.group else None


def normalise(raw: dict) -> Finding | None:
    pkg = _first(raw, "package", "detailedName", "packageName", "component", "library", "name_of_package", default="")
    cve = _first(raw, "cve", "id", "name", "vulnerability", "externalId", default="")
    if not pkg or not cve:
        return None
    group, artifact = parse_package(str(pkg))
    if raw.get("group") and not group:
        group = raw["group"]
    sev = str(_first(raw, "severity", "vendorSeverity", default="UNKNOWN")).upper()
    cvss = _first(raw, "cvss", "score", "cvssScore")
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    return Finding(
        cve=str(cve).strip(),
        group=group,
        artifact=artifact,
        version=str(_first(raw, "version", "installedVersion", "currentVersion", default="")).strip(),
        fixed_versions=split_versions(_first(raw, "fixed_versions", "fixedVersion", "fixedVersions", "fix")),
        severity=sev if sev in SEVERITY_RANK else "UNKNOWN",
        cvss=cvss,
        has_exploit=bool(_first(raw, "has_exploit", "hasExploit", default=False)),
        cisa_kev=bool(_first(raw, "cisa_kev", "hasCisaKevExploit", "kev", default=False)),
        url=_first(raw, "url", "link", "portalUrl"),
        raw_package=str(pkg),
    )


@dataclass
class Upgrade:
    ga: str
    current: str
    target: str | None
    cves: list[Finding] = field(default_factory=list)
    unfixed_cves: list[Finding] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    declarations: list[dict] = field(default_factory=list)
    also_transitive_in: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        sev = [f.severity for f in self.cves] or ["UNKNOWN"]
        return max(sev, key=lambda s: SEVERITY_RANK.get(s, 0))

    @property
    def max_cvss(self) -> float:
        return max((f.cvss or 0.0 for f in self.cves), default=0.0)

    @property
    def kev(self) -> bool:
        return any(f.cisa_kev for f in self.cves)

    @property
    def exploit(self) -> bool:
        return any(f.has_exploit for f in self.cves)

    @property
    def bump(self) -> str:
        if not self.target:
            return "unknown"
        if mv.major(self.target) != mv.major(self.current):
            return "major"
        if not mv.same_line(self.target, self.current):
            return "minor"
        return "patch"

    def sort_key(self):
        return (-int(self.kev), -SEVERITY_RANK.get(self.max_severity, 0), -self.max_cvss, -int(self.exploit), self.ga)


@dataclass
class Result:
    upgrades: list[Upgrade]
    no_fix: list[Upgrade]                       # direct deps whose CVEs have no fixed version
    skipped_transitive: dict[str, list[str]]    # ga -> CVEs (not fixable by a direct bump)
    already_fixed: dict[str, list[str]]         # direct deps already at/above the fix (stale Wiz data)
    unmatched: dict[str, list[str]]             # packages not in the Maven tree at all
    total_findings: int


def _match_direct(f: Finding, inv: Inventory) -> str | None:
    if f.ga:
        return f.ga if f.ga in inv.direct else None
    # Wiz sometimes reports only the artifactId: accept it when it is unambiguous
    hits = [g for g in inv.direct if g.split(":", 1)[1] == f.artifact]
    return hits[0] if len(hits) == 1 else None


def _match_transitive(f: Finding, inv: Inventory) -> str | None:
    if f.ga and f.ga in inv.transitive:
        return f.ga
    if f.group is None:
        hits = [g for g in inv.transitive if g.split(":", 1)[1] == f.artifact]
        if len(hits) == 1:
            return hits[0]
    return None


def evaluate(raw_findings: list[dict], inv: Inventory) -> Result:
    by_direct: dict[str, dict[str, Finding]] = {}
    skipped: dict[str, set] = {}
    unmatched: dict[str, set] = {}
    total = 0
    for raw in raw_findings:
        f = normalise(raw)
        if f is None:
            continue
        total += 1
        g = _match_direct(f, inv)
        if g:
            # same CVE reported for several modules/paths: merge fixed versions
            prev = by_direct.setdefault(g, {}).get(f.cve)
            if prev:
                prev.fixed_versions = sorted(set(prev.fixed_versions) | set(f.fixed_versions), key=mv.sort_key)
                prev.cisa_kev |= f.cisa_kev
                prev.has_exploit |= f.has_exploit
                if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(prev.severity, 0):
                    prev.severity = f.severity
                prev.cvss = max(prev.cvss or 0.0, f.cvss or 0.0) or None
            else:
                by_direct[g][f.cve] = f
            continue
        t = _match_transitive(f, inv)
        if t:
            skipped.setdefault(t, set()).add(f.cve)
        else:
            unmatched.setdefault(f.ga or f.artifact, set()).add(f.cve)

    upgrades, no_fix, already = [], [], {}
    for g, cves in by_direct.items():
        d = inv.direct[g]
        current = d.version
        fixable = [f for f in cves.values() if f.fixed_versions]
        unfixed = [f for f in cves.values() if not f.fixed_versions]
        still_open = [f for f in fixable if not mv.fixes(current, f.fixed_versions)]
        stale = [f.cve for f in fixable if mv.fixes(current, f.fixed_versions)]
        if stale:
            already[g] = sorted(stale)
        base = dict(ga=g, current=current, modules=sorted(d.modules), scopes=sorted(d.scopes),
                    declarations=d.declarations, also_transitive_in=sorted(d.also_transitive_in))
        if still_open:
            target = mv.minimal_safe_version(current, [f.fixed_versions for f in still_open])
            if target is None:  # no single listed version fixes all: take the highest listed fix
                target = max((v for f in still_open for v in f.fixed_versions), key=mv.sort_key)
            upgrades.append(Upgrade(target=target, cves=sorted(still_open, key=_cve_order),
                                    unfixed_cves=sorted(unfixed, key=_cve_order), **base))
        elif unfixed:
            no_fix.append(Upgrade(target=None, cves=sorted(unfixed, key=_cve_order), **base))

    upgrades.sort(key=Upgrade.sort_key)
    no_fix.sort(key=Upgrade.sort_key)
    return Result(
        upgrades=upgrades,
        no_fix=no_fix,
        skipped_transitive={k: sorted(v) for k, v in sorted(skipped.items())},
        already_fixed=already,
        unmatched={k: sorted(v) for k, v in sorted(unmatched.items())},
        total_findings=total,
    )


def _cve_order(f: Finding):
    return (-int(f.cisa_kev), -SEVERITY_RANK.get(f.severity, 0), -(f.cvss or 0.0), f.cve)
