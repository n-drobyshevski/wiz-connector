"""Find WHERE a direct dependency's version is declared, so the issue can say exactly what to edit.

Resolution order for a dependency of module M (following in-repo parents via <relativePath>):
  1. <dependencies> of M or an in-repo parent  -> literal <version> or ${property}
  2. no <version>: <dependencyManagement> of M or an in-repo parent -> literal or ${property}
  3. ${property} not defined in the repo -> defined by an external parent (e.g. spring-boot-starter-parent);
     overriding the property in the top in-repo POM works
  4. still unmanaged -> imported BOM or external parent manages it; add a dependencyManagement override
     or bump the BOM / parent
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "target", "node_modules", ".mvn", ".idea", "build", "out", ".gradle"}
_PROP = re.compile(r"^\$\{([^}]+)\}$")


def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _text(el: ET.Element | None, path: str) -> str | None:
    if el is None:
        return None
    found = el.find(path)
    return found.text.strip() if found is not None and found.text else None


@dataclass
class Pom:
    path: Path                      # absolute
    rel: str                        # repo-relative, posix
    root: ET.Element
    group_id: str
    artifact_id: str
    parent_ga: str | None
    parent_rel_path: str | None
    properties: dict[str, str] = field(default_factory=dict)

    @property
    def ga(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


class PomIndex:
    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root).resolve()
        self.by_path: dict[Path, Pom] = {}
        self.by_ga: dict[str, Pom] = {}
        for p in self._discover():
            pom = self._parse(p)
            if pom:
                self.by_path[pom.path] = pom
                self.by_ga.setdefault(pom.ga, pom)

    def _discover(self):
        for dirpath, dirnames, filenames in os.walk(self.repo_root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            if "pom.xml" in filenames:
                yield Path(dirpath) / "pom.xml"

    def _parse(self, path: Path) -> Pom | None:
        try:
            root = _strip_ns(ET.parse(path).getroot())
        except ET.ParseError:
            return None
        parent = root.find("parent")
        group = _text(root, "groupId") or _text(parent, "groupId") or ""
        artifact = _text(root, "artifactId") or ""
        parent_ga = None
        rel_path = None
        if parent is not None:
            parent_ga = f"{_text(parent, 'groupId')}:{_text(parent, 'artifactId')}"
            rel_path = _text(parent, "relativePath")
            if rel_path is None:
                rel_path = "../pom.xml"
        props = {}
        pe = root.find("properties")
        if pe is not None:
            for child in pe:
                if isinstance(child.tag, str):
                    props[child.tag] = (child.text or "").strip()
        rel = path.resolve().relative_to(self.repo_root).as_posix()
        return Pom(path=path.resolve(), rel=rel, root=root, group_id=group, artifact_id=artifact,
                   parent_ga=parent_ga, parent_rel_path=rel_path, properties=props)

    def parent_of(self, pom: Pom) -> Pom | None:
        if not pom.parent_ga:
            return None
        if pom.parent_rel_path:  # empty relativePath means "look up in repositories"
            candidate = (pom.path.parent / pom.parent_rel_path)
            if candidate.is_dir():
                candidate = candidate / "pom.xml"
            cand = self.by_path.get(candidate.resolve())
            if cand and cand.ga == pom.parent_ga:
                return cand
        return self.by_ga.get(pom.parent_ga)

    def chain(self, pom: Pom) -> list[Pom]:
        out, seen = [], set()
        cur: Pom | None = pom
        while cur and cur.path not in seen:
            out.append(cur)
            seen.add(cur.path)
            cur = self.parent_of(cur)
        return out

    def external_parent(self, pom: Pom) -> str | None:
        top = self.chain(pom)[-1]
        return top.parent_ga if top.parent_ga and not self.parent_of(top) else None


def _resolve_simple(value: str, chain: list[Pom]) -> str:
    """Resolve ${project.groupId}-style placeholders used in groupId/artifactId."""
    m = _PROP.match(value or "")
    if not m:
        return value
    name = m.group(1)
    if name in ("project.groupId", "pom.groupId", "groupId"):
        return chain[0].group_id
    for p in chain:
        if name in p.properties:
            return p.properties[name]
    return value


def _find_dep(section: ET.Element | None, ga: str, chain: list[Pom]) -> ET.Element | None:
    if section is None:
        return None
    g, a = ga.split(":", 1)
    for dep in section.findall("dependency"):
        dg = _resolve_simple(_text(dep, "groupId") or "", chain)
        da = _resolve_simple(_text(dep, "artifactId") or "", chain)
        if dg == g and da == a:
            return dep
    return None


def _property_location(name: str, chain: list[Pom]) -> Pom | None:
    for p in chain:
        if name in p.properties:
            return p
    return None


def _describe_version(pom: Pom, dep: ET.Element, chain_from_pom: list[Pom], section: str) -> dict:
    version = _text(dep, "version")
    if version is None:
        return {}
    m = _PROP.match(version)
    if not m:
        return {"kind": "literal", "file": pom.rel, "section": section, "value": version}
    prop = m.group(1)
    if prop in ("project.version", "pom.version", "version"):
        return {"kind": "project-version", "file": pom.rel, "section": section}
    owner = _property_location(prop, chain_from_pom)
    if owner:
        return {"kind": "property", "file": owner.rel, "property": prop,
                "value": owner.properties[prop], "used_in": pom.rel, "section": section}
    return {"kind": "external-property", "property": prop, "used_in": pom.rel, "section": section,
            "hint": f"Property ${{{prop}}} comes from an external parent; override it in <properties> of the top POM."}


def locate(index: PomIndex, module_ga: str, dep_ga: str) -> dict:
    pom = index.by_ga.get(module_ga)
    if pom is None:
        return {"kind": "unknown", "hint": f"POM for module {module_ga} not found in repo"}
    chain = index.chain(pom)

    # 1. declared in <dependencies> (module itself or inherited from an in-repo parent)
    for i, p in enumerate(chain):
        dep = _find_dep(p.root.find("dependencies"), dep_ga, chain[i:])
        if dep is None:
            for prof in p.root.findall("profiles/profile"):
                dep = _find_dep(prof.find("dependencies"), dep_ga, chain[i:])
                if dep is not None:
                    break
        if dep is not None:
            desc = _describe_version(p, dep, chain[i:], "dependencies")
            if desc:
                return desc
            break  # declared without version -> managed

    # 2. managed in <dependencyManagement> of the chain
    for i, p in enumerate(chain):
        dep = _find_dep(p.root.find("dependencyManagement/dependencies"), dep_ga, chain[i:])
        if dep is not None:
            desc = _describe_version(p, dep, chain[i:], "dependencyManagement")
            if desc:
                return desc

    # 3. managed outside the repo
    boms = []
    for p in chain:
        dm = p.root.find("dependencyManagement/dependencies")
        if dm is None:
            continue
        for dep in dm.findall("dependency"):
            if (_text(dep, "scope") or "") == "import":
                boms.append(f"{_text(dep, 'groupId')}:{_text(dep, 'artifactId')}:{_text(dep, 'version')} ({p.rel})")
    ext = index.external_parent(pom)
    top = chain[-1].rel
    hint = (f"Version is managed outside this repo (BOM or external parent). Pin {dep_ga} in "
            f"<dependencyManagement> of {top} (local entries win over imported BOMs), or bump the "
            f"managing BOM/parent. If an external parent declares it in <dependencies> with a version, "
            f"redeclare it with the new <version> instead.")
    return {"kind": "managed-external", "file": top, "boms": boms, "external_parent": ext, "hint": hint}
