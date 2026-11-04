"""Parse `mvn dependency:tree -DoutputType=json` output into direct / transitive inventories.

With `-DappendOutput=true -DoutputFile=<one file>` the plugin writes one JSON object per
reactor module, concatenated (not a JSON array). Per-module files work as well.

"Direct" = depth-1 dependency of any reactor module, excluding the reactor's own modules.
A dependency reached only through another reactor module (web -> core -> jackson) is direct
for `core`, so subtrees under reactor modules are skipped: their own tree covers them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def ga(node: dict) -> str:
    return f"{node['groupId']}:{node['artifactId']}"


def load_trees(paths: list[Path]) -> list[dict]:
    roots: list[dict] = []
    decoder = json.JSONDecoder()
    for path in paths:
        text = Path(path).read_text(encoding="utf-8")
        pos = 0
        while True:
            while pos < len(text) and text[pos].isspace():
                pos += 1
            if pos >= len(text):
                break
            obj, pos = decoder.raw_decode(text, pos)
            if isinstance(obj, list):
                roots.extend(obj)
            else:
                roots.append(obj)
    # a module can appear twice if the file was appended to on an earlier run: the LAST one is current
    latest: dict[str, dict] = {}
    for r in roots:
        latest.pop(ga(r), None)
        latest[ga(r)] = r
    return list(latest.values())


@dataclass
class DirectDep:
    ga: str
    version: str
    scopes: set[str] = field(default_factory=set)
    modules: set[str] = field(default_factory=set)        # reactor module GAs declaring it
    module_versions: dict[str, str] = field(default_factory=dict)  # module GA -> resolved version
    optional: bool = False
    other_versions: set[str] = field(default_factory=set)  # differing resolved versions across modules
    also_transitive_in: set[str] = field(default_factory=set)
    declarations: list[dict] = field(default_factory=list)  # filled by pomlocate


@dataclass
class TransitiveDep:
    ga: str
    versions: set[str] = field(default_factory=set)
    via: set[str] = field(default_factory=set)            # direct dependency GAs that pull it in
    modules: set[str] = field(default_factory=set)


@dataclass
class Inventory:
    reactor: dict[str, str]                      # module GA -> version
    direct: dict[str, DirectDep]
    transitive: dict[str, TransitiveDep]
    maven_dir: str = "."                         # reactor root, relative to the repository root

    def to_json(self) -> dict:
        return {
            "maven_dir": self.maven_dir,
            "reactor": sorted(self.reactor),
            "direct": [
                {
                    "ga": d.ga,
                    "version": d.version,
                    "other_versions": sorted(d.other_versions),
                    "scopes": sorted(d.scopes),
                    "modules": sorted(d.modules),
                    "module_versions": dict(sorted(d.module_versions.items())),
                    "optional": d.optional,
                    "also_transitive_in": sorted(d.also_transitive_in),
                    "declarations": d.declarations,
                }
                for d in sorted(self.direct.values(), key=lambda x: x.ga)
            ],
            "transitive": [
                {"ga": t.ga, "versions": sorted(t.versions), "via": sorted(t.via), "modules": sorted(t.modules)}
                for t in sorted(self.transitive.values(), key=lambda x: x.ga)
            ],
        }

    @classmethod
    def from_json(cls, data: dict) -> "Inventory":
        """Inverse of to_json (used by the publish job, which has no POMs or trees)."""
        direct = {}
        for d in data.get("direct", []):
            direct[d["ga"]] = DirectDep(
                ga=d["ga"], version=d["version"], scopes=set(d.get("scopes", [])),
                modules=set(d.get("modules", [])), optional=bool(d.get("optional")),
                module_versions=dict(d.get("module_versions", {})),
                other_versions=set(d.get("other_versions", [])),
                also_transitive_in=set(d.get("also_transitive_in", [])),
                declarations=list(d.get("declarations", [])),
            )
        transitive = {
            t["ga"]: TransitiveDep(ga=t["ga"], versions=set(t.get("versions", [])),
                                   via=set(t.get("via", [])), modules=set(t.get("modules", [])))
            for t in data.get("transitive", [])
        }
        return cls(reactor={g: "" for g in data.get("reactor", [])}, direct=direct, transitive=transitive,
                   maven_dir=data.get("maven_dir", "."))


def build_inventory(roots: list[dict]) -> Inventory:
    reactor = {ga(r): r.get("version", "") for r in roots}
    direct: dict[str, DirectDep] = {}
    transitive: dict[str, TransitiveDep] = {}

    for root in roots:
        module = ga(root)
        for child in root.get("children", []) or []:
            cga = ga(child)
            if cga in reactor:
                continue
            d = direct.get(cga)
            if d is None:
                d = direct[cga] = DirectDep(ga=cga, version=child.get("version", ""))
            elif child.get("version") and child.get("version") != d.version:
                d.other_versions.add(child["version"])
            d.modules.add(module)
            if child.get("version"):
                d.module_versions[module] = child["version"]
            if child.get("scope"):
                d.scopes.add(child["scope"])
            if str(child.get("optional", "false")).lower() == "true":
                d.optional = True
            _walk_transitive(child.get("children", []) or [], cga, module, reactor, transitive)

    for t in transitive.values():
        if t.ga in direct:
            direct[t.ga].also_transitive_in |= (t.modules - direct[t.ga].modules)
    for g in list(transitive):
        if g in direct and not direct[g].also_transitive_in:
            # only ever seen transitively in modules that also declare it directly
            del transitive[g]
    return Inventory(reactor=reactor, direct=direct, transitive=transitive)


def _walk_transitive(nodes, via, module, reactor, out):
    stack = list(nodes)
    while stack:
        n = stack.pop()
        g = ga(n)
        if g not in reactor:
            t = out.get(g)
            if t is None:
                t = out[g] = TransitiveDep(ga=g)
            if n.get("version"):
                t.versions.add(n["version"])
            t.via.add(via)
            t.modules.add(module)
        stack.extend(n.get("children", []) or [])
