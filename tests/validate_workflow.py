"""Validate gh-aw workflow frontmatter against gh-aw's published JSON schema.

  python tests/validate_workflow.py <main_workflow_schema.json> workflows/*.md shared/**/*.md

The schema ships in github/gh-aw at pkg/parser/schemas/main_workflow_schema.json (pin the tag you
compile with). This is a structural check only; `gh aw compile --validate --strict` is authoritative.
Needs PyYAML + jsonschema.
"""

import json
import sys

import jsonschema
import yaml


class _Loader(yaml.SafeLoader):
    pass


# GitHub Actions YAML treats `on` as a string; PyYAML (YAML 1.1) would turn it into True.
for ch in "oOyYnN":
    _Loader.yaml_implicit_resolvers[ch] = [
        (tag, rx) for tag, rx in _Loader.yaml_implicit_resolvers.get(ch, []) if tag != "tag:yaml.org,2002:bool"
    ]


def frontmatter(path: str) -> dict:
    text = open(path, encoding="utf-8").read()
    if not text.startswith("---\n"):
        raise SystemExit(f"{path}: no frontmatter")
    return yaml.load(text.split("---\n", 2)[1], Loader=_Loader)


def main() -> int:
    schema = json.load(open(sys.argv[1], encoding="utf-8"))
    validator = jsonschema.validators.validator_for(schema)(schema)
    failed = 0
    for path in sys.argv[2:]:
        data = frontmatter(path)
        shared = "on" not in data  # shared import components have no trigger
        errors = [e for e in validator.iter_errors(data)
                  if not (shared and e.validator == "required" and "'on'" in e.message)]
        for e in errors:
            print(f"{path}: {'/'.join(map(str, e.path)) or '<root>'}: {e.message[:300]}")
        failed += bool(errors)
        print(f"{path}: {'OK' if not errors else f'{len(errors)} error(s)'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
