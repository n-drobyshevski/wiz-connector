# wiz-demo-app: test repository for wiz-connector

A small multi-module Spring Boot 2.6 app with **deliberately vulnerable** dependencies. It is not
meant to run anywhere. Every declaration exercises one branch of wiz-connector, so it serves as:

- the golden test (`tests/test_test_repo.py`, offline, using a captured dependency tree);
- a live CI end-to-end run (`tests/e2e_test_repo.sh`): resolve, render the issue, run its fix
  commands, make the "edit by hand" changes, `mvn verify`, and check that nothing is left;
- a sandbox to try the real gh-aw workflow against Wiz (`scripts/make-test-repo.sh`).

## What each dependency tests

| Module | Dependency | Declared as | Branch exercised | Expected issue row |
|---|---|---|---|---|
| service | `log4j-core 2.14.1` | literal `<version>` | CISA-KEV sorting, per-line fixes | `2.14.1 → 2.17.1`, `use-dep-version` |
| api, batch | `commons-text` | `${commons-text.version}`: `1.9` in root, `1.10.0` override in batch | modules resolving different versions, property in two POMs | `1.9 (also 1.10.0) → 1.10.0`, `set-property` |
| service | `snakeyaml` | `${snakeyaml.version}` defined only by the Spring Boot parent | external property, major bump | `1.29 → 2.0`, edit by hand (add the property) |
| service | `h2 1.4.200` | literal, `test` scope | test-scoped direct dependency | `1.4.200 → 2.1.210`, `use-dep-version` |
| api | `jackson-databind` | no version (Spring Boot BOM) | managed outside the repo, one stale CVE, one CVE without a fix | `2.13.2.2 → 2.13.4.2`, edit by hand (pin) |
| api | `guava 30.1-jre` | literal | flavour kept (`-jre`, never `-android`) | `30.1-jre → 32.0.0-jre`, `use-dep-version` |
| service | `spring-boot-starter-web` | managed by the parent | vulnerable **transitive** deps (spring-web, tomcat, logback) | not listed, counted |
| service | `api` (sibling module) | `${project.version}` | reactor modules are never dependency rows | none |

[`wiz-findings.sample.json`](wiz-findings.sample.json) is synthetic Wiz-shaped data in Wiz's own
field names (`id` UUID, `name`, `detailedName`, comma-separated `fixedVersion`, `hasCisaKevExploit`).
The CVE ids, versions and fixed versions are real; ids, URLs and scores are illustrative. It also
contains an npm finding (not in the Maven tree) and a prompt-injection record that must be rejected.
The expected result is in [`expected.json`](expected.json).

## Run the checks (from the wiz-connector repository)
```bash
python3 -m unittest tests.test_test_repo        # offline golden test
bash tests/e2e_test_repo.sh                      # live: JDK 17+, Maven, Maven Central
```

## Try the real workflow (from the wiz-connector repository)
```bash
scripts/make-test-repo.sh ../wiz-demo-app        # standalone repo with workflow + Copilot files
```
Then follow the printed steps: push it to GitHub, compile the workflow, add the Wiz secrets, add the
repository to your Wiz Code connector, and run the workflow once with `staged=true`.

GitHub's dependency graph and Dependabot will (correctly) report these vulnerable dependencies,
in this repository and in the exported one.
