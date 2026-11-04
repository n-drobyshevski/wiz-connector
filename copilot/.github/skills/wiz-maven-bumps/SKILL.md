---
name: wiz-maven-bumps
description: Apply the Maven security version bumps listed in a wiz-connector GitHub issue (label wiz-sca, title "[wiz-sca] N direct Maven dependencies to bump"), verify them with Maven and open one pull request. Use when asked to fix, implement or work on a Wiz vulnerability issue or a list of Maven dependency bumps.
argument-hint: "[issue number or URL]"
---

# Apply Wiz Maven bumps

1. Get the issue body, first option that works:
   - GitHub MCP tool `issue_read` (method `get`) with owner, repo and issue number;
   - terminal: `gh issue view <number-or-url> --json title,body -q .body`;
   - otherwise ask the user to paste the issue URL.
2. The table and the **Fix commands** block are authoritative. The JSON block in
   *Machine-readable* has the same rows (`ga`, `current`, `target`, `edit[]`) if you need them.
3. Run the **Fix commands** from the repository root, one by one. They only touch the declaration
   named in the **Edit** column:
   - property: `versions-maven-plugin:2.23.0:set-property -Dproperty=<name> -DnewVersion=<target>`
   - literal `<version>`: `versions-maven-plugin:2.23.0:use-dep-version -Dincludes=<g:a> -DdepVersion=<target> -DprocessProperties=true`
   - rows marked "edit by hand": edit the named POM (add the `<properties>` entry or the
     `<dependencyManagement>` pin described in the **Edit** column).
   Always pass `-DgenerateBackupPoms=false`. Do not use `-q`: it hides the WARNING the plugin
   prints when a version is managed elsewhere and nothing changed.
4. `git diff --stat` must show every file named in **Edit**. If one did not change, edit it by hand.
5. Verify: `mvn -B -ntp verify`, then the `maven-dependency-plugin:3.11.0:tree -Dincludes=...`
   command from the issue must show a version ≥ target for every row in every listed module.
6. Fix only compile/test breakage caused by the bumps (`major`/`minor` rows: check release notes).
   Never add, remove or exclude dependencies and never pin transitive dependencies.
7. Unless you are the Copilot cloud agent (which opens the PR itself), open one PR titled
   `fix(deps): security bumps from Wiz` with the CVEs fixed and `Fixes #<issue>`.
