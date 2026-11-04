---
applyTo: "pom.xml,**/pom.xml"
---
- If a dependency version is `${property}`, change the `<properties>` entry; never inline a literal over a property.
- Bump a property shared by several artifacts once, to the highest required version, and name all affected artifacts in the PR.
- Never add `<exclusions>`, new dependencies or transitive overrides to fix a CVE unless an issue asks for it.
- Prefer `org.codehaus.mojo:versions-maven-plugin:2.23.0` goals (`set-property`, `use-dep-version`, always with `-DgenerateBackupPoms=false`) over rewriting POMs by hand.
- After editing any POM, run `mvn -B -ntp verify` from the repository root.
