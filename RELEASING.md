# Releasing libstirshaken

Releases are keyed from upstream version tags. The upstream version is stored in
`VERSION`, and Debian packages use the matching package version with Debian
revision `-1`.

## Create a Release

Start from an up-to-date `master` branch with a clean working tree.

```bash
git checkout master
git pull origin master
./prepare-release.sh 1.0.1
```

Review the generated commit and tag:

```bash
git show --stat HEAD
git tag -n v1.0.1
```

Push the release commit and tag:

```bash
git push origin master
git push origin v1.0.1
```

Pushing the tag starts the GitHub Actions release workflow. The workflow builds
Debian packages, creates the GitHub release, and uploads the Debian package
assets.

## Version Policy

Use plain semantic versions for upstream releases, for example `1.0.1`. Do not
include a leading `v` in `VERSION` or when calling `prepare-release.sh`; the Git
tag adds that prefix.

The current release process always maps:

```text
v1.0.1 -> 1.0.1-1
```

Debian-only revisions such as `1.0.1-2` are intentionally unsupported for now.
If packaging-only releases become necessary, add explicit support for them then.
