#!/usr/bin/env bash
# Prints the GitHub release notes for a tag: that version's section of CHANGELOG.md, followed
# by a standard footer (downloads, verifying them, docs). Fails when the changelog has no
# section for the version, so nothing ships without notes.
#
#   scripts/release-notes.sh v0.4.0 [owner/repo] > notes.md
set -euo pipefail

tag="${1:?usage: release-notes.sh <tag> [owner/repo]}"
repo="${2:-${GITHUB_REPOSITORY:-guscatalano/Groundhog}}"
version="${tag#v}"
changelog="$(dirname "$0")/../CHANGELOG.md"

# The section runs from "## [x.y.z]" to the next "## [" heading or the link references.
section="$(awk -v v="$version" '
  /^## \[/ { if (found) exit; if (index($0, "## [" v "]") == 1) { found = 1; next } }
  /^\[[^]]+\]: / { if (found) exit }
  found { print }
' "$changelog")"

if [[ -z "${section//[[:space:]]/}" ]]; then
  echo "CHANGELOG.md has no section for $version; add one before releasing $tag." >&2
  exit 1
fi

# The tag just before this one in version order (or the newest tag, if this one doesn't exist yet).
previous="$(git tag --list 'v*' --sort=v:refname | awk -v t="$tag" '$0 == t { found = 1; exit } { prev = $0 } END { print prev }')"
if [[ -n "$previous" ]]; then
  diff_link="[\`$previous...$tag\`](https://github.com/$repo/compare/$previous...$tag)"
else
  diff_link="[all commits](https://github.com/$repo/commits/$tag)"
fi

# Trim blank lines at the start and end of the section.
printf '%s\n' "$section" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'

cat <<EOF

---

### Downloads

| File | What it is |
| --- | --- |
| \`groundhog-agent-x64.exe\`, \`groundhog-agent-arm64.exe\` | The agent on its own: one file, no runtime. Copy it into any machine or VM template. |
| \`groundhog-x64.zip\`, \`groundhog-arm64.zip\` | The host CLI plus the agent, for \`groundhog sandbox\` and \`groundhog pending\`. |
| \`SHA256SUMS.txt\` | Checksums for everything above. |

The newest agent is always at
\`https://github.com/$repo/releases/latest/download/groundhog-agent-x64.exe\` (or \`-arm64.exe\`).

### Verifying a download

Each file has a build provenance attestation tying it to this repository's release workflow:

\`\`\`powershell
gh attestation verify groundhog-agent-x64.exe -R $repo
\`\`\`

Or compare \`(Get-FileHash groundhog-agent-x64.exe).Hash\` with \`SHA256SUMS.txt\`. The files aren't
code-signed yet, so SmartScreen may warn the first time one runs.

**Docs:** [README](https://github.com/$repo/blob/$tag/README.md) ·
[Groundhogfile reference](https://github.com/$repo/blob/$tag/docs/groundhogfile.md) ·
[Changelog](https://github.com/$repo/blob/$tag/CHANGELOG.md) · **Changes:** $diff_link
EOF
