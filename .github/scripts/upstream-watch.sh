#!/usr/bin/env bash
# Reports when something this repository pins by hand has moved upstream, and
# with --file-issues opens a GitHub issue for each finding.
#
# Why this exists: this is C with no package manager, so nothing here is a
# manifest Dependabot reads. The vendored sources under third_party/ and the
# tool versions pinned as Dockerfile build args only move when someone
# notices, and for a module that decides who gets in, "nobody noticed" is the
# failure to design against.
#
# What it reads: .github/upstream-watch.conf, one entry per line.
#
#   vendored <name> <owner/repo> <local dir> <upstream dir> <file>...
#       Vendored source. The pinned tag and the sha256 of each file come from
#       <local dir>/README.md ("pinned at **<tag>**" and "sha256  <hex>
#       <file>" lines), which is where a person updating it records them.
#   arg <name> <owner/repo> <file> <ARG name>
#       A tool version pinned as `ARG <name>=<version>` in a Dockerfile.
#
# What it checks, per vendored entry:
#   1. Integrity: every file still has the sha256 its README records. A
#      mismatch is an error, not a finding: the tree no longer holds the
#      source the README says it holds.
#   2. A newer upstream release tag than the pinned one.
#   3. Otherwise, whether the same files on upstream's default branch differ
#      from the vendored ones. This is the case a tag watch misses: both
#      upstreams here go years between tags and fix things in between.
# and per arg entry: a newer upstream release than the pinned version.
#
# One issue per finding, matched by exact title in any state. Closing an
# issue without acting on it means "seen, not taking this one", and it is not
# filed again. A finding of kind 3 carries a fingerprint of upstream's
# current files in its title, so a later upstream change is a new finding.
#
# It files issues and never changes the tree. Vendored code is compiled into
# a module that runs inside sudo and sshd; a person reads the upstream diff
# before it comes in.
#
# Usage: .github/scripts/upstream-watch.sh [--file-issues]
#   Needs gh, authenticated (GH_TOKEN in Actions); --file-issues needs
#   issues: write. Without the flag it only prints what it would file.
# Exit status: 0 whether or not there are findings; non-zero when an
# integrity check failed or a check could not run.
set -euo pipefail

readonly CONF=.github/upstream-watch.conf

file_issues=0
case "${1:-}" in
"") ;;
--file-issues) file_issues=1 ;;
*)
	echo "usage: $0 [--file-issues]" >&2
	exit 2
	;;
esac

status=0
findings=$(mktemp -d)
trap 'rm -rf "$findings"' EXIT
count=0

# True when $1 < $2 under version ordering, leading "v" ignored.
version_lt() {
	local a=${1#v} b=${2#v}
	[ "$a" != "$b" ] && [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n 1)" = "$a" ]
}

# sha256 of stdin, hex only. sha256sum on Linux, shasum on macOS.
sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | cut -d' ' -f1
	else
		shasum -a 256 | cut -d' ' -f1
	fi
}

# Records one finding: $1 is the issue title, stdin its body.
finding() {
	count=$((count + 1))
	printf '%s\n' "$1" >"$findings/$count.title"
	cat >"$findings/$count.body"
}

# Reports a check that could not run, and makes the script exit non-zero.
problem() {
	echo "error: $*" >&2
	status=1
}

# The newest release tag of repository $1: the release GitHub marks latest,
# or, for an upstream that tags without publishing releases, the highest tag.
latest_tag() {
	local tag
	tag=$(gh api "repos/$1/releases/latest" --jq .tag_name 2>/dev/null || true)
	if [ -z "$tag" ]; then
		tag=$(gh api "repos/$1/tags?per_page=100" --jq '.[].name' | sort -V | tail -n 1)
	fi
	printf '%s\n' "$tag"
}

# vendored <name> <repo> <local dir> <upstream dir> <file>...
check_vendored() {
	local name=$1 repo=$2 dir=$3 updir=$4
	shift 4
	local readme="$dir/README.md" pinned latest branch file want have path up
	local intact=1 differing="" fingerprint=""

	pinned=$(sed -n 's/.*pinned at \*\*\([^*]*\)\*\*.*/\1/p' "$readme" | head -n 1)
	if [ -z "$pinned" ]; then
		problem "$readme does not say 'pinned at **<tag>**'"
		return 0
	fi

	# 1. Integrity against the README's own record.
	for file in "$@"; do
		want=$(awk -v f="$file" '$1 == "sha256" && $3 == f { print $2; exit }' "$readme")
		have=$(sha256 <"$dir/$file")
		if [ -z "$want" ]; then
			problem "$readme records no sha256 for $file"
			intact=0
		elif [ "$want" != "$have" ]; then
			problem "$dir/$file is $have, but $readme records $want"
			intact=0
		fi
	done
	if [ "$intact" -ne 1 ]; then
		return 0
	fi

	# 2. A newer tag.
	if ! latest=$(latest_tag "$repo") || [ -z "$latest" ]; then
		problem "could not read the latest tag of $repo"
		return 0
	fi
	if version_lt "$pinned" "$latest"; then
		finding "$name $latest is available (vendored $pinned)" <<EOF
$dir holds [$repo](https://github.com/$repo) at $pinned. Upstream has tagged $latest.

What changed: https://github.com/$repo/compare/$pinned...$latest

Read the diff of the vendored files ($*) before taking it, then follow "Updating" in $readme.

Close this issue without updating to skip $latest. It is not filed again.
EOF
		return 0
	fi

	# 3. The same files on upstream's default branch.
	if ! branch=$(gh api "repos/$repo" --jq .default_branch) || [ -z "$branch" ]; then
		problem "could not read the default branch of $repo"
		return 0
	fi
	for file in "$@"; do
		path=$file
		if [ "$updir" != "." ]; then
			path="$updir/$file"
		fi
		if ! up=$(gh api -H "Accept: application/vnd.github.raw" "repos/$repo/contents/$path?ref=$branch" | sha256) ||
			[ "$up" = "$(printf '' | sha256)" ]; then
			problem "could not read $path from $repo@$branch"
			return 0
		fi
		fingerprint="$fingerprint$up"
		if [ "$up" != "$(sha256 <"$dir/$file")" ]; then
			differing="$differing $path"
		fi
	done
	if [ -n "$differing" ]; then
		fingerprint=$(printf '%s' "$fingerprint" | sha256 | cut -c1-12)
		finding "$name: upstream has changed since $pinned (fingerprint $fingerprint)" <<EOF
$dir holds [$repo](https://github.com/$repo) at $pinned, which is still upstream's newest tag. On upstream's $branch branch these files now differ from the vendored ones:$differing

What changed: https://github.com/$repo/compare/$pinned...$branch

There is no tag to move to, so this is a judgement: read the diff of those files and decide whether anything in it matters here (a parsing fix, a bounds check). To take it, vendor the files at a specific upstream commit and record that commit and the new hashes in $readme.

Close this issue once it has been read. It is filed again only when upstream changes these files again.
EOF
	fi
}

# arg <name> <repo> <file> <ARG name>
check_arg() {
	local name=$1 repo=$2 file=$3 arg=$4 pin latest
	pin=$(awk -F= -v a="$arg" '$1 ~ "^ARG[ \t]+" a "$" { print $2; exit }' "$file")
	if [ -z "$pin" ]; then
		problem "$file has no 'ARG $arg=' line"
		return 0
	fi
	if ! latest=$(latest_tag "$repo") || [ -z "$latest" ]; then
		problem "could not read the latest release of $repo"
		return 0
	fi
	if version_lt "$pin" "$latest"; then
		finding "$name ${latest#v} is available ($file pins $pin)" <<EOF
$file pins \`ARG $arg=$pin\`. [$repo](https://github.com/$repo) has released ${latest#v}.

Release notes: https://github.com/$repo/releases/tag/$latest

Bump the ARG line. Close this issue without bumping to skip ${latest#v}.
EOF
	fi
}

# Walk the config. Blank lines and # comments are skipped. Read on fd 3 so
# nothing a check runs can swallow the rest of the file from stdin.
while read -r kind rest <&3; do
	case "$kind" in
	"" | \#*) continue ;;
	vendored | arg)
		# shellcheck disable=SC2086 # the fields are meant to split
		"check_$kind" $rest
		;;
	*) problem "$CONF: unknown entry kind '$kind'" ;;
	esac
done 3<"$CONF"

if [ "$count" -eq 0 ]; then
	echo "Nothing pinned here is behind upstream."
	exit "$status"
fi

# Print every finding, and file the ones not already reported.
i=1
while [ "$i" -le "$count" ]; do
	title=$(cat "$findings/$i.title")
	echo "== $title"
	if [ "$file_issues" -eq 1 ]; then
		existing=$(gh issue list --state all --search "\"$title\" in:title" --json number,title --limit 50 |
			jq -r --arg title "$title" '[.[] | select(.title == $title)] | sort_by(.number) | last | select(. != null) | .number')
		if [ -n "$existing" ]; then
			echo "   already reported in #$existing"
		else
			echo "   filed $(gh issue create --title "$title" --body-file "$findings/$i.body")"
		fi
	else
		sed 's/^/   /' "$findings/$i.body"
	fi
	i=$((i + 1))
done
exit "$status"
