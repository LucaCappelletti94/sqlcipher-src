#!/bin/sh -e
# Drives release-branch.sh against a local bare remote and a fake gh, one case per situation it handles, for both
# the release line and the next line.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The user's git configuration, such as commit signing, stays out of the cases.
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM

BOT_EMAIL="1+release[bot]@users.noreply.github.com"
RELEASE_PATHS="Cargo.toml Cargo.lock interop/web/Cargo.lock tools/releases.sh src/lib.rs sqlcipher"
failed=""

mkdir "$WORK/bin"
cat > "$WORK/bin/gh" <<'EOF'
#!/bin/sh -e
# Answers release-branch.sh's gh calls from the files in $GH_STATE, logging every write.
prs=$GH_STATE/prs
comments=$GH_STATE/comments
sub="$1 $2"
shift 2
case $sub in
"pr list")
    while [ $# -gt 0 ]; do [ "$1" != --head ] || head=$2; shift; done
    awk -v head="$head" '$2 == head && $3 == "open" { print $1; exit }' "$prs" ;;
"pr view")
    awk -F '\t' -v n="$1" '$1 == n { print $2 }' "$comments" ;;
"pr comment")
    printf '%s\t%s\n' "$1" "$3" >> "$comments"
    echo "comment $1 $3" >> "$GH_STATE/log" ;;
"pr close")
    printf '%s\t%s\n' "$1" "$3" >> "$comments"
    awk -v n="$1" '$1 == n { $3 = "closed" } { print }' "$prs" > "$prs.new"
    mv "$prs.new" "$prs"
    echo "close $1 $3" >> "$GH_STATE/log" ;;
"pr create")
    while [ $# -gt 0 ]; do [ "$1" != --head ] || head=$2; shift; done
    echo "$(($(wc -l < "$prs") + 1)) $head open" >> "$prs"
    echo "create $head" >> "$GH_STATE/log" ;;
*)
    echo "fake gh: unexpected gh $sub $*" >&2
    exit 1 ;;
esac
EOF
chmod +x "$WORK/bin/gh"

# Commits as a human in the current directory.
human_commit() {
    git add -A
    GIT_AUTHOR_NAME=Luca GIT_AUTHOR_EMAIL=luca@example.com GIT_COMMITTER_NAME=Luca \
        GIT_COMMITTER_EMAIL=luca@example.com git commit --quiet "$@"
}

# Selects the line whose cases follow: its branch prefix, the file its bot commit changes, the paths it commits,
# its title before the version, and the older and newer versions it moves to.
line() {
    LINE=$1
    PREFIX=$2
    VENDORED=$3
    LINE_PATHS=$4
    TITLE_STEM=$5
    OLD=$PREFIX$6
    NEW=$PREFIX$7
    OLD_VERSION=$6
    NEW_VERSION=$7
}

# Starts case $1 of the current line with a remote whose main holds SQLCipher 4.20.0 and no release branch.
start() {
    CASE=$WORK/$LINE-$1
    mkdir -p "$CASE/gh" "$CASE/seed"
    : > "$CASE/gh/prs"
    : > "$CASE/gh/comments"
    : > "$CASE/gh/log"
    git init --quiet --bare -b main "$CASE/remote.git"
    cd "$CASE/seed"
    git init --quiet -b main
    mkdir -p src sqlcipher tools interop/web
    echo 'pub const SQLCIPHER_VERSION: &str = "4.20.0";' > src/lib.rs
    echo "release 4.20.0" > sqlcipher/sqlite3.c
    echo "next 5.0.0-beta.1" > tools/releases.sh
    for file in Cargo.toml Cargo.lock interop/web/Cargo.lock README.md NOTES.md; do echo "$file" > "$file"; done
    human_commit -m "Generate from SQLCipher 4.20.0"
    git push --quiet "$CASE/remote.git" main
}

# Runs the bot of the current line on a fresh checkout of main, moving to version $1 with vendored text $2.
bot() {
    cd "$CASE"
    rm -rf "$CASE/run"
    git clone --quiet "$CASE/remote.git" "$CASE/run"
    cd "$CASE/run"
    git config user.name "release[bot]"
    git config user.email "$BOT_EMAIL"
    echo "${2:-$LINE $1}" > "$VENDORED"
    cp "$ROOT/release-branch.sh" .
    PATH="$WORK/bin:$PATH" GH_STATE="$CASE/gh" PREFIX="$PREFIX" VERSION="$1" TITLE="$TITLE_STEM $1" \
        PATHS="$LINE_PATHS" BODY="SQLCipher $1" ./release-branch.sh > "$CASE/out" 2>&1 ||
        { echo "release-branch.sh $1 failed:"; cat "$CASE/out"; }
}

# Commits file $2 with text $3 as a human on remote branch $1, merging main in first when $4 is merge.
push_as_human() {
    cd "$CASE"
    rm -rf "$CASE/human"
    git clone --quiet --branch "$1" "$CASE/remote.git" "$CASE/human"
    cd "$CASE/human"
    if [ "${4:-}" = merge ]; then
        GIT_AUTHOR_NAME=Luca GIT_AUTHOR_EMAIL=luca@example.com GIT_COMMITTER_NAME=Luca \
            GIT_COMMITTER_EMAIL=luca@example.com git merge --quiet --no-edit origin/main
    fi
    echo "$3" > "$2"
    human_commit -m "Change $2 on $1"
    git push --quiet origin "$1"
}

remote() { git --git-dir="$CASE/remote.git" "$@"; }
tip() { remote rev-parse -q --verify "refs/heads/$1" || true; }
subjects() { remote log --format=%s "main..$1" | tr '\n' '|'; }
logged() { grep -c "$1" "$CASE/gh/log" || true; }

# Records a failure of case $1, described by $2, unless the observed $3 equals the wanted $4.
expect() {
    if [ "$3" != "$4" ]; then
        printf 'FAIL  %s/%s  %s\n    got:  %s\n    want: %s\n' "$LINE" "$1" "$2" "$3" "$4"
        sed 's/^/    /' "$CASE/out"
        failed="$failed $LINE/$1"
    fi
}

cases() {
    start new-branch
    bot "$NEW_VERSION"
    expect new-branch "the bot commit is one commit on main" "$(subjects "$NEW")" "$TITLE_STEM $NEW_VERSION|"
    expect new-branch "the branch holds the version" "$(remote show "$NEW:$VENDORED")" "$LINE $NEW_VERSION"
    expect new-branch "its pull request opens" "$(logged "^create $NEW$")" 1

    start unchanged
    bot "$NEW_VERSION"
    before=$(tip "$NEW")
    bot "$NEW_VERSION"
    expect unchanged "the branch stays" "$(tip "$NEW")" "$before"
    expect unchanged "no second pull request opens" "$(logged "^create")" 1

    start version-changed
    bot "$NEW_VERSION" "$LINE $NEW_VERSION first build"
    bot "$NEW_VERSION" "$LINE $NEW_VERSION second build"
    expect version-changed "the branch holds the new build" "$(remote show "$NEW:$VENDORED")" "$LINE $NEW_VERSION second build"
    expect version-changed "the bot commit is still one commit" "$(remote rev-list --count "main..$NEW")" 1

    start main-moved
    bot "$NEW_VERSION"
    push_as_human main README.md "main moved"
    bot "$NEW_VERSION"
    expect main-moved "the branch sits on the current main" "$(remote rev-parse "$NEW^")" "$(tip main)"
    expect main-moved "the bot commit is still one commit" "$(remote rev-list --count "main..$NEW")" 1

    start fix-kept
    bot "$NEW_VERSION"
    push_as_human "$NEW" fix.txt fixed
    before=$(tip "$NEW")
    bot "$NEW_VERSION"
    expect fix-kept "the branch with its fix stays" "$(tip "$NEW")" "$before"

    start fix-kept-version-changed
    bot "$NEW_VERSION"
    push_as_human "$NEW" fix.txt fixed
    before=$(tip "$NEW")
    bot "$NEW_VERSION" "$LINE $NEW_VERSION second build"
    bot "$NEW_VERSION" "$LINE $NEW_VERSION second build"
    expect fix-kept-version-changed "the branch with its fix stays" "$(tip "$NEW")" "$before"
    expect fix-kept-version-changed "one comment names the changed file" "$(logged "^comment 1 .* $VENDORED")" 1

    start bot-commit-amended
    bot "$NEW_VERSION"
    cd "$CASE" && git clone --quiet --branch "$NEW" "$CASE/remote.git" amend && cd amend
    GIT_COMMITTER_NAME=Luca GIT_COMMITTER_EMAIL=luca@example.com git commit --quiet --amend -m "$TITLE_STEM $NEW_VERSION, amended"
    git push --quiet --force origin "$NEW"
    before=$(tip "$NEW")
    bot "$NEW_VERSION"
    bot "$NEW_VERSION"
    expect bot-commit-amended "the amended branch stays" "$(tip "$NEW")" "$before"
    expect bot-commit-amended "one comment names the vendored file" "$(logged "^comment 1 .* $VENDORED")" 1

    start fix-replayed
    bot "$NEW_VERSION"
    push_as_human "$NEW" fix.txt fixed
    push_as_human main README.md "main moved"
    bot "$NEW_VERSION"
    expect fix-replayed "the fix sits on the bot commit on the current main" "$(remote rev-parse "$NEW~2")" "$(tip main)"
    expect fix-replayed "the fix keeps its text" "$(remote show "$NEW:fix.txt")" fixed
    expect fix-replayed "the fix keeps its author" "$(remote log -1 --format=%ae "$NEW")" luca@example.com
    expect fix-replayed "the bot commit is rebuilt" "$(subjects "$NEW")" "Change fix.txt on $NEW|$TITLE_STEM $NEW_VERSION|"

    start fix-already-on-main
    bot "$NEW_VERSION"
    push_as_human "$NEW" fix.txt fixed
    push_as_human main fix.txt fixed
    bot "$NEW_VERSION"
    expect fix-already-on-main "the fix main holds is dropped" "$(subjects "$NEW")" "$TITLE_STEM $NEW_VERSION|"

    start fix-conflicts-with-main
    bot "$NEW_VERSION"
    push_as_human "$NEW" README.md "branch readme"
    push_as_human main README.md "main readme"
    before=$(tip "$NEW")
    bot "$NEW_VERSION"
    bot "$NEW_VERSION"
    expect fix-conflicts-with-main "the branch stays" "$(tip "$NEW")" "$before"
    expect fix-conflicts-with-main "one comment names the commit" "$(logged "^comment 1 .*$before")" 1

    start merge-commit
    bot "$NEW_VERSION"
    push_as_human main README.md "main moved"
    push_as_human "$NEW" fix.txt fixed merge
    push_as_human main NOTES.md "main moved again"
    before=$(tip "$NEW")
    bot "$NEW_VERSION"
    bot "$NEW_VERSION"
    expect merge-commit "the branch stays" "$(tip "$NEW")" "$before"
    expect merge-commit "one comment names the merge" "$(logged "^comment 1 .*$(remote rev-parse "$NEW^")")" 1

    start superseded
    bot "$OLD_VERSION"
    bot "$NEW_VERSION"
    expect superseded "the old branch is deleted" "$(tip "$OLD")" ""
    expect superseded "the old pull request closes" "$(logged "^close 1 Superseded by SQLCipher $NEW_VERSION.$")" 1
    expect superseded "the new branch holds only its bot commit" "$(remote rev-list --count "main..$NEW")" 1

    start superseded-fix-carried
    bot "$OLD_VERSION"
    push_as_human "$OLD" fix.txt fixed
    bot "$NEW_VERSION"
    expect superseded-fix-carried "the fix moves to the new branch" "$(subjects "$NEW")" "Change fix.txt on $OLD|$TITLE_STEM $NEW_VERSION|"
    expect superseded-fix-carried "the old branch is deleted" "$(tip "$OLD")" ""
    expect superseded-fix-carried "the old pull request closes naming the new branch" "$(logged "^close 1 .*$NEW")" 1

    start superseded-fix-conflicts
    bot "$OLD_VERSION"
    push_as_human "$OLD" "$VENDORED" "$LINE $OLD_VERSION patched"
    before=$(tip "$OLD")
    bot "$NEW_VERSION"
    bot "$NEW_VERSION"
    expect superseded-fix-conflicts "the new branch holds only its bot commit" "$(remote rev-list --count "main..$NEW")" 1
    expect superseded-fix-conflicts "the old branch stays" "$(tip "$OLD")" "$before"
    expect superseded-fix-conflicts "the old pull request closes once, naming the commit" "$(logged "^close 1 .*$before")" 1
    expect superseded-fix-conflicts "the closed pull request gets no further comment" "$(logged "^comment 1")" 0

    start superseded-fix-no-pr
    bot "$OLD_VERSION"
    push_as_human "$OLD" fix.txt fixed
    printf '1 %s closed\n' "$OLD" > "$CASE/gh/prs"
    before=$(tip "$OLD")
    bot "$NEW_VERSION"
    expect superseded-fix-no-pr "the old branch stays" "$(tip "$OLD")" "$before"
    expect superseded-fix-no-pr "the new branch holds only its bot commit" "$(remote rev-list --count "main..$NEW")" 1
}

release_line() { line release sqlcipher/v sqlcipher/sqlite3.c "$RELEASE_PATHS" "Generate from SQLCipher" "$1" "$2"; }
next_line() { line next sqlcipher-next/v tools/releases.sh tools/releases.sh "Test SQLCipher as the next line at" "$1" "$2"; }

release_line 4.20.1 4.21.0
cases
next_line 5.0.0-beta.2 5.0.0-rc1
cases

# Each line supersedes only its own branches.
release_line 4.20.1 4.21.0
start lines-apart
bot 4.21.0
next_line 5.0.0-beta.2 5.0.0-rc1
bot 5.0.0-rc1
next=$(tip "$NEW")
release_line 4.21.0 4.21.1
bot 4.21.1
expect lines-apart "the next branch stays" "$(tip sqlcipher-next/v5.0.0-rc1)" "$next"
expect lines-apart "the next pull request stays open" "$(grep -c '^2 sqlcipher-next/v5.0.0-rc1 open$' "$CASE/gh/prs")" 1
expect lines-apart "only the old release pull request closes" "$(logged '^close')" 1
expect lines-apart "the release line moves on" "$(tip "$OLD")" ""

[ -z "$failed" ] || { echo "Failed:$failed" >&2; exit 1; }
echo "pass  every release branch case"
