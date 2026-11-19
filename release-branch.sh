#!/bin/sh -e
# Commits PATHS as the bot commit TITLE onto the branch PREFIX VERSION, opens its pull request with BODY and retires
# every other branch of PREFIX. A commit whose author or committer is not this bot is human work, which no push
# ever drops.
: "${PREFIX:?}" "${VERSION:?}" "${TITLE:?}" "${PATHS:?}" "${BODY:?}"

cd "$(dirname "$0")"
branch="$PREFIX$VERSION"
bot=$(git config user.email)
retired=$(mktemp)
trap 'rm -f "$retired"' EXIT

git fetch --quiet --prune origin main "+refs/heads/$PREFIX*:refs/remotes/origin/$PREFIX*"
main=$(git rev-parse HEAD)
git checkout --quiet -b "$branch"
# shellcheck disable=SC2086 # PATHS is a list of paths without spaces.
git add $PATHS
git commit --quiet -m "$TITLE"
fresh=$(git rev-parse HEAD)

# Prints the commits in main..$1 whose author or committer is not this bot, oldest first.
human_commits() {
    git log --reverse --format='%H %ae %ce' "$main..$1" | awk -v bot="$bot" '$2 != bot || $3 != bot { print $1 }'
}

# Prints the last commit in main..$1 this bot both wrote and committed.
bot_commit() {
    git log --format='%H %ae %ce' "$main..$1" | awk -v bot="$bot" '$2 == bot && $3 == bot { print $1; exit }'
}

# Names the files whose change in the fresh commit differs from their change in commit $1, or every file the
# fresh commit changes when $1 is empty.
changed_files() {
    if [ -z "$1" ]; then
        git diff --name-only "$fresh^" "$fresh" | sed 's/^/ /' | tr -d '\n'
        return
    fi
    for file in $({ git diff --name-only "$fresh^" "$fresh" && git diff --name-only "$1^" "$1"; } | sort -u); do
        [ "$(git diff "$fresh^" "$fresh" -- "$file" | git patch-id --stable)" = \
            "$(git diff "$1^" "$1" -- "$file" | git patch-id --stable)" ] || printf ' %s' "$file"
    done
}

# Cherry-picks the human commits of $1 onto HEAD, dropping those main already holds. On a merge commit or a
# conflict it names that commit in $stuck, puts HEAD back and fails.
replay() {
    start=$(git rev-parse HEAD)
    stuck=$(git rev-list --merges -n 1 "$main..$1")
    [ -z "$stuck" ] || return 1
    for commit in $(human_commits "$1"); do
        if ! git cherry-pick --no-commit "$commit" > /dev/null 2>&1; then
            stuck=$commit
            git reset --quiet --hard "$start"
            return 1
        fi
        git diff --cached --quiet || git commit --quiet --reuse-message="$commit"
    done
}

open_pr() {
    gh pr list --head "$1" --state open --json number --jq '.[0].number // empty'
}

# Comments $3 on the open pull request of $1 unless an earlier comment there carries the marker $2.
comment_once() {
    number=$(open_pr "$1")
    [ -n "$number" ] || return 0
    gh pr view "$number" --json comments --jq '.comments[].body' | grep -qF "$2" ||
        gh pr comment "$number" --body "$3 $2"
}

old=$(git rev-parse -q --verify "refs/remotes/origin/$branch" || true)
if [ -z "$old" ]; then
    echo "$branch is new"
elif [ -z "$(human_commits "$old")" ]; then
    if [ "$(git rev-parse "$old^{tree}")" = "$(git rev-parse "$fresh^{tree}")" ] && [ "$(git rev-parse "$old^")" = "$main" ]; then
        echo "$branch already holds this version on the current main"
        git reset --quiet --hard "$old"
    else
        echo "$branch moves to this version on the current main"
    fi
elif [ "$(git merge-base "$old" "$main")" = "$main" ]; then
    changed=$(changed_files "$(bot_commit "$old")")
    git reset --quiet --hard "$old"
    if [ -z "$changed" ]; then
        echo "$branch already holds this version and commits of its own on the current main"
    else
        echo "$branch keeps its own commits over a version that differs in$changed"
        comment_once "$branch" "<!-- release-bot $(git rev-parse "$fresh^{tree}") -->" \
            "The sources generated today differ from this branch's in$changed, and this branch has commits of its own, so it was left as it is."
    fi
elif replay "$old"; then
    echo "$branch moves to this version on the current main, with its own commits"
else
    git reset --quiet --hard "$old"
    echo "$branch stays, because $stuck does not apply on the current main"
    comment_once "$branch" "<!-- release-bot $main $stuck -->" \
        "Main moved to $main, and $stuck does not apply onto the sources generated there, so this branch was left as it is."
fi

# Older versions first, so their commits land in the order they were written.
for ref in $(git for-each-ref --format='%(refname:strip=3)' "refs/remotes/origin/$PREFIX*" | sort -V); do
    [ "$ref" != "$branch" ] || continue
    number=$(open_pr "$ref")
    if [ -z "$(human_commits "origin/$ref")" ]; then
        echo "$ref ${number:--} retire" >> "$retired"
    elif [ -z "$number" ]; then
        echo "$ref has commits of its own and no open pull request, so it stays"
    elif replay "origin/$ref"; then
        echo "$ref $number carried" >> "$retired"
    else
        echo "$ref $number stuck $stuck" >> "$retired"
    fi
done

# The branch is pushed before any branch whose commits it carries is deleted.
[ "$(git rev-parse HEAD)" = "$old" ] ||
    git push --quiet --force-with-lease="refs/heads/$branch:$old" origin "HEAD:refs/heads/$branch"
[ -n "$(open_pr "$branch")" ] || gh pr create --base main --head "$branch" --title "$TITLE" --body "$BODY"

while read -r ref number outcome stuck; do
    case $outcome in
    retire)
        [ "$number" = - ] || gh pr close "$number" --comment "Superseded by SQLCipher $VERSION." ;;
    carried)
        gh pr close "$number" --comment "Superseded by SQLCipher $VERSION, whose branch $branch carries this branch's commits." ;;
    stuck)
        gh pr close "$number" --comment "Superseded by SQLCipher $VERSION. $stuck does not apply onto $branch, so this branch is kept."
        continue ;;
    esac
    git push --quiet --force-with-lease="refs/heads/$ref:$(git rev-parse "origin/$ref")" origin ":refs/heads/$ref"
done < "$retired"
