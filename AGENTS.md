# AGENTS.md — construct-transport

## Git workflow (branch + PR only)

**Never commit on `main`.** Every change goes on a topic branch cut from an up-to-date `main`
(`feat|fix|docs|chore|test/<topic>`) and lands through a GitHub pull request. Agents push and
open the PR only when asked.

`main` is what a release is built from, so it moves only by a reviewed merge. From 2026-09-11 to
2026-10-01 changes went straight to `main` across the construct-* repos — two people on the
project made a branch per change look like ceremony. That was reversed on purpose: the habit has
to be in place before there is a release for it to break.

A commit that landed on `main` by mistake and is not pushed moves off it with
`git branch <topic> && git reset --keep origin/main && git switch <topic>`. Pushed history is
never rewritten.
