# Git workflow

- Repository: https://github.com/abolfazlhadinezhad/Mini-NIDS
- Remote: `origin`; primary/default branch: `main`.
- Repository-local identity: abolfazlhadinezhad <aboluix@gmail.com>.
- Initial preserved commit: `0fe5f48` (includes original specification PDF).

## Branch, commit and push procedure

Small completed changes may use main. Larger work uses a short-lived
`feature/<description>` branch from current main. Initial implementation uses
`feature/offline-nids`. Test each logical unit, run Ruff, inspect `git status`,
`git diff --check`, and staged diff before committing. Use Conventional Commits:
`feat`, `fix`, `test`, `refactor`, `docs`, `chore`, `perf`, `build`.

Push each tested commit promptly and verify the remote branch SHA. Merge only
after the relevant full test suite passes; merge into main preserving commits,
push main, and verify local/remote equality. Respect branch protections; use a PR
if necessary. Record push failures accurately and retain local commits.

## Safety

Never force push, reset hard, clean untracked work, rewrite published history,
delete unmerged branches or alter unrelated projects. Do not stage secrets,
virtual environments, datasets, caches or temporary output. Stage explicit paths.
The PDF was already tracked: ignore future local PDFs at its exact source path
but preserve the original commit and file. Generated final report is separate.

## Release

1. Run lint, tests, package installation and CLI smoke tests.
2. Regenerate validation evidence and PDF report; identify outstanding external
   dataset/live validation. Update status/traceability and changelog.
3. Review staged diff and commit. Push feature branch and verify.
4. Merge into main without squashing granular feature history; push and verify.
5. Create a version tag only when its acceptance scope is documented and met.
   No release may imply external dataset validation that did not happen.

## Phase log

Initial inspection: main and origin/main both 0fe5f48; no divergence or unfinished
tracked changes. Planning/implementation branch: feature/offline-nids. Final
commits, merges and remote state are recorded in reports/VALIDATION.md.

## Completed development and integration phase: 2026-11-26

- Branch used: feature/offline-nids; 19 logical commits from e5f4503 through
  4fab486, each tested/reviewed and successfully pushed after completion.
- Parser/state/rule checkpoints: 7339a22, 869f7c6, 18bd33f, 83ccea0,
  cdb6c27, 0a7b55b, 17ccd1b. Pipeline/evaluation/QA: b472a7e, c4618e0,
  19615d5; subsequent fixes, bounded-DNS hardening and delivery documentation
  remain separate commits. Full checkpoint table: reports/VALIDATION.md.
- Feature branch CI run 45801637445 at 4fab486 passed all five jobs.
- Merge completed without squashing/history rewriting: 1d80b4c, main.
- Updated main pushed to origin; local and remote both verified as
  1d80b4c15d253afb79509f01ec1341537c83ffd9 before this closure documentation.
- Main CI run 45802235847 passed all five jobs on that merge commit.
- The feature branch is retained and fully integrated; no completed code is
  isolated from main. This closure documentation is a small direct-main change.
- Original commit 0fe5f48 and original PDF preserved. No force pushes, resets,
  unmerged branch deletions or credential/dataset commits.
- Version 0.1.0 describes validated offline software, with real-course evaluation
  still pending. No claim of a fully evaluated academic/production release.
