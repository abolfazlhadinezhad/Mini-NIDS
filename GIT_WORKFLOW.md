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
