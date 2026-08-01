# Hermes Vault — Draft Release Notes 0.23.0

> **DRAFT — not for release yet.** This file is a working draft produced by
> task t_5622783c. It does not modify `CHANGELOG.md`, `pyproject.toml`, or any
> version manifest. Proposed content is grouped by category; the "Needs merge
> before release" section lists changes that exist in the repo but are not yet
> on `release/v0.23.0`.

**Branch:** `release/v0.23.0` (cut from `origin/master` @ `ecc9947`)
**Previous release:** `v0.22.0` (tag `b9e0106` → commit `6581112`)
**Status:** Unreleased

---

## Proposed CHANGELOG entry

```markdown
## Unreleased

### Added

- (none yet — 0.23.0 is currently a maintenance/docs release)

### Fixed

- (pending — see "Needs merge before release")

### Changed

- (none yet)

### Docs

- Add post-release verification record for the v0.21.0 release to the
  release-readiness report (`release-readiness/v0.21.0/readiness-report.md`).

### Dependencies

- (none — `uv.lock` unchanged since v0.22.0)
```

---

## Changes since v0.22.0, by category

### Commits on `release/v0.23.0` since the v0.22.0 tag

`git log v0.22.0..HEAD --oneline`:

```
ecc9947 docs: add post-release verification record
09f7f82 Merge v0.22.0 — Vault Intelligence (#48)
```

- `09f7f82` is the squash merge of the v0.22.0 content onto `master` (the
  v0.22.0 tag itself lives on the local feature branch; see "Repository state
  notes" below). Its content is already released — not new for 0.23.0.
- `ecc9947` is the only genuinely new commit on the mainline since v0.22.0:
  a docs-only commit adding the post-release verification record.

### Docs (in this branch)

- **Post-release verification record** — `release-readiness/v0.21.0/readiness-report.md`
  gained the independent post-release sanity verification write-up
  (`ecc9947`, +93 lines).

### Chores / housekeeping (in this branch)

- README "What's New" section and dashboard version refs were already synced to
  v0.22.0 on `master` via PR #48; the v0.22.0 tag itself was cut before that
  sync landed (the tagged tree still says 0.21.0 in places). No further
  action needed on the branch — the delta tag→`master` for `README.md` and
  `tests/test_release_regression.py` is the v0.22.0 sync, not new 0.23.0 work.

### Dependencies

- `uv.lock` and `pyproject.toml` are unchanged between the v0.22.0 tag and
  `HEAD` (no dependency churn).

---

## Needs merge before release (currently NOT on this branch)

These commits exist on `origin/release/v0.22.0` but were **never merged to
`master`**, so they are not on `release/v0.23.0`:

| Commit | Type | Change | Recommendation |
|--------|------|--------|----------------|
| `a9057bd` | fix | Guard `tests/conftest.py` against PYTHONPATH pollution from the Hermes agent venv (+29 lines) | **Merge into `release/v0.23.0`** — genuine test-suite robustness fix, low risk |
| `924a517` | fix | Update `test_release_regression.py` heading assertion (0.21.0 → 0.22.0) | Skip — content already present on master via PR #48 |
| `24186c5` | docs | Sync README "What's New" to v0.22.0 | Skip — content already present on master via PR #48 |

Suggested action: cherry-pick `a9057bd` onto `release/v0.23.0`:

```bash
git checkout release/v0.23.0
git cherry-pick a9057bd
```

---

## Repository state notes (for the release engineer)

- **v0.22.0 tag is not in `master` ancestry.** The tag points to feature-branch
  commit `6581112`; the released content reached `master` via squash PR #48
  (`09f7f82`). When writing the final 0.23.0 changelog, diff against the tag
  tree (`git diff v0.22.0 HEAD`) rather than trusting `git log v0.22.0..HEAD`,
  which will show the PR merge commit as a spurious entry.
- **Local `master` is divergent/stale** (contains un-pushed phase-merge history
  and an older README). Use `origin/master` as the source of truth. Local
  `master` was not touched by this task.
- **Stash preserved:** an unrelated local `site/.gitignore` tweak (`/.vercel`)
  was stashed as `stash@{0}` ("site/.gitignore: /.vercel tweak (unrelated to
  0.23.0)"). It was not committed to the release branch.
- **No version surfaces were modified** in this task: `CHANGELOG.md`,
  `pyproject.toml`, `src/hermes_vault/__init__.py`, `site/index.html`, and
  `tests/test_release_regression.py` are untouched by the release-notes commit.

---

## Open questions for the 0.23.0 release

1. Is there feature work in flight that should land before 0.23.0 is cut? As of
   this draft, 0.23.0 is a maintenance/docs release with no new features.
2. Should `a9057bd` (PYTHONPATH guard) be merged in? Recommended yes — it is the
   only substantive code fix pending since v0.22.0.
