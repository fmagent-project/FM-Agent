# Git branches and work memory

## Inspect safely

Start in `D:\fmagent\FM-Agent`:

```powershell
git status --short
git branch --show-current
git remote -v
git branch --all --no-color
git log --oneline --decorate -20
```

The worktree may contain user changes. Never reset, clean, stash, overwrite, or
switch away from a dirty branch without explicit authorization.

## Read another branch without switching

Prefer read-only inspection:

```powershell
git show public/main:src/plugin.py
git show public/feat/stage3-python-plugin-hooks:docs/plugins_zh.md
git diff public/main...public/feat/stage3-python-plugin-hooks -- src/plugin.py
git log --oneline public/main..public/feat/stage3-python-plugin-hooks
```

Use the PR head SHA/ref returned by GitHub when available. A public PR branch may
also exist as `private/<branch>`.

## When switching is useful

Switch only when:

- the worktree is clean;
- runtime inspection needs a coherent branch checkout;
- the branch exists locally or on a known remote;
- the original branch name is recorded.

Use `git switch <branch>` and return to the recorded original branch after
read-only inspection. Do not pull, merge, commit, or push merely to make a PPT.

If the worktree is dirty, remain on it and use `git show`/`git diff`, or create a
separate worktree only when the task genuinely requires execution and the user
has authorized the additional checkout.

## Reconstruct work memory

Use, in order:

1. Current conversation and any supplied conversation summary.
2. `D:\fmagent\experience.MD` and `D:\fmagent\plan.md`.
3. `D:\fmagent\docs\插件化方案.pptx`.
4. Branch commits, diffs, PR bodies, issue bodies, and review comments.
5. Implementation docs such as `docs/plugins.md` and `docs/plugins_zh.md`.
6. Tests, demos, and manual validation recorded in the PR.

Search broadly:

```powershell
rg -n "plugin|插件|stage3|entry_reasoning|pass|replace|modify|spec.json|info.json" `
  D:\fmagent\experience.MD D:\fmagent\plan.md D:\fmagent\FM-Agent
```

Chat history outside the active thread may not be retrievable. Treat local notes
and repository history as durable memory, and make provenance explicit.

## Known 2026-07-27 branch mapping

- PR #116: `feat/rebuild-structured-function-metadata`
- PR #150: `feat/stage3-python-plugin-hooks`
- Issue #160: entry reasoning plugin work; identify the active branch from the
  current checkout, issue linkage, or later commits rather than guessing.

