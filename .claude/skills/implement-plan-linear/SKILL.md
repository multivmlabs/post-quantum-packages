---
name: implement-plan-linear
description: "Implements approved technical plans from thoughts/shared/plans with phased execution, automated acceptance checks, manual verification pauses, Linear progress updates, and Graphite stack creation/submission. Use when asked to execute a plan and keep Linear plus PR stack workflow in sync."
argument-hint: "[plan-file-path] [linear-issue-key]"
---

# Implement Plan Linear

Implements an approved plan phase-by-phase and keeps delivery workflow synced across code, Linear, and Graphite.

## Inputs

- Require a plan path in `thoughts/shared/plans/`.
- Require the Linear issue key for the phase being implemented (for example `ENG-1228`).
- If either input is missing, ask once before starting.

## Start-Up

- Read the full plan and all files referenced by the plan before editing.
- Read files fully (no limit/offset); ensure complete context.
- Respect existing completed checkboxes (`- [x]`); start from the first unchecked item.
- Build a todo list for the current phase before code changes.
- Think through how the pieces fit together before making changes.
- Keep scope aligned to the plan; raise mismatches before continuing.

Mismatch format:

```text
Issue in Phase [N]:
Expected: [what the plan says]
Found: [actual situation]
Why this matters: [impact]

How should I proceed?
```

## Phase Execution Order

For each phase, execute in this order:

1. Implement all code changes for the phase.
2. Update plan checkboxes for completed implementation work.
3. Run automated acceptance criteria.
4. Pause and wait for explicit manual verification confirmation.
5. After confirmation, run Graphite stack commands.
6. Update Linear issue status/comments with outcome and links.

## Implementation Philosophy

- Follow the plan's intent while adapting to what you find.
- Implement each phase fully before moving to the next.
- Verify changes make sense in the broader codebase context.
- Update checkboxes in the plan as sections are completed.

## Acceptance Criteria

- Run the exact commands required by the plan and repository acceptance checklist.
- If phase-specific commands are not provided, default to the repo acceptance criteria in `CLAUDE.md`.
- Do not continue to Graphite or final Linear state updates until automated checks pass.
- If checks fail, fix issues and rerun until passing or blocked.

## Manual Verification Pause

After automated checks pass, send:

```text
Phase [N] Complete - Ready for Manual Verification

Automated checks passed:
- [command 1]
- [command 2]
- [command 3]

Please run the manual verification steps for this phase and confirm when complete.
```

- Do not mark manual verification complete until the user explicitly confirms.

## Linear Workflow

- Resolve the target issue with `mcp__linear__get_issue` using the provided issue key or ID.
- Read and store the branch name returned on that issue; treat it as the canonical branch for Graphite.
- If the issue has no branch name, stop and ask the user to confirm how to proceed.
- Post a concise progress comment after each phase with:
  - completed scope
  - acceptance commands run
  - manual verification state
  - blockers/risks
- After manual confirmation and successful Graphite submit:
  - move the issue to an in-review status using `mcp__linear__update_issue`
  - post stack/PR links with `mcp__linear__create_comment`
- If in-review status is unclear, query statuses via `mcp__linear__list_issue_statuses` and ask before changing state.

## Graphite Workflow

After manual confirmation for a phase, run these three steps in order:

1. **Sync trunk and clean up merged branches:**
   - `gt sync` — pulls latest trunk, restacks open branches, prompts to delete merged branches (accept deletions when prompted).

2. **Create the branch with all changes committed:**
   - Fetch the branch name from the Linear issue via `mcp__linear__get_issue` (the `gitBranchName` field).
   - `gt create -am "<phase commit message>" <linear-branch-name>`
   - This stages all changes, commits them, and creates a new Graphite branch in one step. The branch name MUST be the one from the Linear issue (e.g. `feature/eng-1242`).

3. **Submit and publish the stack:**
   - `gt submit --publish`

4. **Trigger automated review:**
   - After the PR is created/updated, post a review trigger comment:
   - `gh pr comment <PR-number> --body "@codex review"`

Rules:

- Always run `gt sync` first to avoid "already merged" errors blocking submit.
- The branch name comes from Linear's `gitBranchName` field — never invent branch names.
- `gt create -am` handles staging, committing, and branch creation — do not use `git add` or `git commit` separately.
- Use commit messages tied to phase scope, not generic text.
- Do not run `gt submit --publish` before manual confirmation.
- If a `gt` command fails, report the exact command and error output.

## When to Use Sub-agents

Spawn sub-agents via the Task tool when you get stuck or need deeper understanding:

- **`codebase-analyzer`** — trace how a specific component works when you need deeper understanding
- **`codebase-pattern-finder`** — find existing patterns to follow when implementing something unfamiliar
- **`web-search-researcher`** — research external APIs, unfamiliar errors, or version-specific docs

Keep sub-agent usage focused; provide specific questions and file paths when spawning them.

## Reporting

For each completed phase, report:

- files changed
- acceptance commands and pass/fail result
- manual verification confirmation state
- Linear updates performed
- Graphite branch and stack/PR submission result

## Resuming Work

- If the plan has existing checkmarks, trust completed work and start from the first unchecked item.
- Verify previous work only if something seems off.
- Maintain forward momentum toward the end goal.

## If Blocked

- Re-read relevant plan and code before assuming root cause.
- Consider whether the codebase evolved since the plan was written.
- Surface blockers with exact command errors or plan/code mismatches.
- Ask one focused question to unblock.
