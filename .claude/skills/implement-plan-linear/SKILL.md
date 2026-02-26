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

Phases form a **Graphite stack** — each phase branch stacks on top of the previous one. The stack is created incrementally: phase 1 branches off trunk, phase 2 branches off phase 1, and so on. The entire stack is merged together after all phases are complete and reviewed.

After manual confirmation for a phase, run these steps in order:

1. **Sync trunk and restack:**
   - `gt sync` — pulls latest trunk, restacks open branches, accepts deletion of merged branches. Safe to run whether on trunk or on an existing stack branch.

2. **Create the branch with all changes committed:**
   - Fetch the branch name from the Linear issue via `mcp__linear__get_issue` (the `gitBranchName` field).
   - `gt create -am "<type>(<package>/<language>): phase <N> - <description> (<issue-key>)" <linear-branch-name>`
   - `gt create` stacks on whatever branch you are currently on — trunk for phase 1, the previous phase's branch for phase 2+.
   - Commit message format:
     - `<type>`: conventional commit type derived from the phase's intent:
       - `feat` — new functionality, new API surface, new exports
       - `fix` — bug fixes, correcting broken behavior
       - `refactor` — restructuring without behavior change
       - `test` — adding/updating tests only
       - `docs` — documentation, README, comments only
       - `chore` — build config, CI, package metadata, tooling
     - `<package>`: package folder name under `packages/` (e.g. `pq-jws`, `pq-oid`, `pq-key-encoder`)
     - `<language>`: language folder under the package (`ts`, `rust`, or `python`)
     - `<N>`: phase number from the plan
     - `<description>`: concise summary of the phase scope
     - `<issue-key>`: Linear issue key provided at invocation (e.g. `ENG-1640`)
   - Determine `<type>` by reading the phase title and scope from the plan — pick the type that best describes the primary intent of the phase.
   - Examples:
     - `feat(pq-jws/ts): phase 1 - define public contracts (ENG-1640)`
     - `test(pq-jws/ts): phase 4 - comprehensive test suite (ENG-1643)`
     - `fix(pq-oid/rust): phase 2 - correct DER length encoding (ENG-1500)`

3. **Submit and publish the stack:**
   - `gt submit --publish` — pushes all branches in the stack and creates/updates PRs for each.

Rules:

- Always run `gt sync` before `gt create` — it is safe on stack branches and keeps the stack rebased on latest trunk.
- The branch name comes from Linear's `gitBranchName` field — never invent branch names.
- `gt create -am` handles staging, committing, and branch creation — do not use `git add` or `git commit` separately.
- Commit message must follow: `<type>(<package>/<language>): phase <N> - <description> (<issue-key>)` — derive type from the phase intent, package/language from the plan path, phase number from the plan, and issue key from the input.
- Do not run `gt submit --publish` before manual confirmation.
- Do **not** merge individual phase PRs — the entire stack is merged together after all phases are complete.
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
