---
name: implement-plan
description: "Implements approved technical plans from thoughts/shared/plans with phased execution and verification. Use when asked to implement or carry out a plan file."
argument-hint: "[plan-file-path] [linear-issue-key (optional)]"
---

# Implement Plan

Implements an approved technical plan from `thoughts/shared/plans/` with phased execution and verification.

## Getting Started

- If a plan path is provided as `$ARGUMENTS`, read the plan completely and check for any existing checkmarks (`- [x]`).
- If a Linear issue key is provided (e.g. `ENG-1241`), resolve it via `mcp__linear-server__get_issue` and use it for progress updates throughout execution.
- Read the original ticket and all files mentioned in the plan.
- Read files fully (no limit/offset); ensure complete context.
- Think through how the pieces fit together before making changes.
- Create a todo list to track progress.
- Start implementing once the scope is clear.
- If no plan path is provided, ask for one.

## Implementation Philosophy

- Follow the plan's intent while adapting to what you find.
- Implement each phase fully before moving to the next.
- Verify changes make sense in the broader codebase context.
- Update checkboxes in the plan as sections are completed.

If you encounter a mismatch between plan and codebase:

```
Issue in Phase [N]:
Expected: [what the plan says]
Found: [actual situation]
Why this matters: [explanation]

How should I proceed?
```

## Verification Approach

After implementing a phase:

- Run the success criteria checks (usually `make check test` covers everything).
- Fix any issues before proceeding.
- Update progress in both the plan and your todos.
- Check off completed items in the plan file itself.
- Pause for human verification after automated checks unless explicitly instructed to execute multiple phases.

Manual verification pause format:

```
Phase [N] Complete - Ready for Manual Verification

Automated verification passed:
- [List automated checks that passed]

Please perform the manual verification steps listed in the plan:
- [List manual verification items from the plan]

Let me know when manual testing is complete so I can proceed to Phase [N+1].
```

Do not check off manual testing items until the user confirms completion.

## Linear Progress Updates (when issue key provided)

When a Linear issue key is provided, keep the issue synced as work progresses:

- **After automated checks pass for a phase**:
  - Update the Linear issue description to check off the corresponding checkboxes (e.g. `- [ ]` → `- [x]`) using `mcp__linear-server__update_issue` with the updated description markdown.
  - Post a concise progress comment via `mcp__linear-server__create_comment` summarizing completed scope, acceptance commands run, and results.
  - Move the issue to in-review status via `mcp__linear-server__update_issue`.
    - If the correct status name is unclear, query via `mcp__linear-server__list_issue_statuses` and ask before changing state.
- **After manual verification is confirmed**: update the description to check off manual verification checkboxes and post a confirming comment.

Rules:
- Always read the current issue description before updating it to avoid overwriting other changes.
- Only check off items in the description that have actually been verified to pass.
- Do not change issue status before automated checks pass.

## If You Get Stuck

- Re-read all relevant code before making assumptions.
- Consider whether the codebase evolved since the plan was written.
- Present the mismatch clearly and ask for guidance.
- Spawn sub-agents via the Task tool for targeted investigation:
  - **`codebase-analyzer`** — trace how a specific component works when you need deeper understanding
  - **`codebase-pattern-finder`** — find existing patterns to follow when implementing something unfamiliar
  - **`web-search-researcher`** — research external APIs, unfamiliar errors, or version-specific docs
- Keep sub-agent usage focused; provide specific questions and file paths when spawning them.

## Resuming Work

- If the plan has existing checkmarks, trust completed work and start from the first unchecked item.
- Verify previous work only if something seems off.
- Maintain forward momentum toward the end goal.
