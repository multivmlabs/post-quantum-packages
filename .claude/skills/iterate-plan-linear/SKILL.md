---
name: iterate-plan-linear
description: "Iterate and refine existing implementation plan files using user feedback, then after explicit approval update the related Linear project and phase/subphase issues with the revised plan content. Use when asked to revise a plan and keep Linear tracking artifacts synchronized."
argument-hint: "[plan-file-path] [feedback]"
---

# Iterate Plan + Linear Sync

Revise an existing plan first. After user approval, sync the approved revision to Linear project and issue records.

## Input Handling

- Identify plan path and requested feedback from `$ARGUMENTS`.
- If the plan path is missing, ask for it and stop.
- If feedback is missing, ask what to change and stop.
- Capture Linear context early when available:
  - project identifier or name
  - team
  - initiative
  - existing issue mapping (phase -> issue ID)

## Step 1: Read and Understand Current Plan

1. Read the entire plan file.
   - Use the Read tool with no range for the initial read.
   - If the file exceeds the default window, read additional ranges until complete.
2. Extract:
   - plan title
   - top-level phases
   - subphases
   - success criteria and scope boundaries
3. Parse requested edits and determine whether codebase research is needed.

## Step 2: Research Only When Needed

- Use Grep/Glob for quick targeted lookups.
- Spawn parallel sub-agents via the Task tool for deeper investigation:
  - **`codebase-analyzer`** — understand how specific components work
  - **`codebase-pattern-finder`** — find existing patterns or conventions to follow
  - **`thoughts-analyzer`** — extract insights from prior research in `thoughts/`
  - **`thoughts-locator`** — discover relevant documents in `thoughts/`
  - **`web-search-researcher`** — research external APIs, libraries, or best practices
- Read identified files fully and capture file:line references for any new claims added to the plan.
- Run independent research tasks in parallel when possible.
- Skip external research unless the change depends on external, time-sensitive information.

## Step 3: Confirm Change Intent Before Editing

Summarize:
- requested changes
- relevant constraints discovered
- exact edits you intend to make

Ask for confirmation before modifying the plan.

## Step 4: Update the Plan Surgically

- Preserve existing structure unless the user explicitly requests structural changes.
- Keep edits precise; avoid full rewrites.
- Keep automated and manual verification sections separate.
- If scope changes, update out-of-scope sections and affected phases.
- Keep any file:line references accurate.
- Ensure consistency:
  - If adding a new phase, follow the existing pattern.
  - If modifying scope, update the "What We Are Not Doing" section.
  - If changing approach, update "Implementation Approach".

## Step 5: Present Updates

Present the updates before requesting Linear sync approval:

```
I've updated the plan at `thoughts/shared/plans/[filename].md`

Changes made:
- [Specific change 1]
- [Specific change 2]

The updated plan now:
- [Key improvement]
- [Another improvement]

Would you like any further adjustments, or approve syncing these revisions to Linear?
```

Be ready to iterate further based on feedback.

## Step 6: Approval Gate for Linear Sync (Mandatory)

After plan edits are finalized, pause and ask for explicit approval, for example:

`I updated <plan-path>. Approve syncing these revisions to Linear project/issues?`

Rules:
- Never create or update Linear records before explicit approval.
- If the user requests more plan changes, iterate again and ask for approval again.

## Step 7: Sync Approved Plan Changes to Linear

Run only after approval.

1. Resolve target project
- Prefer a user-provided project ID or project name.
- If missing, infer from prior sync context in the plan or recent conversation.
- If ambiguous, ask the user to choose; do not guess.

2. Resolve team and assignee
- Use the provided team, or infer from the existing project.
- Resolve assignee via `mcp__linear__get_user` with query `timur guvenkaya`.
- If no exact match is found, ask before assigning alternatives.

3. Update project record
- Update the Linear project summary and description with the approved plan via `mcp__linear__create_project` or the appropriate update MCP call.
- Keep wording grounded in the approved plan; do not add new scope.

4. Prepare labels and severity
- Derive labels from phase scope (for example: `consensus`, `execution`, `networking`, `docs`, `testing`).
- For each required label:
  - Check existing labels via `mcp__linear__list_issue_labels`.
  - Create missing labels via `mcp__linear__create_issue_label`.
- Default severity mapping:
  - `critical` -> priority `1`, label `severity:critical`
  - `high` -> priority `2`, label `severity:high`
  - `medium` -> priority `3`, label `severity:medium`
  - `low` -> priority `4`, label `severity:low`
- If severity is unclear from the plan, default to `medium`.

5. Sync phase issues
- Map each top-level phase to an existing issue (prefer explicit IDs; otherwise exact-title match inside the project).
- Update matched issues with revised scope, success criteria, labels, and priority.
- Create missing phase issues when no reliable match exists.
- Assign each issue to Timur.

6. Sync subphase issues
- For each subphase, update or create a child issue under the parent phase issue using `parentId`.
- Keep child issue descriptions aligned to the updated plan text.

7. Handle removed or renamed phases safely
- Do not auto-close or delete unmatched issues.
- Present unmatched items and ask whether to close, rename, or leave unchanged.

8. Return sync report
- Report the project updated.
- List issues created, updated, and unmatched.
- Call out assumptions and any clarifications requested.

## Important Guidelines

### Be Skeptical
- Don't blindly accept change requests that seem problematic.
- Question vague feedback and ask for clarification.
- Verify feasibility with code research.
- Point out conflicts with existing phases.

### Be Surgical
- Make precise edits, not wholesale rewrites.
- Preserve content that doesn't need changing.
- Research only what the specific changes require.

### No Open Questions
- If the requested change raises questions, ask.
- Do not update the plan with unresolved issues.

## Execution Rules

- Never skip the approval gate.
- Never mutate Linear with ambiguous project, team, or assignee selection.
- Prefer deterministic mappings from plan phase names to issue records.
- Keep output auditable by including identifiers for all updated and created records.
