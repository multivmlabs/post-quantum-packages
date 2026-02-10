---
name: create-plan-linear
description: "Create detailed implementation plans with codebase research and, after explicit user approval, publish the approved phased plan to Linear by creating a project under a chosen initiative plus phase and subphase issues assigned to Timur Guvenkaya."
argument-hint: "[ticket-or-file-path]"
---

# Create Plan Linear

Create a detailed implementation plan first. Only after explicit user approval, create a matching Linear project and issues.

## Intake

- Read any provided ticket, plan, or file paths fully before planning.
- If key inputs are missing, ask for them: objective, constraints, references, and preferred project name.
- Capture initiative and team context early when available.
- Ask only questions that cannot be answered from the codebase or provided context.

## Research

- Read all mentioned files completely; avoid partial reads.
- Use Grep/Glob for quick targeted lookups.
- Spawn parallel sub-agents via the Task tool for deeper investigation:
  - **`codebase-analyzer`** — understand how specific components work (data flow, logic, patterns)
  - **`codebase-pattern-finder`** — find similar implementations or conventions to model after
  - **`thoughts-analyzer`** — deep-dive on research docs in `thoughts/` for prior decisions
  - **`thoughts-locator`** — discover relevant documents in `thoughts/` directory
  - **`web-search-researcher`** — research external APIs, libraries, or technologies
- Gather MCP context before planning:
  - Call `list_mcp_resources` and `list_mcp_resource_templates`.
  - Read relevant resources such as tickets, docs, and runbooks.
- Spawn multiple sub-agents in parallel for efficiency; wait for all to complete before synthesizing.

## Plan Development

- Build a phased implementation plan with clear top-level phases and explicit subphases where needed.
- Use file:line references for current-state analysis and proposed edits.
- Keep automated and manual verification sections separate.
- Use project-standard commands for build/test/lint/docs.
- Save the plan to `<repo_root>/thoughts/shared/plans/<YYYY-MM-DD>-<name>.md`.

### Plan Template

```markdown
# [Feature/Task Name] Implementation Plan

## Overview
[What we are implementing and why]

## Current State Analysis
[What exists now, what is missing, constraints; include file:line references]

## Desired End State
[What "done" looks like and how to verify it]

## What We Are Not Doing
[Explicit out-of-scope list]

## Implementation Approach
[High-level strategy and rationale]

## Phase 1: [Descriptive Name]
[What this phase accomplishes]

### Changes Required
- File: `path/to/file.ext` (file:line)
- Summary of edits

### Success Criteria

#### Automated Verification
- [ ] Command or test that must pass

#### Manual Verification
- [ ] Human validation steps

**Implementation Note**: After completing this phase and automated verification, pause for manual confirmation before proceeding.

---

## Phase 2: [Descriptive Name]
[Repeat structure]

---

## Testing Strategy
- Unit tests
- Integration tests
- Manual testing steps

## Performance Considerations
[Implications and mitigations]

## Migration Notes
[If applicable]

## References
- Ticket or request reference
- Related research docs
- Similar implementations (file:line)
```

## Approval Gate (Mandatory)

- After drafting the plan, stop and request explicit approval.
- Use a direct approval question, for example:
  - `I created the plan at <path>. Approve syncing this plan to Linear?`
- Do not create or modify Linear projects, issues, labels, or comments before approval.
- If the user requests edits, revise the plan and request approval again.

## Linear Sync Workflow (Run Only After Approval)

1. Resolve initiative
- If the initiative name is missing, ask the user for it.
- Use `mcp__linear__get_initiative` (or list/search equivalents) to resolve it.
- If multiple initiatives match, ask the user to choose.

2. Resolve team
- Prefer a team provided by the user.
- If missing, infer from initiative context when possible.
- If still unclear, ask the user for the target Linear team before creating anything.

3. Create project (epic)
- Use `mcp__linear__create_project`.
- Set `name` to the project name.
- Set `initiative` to the resolved initiative.
- Set `team` to the resolved team.
- Set `description` to the full approved plan markdown.
- Set `summary` to a concise one-line overview from the plan.

4. Resolve assignee
- Resolve Timur via `mcp__linear__get_user` with query `timur guvenkaya`.
- If no exact match is found, ask the user before assigning to another user.

5. Prepare labels and severity
- Derive labels from phase scope (for example: `consensus`, `execution`, `networking`, `docs`, `testing`).
- For each required label:
  - Check existing labels via `mcp__linear__list_issue_labels`.
  - Create missing labels via `mcp__linear__create_issue_label`.
- Apply severity to each issue using both priority and a severity label.
- Default severity mapping:
  - `critical` -> priority `1`, label `severity:critical`
  - `high` -> priority `2`, label `severity:high`
  - `medium` -> priority `3`, label `severity:medium`
  - `low` -> priority `4`, label `severity:low`
- If severity is unclear from the plan, default to `medium`.

6. Create phase issues
- Create one Linear issue per top-level phase under the created project.
- Set issue title to the phase title.
- Set issue description to the phase plan content (scope, changes, and success criteria).
- Assign each issue to Timur.
- Add derived labels, severity label, and priority.

7. Create subphase sub-issues
- For each subphase under a phase, create a child issue with `parentId` set to the parent phase issue.
- Use subphase title for the child issue title.
- Use subphase details for description.
- Apply the same assignment, labels, and severity policy unless subphase context implies a different severity.

8. Return sync summary
- Report created project identifier/name.
- Report each created phase issue and sub-issue with identifiers.
- Call out any assumptions made (team inference, severity defaults, inferred labels).

## Execution Rules

- Never skip the user approval gate.
- Never proceed with ambiguous initiative/team/assignee without clarifying.
- Keep issue text grounded in the approved plan; do not invent new scope.
- Prefer deterministic, auditable mappings from plan phase to Linear issue.
