---
name: create-plan
description: "Create detailed implementation plans with codebase research, phased steps, file:line references, and verification criteria. Use when asked to plan, spec, or design a feature."
argument-hint: "[ticket-or-file-path]"
---

# Create Plan

Creates detailed implementation plans and technical specifications.

## Intake

- If a ticket or file path is provided as `$ARGUMENTS`, read it fully first.
- If no inputs are provided, ask for: task/ticket, constraints, and related references or links.
- Ask only questions that cannot be resolved by code or docs.

## Research

- Read all mentioned files completely; avoid partial reads.
- Use Grep/Glob for quick targeted lookups.
- Spawn parallel sub-agents via the Task tool for deeper investigation:
  - **`codebase-analyzer`** — understand how specific components work (data flow, logic, patterns)
  - **`codebase-pattern-finder`** — find similar implementations or conventions to model after
  - **`thoughts-analyzer`** — deep-dive on research docs in `thoughts/` for prior decisions
  - **`thoughts-locator`** — discover relevant documents in `thoughts/` directory
  - **`web-search-researcher`** — research external APIs, libraries, or technologies
- Discover and use MCP servers for additional context:
  - Call `list_mcp_resources` and `list_mcp_resource_templates`.
  - Read relevant resources (tickets, docs, schemas, runbooks).
- Spawn multiple sub-agents in parallel for efficiency; wait for all to complete before synthesizing.

## Synthesis

- Summarize current state with file:line references and constraints.
- If the user corrects something, re-check sources before proceeding.

## Plan Development

- Propose design options with pros/cons and align on approach.
- Present a phase outline and confirm ordering.
- Write the detailed plan using the template below.
- Keep automated and manual verification separate.
- Use project-standard commands for build/test/lint/docs.

## Completion Rules

- Do not finalize the plan with open questions.
- Make decisions explicit; verify assumptions with sources.

## Output Location

- Save the plan to `<repo_root>/thoughts/shared/plans/<current_date>-<name-of-plan>.md`.
- If the repo root is ambiguous, detect it from the current working directory or ask.
- Use the current date in `YYYY-MM-DD` format (e.g., `2025-01-30-auth-refactor.md`).

## Template

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
```[language]
# Pseudocode or key snippets if helpful
```

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
