---
name: iterate-plan
description: "Iterates on existing implementation plans using user feedback, updating phases, scope, and verification criteria. Use when asked to revise, adjust, or refine a plan file."
argument-hint: "[plan-file-path] [feedback]"
---

# Iterate Implementation Plan

Updates an existing implementation plan based on user feedback. Be skeptical, thorough, and ground changes in codebase reality.

## Initial Response

When invoked, parse `$ARGUMENTS` to identify:
- Plan file path (example: `thoughts/shared/plans/2025-10-16-feature.md`)
- Requested changes/feedback

Handle input scenarios:

### No plan file provided

```
I'll help you iterate on an existing implementation plan.

Which plan would you like to update? Please provide the path to the plan file (e.g., `thoughts/shared/plans/2025-10-16-feature.md`).

Tip: You can list recent plans with `ls -lt thoughts/shared/plans/ | head`
```

Wait for user input, then re-check for feedback.

### Plan file provided but no feedback

```
I've found the plan at [path]. What changes would you like to make?

For example:
- "Add a phase for migration handling"
- "Update the success criteria to include performance tests"
- "Adjust the scope to exclude feature X"
- "Split Phase 2 into two separate phases"
```

Wait for user input.

### Plan file and feedback provided

Proceed immediately to Step 1. No preliminary questions needed.

## Process Steps

### Step 1: Read and Understand Current Plan

1. Read the existing plan file completely.
2. Understand the current structure, phases, and scope.
3. Note the success criteria and implementation approach.
4. Parse the requested changes and identify whether codebase research is required.

### Step 2: Research if Needed

Only research if the feedback requires new technical understanding or validation.

1. Create a research todo list if the work is complex.
2. Use Grep/Glob for quick targeted lookups.
3. Spawn parallel sub-agents via the Task tool for deeper investigation:
   - **`codebase-analyzer`** — understand how specific components work
   - **`codebase-pattern-finder`** — find existing patterns or conventions to follow
   - **`thoughts-analyzer`** — extract insights from prior research in `thoughts/`
   - **`thoughts-locator`** — discover relevant documents in `thoughts/`
   - **`web-search-researcher`** — research external APIs, libraries, or best practices
4. Wait for all sub-agents to complete before proceeding.
5. Read any new files identified by sub-agents fully into context.

### Step 3: Present Understanding and Approach

Before editing the plan, confirm understanding:

```
Based on your feedback, I understand you want to:
- [Change 1 with specific detail]
- [Change 2 with specific detail]

My research found:
- [Relevant code pattern or constraint]
- [Important discovery that affects the change]

I plan to update the plan by:
1. [Specific modification to make]
2. [Another modification]

Does this align with your intent?
```

Get user confirmation before making changes.

### Step 4: Update the Plan

1. Make focused, precise edits to the existing plan.
2. Preserve the existing structure unless explicitly changing it.
3. Keep all file:line references accurate.
4. Update success criteria if needed.
5. Ensure consistency:
   - If adding a new phase, follow the existing pattern.
   - If modifying scope, update the "What We Are Not Doing" section.
   - If changing approach, update "Implementation Approach".
   - Maintain automated vs manual success criteria separation.

### Step 5: Sync and Review

Present the updates:

```
I've updated the plan at `thoughts/shared/plans/[filename].md`

Changes made:
- [Specific change 1]
- [Specific change 2]

The updated plan now:
- [Key improvement]
- [Another improvement]

Would you like any further adjustments?
```

Be ready to iterate further based on feedback.

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

### Be Thorough
- Read the entire plan before changing it.
- Research code patterns if changes require new understanding.
- Ensure updated sections maintain quality standards.
- Verify success criteria remain measurable.

### No Open Questions
- If the requested change raises questions, ask.
- Do not update the plan with unresolved issues.

## Success Criteria Guidelines

Always keep two categories:

1. **Automated Verification**: Commands, tests, compilation, linting
2. **Manual Verification**: UI/UX, performance, edge cases, user acceptance
