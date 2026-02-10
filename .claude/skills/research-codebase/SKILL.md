---
name: research-codebase
description: "Document codebase as-is without evaluation or recommendations. Use when asked to research, explore, or document how code works."
argument-hint: "[research-question]"
---

# Research Codebase

Conducts comprehensive research across the codebase to answer questions by spawning parallel sub-agents and synthesizing findings.

## Critical Rule

Your only job is to document and explain the codebase as it exists today.
- Do NOT suggest improvements, changes, or future enhancements.
- Do NOT critique the implementation or identify problems.
- Do NOT recommend refactoring, optimization, or architectural changes.
- Only describe what exists, where it exists, how it works, and how components interact.

## Initial Setup

If `$ARGUMENTS` contains a research question, proceed immediately. Otherwise ask:

```
I'm ready to research the codebase. Please provide your research question or area of interest, and I'll analyze it thoroughly by exploring relevant components and connections.
```

## Steps

### 1. Read Mentioned Files

If the user mentions specific files, read them fully before spawning sub-tasks.

### 2. Decompose the Research Question

- Break down the query into composable research areas.
- Identify specific components, patterns, or concepts to investigate.
- Create a research plan using TodoWrite.

### 3. Spawn Parallel Sub-agents

Use the Task tool to spawn specialized subagent types concurrently:

- **`codebase-analyzer`** — understand HOW specific code works (data flow, logic, patterns). Instruct it to document only, not critique.
- **`codebase-pattern-finder`** — find examples of existing patterns and conventions with concrete code snippets.
- **`thoughts-analyzer`** — deep-dive on research docs in `thoughts/` for prior decisions and context.
- **`thoughts-locator`** — discover relevant documents in `thoughts/` directory.
- **`Explore`** — fast broad search to find WHERE files and components live.

All agents are documentarians, not critics. Instruct them to describe what exists without suggesting improvements.

For web research (only if user explicitly asks):
- **`web-search-researcher`** — include returned links in the final report

### 4. Synthesize Findings

Wait for all sub-agents to complete, then:
- Compile results, prioritizing live codebase findings as primary source of truth.
- Connect findings across different components.
- Include specific file paths and line numbers.
- Answer the user's questions with concrete evidence.

### 5. Gather Metadata

Run commands to generate:
- Current date and time
- Git commit hash and branch
- Repository name

### 6. Write Research Document

Save to `thoughts/shared/research/YYYY-MM-DD-description.md` (include ENG-XXXX if a ticket is referenced).

Use this structure:

```markdown
---
date: [ISO date with timezone]
git_commit: [commit hash]
branch: [branch name]
repository: [repo name]
topic: "[Research question]"
tags: [research, codebase, relevant-component-names]
status: complete
---

# Research: [Topic]

## Research Question
[Original query]

## Summary
[High-level documentation answering the question]

## Detailed Findings

### [Component/Area 1]
- Description with file:line references
- How it connects to other components

### [Component/Area 2]
...

## Code References
- `path/to/file.ext:123` - Description

## Architecture Documentation
[Current patterns, conventions, and design implementations]

## Open Questions
[Areas needing further investigation]
```

### 7. Present Findings

- Provide a concise summary to the user.
- Include key file references for navigation.
- Ask if they have follow-up questions.

### 8. Handle Follow-ups

- Append to the same research document.
- Add a `## Follow-up Research [timestamp]` section.
- Spawn new sub-agents as needed.

## Important Notes

- Always use parallel sub-agents for efficiency.
- Run fresh codebase research; never rely solely on existing docs.
- Focus on concrete file paths and line numbers.
- Document what IS, not what SHOULD BE.
- Read mentioned files fully before spawning sub-tasks.
