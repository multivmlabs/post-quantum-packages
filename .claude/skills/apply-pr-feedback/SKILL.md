---
name: apply-pr-feedback
description: "Evaluates PR review feedback (file, line, comment), classifies it as valid or false-positive, applies fixes for valid feedback, runs acceptance checks, and pushes updates via Graphite. Use when applying code review comments to an open PR."
argument-hint: "<file-path:line-range> <feedback-text>"
---

# Apply PR Feedback

Evaluates and applies PR review feedback one item at a time. For each piece of feedback: assess validity, fix if valid, then after all feedback is processed run checks and push.

## Inputs

Each feedback item consists of:

- **File path** and **line range** — the code location being reviewed.
- **Feedback text** — the reviewer's comment describing the issue or suggestion.

The user may provide multiple feedback items in sequence. Process them one at a time in conversation order.

## Feedback Evaluation

For each feedback item:

1. Read the referenced file and line range with full surrounding context.
2. Evaluate the feedback against the actual code:
   - **Valid** — the feedback identifies a real issue (bug, safety concern, spec violation, missing edge case, etc.)
   - **Improvement** — the feedback suggests a better approach that is correct but not strictly a bug.
   - **False positive** — the feedback describes a problem that does not actually exist in the code.

3. Report your assessment concisely:

```text
[file:lines] — <Valid | Improvement | False positive>
Reason: <1-2 sentence explanation>
```

4. If **false positive**, explain why and ask the user to confirm before skipping.
5. If **valid** or **improvement**, apply the fix immediately.

## Applying Fixes

When applying a fix:

- Make the minimal change that addresses the feedback.
- If the fix changes function signatures or behavior, update all callers.
- If the fix changes error handling or edge cases, add or update tests to cover the new behavior.
- Do not make unrelated changes or refactor surrounding code.

## Batch Flow

The user will provide feedback items one at a time or in batches. Follow this flow:

1. For each item: evaluate, report assessment, apply fix (or flag false positive).
2. After applying a fix, confirm it's done and ask if there is more feedback.
3. When the user says all feedback is provided, proceed to **Verification & Push**.

## Verification & Push

After all feedback items are resolved:

1. Run the repository acceptance criteria:
   - Build commands (including no_std if applicable).
   - Linter / clippy with warnings as errors.
   - Formatter check.
   - Full test suite.
2. If any check fails, fix the issue and rerun until passing.
3. Once all checks pass, push the update:
   - `git add <changed-files>` — stage only the files that were modified.
   - `gt modify` — amend the changes into the current branch commit.
   - `gt submit` — push the updated branch.

## Reporting

After push, summarize:

```text
PR feedback applied:
- [file:lines] — <assessment> — <what was changed>
- [file:lines] — <assessment> — <what was changed>

Checks passed:
- <command 1>
- <command 2>

Pushed via: gt modify + gt submit
```

## Rules

- Never push before all acceptance checks pass.
- Keep fixes minimal and targeted to the feedback.
- Do not use `git commit` directly — use `gt modify` to amend into the existing branch commit.
- If a fix introduces a test failure elsewhere, investigate and fix before pushing.
- If feedback is ambiguous, ask the user to clarify before making changes.
