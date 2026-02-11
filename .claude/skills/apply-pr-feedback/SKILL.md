---
name: apply-pr-feedback
description: "Automated PR review loop: fetches all PR comments, checks the last one to determine state, evaluates and fixes codex findings, pushes, re-triggers review, and repeats until clean — then squash-merges."
argument-hint: "[pr-number-or-url]"
---

# Apply PR Feedback

Deterministic loop that processes codex review feedback on a PR until clean, then merges.

## Inputs

- **PR number or URL** — optional. If not provided, detect from the current Graphite branch (`gt ls` or `gh pr list --head <branch>`).

No manual copy-paste of feedback is needed — the skill reads comments directly from the PR.

## Setup

1. Determine the PR number (from argument or current branch).
2. Determine the repo owner/name from `git remote get-url origin`.

## Step 1: Get All Comments

Fetch all comments on the PR (both issue comments and PR review comments are visible here):
```bash
gh api repos/{owner}/{repo}/issues/{pr}/comments \
  --jq '[.[] | {id, user: .user.login, body: .body, created_at}] | sort_by(.created_at)'
```

Also fetch PR reviews (codex sometimes posts as a PR review instead of an issue comment):
```bash
gh api repos/{owner}/{repo}/pulls/{pr}/reviews \
  --jq '[.[] | {id, user: .user.login, body: .body, submitted_at}] | sort_by(.submitted_at)'
```

Combine both lists and sort by timestamp. Identify the **last comment/review** across both.

## Step 2: Check the Last Comment

Look at the last comment/review and branch:

### (a) Last comment contains `@codex review`

Review is still pending. Sleep 60 seconds, then go back to **Step 1**.

### (b) Last comment/review is from `chatgpt-codex-connector[bot]`

Check if it indicates a clean review or has findings:

- **Clean review** — the body contains "Didn't find any major issues" or similar pass message → go to **Step 8**.
- **Has findings** — codex posted inline review comments → go to **Step 3**.

To check for inline findings:
```bash
gh api repos/{owner}/{repo}/pulls/{pr}/comments \
  --jq '[.[] | select(.user.login == "chatgpt-codex-connector[bot]")]'
```
Filter to only unresolved comments (check against resolved threads). If there are unresolved codex comments, proceed to **Step 3**. If all are resolved (or there are none), treat as clean → go to **Step 8**.

### (c) Last comment is something else (e.g., Greptile, a human)

Ignore it. Look at the comment before it and repeat this check. Walk backwards through comments until you find either `@codex review` or a `chatgpt-codex-connector[bot]` response.

## Step 3: Evaluate Findings

For each unresolved codex inline comment:

1. Read the referenced file and line range with full surrounding context.
2. Evaluate the feedback against the actual code:
   - **Valid** — real issue (bug, safety concern, spec violation, missing edge case)
   - **Improvement** — better approach, correct but not strictly a bug
   - **False positive** — problem does not actually exist in the code

3. Report assessment:
   ```text
   [file:lines] — <Valid | Improvement | False positive>
   Reason: <1-2 sentence explanation>
   ```

4. If **valid** or **improvement**, apply the fix immediately.
5. If **false positive**, reply to the comment with a brief reason explaining why.

## Step 4: Resolve PR Conversations

After evaluating ALL comments and applying all fixes, resolve each review thread:

To resolve a review thread, use the GraphQL API. First fetch thread IDs:
```bash
gh api graphql -f query='
  query {
    repository(owner: "<owner>", name: "<repo>") {
      pullRequest(number: <pr>) {
        reviewThreads(last: 50) {
          nodes { id isResolved comments(first: 1) { nodes { body author { login } } } }
        }
      }
    }
  }
'
```

Then resolve each unresolved codex thread:
```bash
gh api graphql -f query='
  mutation {
    resolveReviewThread(input: {threadId: "<thread_id>"}) {
      thread { isResolved }
    }
  }
'
```

**Important:** `resolveReviewThread` requires a `PullRequestReviewThread` ID (starts with `PRRT_`), not a review comment ID. Match threads to comments by the first comment body and author.

## Step 5: Run Acceptance Checks

1. Run the repository acceptance criteria:
   - Build commands (including no_std if applicable).
   - Linter / clippy with warnings as errors.
   - Formatter check.
   - Full test suite.
2. If any check fails, fix the issue and rerun until passing.

## Step 6: Push Changes

Once all checks pass:
```bash
git add <changed-files>
gt modify
gt submit
```

Report summary:
```text
| File:Lines | Assessment | Action |
|---|---|---|
| file.rs:10-15 | Valid | Brief description of fix applied |
| file.rs:42-44 | False positive | Reason (no change) |

Checks passed:
- <command 1>
- <command 2>

Pushed via: gt modify + gt submit
```

## Step 7: Trigger Review and Loop

```bash
gh pr comment {pr-number} --body "@codex review"
sleep 60
```

Go back to **Step 1**.

## Step 8: Merge PR

Codex review passed with no issues. Ask the user: "Codex review passed. Shall I squash-merge this PR?"

If the user accepts:
```bash
gh pr merge {pr-number} --squash --delete-branch
```

Report the merge result.

## Rules

- Never push before all acceptance checks pass.
- Keep fixes minimal and targeted to the feedback.
- Do not use `git commit` directly — use `gt modify` to amend into the existing branch commit.
- If a fix introduces a test failure elsewhere, investigate and fix before pushing.
- If feedback is ambiguous, ask the user to clarify before making changes.
- Only process comments from `chatgpt-codex-connector[bot]` — ignore other reviewers.
- Push autonomously — no user confirmation needed between loop iterations.
- When waiting for review, poll every 60 seconds — do not busy-loop.
