#!/bin/bash
set -euo pipefail

if [ -z "${1-}" ] || [ -z "${2-}" ]; then
  echo "Usage: $0 <package-name> <iterations>"
  echo "Example: $0 pq-oid 12"
  exit 1
fi

PACKAGE=$1
ITERATIONS=$2
PACKAGE_DIR="packages/$PACKAGE"
CODEX_BIN="${CODEX_BIN:-codex}"
CODEX_ARGS="${CODEX_ARGS:-exec}"

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [ "$ITERATIONS" -le 0 ]; then
  echo "Error: iterations must be a positive integer"
  exit 1
fi

if [ ! -d "$PACKAGE_DIR" ]; then
  echo "Error: Package directory $PACKAGE_DIR does not exist"
  exit 1
fi

if [ ! -f "$PACKAGE_DIR/PRD.md" ]; then
  echo "Error: Missing $PACKAGE_DIR/PRD.md"
  exit 1
fi

if [ ! -f "$PACKAGE_DIR/progress.txt" ]; then
  echo "Error: Missing $PACKAGE_DIR/progress.txt"
  exit 1
fi

for ((i=1; i<=$ITERATIONS; i++)); do
  result=$(cd "$PACKAGE_DIR" && "$CODEX_BIN" $CODEX_ARGS "Follow PRD.md and progress.txt. Use the ts/ subdirectory for code changes.
1. Find the highest-priority task and implement it (edit files under ts/ as needed).
2. Run your tests and type checks (cd ts && bun test, npm run build).
3. Update PRD.md with what was done.
4. Append your progress to progress.txt.
5. Commit your changes.
ONLY WORK ON A SINGLE TASK.
If the PRD is complete, output <promise>COMPLETE</promise>.")

  echo "$result"

  if [[ "$result" == *"<promise>COMPLETE</promise>"* ]]; then
    echo "PRD complete after $i iterations."
    exit 0
  fi
done

echo "Completed $ITERATIONS iterations. PRD may not be fully complete."
