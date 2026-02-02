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
  result=$(docker sandbox run claude --permission-mode acceptEdits -p "@$PACKAGE_DIR/PRD.md @$PACKAGE_DIR/progress.txt \
  Working directory for this package: $PACKAGE_DIR/ts/ \
  1. Find the highest-priority task and implement it. \
  2. Run your tests and type checks. \
  3. Update the PRD with what was done. \
  4. Append your progress to progress.txt. \
  5. Commit your changes. \
  ONLY WORK ON A SINGLE TASK. \
  If the PRD is complete, output <promise>COMPLETE</promise>.")

  echo "$result"

  if [[ "$result" == *"<promise>COMPLETE</promise>"* ]]; then
    echo "PRD complete after $i iterations."
    exit 0
  fi
done

echo "Completed $ITERATIONS iterations. PRD may not be fully complete."
