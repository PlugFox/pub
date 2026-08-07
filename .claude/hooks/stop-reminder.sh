#!/usr/bin/env bash
# Stop hook: reminds about required checks when server/ or web/ files were edited.
# Reads the Stop-hook JSON event on stdin, extracts the transcript path,
# and scans tool_use entries for Edit/Write targets under server/ or web/.
# Adapted from foxic's stop-reminder.sh.

set -euo pipefail

# stop_hook_active=true means we're being re-entered from our own decision —
# bail out to avoid infinite loops (per Claude Code hook spec).
event=$(cat)
if printf '%s' "$event" | jq -e '.stop_hook_active == true' >/dev/null 2>&1; then
    exit 0
fi

transcript=$(printf '%s' "$event" | jq -r '.transcript_path // empty')
if [[ -z "$transcript" || ! -f "$transcript" ]]; then
    exit 0
fi

# Collect Edit/Write targets. Transcript is JSONL: one message per line.
paths=$(jq -r '
    select(.type == "assistant")
    | .message.content[]?
    | select(.type == "tool_use" and (.name == "Edit" or .name == "Write" or .name == "NotebookEdit"))
    | .input.file_path // empty
' "$transcript" 2>/dev/null || true)

server_touched=false
web_touched=false

while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    case "$p" in
        */server/*.rs|*/server/*.toml|*/server/*/migrations/*) server_touched=true ;;
        */web/*.ts|*/web/*.tsx|*/web/*.astro|*/web/*.css|*/web/*.json|*/web/*.yaml) web_touched=true ;;
    esac
done <<< "$paths"

if ! $server_touched && ! $web_touched; then
    exit 0
fi

msg="Reminder before reporting task as done:"
if $server_touched; then
    msg+=$'\n  server/ changed -> cd server && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --workspace'
fi
if $web_touched; then
    msg+=$'\n  web/ changed -> cd web && bun run check && bun run build && bun test'
fi

# Stop events don't support hookSpecificOutput/additionalContext; the schema-valid
# way to feed text back into the model is decision:"block" + reason. The
# stop_hook_active guard above means this fires at most once per turn (the
# re-entry it triggers carries stop_hook_active=true and exits early).
jq -n --arg c "$msg" '{decision: "block", reason: $c}'
