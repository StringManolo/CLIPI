#!/usr/bin/env bash

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CLIPI_BIN="$SCRIPT_DIR/../../clipi.js"
SERVER_JS="$SCRIPT_DIR/server.js"
URL="http://127.0.0.1:3000"
HISTORY_FILE="$SCRIPT_DIR/.cromite_history"

touch "$HISTORY_FILE"

cleanup() {
  pkill -9 -f "node $SERVER_JS"
  pkill -9 -f "$CLIPI_BIN"
  exit
}

trap cleanup SIGINT SIGTERM

node "$SERVER_JS" &
"$CLIPI_BIN" -H 127.0.0.1 -p 8080 > /dev/null 2>&1 &

sleep 2

echo "--- CROMITE CLI ---"
echo "Use arrows to navigate history and edit lines."

while true; do
  echo ""
  history -r "$HISTORY_FILE"
  read -e -p "cromite > " IN
  
  if [[ "$IN" == "exit" ]]; then cleanup; fi
  
  if [[ -n "$IN" ]]; then
    echo "$IN" >> "$HISTORY_FILE"
    history -s "$IN"
    
    PAYLOAD=$(jq -n --arg ac "eval" --arg cd "$IN" '{action: $ac, code: $cd}')
    curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$URL"
  fi
done
