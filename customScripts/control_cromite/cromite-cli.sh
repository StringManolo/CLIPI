#!/usr/bin/env bash

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CLIPI_BIN="$SCRIPT_DIR/../../clipi.js"
SERVER_JS="$SCRIPT_DIR/server.js"
CONTROL_URL="http://127.0.0.1:3000"

cleanup() {
  echo -e "\n[*] Killing processes..."
  pkill -9 -f "node $SERVER_JS"
  pkill -9 -f "$CLIPI_BIN"
  fuser -k 3000/tcp 2>/dev/null
  exit
}

trap cleanup SIGINT SIGTERM

fuser -k 3000/tcp 2>/dev/null
pkill -9 -f "node $SERVER_JS"
pkill -9 -f "$CLIPI_BIN"

node "$SERVER_JS" &
"$CLIPI_BIN" -H 127.0.0.1 -p 8080 > /dev/null 2>&1 &

sleep 2

echo "------------------------------------------------"
echo "  CROMITE INTERACTIVE CLI (Type 'exit' to quit)"
echo "------------------------------------------------"

while true; do
  echo ""
  read -p "JS Code > " USER_INPUT

  if [[ "$USER_INPUT" == "exit" ]]; then
    cleanup
  fi

  PAYLOAD=$(jq -n --arg ac "eval" --arg cd "$USER_INPUT" '{action: $ac, code: $cd}')

  curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$CONTROL_URL"
done
