#!/bin/bash

PUBLIC_RPC="https://polygon-bor-rpc.publicnode.com"
LOCAL_RPC="http://127.0.0.1:8545"
INTERVAL=5

# Colors
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

get_block_number() {
  curl -s -X POST "$1" \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    | jq -r .result
}

hex_to_dec() {
  printf "%d" "$1"
}

format_time() {
  secs=$1
  printf "%02dd %02dh %02dm %02ds" \
    $((secs/86400)) \
    $((secs%86400/3600)) \
    $((secs%3600/60)) \
    $((secs%60))
}

PREV_LOCAL=0
PREV_TIME=0

while true; do
  CURRENT_TIME=$(date +%s)

  PUBLIC_HEX=$(get_block_number $PUBLIC_RPC)
  LOCAL_HEX=$(get_block_number $LOCAL_RPC)

  if [[ -z "$PUBLIC_HEX" || -z "$LOCAL_HEX" ]]; then
    echo -e "${RED}Error fetching block numbers${NC}"
    sleep $INTERVAL
    continue
  fi

  PUBLIC_BLOCK=$(hex_to_dec $PUBLIC_HEX)
  LOCAL_BLOCK=$(hex_to_dec $LOCAL_HEX)

  DIFF=$((PUBLIC_BLOCK - LOCAL_BLOCK))
  [ "$DIFF" -lt 0 ] && DIFF=0

  PROGRESS=$(awk "BEGIN { printf \"%.4f\", ($LOCAL_BLOCK/$PUBLIC_BLOCK)*100 }")

  # Sync speed calculation
  SPEED=0
  if [ "$PREV_LOCAL" -ne 0 ]; then
    BLOCK_DIFF=$((LOCAL_BLOCK - PREV_LOCAL))
    TIME_DIFF=$((CURRENT_TIME - PREV_TIME))
    if [ "$TIME_DIFF" -gt 0 ]; then
      SPEED=$(awk "BEGIN { printf \"%.2f\", $BLOCK_DIFF/$TIME_DIFF }")
    fi
  fi

  # ETA calculation
  ETA="N/A"
  if (( $(echo "$SPEED > 0" | bc -l) )); then
    ETA_SECONDS=$(awk "BEGIN { printf \"%d\", $DIFF/$SPEED }")
    ETA=$(format_time $ETA_SECONDS)
  fi

  clear
  echo -e "${BLUE}======================================${NC}"
  echo -e "${BLUE}      Polygon Sync Monitor${NC}"
  echo -e "${BLUE}======================================${NC}"
  echo -e "Public Block  : ${YELLOW}$PUBLIC_BLOCK${NC}"
  echo -e "Local Block   : ${YELLOW}$LOCAL_BLOCK${NC}"
  echo -e "Blocks Behind : ${RED}$DIFF${NC}"
  echo -e "Sync Progress : ${GREEN}$PROGRESS %${NC}"
  echo -e "Sync Speed    : ${GREEN}$SPEED blocks/sec${NC}"
  echo -e "ETA           : ${GREEN}$ETA${NC}"

  if [ "$DIFF" -eq 0 ]; then
    echo -e "Status        : ${GREEN}FULLY SYNCED ✅${NC}"
  else
    echo -e "Status        : ${YELLOW}SYNCING ⏳${NC}"
  fi

  PREV_LOCAL=$LOCAL_BLOCK
  PREV_TIME=$CURRENT_TIME

  sleep $INTERVAL
done

