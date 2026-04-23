#!/usr/bin/env bash
set -euo pipefail

RUNS=${1:-10}

echo "Rebuilding containers..."
docker compose build --no-cache

for i in $(seq 1 "$RUNS"); do

  echo ""
  echo "============================"
  echo "RUN $i / $RUNS"
  echo "============================"

  RUN_ID="run_$i" docker compose up -d

  echo "Waiting for device_sim container id..."
  DEVICE_CID=""
  for attempt in $(seq 1 30); do
    DEVICE_CID=$(docker compose ps -q device_sim || true)
    if [ -n "$DEVICE_CID" ]; then
      break
    fi
    sleep 1
  done

  if [ -z "$DEVICE_CID" ]; then
    echo "ERROR: device_sim container id not found"
    docker compose logs device_sim || true
    docker compose down || true
    exit 1
  fi

  echo "Waiting for device_sim to finish..."
  EXIT_CODE=$(docker wait "$DEVICE_CID")
  echo "device_sim exited with code: $EXIT_CODE"

  if [ "$EXIT_CODE" -ne 0 ]; then
    echo "ERROR: device_sim failed during run $i"
    docker compose logs device_sim || true
    docker compose down || true
    exit 1
  fi

  echo "Run $i completed"

  # se è l'ultima run, esporta il ledger PRIMA del down
  if [ "$i" -eq "$RUNS" ]; then
    echo "Exporting ledger events..."
    curl --fail http://localhost:8003/events > experiments/ledger_events.json || true
  fi

  docker compose down

done

echo "Experiments completed"
