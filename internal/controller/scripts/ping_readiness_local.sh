#!/bin/sh
set -e

VALKEY_STATUS_FILE=/tmp/.valkey_cluster_check
if [ ! -z "$VALKEY_PASSWORD" ]; then export REDISCLI_AUTH=$VALKEY_PASSWORD; fi;
response=$(
  timeout -s 15 $1 \
  valkey-cli \
    -h localhost \
    -p $VALKEY_PORT_NUMBER \
    ping
)
if [ "$?" -eq "124" ]; then
  echo "Timed out"
  exit 1
fi
if [ "$response" != "PONG" ]; then
  echo "$response"
  exit 1
fi
if [ ! -f "$VALKEY_STATUS_FILE" ]; then
  response=$(
    timeout -s 15 $1 \
    valkey-cli \
      -h localhost \
      -p $VALKEY_PORT_NUMBER \
      CLUSTER INFO | grep cluster_state | tr -d '[:space:]'
  )
  if [ "$?" -eq "124" ]; then
    echo "Timed out"
    exit 1
  fi
  if [ "$response" != "cluster_state:ok" ]; then
    echo "$response"
    exit 1
  else
    touch "$VALKEY_STATUS_FILE"
  fi
fi
