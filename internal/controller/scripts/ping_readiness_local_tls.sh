#!/bin/sh
set -e

VALKEY_STATUS_FILE=/tmp/.valkey_cluster_check
if [ ! -z "$VALKEY_PASSWORD" ]; then export REDISCLI_AUTH=$VALKEY_PASSWORD; fi;

	response=$(
	timeout --foreground -s 15 $1 \
	valkey-cli \
		-h localhost \
		-p $VALKEY_TLS_PORT_NUMBER \
		--tls \
		--cacert $VALKEY_TLS_CA_FILE \
		ping
		#--cert $VALKEY_TLS_CERT_FILE \
		#--key $VALKEY_TLS_KEY_FILE \
)

if [ "$?" -eq "124" ]; then
	echo "Timed out"
	exit 1
fi

if [ "$response" != "PONG" ]; then
	echo "$response"
	exit 1
fi
count=$(echo $VALKEY_NODES | wc -w)
if [ ! -f "$VALKEY_STATUS_FILE" ] && [ "$count" != "1" ]; then
	response=$(
		timeout --foreground -s 15 $1 \
		valkey-cli \
			-h localhost \
			-p $VALKEY_TLS_PORT_NUMBER \
			--tls \
			--cacert $VALKEY_TLS_CA_FILE \
			CLUSTER INFO | grep cluster_state | tr -d '[:space:]'
			#--cert $VALKEY_TLS_CERT_FILE \
			#--key $VALKEY_TLS_KEY_FILE \
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
