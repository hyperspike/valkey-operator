#!/bin/sh
set -e

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

responseFirstWord=$(echo $response | head -n1 | awk '{print $1;}')
if [ "$response" != "PONG" ] && [ "$responseFirstWord" != "LOADING" ] && [ "$responseFirstWord" != "MASTERDOWN" ]; then
	echo "$response"
	exit 1
fi
