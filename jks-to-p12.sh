#!/usr/bin/env bash

set -e

STOREPASS="storepwd"

function checkPathHas {
    UTILITY=$(command -v "$1")
    if [ "$UTILITY" == "" ]; then
        echo "[ERROR] Could not find '$1' utility in your path."
        exit 1
    fi
}
function usage {
    echo "Usage: $0 <jks-file> <new-p12-file> <key-alias> <key-pass>"
    exit 1
}

checkPathHas keytool
checkPathHas realpath
if [ "$#" != "4" ]; then
    usage
fi

JKS_REAL_PATH=$(realpath -Le "$1")
P12_REAL_PATH=$(realpath -Lm "$2")
PASS_REAL_PATH=$(echo "$P12_REAL_PATH" | sed 's/\.p12$/\.password/')
if [ "$P12_REAL_PATH" == "$PASS_REAL_PATH" ]; then
    echo "[ERROR] P12 file must have a .p12 extension."
fi

echo ""
echo "JKS: $JKS_REAL_PATH"
echo "P12: $P12_REAL_PATH"
echo "Pass File: $PASS_REAL_PATH"
echo ""

keytool -importkeystore \
    -srckeystore "$JKS_REAL_PATH" \
    -srcstorepass "$STOREPASS" \
    -destkeystore "$P12_REAL_PATH" \
    -deststoretype PKCS12 \
    -srcalias "$3" \
    -srckeypass "$4" \
    -deststorepass "$STOREPASS" \
    -destkeypass "$STOREPASS"   # must be the same as deststorepass for reasons known only to keytool...

