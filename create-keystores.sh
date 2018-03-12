#!/usr/bin/env bash

STOREPASS="storepwd"
WARN_DELAY=1
ERROR_DELAY=2

function checkPathHas {
    UTILITY=$(command -v "$1")
    if [ "$UTILITY" == "" ]; then
        echo "[ERROR] Could not find '$1' utility in your path."
        exit 1
    fi
}
checkPathHas keytool
checkPathHas openssl
checkPathHas realpath
checkPathHas mktemp

BIN_PATH=$(dirname "${BASH_SOURCE[0]}")
CERT_DIR=$(realpath -Le "$BIN_PATH/../etc/certs")

echo ""
echo " - etc/truststore:"
CERT_COUNT=0
TEMP_TRUST_STORE=$(mktemp -u)
for cert_file in ${CERT_DIR}/*.pem
do
    CERT_BASENAME=$(basename "$cert_file")
    CERT_ALIAS=$(echo "$CERT_BASENAME" | sed 's/^.*--//' | sed 's/.pem$//')
    CERT_EXPIRED_STRING=$(openssl x509 -in "$cert_file" -checkend 0)
    if [ "$CERT_EXPIRED_STRING" == "Certificate will expire" ]; then
        CERT_END_DATE=$(openssl x509 -in "$cert_file" -noout -enddate | sed 's/notAfter=//')
        echo "  (!) [ERROR] Excluding $CERT_BASENAME, as it has expired: $CERT_END_DATE"
        sleep ${ERROR_DELAY}
        continue
    fi
    CERT_EXPIRING_STRING=$(openssl x509 -in "$cert_file" -checkend 5184000)
    if [ "$CERT_EXPIRING_STRING" == "Certificate will expire" ]; then
        CERT_END_DATE=$(openssl x509 -in "$cert_file" -noout -enddate | sed 's/notAfter=//')
        echo "   !  [WARNING] $CERT_BASENAME will expire within the next 60 days: $CERT_END_DATE"
        sleep ${WARN_DELAY}
    fi

    echo "   +  Importing $CERT_ALIAS ($CERT_BASENAME)"
    keytool -importcert \
        -alias "$CERT_ALIAS" \
        -file "$cert_file" \
        -keystore "$TEMP_TRUST_STORE" \
        -storepass "$STOREPASS" \
        -noprompt 2>&1 | grep -v "Certificate was added to keystore"

    if [ "${PIPESTATUS[0]}" == "0" ]; then
        CERT_COUNT=$((CERT_COUNT + 1))
    fi
done
echo " - Created trusted certificate store with $CERT_COUNT certificates."
mv "$TEMP_TRUST_STORE" "$BIN_PATH/../etc/truststore" || unlink "$TEMP_TRUST_STORE"


KEY_DIR=$(realpath -Le "$BIN_PATH/../etc/keys")
for directory in $(find "${KEY_DIR}" -type d);
do
    if [ "$KEY_DIR" == "$directory" ]; then
        continue
    fi

    KEY_DIRECTORY_BASENAME=$(basename "$directory")
    KEY_DIRECTORY_REAL_PATH=$(realpath -Le "$directory")
    KEY_STORE_PATH="etc/$KEY_DIRECTORY_BASENAME.jks"
    KEY_STORE_REAL_PATH=$(realpath -Lm "$BIN_PATH/../$KEY_STORE_PATH")
    echo ""
    echo " - $KEY_STORE_PATH ($KEY_STORE_REAL_PATH)"

    ITEM_COUNT=0
    TEMP_KEY_STORE=$(mktemp -u)

    for trust_cert_file in ${KEY_DIRECTORY_REAL_PATH}/*.pem
    do
        if [[ ${trust_cert_file} == *\*.pem ]]; then
            continue
        fi
        TRUST_CERT_BASENAME=$(basename "$trust_cert_file")
        TRUST_CERT_ALIAS=$(echo "$TRUST_CERT_BASENAME" | sed 's/^.*--//' | sed 's/.pem$//')
        TRUST_CERT_EXPIRED_STRING=$(openssl x509 -in "$trust_cert_file" -checkend 0)
        if [ "$TRUST_CERT_EXPIRED_STRING" == "Certificate will expire" ]; then
            TRUST_CERT_END_DATE=$(openssl x509 -in "$trust_cert_file" -noout -enddate | sed 's/notAfter=//')
            echo "  (!) [ERROR] Excluding $TRUST_CERT_BASENAME, as it has expired: $TRUST_CERT_END_DATE"
            sleep ${ERROR_DELAY}
            continue
        fi
        TRUST_CERT_EXPIRING_STRING=$(openssl x509 -in "$trust_cert_file" -checkend 5184000)
        if [ "$TRUST_CERT_EXPIRING_STRING" == "Certificate will expire" ]; then
            TRUST_CERT_END_DATE=$(openssl x509 -in "$trust_cert_file" -noout -enddate | sed 's/notAfter=//')
            echo "   !  [WARNING] $TRUST_CERT_BASENAME will expire within the next 60 days: $TRUST_CERT_END_DATE"
            sleep ${WARN_DELAY}
        fi

        echo "   +  Importing $TRUST_CERT_ALIAS ($TRUST_CERT_BASENAME)"
        keytool -importcert \
            -alias "$TRUST_CERT_ALIAS" \
            -file "$trust_cert_file" \
            -keystore "$TEMP_KEY_STORE" \
            -storepass "$STOREPASS" \
            -noprompt 2>&1 | grep -v "Certificate was added to keystore"

        if [ "${PIPESTATUS[0]}" == "0" ]; then
            ITEM_COUNT=$((ITEM_COUNT + 1))
        fi
    done

    for key_file in ${KEY_DIRECTORY_REAL_PATH}/*.p12
    do
        if [[ ${trust_cert_file} == *\*.p12 ]]; then
            continue
        fi
        KEY_BASENAME=$(basename "$key_file")
        KEY_ALIAS=$(echo "$KEY_BASENAME" | sed 's/^.*--//' | sed 's/.p12$//')
        PASS_PATH=$(echo "$key_file" | sed 's/\.p12$/\.password/')
        KEY_PASS=$(cat "$PASS_PATH")
        CERT=$(openssl pkcs12 -in "$key_file" -password pass:${STOREPASS} -nokeys -nomacver)

        KEY_EXPIRED_STRING=$(echo "$CERT" | openssl x509 -checkend 0)
        if [ "$KEY_EXPIRED_STRING" == "Certificate will expire" ]; then
            KEY_END_DATE=$(echo "$CERT" | openssl x509 -noout -enddate | sed 's/notAfter=//')
            echo "  (!) [ERROR] Excluding $KEY_BASENAME, as it has expired: $KEY_END_DATE"
            sleep ${ERROR_DELAY}
            continue
        fi
        KEY_EXPIRING_STRING=$(echo "$CERT" | openssl x509 -checkend 51840000)
        if [ "$KEY_EXPIRING_STRING" == "Certificate will expire" ]; then
            KEY_END_DATE=$(echo "$CERT" | openssl x509 -noout -enddate | sed 's/notAfter=//')
            echo "   !  [WARNING] $KEY_BASENAME will expire within the next 60 days: $KEY_END_DATE"
            sleep ${WARN_DELAY}
        fi

        echo "   +  Importing $KEY_ALIAS ($KEY_BASENAME)"
        keytool -importkeystore \
            -srckeystore "$key_file" \
            -srcstorepass "$STOREPASS" \
            -destkeystore "$TEMP_KEY_STORE" \
            -deststorepass "$STOREPASS" \
            -srcalias "$KEY_ALIAS" \
            -destalias "$KEY_ALIAS" \
            -destkeypass "$KEY_PASS" \
            -noprompt 2>&1 \
                | grep -v "Importing keystore" \
                | grep -v "^[\t ]*$" \
                | grep -v "^Warning:$" \
                | grep -v "The JKS keystore uses a proprietary format."

        if [ "${PIPESTATUS[0]}" == "0" ]; then
            ITEM_COUNT=$((ITEM_COUNT + 1))
        fi
    done


    if [ "$ITEM_COUNT" == "0" ]; then
        echo "   !  [WARNING] No certificates were found for $KEY_DIRECTORY_BASENAME"
        sleep ${WARN_DELAY}
        continue
    fi

    echo " - Created key store with $ITEM_COUNT certificates."
    mv "$TEMP_KEY_STORE" "$KEY_STORE_REAL_PATH" || unlink "$TEMP_KEY_STORE"
done
