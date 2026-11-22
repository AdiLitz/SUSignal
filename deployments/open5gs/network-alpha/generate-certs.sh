#!/bin/sh
set -eu

ca_dir=/run/susignal-alpha-ca
mkdir -p "$ca_dir"

if [ ! -f "$ca_dir/ca.key" ] || [ ! -f "$ca_dir/ca.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$ca_dir/ca.key" \
        -out "$ca_dir/ca.crt" \
        -days 3650 \
        -subj "/CN=SUSignal Network Alpha Test CA"
    chmod 0600 "$ca_dir/ca.key"
fi

for nf in nrf amf smf ausf udm pcf udr; do
    cert_dir="/run/susignal-alpha-$nf"
    mkdir -p "$cert_dir"
    if [ ! -f "$cert_dir/server.key" ] || [ ! -f "$cert_dir/server.crt" ]; then
        openssl req -new -newkey rsa:2048 -nodes \
            -keyout "$cert_dir/server.key" \
            -out "$cert_dir/server.csr" \
            -subj "/CN=$nf"
        printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$nf" \
            > "$cert_dir/extensions.cnf"
        openssl x509 -req \
            -in "$cert_dir/server.csr" \
            -CA "$ca_dir/ca.crt" \
            -CAkey "$ca_dir/ca.key" \
            -CAcreateserial \
            -out "$cert_dir/server.crt" \
            -days 365 \
            -extfile "$cert_dir/extensions.cnf"
        chmod 0600 "$cert_dir/server.key"
        rm -f "$cert_dir/server.csr" "$cert_dir/extensions.cnf"
    fi
    cp "$ca_dir/ca.crt" "$cert_dir/ca.crt"
    chmod 0644 "$cert_dir/ca.crt" "$cert_dir/server.crt"
done
