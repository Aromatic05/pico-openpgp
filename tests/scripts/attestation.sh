#!/bin/bash

source ./tests/scripts/func.sh

echo -n "  Fetch attestation certificate... "
piv read-cert -sf9 -o sf9.pem
test $? -eq 0 && echo -e ".\t${OK}" || exit $?

algs=("RSA1024" "RSA2048" "ECCP256" "ECCP384")
slots=("9a" "9c" "9d" "9e" "82" "83" "84" "85" "86" "87" "88" "89" "8a" "8b" "8c" "8d" "8e" "8f" "90" "91" "92" "93" "94" "95")

check_attestation_extensions() {
    local parsed signature_count device_serial serial_hex serial_der serial_der_len first_byte
    parsed=$(openssl asn1parse -in attestation.pem -inform PEM -i) || return 1

    device_serial=$(piv status 2>/dev/null | sed -n 's/^Serial Number:[[:space:]]*//p')
    [[ "$device_serial" =~ ^[0-9]+$ ]] || return 1
    printf -v serial_hex '%X' "$device_serial"
    if (( ${#serial_hex} % 2 )); then
        serial_hex="0${serial_hex}"
    fi
    first_byte=${serial_hex:0:2}
    if (( 16#$first_byte >= 128 )); then
        serial_hex="00${serial_hex}"
    fi
    printf -v serial_der '02%02X%s' "$(( ${#serial_hex} / 2 ))" "$serial_hex"
    serial_der_len=$(( ${#serial_der} / 2 ))

    grep -A1 '1.3.6.1.4.1.41482.3.3' <<< "$parsed" | tail -1 | grep -Eq 'l= *3 .*OCTET STRING.*\[HEX DUMP\]:[0-9A-F]{6}' || return 1
    grep -A1 '1.3.6.1.4.1.41482.3.7' <<< "$parsed" | tail -1 | grep -Eq "l= *${serial_der_len} .*OCTET STRING.*\[HEX DUMP\]:${serial_der}" || return 1
    grep -A1 '1.3.6.1.4.1.41482.3.8' <<< "$parsed" | tail -1 | grep -Eq 'l= *2 .*OCTET STRING.*\[HEX DUMP\]:[0-9A-F]{4}' || return 1
    grep -A1 '1.3.6.1.4.1.41482.3.9' <<< "$parsed" | tail -1 | grep -Eq 'l= *1 .*OCTET STRING.*\[HEX DUMP\]:[0-9A-F]{2}' || return 1

    signature_count=$(openssl x509 -in attestation.pem -noout -text | grep -c 'Signature Algorithm: ecdsa-with-SHA256')
    test "$signature_count" -eq 2 || return 1
}
for alg in ${algs[*]}; do
    for slot in ${slots[*]}; do
        echo "  Test attestation with ${alg} in slot ${slot}"
        echo -n "    Keygen... "
        gen_and_check $alg $slot && echo -e ".\t${OK}" || exit $?

        echo -n "    Fetch attesting certificate... "
        piv attest -s$slot -o attestation.pem
        test $? -eq 0 && echo -e ".\t${OK}" || exit $?

        echo -n "    OpenSSL verify attestation... "
        e=$(openssl verify -CAfile sf9.pem attestation.pem 2>&1)
        test $? -eq 0 && echo -n "." || exit $?
        grep -q ": OK" <<< $e && echo -e ".\t${OK}" || exit $?

        if test "$slot" = "9a"; then
            echo -n "    Verify Yubico attestation extensions... "
            check_attestation_extensions && echo -e ".\t${OK}" || exit $?
        fi

        echo -n "    Key deletion... "
        delete_key $alg $slot && echo -e ".\t${OK}" || exit $?

    done
done

rm -rf cert.pem
rm -rf sf9.pem
