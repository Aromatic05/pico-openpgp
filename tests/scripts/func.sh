#!/bin/bash

OK="\033[32mok\033[0m"
FAIL="\033[31mfail\033[0m"

READER="u"

piv() {
    yubico-piv-tool -r${READER} -a$@
}

piv_alg_id() {
    case "$1" in
        RSA1024) echo 06 ;;
        RSA2048) echo 07 ;;
        ECCP256) echo 11 ;;
        ECCP384) echo 14 ;;
        *) return 1 ;;
    esac
}

piv_metadata_alg() {
    python3 - "$1" <<'PY'
import sys
from smartcard.System import readers

slot = int(sys.argv[1], 16)
reader = [r for r in readers() if 'Virtual PCD 00 00' in str(r)][0]
conn = reader.createConnection()
conn.connect()
aid = bytes.fromhex('A000000308')
_, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid), *aid])
if sw1 != 0x61 and (sw1, sw2) != (0x90, 0x00):
    raise SystemExit(2)
data, sw1, sw2 = conn.transmit([0x00, 0xF7, 0x00, slot])
full = bytearray(data)
while sw1 == 0x61:
    data, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
    full.extend(data)
if (sw1, sw2) != (0x90, 0x00):
    raise SystemExit(1)
data = bytes(full)
if len(data) < 3 or data[0:2] != b'\x01\x01':
    raise SystemExit(3)
print(f'{data[2]:02x}')
PY
}

gen_and_check() {
    e=$(piv generate -s$2 -A$1 -opublic.pem 2>&1)
    test $? -eq 0 && echo -n "." || exit $?
    grep -q "Successfully generated a new private key" <<< $e && echo -n "." || exit $?
    expected=$(piv_alg_id "$1") || exit $?
    actual=$(piv_metadata_alg "$2") || exit $?
    test "$actual" = "$expected" && echo -n "." || exit 1
}
delete_key() {
    piv delete-key -s$2 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    piv delete-cert -s$2 > /dev/null 2>&1
    test $? -eq 0 && echo -n "." || exit $?
    if piv_metadata_alg "$2" >/dev/null 2>&1; then
        exit 1
    else
        echo -n "."
    fi
    rm -rf public.pem
}
gen_and_delete() {
    gen_and_check $1 $2
    test $? -eq 0 && echo -n "." || exit $?
    delete_key $1 $2
    test $? -eq 0 && echo -n "." || exit $?
}
