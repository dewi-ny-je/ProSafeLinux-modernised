#!/bin/sh
# Talk to a simulated switch on this host through every reply mode and
# password scheme.  usage: tests/smoke_test.sh [python]
PY=${1:-python3}
cd "$(dirname "$0")/.." || exit 1
IFACE=$($PY -c 'import psl_class; print(psl_class.default_interface())')
IP=$($PY -c "import psl_class; print(psl_class.get_ip_address('$IFACE'))")
BCAST=$($PY -c "import psl_class; print(psl_class.get_broadcast_address('$IFACE'))")
MAC=b0:b9:8a:57:f6:56
LOG=$(mktemp)
RC=0
echo "using $IFACE ($IP, broadcast $BCAST)"

fail() { echo "FAIL: $*"; RC=1; }

# expected password TLV for "secret" with the simulator's MAC and nonce
password_tlv() {
  case $1 in
    -1|0) echo "000a=736563726574" ;;   # plaintext
    1) echo "000a=3d1104003619" ;;      # XOR with NtgrSmartSwitchRock
    8) echo "0018=8d23d8b4" ;;          # 32-bit hash
    16) echo "001a=9d23dfa3e840acc0" ;; # 64-bit hash
  esac
}

for MODE in unicast broadcast; do
  for ENC in -1 0 1 8 16; do
    echo "--- $MODE replies, enhanced_encryption=$ENC"
    # macOS refuses sends to 255.255.255.255, so the simulator answers on
    # the subnet broadcast address (old firmware uses 255.255.255.255)
    $PY tests/fake_switch.py "$IP" $MODE $ENC "$BCAST" >"$LOG" 2>&1 &
    PID=$!
    sleep 1
    OUT=$($PY psl-cli.py --interface "$IFACE" --timeout 1 discover)
    echo "$OUT" | grep -q "MAC: $MAC" || fail "discover: $OUT"
    [ "$(echo "$OUT" | grep -c "MAC: ")" = 1 ] || fail "discover duplicates"
    OUT=$($PY psl-cli.py --interface "$IFACE" --timeout 1 query --mac $MAC \
          model serial_number number_of_ports)
    echo "$OUT" | grep -q "GS108Ev3" || fail "query model: $OUT"
    echo "$OUT" | grep -q "4XB12345A0001" || fail "query serial: $OUT"
    PLAIN=""
    if [ "$ENC" -le 0 ]; then
      # plaintext firmware: refused unless explicitly allowed
      OUT=$($PY psl-cli.py --interface "$IFACE" --timeout 1 set --mac $MAC \
            --passwd secret --name smoke 2>&1)
      echo "$OUT" | grep -q "allow-plaintext" || fail "plaintext not refused: $OUT"
      grep -a -q "^0103" "$LOG" && fail "password sent without --allow-plaintext"
      PLAIN=--allow-plaintext
    fi
    OUT=$($PY psl-cli.py --interface "$IFACE" --timeout 1 $PLAIN set --mac $MAC \
          --passwd secret --name smoke 2>&1)
    echo "$OUT" | grep -q -E "FAILED|Traceback" && fail "set: $OUT"
    # name "smoke" = 736d6f6b65, sent after the password
    grep -a "^0103" "$LOG" | grep -q "^0103 $(password_tlv $ENC) 0003=736d6f6b65" \
      || fail "set not received as expected: $(grep -a '^0103' "$LOG")"
    $PY psl-cli.py --interface "$IFACE" --timeout 1 $PLAIN set --mac $MAC \
      --passwd secret --broadcast_filtering off --delete_vlan 15 >/dev/null 2>&1
    SETLOG=$(grep -a "^0103" "$LOG" | tail -1)
    echo "$SETLOG" | grep -q "5400=00" || fail "broadcast_filtering off: $SETLOG"
    echo "$SETLOG" | grep -q "2c00=000f" || fail "delete_vlan 15: $SETLOG"
    kill $PID
    wait $PID 2>/dev/null
  done
done
rm -f "$LOG"
[ $RC = 0 ] && echo "all smoke tests passed"
exit $RC
