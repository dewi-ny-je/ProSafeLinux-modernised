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

for MODE in unicast broadcast; do
  for ENC in 0 1 8 16; do
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
    OUT=$($PY psl-cli.py --interface "$IFACE" --timeout 1 set --mac $MAC \
          --passwd secret --name smoke 2>&1)
    echo "$OUT" | grep -q -E "FAILED|Traceback" && fail "set: $OUT"
    # name "smoke" = 736d6f6b65
    grep -a "^0103" "$LOG" | grep -q "0003=736d6f6b65" || fail "set not received"
    kill $PID
    wait $PID 2>/dev/null
  done
done
rm -f "$LOG"
[ $RC = 0 ] && echo "all smoke tests passed"
exit $RC
