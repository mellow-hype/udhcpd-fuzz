FUZZDIR="fuzz-runs/fuzz_$(date '+%s')"

echo "[+] using directory $FUZZDIR"
mkdir "$FUZZDIR"
echo "[+] created directory $FUZZDIR/outs"
mkdir "$FUZZDIR/outs" 

cp -a testcases "$FUZZDIR/ins"
echo "[+] copied testcases/ to $FUZZDIR/ins"


cp test-udhcpd.conf "$FUZZDIR/."
echo "[+] copied config file to fuzz directory"

cp bin/udhcpd-harness* "$FUZZDIR"
echo "[+] copied bins to $FUZZDIR: $(ls bin/udhcpd-harness*)"
echo "DONE"

echo
echo "  GOTO: $FUZZDIR"
echo