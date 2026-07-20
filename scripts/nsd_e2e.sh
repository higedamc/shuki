#!/bin/zsh
# shuki NSD end-to-end smoke test: socat PTY pair + fake_nsd device.
# Requires: socat, python3. No hardware, no network, no OS keychain writes.
set -e
REPO=${0:a:h:h}
WORK=$(mktemp -d /tmp/shuki-e2e.XXXXXX)
BIN=$REPO/target/debug/shuki
FAKE=$REPO/target/debug/examples/fake_nsd
APP_PTY=$WORK/nsd-app
DEV_PTY=$WORK/nsd-dev

cargo build --manifest-path $REPO/Cargo.toml --bin shuki --example fake_nsd

cleanup() { kill $SOCAT_PID $FAKE_PID 2>/dev/null || true; }
trap cleanup EXIT

socat -d pty,raw,echo=0,link=$APP_PTY pty,raw,echo=0,link=$DEV_PTY &
SOCAT_PID=$!
sleep 1
[ -e $APP_PTY ] || { echo "FAIL: socat pty missing"; exit 1; }

$FAKE $DEV_PTY 2>$WORK/fake_nsd.log &
FAKE_PID=$!
sleep 1

export SHUKI_CONFIG=$WORK/config.json
export SHUKI_DATA_DIR=$WORK/data
export RUST_LOG=warn

# init --nsd writes the config; then pin the port to our PTY (autodetect
# cannot see socat PTYs).
$BIN init --nsd --relay wss://example.invalid >$WORK/init.out 2>&1
python3 - "$SHUKI_CONFIG" "$APP_PTY" <<'EOF'
import json, sys
p, port = sys.argv[1], sys.argv[2]
c = json.load(open(p))
c["signer"] = {"kind": "nsd", "port": port}
json.dump(c, open(p, "w"))
EOF

echo "--- generate"
PW=$($BIN generate web/example.com --no-clip --username alice)
[ ${#PW} -eq 24 ] || { echo "FAIL: unexpected password length"; exit 1; }

echo "--- show"
SHOWN=$($BIN show web/example.com | head -1)
[ "$PW" = "$SHOWN" ] || { echo "FAIL: show mismatch"; exit 1; }

echo "--- ls"
$BIN ls | grep -q "example.com" || { echo "FAIL: ls missing entry"; exit 1; }

echo "--- second entry + find + mv"
$BIN generate bank/main --no-clip >/dev/null
$BIN find bank | grep -q "bank/main" || { echo "FAIL: find"; exit 1; }
$BIN mv bank/main bank/primary
$BIN show bank/primary >/dev/null || { echo "FAIL: mv target missing"; exit 1; }
if $BIN show bank/main >/dev/null 2>&1; then echo "FAIL: mv source still live"; exit 1; fi

echo "--- rm"
$BIN rm -f web/example.com
if $BIN show web/example.com >/dev/null 2>&1; then echo "FAIL: rm did not remove"; exit 1; fi

echo "--- ciphertext-only at rest check"
if grep -rq "$PW" $WORK/data 2>/dev/null; then echo "FAIL: plaintext on disk"; exit 1; fi
ls $WORK/data/store/*.nip44 >/dev/null || { echo "FAIL: no ciphertext files"; exit 1; }

echo "--- device round-trips"
grep -c "sign-message\|shared-secret\|public-key" $WORK/fake_nsd.log || true
rm -rf $WORK
echo "E2E_PASS"
