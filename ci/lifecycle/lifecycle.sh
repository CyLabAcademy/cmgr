#!/usr/bin/env bash
# Lifecycle test: drives cmgr through launches, rebuilds and their failure
# paths on a real docker daemon. `cmgr test` builds, solves and destroys each
# example once; nothing there ever rebuilds or relaunches.
#
# usage: ci/lifecycle/lifecycle.sh <cmgr binary>
# Needs docker, jq and curl, and host ports 42000-42050 free. Exits non-zero
# if any check fails.
set -u

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
	echo "usage: $0 <cmgr binary>" >&2
	exit 2
fi
BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=$(mktemp -d)

unset CMGR_REGISTRY CMGR_REGISTRY_USER CMGR_REGISTRY_TOKEN
export CMGR_DB=$WORK/cmgr.db CMGR_DIR=$WORK/challenges CMGR_ARTIFACT_DIR=$WORK/artifacts
export CMGR_PORTS=42000-42050 CMGR_LOGGING=${CMGR_LOGGING:-warn}

checks=0
failures=0
pass() { checks=$((checks + 1)); echo "PASS: $*"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); echo "FAIL: $*"; }
cm() { "$BIN" "$@" 2>>"$WORK/cmgr.log"; }
instance_id() { sed -n 's/^Instance ID: \([0-9][0-9]*\)$/\1/p'; }
field() { jq -r "$2" <<<"$1"; }

# serves <port> <body>: the service answers with body within ten seconds.
serves() {
	local i
	for i in $(seq 20); do
		[ "$(curl -fsS -m 2 "http://localhost:$1/" 2>/dev/null)" = "$2" ] && return 0
		sleep 0.5
	done
	return 1
}

STALE=""
cleanup() {
	cm remove-schema dyn >/dev/null
	cm remove-schema persist >/dev/null
	[ -n "$STALE" ] && docker network rm "$STALE" >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$CMGR_DIR" "$CMGR_ARTIFACT_DIR"
cp -r "$HERE/challenges/." "$CMGR_DIR/"
# The default policy with an '=' in a comment: valid profile syntax that
# Docker's option parsing splits on.
jq '.syscalls[0].comment = "persona=0xffffffff only queries"' \
	"$REPO/examples/seccomp/default.json" >"$CMGR_DIR/sec/profile.json" || exit 2

echo "== update and converge"
cm update >"$WORK/update1.log" || { cat "$WORK/update1.log"; tail -20 "$WORK/cmgr.log"; exit 2; }
cm add-schema "$HERE/persist.yaml" >"$WORK/persist.log" || cut -c1-200 "$WORK/persist.log"
cm add-schema "$HERE/dyn.yaml" >"$WORK/dyn.log" || cut -c1-200 "$WORK/dyn.log"

P=$(cm show-schema persist)
WEB_BUILD=$(field "$P" '.[] | select(.id=="lifecycle/web") | .builds[0].id')
WEB_INST=$(field "$P" '.[] | select(.id=="lifecycle/web") | .builds[0].instances[0].id // empty')
WEB_PORT=$(field "$P" '.[] | select(.id=="lifecycle/web") | .builds[0].instances[0].ports.http // empty')
SEC_INST=$(field "$P" '.[] | select(.id=="lifecycle/sec") | .builds[0].instances[0].id // empty')
SEC_PORT=$(field "$P" '.[] | select(.id=="lifecycle/sec") | .builds[0].instances[0].ports.http // empty')
DYN_BUILD=$(field "$(cm show-schema dyn)" '.[] | select(.id=="lifecycle/web") | .builds[0].id')

echo "== launches"
SEC_CID=$(docker ps -q --filter "network=cmgr-$SEC_INST" | head -1)
if [ -n "$SEC_PORT" ] && serves "$SEC_PORT" sec &&
	docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$SEC_CID" | grep -q 'persona=0xffffffff'; then
	pass "a challenge's own seccomp profile, with '=' in it, reaches its container (instance $SEC_INST on $SEC_PORT)"
else
	fail "the challenge with a seccomp profile containing '=' did not launch and serve: $(grep -m1 'security-opt' "$WORK/persist.log" | cut -c1-120)"
fi

D1=$(cm start "$DYN_BUILD" | instance_id)
cm stop "$D1" >/dev/null
D2=$(cm start "$DYN_BUILD" | instance_id)
if [ -n "$D1" ] && [ -n "$D2" ] && [ "$D2" != "$D1" ]; then
	pass "a stopped instance's id is not handed out again ($D1 stopped, next launch got $D2)"
else
	fail "instance ids: '$D1' stopped, next launch got '$D2'"
fi

if [ -n "$D2" ]; then
	STALE=cmgr-$((D2 + 1))
	docker network create "$STALE" >/dev/null
	OUT=$(cm start "$DYN_BUILD")
	D3=$(instance_id <<<"$OUT")
	if [ "$D3" = "$((D2 + 1))" ]; then
		pass "a launch whose network was left behind still starts (instance $D3)"
	else
		fail "a launch whose network $STALE was left behind: $(head -1 <<<"$OUT" | cut -c1-160)"
	fi
	docker network rm "$STALE" >/dev/null 2>&1
	STALE=""
else
	fail "a launch whose network was left behind: no instance to number it after"
fi

echo "== rebuild after a source change"
echo v2 >"$CMGR_DIR/web/version.txt"
cm update >"$WORK/update2.log" || sed -n '/^Errors:/,$p' "$WORK/update2.log"

P=$(cm show-schema persist)
PORT_AFTER=$(field "$P" '.[] | select(.id=="lifecycle/web") | .builds[0].instances[0].ports.http // empty')
if [ -n "$WEB_PORT" ] && [ "$PORT_AFTER" = "$WEB_PORT" ] && serves "$PORT_AFTER" v2; then
	pass "the persistent instance keeps port $WEB_PORT across the rebuild and serves the new build"
else
	fail "the persistent instance had port '$WEB_PORT' before the rebuild and '$PORT_AFTER' after (bound: $(docker ps --filter "network=cmgr-$WEB_INST" --format '{{.Ports}}' | head -1))"
fi

LEFT=$(field "$(cm show-schema dyn)" '[.[] | select(.id=="lifecycle/web") | .builds[0].instances[]? | .id] | join(" ")')
if [ -z "$LEFT" ]; then
	pass "the rebuild removed the on-demand instances' records"
else
	fail "on-demand instance records survived the rebuild: $LEFT"
fi

echo "== rebuild that fails validation"
ARCHIVE=$CMGR_ARTIFACT_DIR/$WEB_BUILD.tar.gz
sed 's/notes\.txt/notes2.txt/g' "$CMGR_DIR/web/Dockerfile" >"$WORK/Dockerfile" &&
	mv "$WORK/Dockerfile" "$CMGR_DIR/web/Dockerfile"
if cm update >"$WORK/update3.log"; then
	fail "an update whose build publishes notes2.txt but references notes.txt succeeded"
fi
if [ -f "$ARCHIVE" ] && tar tzf "$ARCHIVE" | grep -qx notes.txt; then
	pass "the failed rebuild left the served archive in place"
else
	fail "the failed rebuild took the served archive $ARCHIVE with it"
fi
if grep -q "unknown artifact 'notes.txt'" "$WORK/update3.log" && grep -q "artifact file 'notes2.txt' published but not referenced" "$WORK/update3.log"; then
	pass "the failed rebuild reported both of its problems"
else
	fail "the failed rebuild did not report both of its problems:"
	sed -n '/^Errors:/,$p' "$WORK/update3.log"
fi

echo "== $checks checks, $failures failed"
if [ "$failures" -ne 0 ]; then
	echo "-- last lines of cmgr's log"
	tail -40 "$WORK/cmgr.log"
	exit 1
fi
