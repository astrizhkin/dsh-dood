#!/usr/bin/env bash
# policy test: guard + fake daemon, no real docker needed
set -u
G="$(cd "$(dirname "$0")" && pwd)"          # script dir: binary + suite live here
GUARD_CMD="${GUARD_CMD:-$G/docker-guard}"
W="${GUARD_TEST_ROOT:-$G/testroot}"        # fake "workspace" used as bind root in tests
if [ ! -x "$GUARD_CMD" ]; then
  echo "ERROR: guard binary not found at $GUARD_CMD" >&2
  echo "build it:  cd $G && go build -o docker-guard ." >&2
  echo "or run:    docker compose run --rm guard-test   (from the workspace root)" >&2
  exit 1
fi
mkdir -p "$W"
S=/tmp/guard-test.sock
printf '{"allowedBindRoots":["%s"]}\n' "$W" > /tmp/guard-main.json
export GUARD_SOCKET=$S DOCKER_DAEMON_SOCKET=/tmp/fake-daemon.sock \
       GUARD_STATE=/tmp/guard-state.json GUARD_CONFIG=/tmp/guard-main.json

rm -f $S /tmp/guard-state.json /tmp/fake-daemon.sock /tmp/fake-daemon.js
# self-contained fake daemon (no external files needed)
cat > /tmp/fake-daemon.js <<'FAKE'
const net = require('net');
const fs = require('fs');
const SOCK = '/tmp/fake-daemon.sock';
try { fs.unlinkSync(SOCK); } catch {}
// keep-alive-aware fake daemon: honors Connection: close like the real daemon,
// otherwise stays open so pipelined requests model real docker CLI behavior.
net.createServer((c) => {
  let buf = Buffer.alloc(0);
  c.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      const idx = buf.indexOf('\r\n\r\n');
      if (idx < 0) return;
      const head = buf.slice(0, idx).toString('latin1');
      const cl = parseInt((head.match(/content-length:\s*(\d+)/i) || [, '0'])[1], 10);
      if (buf.length < idx + 4 + cl) return;
      buf = buf.slice(idx + 4 + cl);
      const [method, url] = head.split('\r\n')[0].split(' ');
      let body = '{"ok":true}';
      if (url.includes('/containers/create')) body = '{"Id":"deadbeefcafebabe00000000000000000000000000000000000000000000abcd","Warnings":[]}';
      else if (url.match(/\/containers\/[^/]+\/exec$/)) body = '{"Id":"execid1"}';
      c.write(`HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
      if (/connection:\s*close/i.test(head)) { c.end(); return; }
    }
  });
}).listen(SOCK, () => console.log('fake daemon on', SOCK));
FAKE
node /tmp/fake-daemon.js > /tmp/fake.log 2>&1 & FAKE=$!
sleep 0.4
$GUARD_CMD > /tmp/guard.log 2>&1 & GUARD=$!
sleep 0.6

ID=deadbeefcafebabe00000000000000000000000000000000000000000000abcd
code() { # code <method> <path> [json]
  local method=$1 path=$2 body=${3-}
  if [ -n "$body" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$method" \
      -H 'Content-Type: application/json' -d "$body" \
      --unix-socket $S "http://localhost$path"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$method" \
      --unix-socket $S "http://localhost$path"
  fi
}
chk() { local want=$1 got=$2 name=$3; if [ "$want" = "$got" ]; then echo "PASS $name ($got)"; else echo "FAIL $name want=$want got=$got"; fi; }

ln -sfn /etc "$W/evil-test"

chk 201 "$(code GET /_ping)" "ping passthrough"
chk 201 "$(code POST '/v1.47/containers/create?name=goodtest' '{"Image":"alpine","HostConfig":{"Binds":["'"$W"'/sub:/x"]}}')" "bind inside workspace"
chk 201 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Binds":["'"$W"'/newdir/deep:/x"]}}')" "non-existent dir inside workspace"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Binds":["/etc:/x"]}}')" "bind /etc"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Binds":["'"$W"'/../etc:/x"]}}')" "dot-dot escape"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Binds":["'"$W"'/evil-test:/x"]}}')" "symlink to /etc"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Binds":["/etc/newdir:/x"]}}')" "non-existent dir outside"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Privileged":true}}')" "privileged"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"PidMode":"host"}}')" "pid=host"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}')" "network=host"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}')" "device passthrough"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"CapAdd":["CAP_SYS_ADMIN"]}}')" "cap-add sys_admin"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}')" "apparmor unconfined"
chk 403 "$(code POST /containers/create '{"Image":"alpine","Mounts":[{"Type":"bind","Source":"/var","Target":"/x"}]}')" "Mounts[] bind /var"
chk 403 "$(code POST /containers/create '{"Image":"alpine","Mounts":[{"Type":"bind","Source":"'"$W"'","Target":"/x","BindOptions":{"Propagation":"rshared"}}]}')" "rshared propagation"
chk 201 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Binds":["myvolume:/data"]}}')" "named volume allowed"
chk 403 "$(code POST /volumes/create '{"Driver":"local","DriverOpts":{"device":"/etc","type":"none","o":"bind"}}')" "volume device bypass"
chk 201 "$(code POST /volumes/create '{"Name":"plainvol"}')" "plain volume"
chk 403 "$(code GET /containers/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/json)" "inspect foreign container"
chk 201 "$(code GET /containers/$ID/json)" "inspect own container"
chk 201 "$(code POST "/containers/$ID/exec" '{"Cmd":["sh"]}')" "exec create own"
chk 403 "$(code POST /containers/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/exec '{"Cmd":["sh"]}')" "exec create foreign"
chk 201 "$(code POST /exec/execid1/start '{"Detach":false}')" "exec start own"
chk 403 "$(code POST /exec/execzzz/start '{"Detach":false}')" "exec start unknown"
chk 403 "$(code POST /auth)" "auth route"
chk 403 "$(code GET /plugins)" "plugins route"
chk 403 "$(code GET /services)" "services route"
chk 201 "$(code POST '/images/create?fromImage=alpine')" "pull allowed"
chk 201 "$(code GET /containers/json)" "ps allowed"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Links":["somecontainer"]}}')" "links denied"

# keep-alive bypass: a second request pipelined onto ONE connection must not
# reach the daemon (the docker CLI reuses connections; the guard must force
# one fully-parsed request per connection).
KA=$(node -e '
const net=require("net");
const c=net.connect("/tmp/guard-test.sock");
let out="";
c.on("data",d=>out+=d.toString("latin1"));
c.on("error",()=>{});
setTimeout(()=>{console.log((out.match(/HTTP\/1\.[01]/g)||[]).length);process.exit(0)},1500);
c.write("GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n");
setTimeout(()=>c.write("GET /containers/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/json HTTP/1.1\r\nHost: x\r\n\r\n"),300);
')
chk 1 "$KA" "keep-alive: pipelined request not relayed to daemon"

# a forged Upgrade: header on a non-hijack route must NOT skip close injection
KA2=$(node -e '
const net=require("net");
const c=net.connect("/tmp/guard-test.sock");
let out="";
c.on("data",d=>out+=d.toString("latin1"));
c.on("error",()=>{});
setTimeout(()=>{console.log((out.match(/HTTP\/1\.[01]/g)||[]).length);process.exit(0)},1500);
c.write("GET /_ping HTTP/1.1\r\nHost: x\r\nUpgrade: tcp\r\n\r\n");
setTimeout(()=>c.write("GET /containers/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/json HTTP/1.1\r\nHost: x\r\n\r\n"),300);
')
chk 1 "$KA2" "keep-alive: forged Upgrade header cannot skip close injection"

# pipelining after a REFUSED upgrade on a hijack route (fake daemon answers
# 201, not 101, to attach) must not reach the daemon: guard hard-closes.
KA3=$(node -e '
const net=require("net");
const c=net.connect("/tmp/guard-test.sock");
let out="";
c.on("data",d=>out+=d.toString("latin1"));
c.on("error",()=>{});
setTimeout(()=>{console.log((out.match(/HTTP\/1\.[01]/g)||[]).length);process.exit(0)},1500);
c.write("POST /containers/"+process.argv[1]+"/attach HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
setTimeout(()=>c.write("GET /containers/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/json HTTP/1.1\r\nHost: x\r\n\r\n"),300);
' "$ID")
chk 1 "$KA3" "keep-alive: pipelining after refused upgrade closed"

# BuildKit gRPC session route must be allowed (docker build through the guard)
chk 201 "$(code POST /session)" "session route allowed (buildkit)"

# second guard instance: forceRuntime=runsc (gVisor) + resource caps
cat > /tmp/guard-runsc.json <<EOF
{"allowedBindRoots":["$W"],"forceRuntime":"runsc","maxMemoryBytes":1073741824,"maxPids":512}
EOF
S2=/tmp/guard-runsc.sock
GUARD_SOCKET=$S2 GUARD_STATE=/tmp/guard-state2.json GUARD_CONFIG=/tmp/guard-runsc.json \
  $GUARD_CMD > /tmp/guard2.log 2>&1 & GUARD2=$!
sleep 0.6
code2() { curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$2" --unix-socket $S2 "http://localhost$1"; }
chk 403 "$(code2 /containers/create '{"Image":"alpine","HostConfig":{}}')" "forceRuntime: default runc denied"
chk 403 "$(code2 /containers/create '{"Image":"alpine","HostConfig":{"Runtime":"runc"}}')" "forceRuntime: explicit runc denied"
chk 201 "$(code2 /containers/create '{"Image":"alpine","HostConfig":{"Runtime":"runsc"}}')" "forceRuntime: runsc allowed"
chk 403 "$(code2 /containers/create '{"Image":"alpine","HostConfig":{"Runtime":"runsc","Memory":999999999999}}')" "memory over 1G cap"
chk 403 "$(code2 /containers/create '{"Image":"alpine","HostConfig":{"Runtime":"runsc","PidsLimit":100000}}')" "pids over 512 cap"
chk 403 "$(code POST /containers/create '{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/var","Target":"/x"}]}}')" "HostConfig.Mounts shape bind /var"

# TOCTOU: create passes with a real dir, agent swaps it for a symlink, start must fail
S3=/tmp/guard-toctou.sock
cat > /tmp/guard-toctou.json <<EOF
{"allowedBindRoots":["$W"]}
EOF
GUARD_SOCKET=$S3 GUARD_STATE=/tmp/guard-state4.json GUARD_CONFIG=/tmp/guard-toctou.json \
  $GUARD_CMD > /tmp/guard3.log 2>&1 & GUARD3=$!
sleep 0.6
mkdir -p "$W/toctou-dir"
TOC=$(curl -s -X POST -H 'Content-Type: application/json' -d '{"Image":"alpine","HostConfig":{"Binds":["'"$W"'/toctou-dir:/x"]}}' --unix-socket $S3 http://localhost/containers/create | sed -n 's/.*"Id":"\([a-f0-9]*\)".*/\1/p')
rm -rf "$W/toctou-dir" && ln -sfn /etc "$W/toctou-dir"
chk 403 "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' --unix-socket $S3 "http://localhost/containers/$TOC/start")" "TOCTOU: start after symlink swap denied"
chk 201 "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' --unix-socket $S3 "http://localhost/containers/$TOC/stop")" "stop still allowed (no mounts)"
rm -rf "$W"

kill $GUARD $GUARD2 $GUARD3 $FAKE 2>/dev/null
