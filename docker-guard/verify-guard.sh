#!/usr/bin/env bash
# verify-guard.sh — run on the HOST. Exercises the guard through its socket.
# Every "expect DENY" must print "docker-guard: ..."; the last one must succeed.
set -u
export DOCKER_HOST=unix:///root/dsh-guard/guard.sock

echo "== expect DENY: bind outside workspace =="
docker run --rm -v /etc:/host-etc alpine ls /host-etc
echo "== expect DENY: symlink inside workspace pointing to /etc =="
ln -sfn /etc /root/dsh-workspace/.evil-link-test
docker run --rm -v /root/dsh-workspace/.evil-link-test:/x alpine ls /x
rm -f /root/dsh-workspace/.evil-link-test
echo "== expect DENY: privileged =="
docker run --rm --privileged alpine id
echo "== expect DENY: --pid=host =="
docker run --rm --pid=host alpine ls /proc/1/root
echo "== expect DENY: --device =="
docker run --rm --device /dev/sda alpine true
echo "== expect DENY: volume-create with device opt =="
docker volume create --driver local -o device=/etc -o type=none -o o=bind sneaky
echo "== expect DENY: exec into a container you did not create =="
docker exec dsh-docker-guard true
echo "== expect ALLOW: workspace bind mount =="
docker run --rm -v /root/dsh-workspace:/work alpine sh -c 'ls /work/docker-guard >/dev/null && echo ALLOWED-OK'
echo "== expect ALLOW: pull + build + run + exec own container =="
docker pull -q alpine >/dev/null
docker run -d --name guard-verify alpine sleep 60
docker exec guard-verify id
docker rm -f guard-verify
