# docker-guard

> **⚠ PRE-ALPHA.** This is an actively developed prototype. Do **not** use it
> in any production system or to contain untrusted code. Policies, config, and
> wire format may change without notice, and no external security review has
> been performed.

A filtering proxy for the Docker daemon socket. It lets an agent container use
Docker (Docker-out-of-Docker) while making sure containers it creates can never
mount host paths outside the workspace or use escape-prone options.

```
agent container ──unix──▶ guard.sock ──▶ [docker-guard] ──unix──▶ docker.sock ──▶ dockerd
```

The real `docker.sock` is mounted **only** into the guard container, which runs
with `--network none`, all capabilities dropped, and a read-only rootfs. The
agent's `DOCKER_HOST` points at `guard.sock`. The guard is a single
stdlib-only Go program (`main.go`, static scratch image ≈ 3 MB).

## Functionality

- **Default-deny routing.** Only an allowlist of daemon routes (containers,
  images, volumes, networks, build, exec, session) is forwarded; everything
  else (swarm, services, plugins, auth, ...) gets `403`.
- **Request-body validation on `POST /containers/create`:**
  - bind sources (all three shapes: `HostConfig.Binds`, top-level `Mounts`,
    `HostConfig.Mounts`) must resolve — via `realpath` with symlink resolution
    and nearest-existing-ancestor walk — under `GUARD_ALLOWED_BIND_ROOTS`;
  - denied: `--privileged`, host `pid/ipc/uts/userns/cgroupns/network`
    namespaces, `--device`, dangerous `--cap-add`, unconfined
    seccomp/apparmor, `label=`, `Links`, shared bind propagation, and
    volume `DriverOpts` (`device=`/`type=`/`o=`) bind bypasses.
- **Ownership tracking.** Containers/execs created through the guard are
  recorded (persisted to a state file); inspect/start/stop/exec/attach/rm etc.
  work **only** for those. Host containers are invisible to these operations.
- **TOCTOU re-validation.** Bind sources are re-checked at `start`/`restart`,
  so swapping a validated directory for a symlink between create and start is
  denied.
- **HTTP framing hardening.** One fully-parsed request per connection
  (`Connection: close` injection); protocol-upgrade routes (`attach`,
  `exec/start`, BuildKit `/session`) are chosen by route only, and only a real
  `101` switches to raw streaming — pipelining and forged-upgrade bypasses are
  closed (covered by regression tests).
- **Audit log.** Every decision is logged to stdout (`docker compose logs guard`).

## Usage

The guard is deployed as part of the stack in `../docker-compose.yaml`
(guard + agent + preflight). From the project root:

```bash
cp .env.example .env      # set DOCKER_GID=$(stat -c %g /var/run/docker.sock)
docker compose up -d      # preflight -> guard -> agent
docker compose logs -f guard
```

Agent-side wiring (already set by compose):

```
-v <guard-dir>:/var/run/dsh-guard     # guard.sock appears here
-e DOCKER_HOST=unix:///var/run/dsh-guard/guard.sock
-v "$WORKSPACE":"$WORKSPACE"          # workspace also at its true host path,
                                      # so `docker -v` sources resolve identically
```

Notes for the agent:

- bind sources passed to `docker -v` must use the workspace's **absolute host
  path** (it is mounted at that path inside the agent as well);
- `docker build` currently requires the legacy builder: `DOCKER_BUILDKIT=0`
  (the BuildKit container driver needs a privileged builder, which is denied);
- the agent container itself must stay unprivileged (no `--privileged`,
  `--network host`, `--pid=host`) and dockerd must not listen on TCP
  2375/2376 — the compose preflight enforces the latter.

## Configuration

Environment (preferred; compose sets these):

| Variable | Meaning |
|---|---|
| `GUARD_ALLOWED_BIND_ROOTS` | comma-separated absolute host paths allowed as bind sources (empty = deny all binds) |
| `GUARD_SOCKET` | unix socket the guard listens on (default `/run/guard/guard.sock`) |
| `DOCKER_DAEMON_SOCKET` | upstream daemon socket (default `/var/run/docker.sock`) |
| `GUARD_STATE` | ownership state file (default `/var/lib/guard/state.json`) |
| `GUARD_FORCE_RUNTIME` | force this runtime for every created container (e.g. `runsc` for gVisor); empty = allow only the default runtime |
| `GUARD_MAX_MEMORY_BYTES`, `GUARD_MAX_PIDS` | reject creates exceeding these caps (0 = no cap) |
| `GUARD_CONFIG` | optional JSON config file (same fields, camelCase); env vars override it |
| `GUARD_DISABLE_SPLICE=1` | disable `splice(2)` zero-copy passthrough (debug) |

The guard resolves bind paths on the **host** filesystem, so the workspace is
mounted into the guard container read-only at the same absolute path.

## Testing

```bash
docker compose run --rm guard-test   # 42-assertion policy suite vs a fake daemon
bash verify-guard.sh                 # live checks against the real daemon (run on host)
```

## Known limitations (pre-alpha)

- `docker ps` / `docker images` still list **host** containers and images;
  image pull/remove is unrestricted (read-only visibility, shared image store).
- Resource exhaustion (CPU, disk via pulls) is only capped if you set the
  `GUARD_MAX_*` variables.
- The guard is a request-level boundary: it cannot stop a confined container
  from exploiting a host-kernel vulnerability. For stronger isolation run a
  rootless daemon or force a sandboxed runtime (`GUARD_FORCE_RUNTIME=runsc`).
- A sub-millisecond create→mount race remains theoretically possible; for a
  hard guarantee set `GUARD_ALLOWED_BIND_ROOTS=` (no bind mounts at all).
