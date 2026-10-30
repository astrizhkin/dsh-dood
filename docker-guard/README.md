# docker-guard: filtered Docker socket for the agent container

Gives the agent container Docker access **without** letting containers it create
mount anything outside the workspace folder.

## How it works

```
host (vm-mint21)
├── /var/run/docker.sock        real daemon socket — mounted ONLY into the guard container
├── <project>/dsh-guard/        shared dir; contains guard.sock + state/
└── <project>/dsh-workspace/    the only bind-mount source the guard allows
                                (GUARD_ALLOWED_BIND_ROOTS; realpath-checked)

agent container ──unix──▶ guard.sock ──validate──▶ [dsh-docker-guard] ──unix──▶ docker.sock ──▶ dockerd
```

The guard is a small Go proxy (`main.go`) running as its own container
(`--network none`, no capabilities). It default-denies routes, validates
`POST /containers/create` bodies, and tracks which containers the agent created
(state in the guard-dir `state/` bind dir) so it can restrict per-container ops.

## Setup (on the host)

Everything is driven by **`../docker-compose.yaml`** in the workspace root
(configured via `.env`, see `.env.example`):

```bash
cp .env.example .env      # fill in DOCKER_GID: stat -c %g /var/run/docker.sock
docker compose run --rm guard-test   # 42-assertion policy suite (builds first)
docker compose up -d      # preflight -> guard -> agent
docker compose logs -f guard          # guard audit log
docker compose down
```

Key properties (enforced by the compose file itself):

- **Ownership**: both long-running containers run as `DSH_UID:DSH_GID` from
  `.env` — the host user that starts the stack. Files the agent creates in
  `dsh-workspace`/`dsh-data` are owned by that user, never root. A one-shot
  `setup` service chowns those dirs accordingly on every `up` (fixes pre-existing
  root-owned trees). If the agent image misbehaves as non-root, set
  `DSH_UID=0`/`DSH_GID=0` — but then workspace files become root-owned again.
- **Preflight**: `setup` refuses to start if dockerd listens on TCP 2375/2376
  (a raw-TCP daemon would bypass the guard entirely).
- The guard runs as the invoking user + `group_add: DOCKER_GID` (required
  because `--cap-drop ALL` removes `CAP_DAC_OVERRIDE`), and takes its config
  from env vars (`GUARD_ALLOWED_BIND_ROOTS` = absolute workspace path from
  `.env`) instead of a generated `guard.json`.
- The agent launches with:

```diff
-  -v /var/run/docker.sock:/var/run/docker.sock
+  -v ./dsh-guard:/var/run/dsh-guard
+  -e DOCKER_HOST=unix:///var/run/dsh-guard/guard.sock
+  -v "$WORKSPACE":"$WORKSPACE"   # same path in agent and daemon (DooD trap)
```

(Keep the agent container itself unprivileged and NOT `--network host` /
`--pid=host` — see Bypasses below.)

Verify: `docker compose run --rm guard-test` (fake daemon, 42 assertions) and
`bash verify-guard.sh` (live checks against the real daemon).

Confirm the **host** path in `.env` (`DSH_WORKSPACE_DIR`) matches reality:

```bash
docker inspect <agent-container> --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'
```

## What the agent can do

- `docker build` / `buildx` (default `docker` driver), `pull`, `push`, image ls/rm
- `docker run` with bind mounts **only** under the workspace (its absolute
  host path, realpath-checked; the agent mounts it at both paths)
- named volumes and tmpfs (but `volume create` with `device=`/`type=`/`o=` driver
  opts is denied — that's a bind-mount bypass)
- start/stop/restart/rm/logs/inspect/exec/attach/docker cp — **only for containers
  the agent created through the guard**
- networks: create/list/delete

## What is denied

| Denial | Why |
|---|---|
| bind source outside workspace (after `realpath`) | the requested restriction |
| symlink inside workspace → outside | daemon doesn't resolve symlinks; guard does |
| non-existent bind source outside workspace | daemon auto-creates bind dirs; guard walks to nearest existing ancestor |
| `--privileged` | raw disk + `/dev` access = host root |
| `--pid=host` | `/proc/1/root` = host filesystem |
| `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host` | host-namespace escapes |
| `--network=host` | sniff/inject host traffic, reach daemon TCP if ever enabled |
| `--device` | direct block/char device access |
| `--cap-add SYS_ADMIN/SYS_PTRACE/SYS_MODULE/SYS_RAWIO/DAC_READ_SEARCH/ALL` | container-escape capabilities |
| `--security-opt seccomp/apparmor=unconfined`, `label=` | removes last-line confinement |
| bind propagation `rshared/rslave/rbind` | re-exposes host mounts inside the container |
| `volume create -o device=... -o type=none -o o=bind` | volume-as-bind bypass |
| plugins / services / swarm / secrets / configs / auth / session | host-root or credential vectors |
| exec/start/... on containers not created through the guard | can't touch or resurrect host workloads |

## Bypass analysis (your question: can bash in the agent container bypass it?)

Not through the socket — unix sockets are filesystem objects and the real
`docker.sock` is not in the agent's mount table. The guard socket is the only
path to the daemon. But the boundary holds only if:

1. **dockerd listens on the unix socket only.** The compose `setup` service
   checks for `:2375/:2376` TCP listeners and refuses to start otherwise.
2. **The agent container stays unprivileged** (no `--privileged`, `--pid=host`,
   `--network=host`). With those, bash could read the host disk or
   `/proc/<dockerd>/root/var/run/docker.sock` directly — no guard can help.
3. **The guard container is not reachable from the agent** — it runs with
   `--network none` and only a unix socket, so yes.
4. Deleting `guard.sock` from inside the agent only breaks the agent's own
   access; the guard re-binds the path within ~2s.

Residual risks (accepted by design): the agent can consume host resources
(image pulls, CPU), delete host images, and read the *list* of containers
(`docker ps` names). Tighten `classify()` in `main.go` if you want those too.

### Found & fixed: keep-alive / HTTP-pipelining bypass (critical)

Live testing inside the guarded agent revealed a real hole in the first
implementation. The guard parsed **only the first request on a connection**,
then raw-piped everything else to the daemon. The `docker` CLI reuses one
connection (`HEAD /_ping`, then the real call), so the *second* request —
`GET /containers/<foreign>/json`, `POST /containers/create` with a `/etc`
bind, `--privileged`, etc. — reached the daemon **unclassified**. curl
(one request per connection) looked safe; the CLI did not.

Fix (`main.go`): force **one fully-parsed request per
connection** by injecting `Connection: close` into every request whose route
is not a protocol-upgrade route. Hijack routes (`attach`, `exec start`,
BuildKit's `/session`) are decided **by route, never by client headers** (a
forged `Upgrade:` header must not skip the injection). On hijack routes the
guard peeks the response: only a real `101` may continue as a raw stream; a
refused upgrade gets its framed response relayed and the connection
hard-closed, so no pipelined follow-up can ride it. Three regression tests
now ship in `policy-test.sh` (pipelined request, forged Upgrade header,
refused-upgrade pipelining) with a keep-alive-aware fake daemon.

Lesson: a socket guard is only as strong as its HTTP framing. Any design that
"trusts the rest of the stream after the first request" is bypassable by any
client that pipelines or keeps the connection alive.

### Live audit notes (post-fix)

- `docker build` through the guard: the **legacy builder** works
  (`DOCKER_BUILDKIT=0 docker build` → plain `POST /build`, no hijack). The
  BuildKit path needs the embedded `docker` driver; this daemon's `/info`
  omits the `Features` buildkit advertisement, so a fresh buildx state falls
  back to the `docker-container` driver — whose builder container runs
  `--privileged` and is **denied by design**. (One such container,
  `buildx_buildkit_default`, was created on the host *through the old
  bypass* before the fix — remove it on the host.)
- `POST /session` (BuildKit gRPC, hijack) is allowed; a real `101` is
  required for the raw stream, refused upgrades hard-close.

## Defense in depth: protecting the host filesystem beyond the guard

The guard is a **request-level** boundary: it stops privileged/host-ns/device
escapes and out-of-workspace binds at the API. It cannot stop a *confined*
container from exploiting a **host kernel vulnerability** (containers share the
kernel). Pick layers by threat model:

| Layer | Stops | Cost | Setup |
|---|---|---|---|
| Guard (this repo) | request-level escapes, bad binds | none | done |
| **gVisor (`runsc`)** | kernel LPE from containers (userspace kernel) | some workloads incompatible | see below, then set `"forceRuntime": "runsc"` in `guard.json` — the guard *forces* it on every agent create, so the agent can't opt out |
| **Rootless daemon** | everything, even privileged containers (daemon itself is unprivileged; "privileged" containers are uid-mapped and harmless to the host) | ports <1024 gone, fuse-overlayfs perf, needs cgroup v2 + `uidmap` | `apt install docker-ce-rootless-extras uidmap && dockerd-rootless-setuptool.sh install`, then point the guard at the rootless socket (`DOCKER_DAEMON_SOCKET=/run/user/<uid>/docker.sock`) and give the rootless user access to the workspace |
| `userns-remap` in daemon.json | container root ≠ host root (uid-mapped writes) | workspace file ownership changes; daemon-wide, affects your own containers too | one line in daemon.json + chown workspace |
| **No bind mounts at all** | any host-path access by agent containers | agent must use `docker cp` / named volumes | set `"allowedBindRoots": []` in `guard.json` (any absolute bind source is then denied); guard already allows named volumes + `docker cp` into owned containers |
| Resource caps | disk/CPU/pids DoS | none | `"maxMemoryBytes"`, `"maxPids"` in `guard.json` |
| Disposable VM | everything below the hypervisor | you're already in one (`vm-mint21`) — snapshot/restore it | keep the VM itself disposable |

**Recommended combo for this setup:** guard + gVisor forced (`forceRuntime`) +
resource caps. If you want the strongest filesystem guarantee, run a **rootless
daemon** dedicated to the agent and point the guard at it — then even a fully
privileged, kernel-exploiting container cannot write host files outside the
rootless user's reach.

### gVisor install (host)

```bash
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt update && sudo apt install runsc
# /etc/docker/daemon.json:  {"runtimes": {"runsc": {"path": "/usr/local/bin/runsc"}}}   then restart docker
# guard.json: "forceRuntime": "runsc"   (rebuild/restart the guard container)
```

## Implementation

Single implementation: **`main.go`** — stdlib-only Go, `splice(2)` zero-copy
passthrough (fallback to buffered copy; disable with `GUARD_DISABLE_SPLICE=1`).
Static scratch image ≈ 5 MB, ~50–150 µs per-call overhead. The original Node
reference implementation was removed after the Go port compiled and passed the
full suite on the host.

Build & deploy with `docker compose` from the workspace root (multi-stage Go →
scratch). `docker compose run --rm guard-test` builds the `test` target
(`node:22-alpine` + curl + bash, binary and suite baked in) and runs the
42-assertion suite — node only provides the fake daemon + curl.

## Comparison with buildkite/sockguard

[buildkite/sockguard](https://github.com/buildkite/sockguard) (Go, 2016–2018)
is the closest prior art — Buildkite built it for exactly this
Docker-out-of-Docker problem, and its design independently converges on ours:

| Aspect | buildkite/sockguard | this guard |
|---|---|---|
| Pattern | proxy socket for DooD, one instance per untrusted worker | same (one instance per agent) |
| Ownership of containers | labels `com.buildkite.sockguard.owner=<id>` applied at create, checked on later ops (survives restarts, multi-tenant) | guard-local state file (single-tenant; also survives restarts) |
| Bind whitelist | `--allow-bind <path>` (string allowlist) | `allowedBindRoots` + **realpath/symlink resolution + ancestor walk** (their docs don't document symlink handling — the known string-allowlist bypass) |
| Escape flags | documented: no `privileged`, no `host` network | those **plus** pid/ipc/uts/userns/cgroupns host, `--device`, dangerous `--cap-add`, `security-opt unconfined/label=`, `Links`, bind propagation, volume `DriverOpts` bypass, runtime forcing |
| create→start TOCTOU | not addressed | bind sources re-validated at `start`/`restart` |
| Image scoping | ownership-labeled: can't touch other tenants' images | images allowed (documented residual risk) — **their model is better here** |
| Resource control | injects `cgroup-parent` | denies over-cap `Memory`/`PidsLimit` |
| Maturity | self-described "Very alpha! … Not yet ready for production", built on API v1.32 (2018), unmaintained | current API, 42-assertion suite, actively hardened |
| Runtime | Go | Go |

**Bottom line:** sockguard validates the architecture (same proxy +
ownership + bind-allowlist design from a serious shop), but it is
explicitly alpha, unmaintained, and its documented policy surface is
narrower than what "nothing outside the workspace" requires. Two ideas
worth stealing from it: **ownership labels** (multi-instance friendly) and
**image scoping** (currently our loosest edge).

## Prior art (web research, 2026-10-29)

How this guard compares to the documented state of the art for
Docker-out-of-Docker hardening:

| Source | Finding | Status here |
|---|---|---|
| [OWASP Docker cheat sheet, Rule #1](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | never expose the socket, even `:ro` (read-only mount is not a mitigation); never enable TCP | guard socket only; compose `setup` refuses if `:2375/:2376` listeners exist |
| [Quarkslab](https://blog.quarkslab.com/why-is-exposing-the-docker-socket-a-really-bad-idea.html), [SecurityCorp](https://securitycorp.net/knowledge/docker-sock-mounting-security-risks) | socket = root-equivalent; verify scoped proxies actually reject privileged-create from inside the client | `verify-guard.sh` does exactly this active test |
| [Tecnativa docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy), LinuxServer socket-proxy, [sockguard](https://github.com/CodesWhat/sockguard) | endpoint/method allowlists only — no body inspection, so no bind-mount or privileged enforcement | this guard validates bodies (binds, Privileged, caps, namespaces) |
| [wollomatic/socket-proxy](https://github.com/wollomatic/socket-proxy) (v1.8+) | **does** inspect bodies for bind mounts (`-allowbindmountfrom`, covers `-v` syntax, `Mounts`, volume `o=bind/rbind`, rejects `VolumesFrom`) — but its own docs state it **cannot resolve host-side symlinks** and **does not restrict privileged/host-ns/caps/devices**; no ownership tracking | guard adds symlink realpath resolution, escape-flag denials, ownership, start-time TOCTOU revalidation |
| [opa-docker-authz #34](https://github.com/open-policy-agent/opa-docker-authz/issues/34) | string-matching `Binds`/`Mounts` is trivially defeated by `ln -s / ~/root` | guard `realpath()`s sources on the host (same fix upstream shipped in v0.10's `BindMounts` enrichment) |
| [moby #36020](https://github.com/moby/moby/issues/36020) | authz checks happen before the daemon resolves/mounts sources → **TOCTOU**: swap a validated dir for a symlink before `start` | guard stores bind sources at create and **re-validates at `start`/`restart`**; residual sub-ms race → use rootless daemon or `allowedBindRoots: []` for a hard guarantee |
| HackTricks [authz plugin notes](https://hacktricks.wiki/en/linux-hardening/containers-namespaces/container-security/authorization-plugins.html) | policies checking only one JSON shape are bypassed (`HostConfig.Binds` vs `Mounts`) | guard checks `HostConfig.Binds`, top-level `Mounts`, **and** `HostConfig.Mounts` |
| [gVisor production guide](https://gvisor.dev/docs/user_guide/production/) | for untrusted/agent code use `runsc`; **inside a VM use the `systrap` platform**; privileged containers under gVisor "never run with capabilities on the host kernel" (also used by GKE Sandbox, Cloud Run, [Ray agent sandboxes](https://cloud.google.com/blog/products/containers-kubernetes/gvisor-sandboxes-for-ray-clusters-on-gke)) | `"forceRuntime": "runsc"` forces it on every agent create |
| moby #36020 maintainer guidance | the only complete answer to bind-mount policy is: no bind mounts, or run containers as the user's own uid | `allowedBindRoots: []` mode + rootless daemon option above |
| Docker Desktop [ECI](https://github.com/docker/docs/blob/main/content/manuals/enterprise/security/hardened-desktop/enhanced-container-isolation/config.md) / [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/governance/access-controls/filesystem/) | Docker's own products for this exact threat model (socket-mount blocking, host-path allow rules for AI agents) — validates the pattern; Linux equivalents are what this repo builds | n/a (Linux VM host) |
| CIS Docker Benchmark / dash0 | add runtime detection (Falco/auditd) for socket access + privileged-create attempts | guard logs every DENY to stdout (`docker logs dsh-docker-guard`) |

**Known residual risk:** the create→start TOCTOU window is closed, but a
sub-millisecond race between the guard's start-time re-check and the daemon's
mount remains theoretically possible. If that matters, run the agent against a
**rootless daemon** (race succeeds → damage limited to the rootless user) or
set `allowedBindRoots: []` (no host paths at all).

## Config

`guard.json` knobs: `allowedBindRoots` (realpath-checked bind roots),
`forceRuntime` (null = runc-only; e.g. `"runsc"` to force gVisor),
`maxMemoryBytes` / `maxPids` (0 = no cap). Keep the bind roots in sync with
the workspace path in your launch script. The guard resolves these paths on
the **host** filesystem (the workspace is mounted into the guard container
read-only at the same path for that purpose).

