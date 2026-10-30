//go:build linux

// docker-guard: filtering proxy between an untrusted container and the host
// Docker daemon socket. Single implementation (same policy, same guard.json,
// same state file format), with splice(2) zero-copy passthrough.
//
// Enforces:
//   - default-deny route allowlist
//   - body validation of POST /containers/create: bind sources are
//     realpath-resolved on the host and must live under allowedBindRoots;
//     privileged / host-namespace / device / capability options are denied
//   - container ownership: per-container ops only for containers created
//     through this guard (state persisted to GUARD_STATE)
//   - start-time revalidation of bind sources (create->start TOCTOU, moby#36020)
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	maxValidatedBody = 16 << 20
	maxHead          = 64 << 10
	spliceChunk      = 65536
	headReadTimeout  = 30 * time.Second
)

var dangerousCaps = map[string]bool{
	"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true,
	"SYS_RAWIO": true, "DAC_READ_SEARCH": true, "ALL": true,
}

/* ---------------- config ---------------- */

type config struct {
	AllowedBindRoots []string `json:"allowedBindRoots"`
	ForceRuntime     string   `json:"forceRuntime"`
	MaxMemoryBytes   int64    `json:"maxMemoryBytes"`
	MaxPids          int64    `json:"maxPids"`
}

/* ---------------- persisted state ---------------- */

type stateFile struct {
	Owned    []string            `json:"owned"`
	Names    []string            `json:"names"`
	Execs    map[string]string   `json:"execs"`
	Sources  map[string][]string `json:"sources"`
	NameToID map[string]string   `json:"nameToId"`
}

type guard struct {
	cfg           config
	roots         []string
	daemonSocket  string
	guardSocket   string
	stateFile     string
	disableSplice bool

	mu       sync.Mutex
	owned    map[string]bool
	names    map[string]bool
	execs    map[string]string
	sources  map[string][]string
	nameToID map[string]string
}

func (g *guard) loadState() {
	b, err := os.ReadFile(g.stateFile)
	if err != nil {
		return
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil {
		return
	}
	for _, id := range s.Owned {
		g.owned[id] = true
	}
	for _, n := range s.Names {
		g.names[n] = true
	}
	for k, v := range s.Execs {
		g.execs[k] = v
	}
	for k, v := range s.Sources {
		g.sources[k] = v
	}
	for k, v := range s.NameToID {
		g.nameToID[k] = v
	}
}

func (g *guard) saveState() { // caller holds g.mu
	s := stateFile{
		Owned:    keysOfBool(g.owned),
		Names:    keysOfBool(g.names),
		Execs:    g.execs,
		Sources:  g.sources,
		NameToID: g.nameToID,
	}
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := g.stateFile + ".tmp"
	if err := os.MkdirAll(filepath.Dir(g.stateFile), 0o755); err != nil {
		log.Printf("state save failed: %v", err)
		return
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("state save failed: %v", err)
		return
	}
	if err := os.Rename(tmp, g.stateFile); err != nil {
		log.Printf("state save failed: %v", err)
	}
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (g *guard) isOwned(id string) bool {
	if id == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.owned[id] || g.names[id] {
		return true
	}
	for o := range g.owned {
		if strings.HasPrefix(o, id) { // docker accepts id prefixes
			return true
		}
	}
	return false
}

func (g *guard) resolveContainerID(id string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.owned[id] {
		return id
	}
	if full, ok := g.nameToID[id]; ok {
		return full
	}
	for o := range g.owned {
		if strings.HasPrefix(o, id) {
			return o
		}
	}
	return ""
}

func (g *guard) sourcesOf(cid string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sources[cid]
}

func (g *guard) execOwner(execID string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cid, ok := g.execs[execID]
	return cid, ok
}

/* ---------------- path policy ---------------- */

// resolveUnder resolves a host bind source (walking up to the nearest existing
// ancestor, then resolving every symlink hop) and requires the result to live
// under one of allowedBindRoots. Returns the resolved path and whether it is allowed.
func (g *guard) resolveUnder(src string) (string, bool) {
	if src == "" || !filepath.IsAbs(src) {
		return "", false
	}
	cur := filepath.Clean(src)
	var missing []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		missing = append([]string{filepath.Base(cur)}, missing...)
		cur = parent
	}
	real, err := filepath.EvalSymlinks(cur)
	if err != nil {
		return "", false
	}
	full := filepath.Join(append([]string{real}, missing...)...)
	for _, r := range g.roots {
		if full == r || strings.HasPrefix(full, r+string(filepath.Separator)) {
			return full, true
		}
	}
	return full, false
}

/* ---------------- request policy ---------------- */

type decision struct {
	action     string // allow deny owned ownedExec ownedExecCreate ownedQuery validate
	kind       string // create volume exec
	id         string
	revalidate bool
	hijack     bool // route-level: attach / exec start are raw-piped
	reason     string
}

var (
	reVersion         = regexp.MustCompile(`^/v\d+(?:\.\d+)?`)
	reContainerRead   = regexp.MustCompile(`^/containers/([^/]+)/(json|changes|top|stats|logs|archive)$`)
	reContainerStart  = regexp.MustCompile(`^/containers/([^/]+)/(start|restart)$`)
	reContainerAction = regexp.MustCompile(`^/containers/([^/]+)/(stop|kill|pause|unpause|wait|rename|attach)$`)
	reExecCreate      = regexp.MustCompile(`^/containers/([^/]+)/exec$`)
	reExecOp          = regexp.MustCompile(`^/exec/([^/]+)/(start|resize)$`)
	reExecInspect     = regexp.MustCompile(`^/exec/([^/]+)/json$`)
	reImageInspect    = regexp.MustCompile(`^/images/[^/]+/json$`)
	reImageOp         = regexp.MustCompile(`^/images/[^/]+/(push|tag)$`)
	reImageDelete     = regexp.MustCompile(`^/images/[^/]+$`)
	reVolumeAny       = regexp.MustCompile(`^/volumes(/[^/]+)?$`)
	reContainerDelete = regexp.MustCompile(`^/containers/([^/]+)$`)
	reArchive         = regexp.MustCompile(`^/containers/([^/]+)/archive$`)
)

func classify(method, rawurl string) decision {
	u, err := url.Parse(rawurl)
	if err != nil {
		return decision{action: "deny", reason: "malformed request URL"}
	}
	p := reVersion.ReplaceAllString(u.Path, "")
	if p == "" {
		p = "/"
	}
	allow := decision{action: "allow"}

	switch method {
	case "GET", "HEAD":
		if p == "/" || p == "/_ping" || p == "/version" || p == "/info" {
			return allow
		}
		if p == "/containers/json" || p == "/images/json" || p == "/images/summary" {
			return allow
		}
		if m := reContainerRead.FindStringSubmatch(p); m != nil {
			return decision{action: "owned", id: unesc(m[1])}
		}
		if reImageInspect.MatchString(p) {
			return allow
		}
		if reVolumeAny.MatchString(p) {
			return allow
		}
		if strings.HasPrefix(p, "/networks") {
			return allow
		}
		if m := reExecInspect.FindStringSubmatch(p); m != nil {
			return decision{action: "ownedExec", id: m[1]}
		}
		if strings.HasPrefix(p, "/build/") {
			return allow
		}
	case "POST":
		if p == "/containers/create" {
			return decision{action: "validate", kind: "create"}
		}
		if m := reContainerStart.FindStringSubmatch(p); m != nil {
			return decision{action: "owned", id: unesc(m[1]), revalidate: true}
		}
		if m := reContainerAction.FindStringSubmatch(p); m != nil {
			return decision{action: "owned", id: unesc(m[1]), hijack: m[2] == "attach"}
		}
		if m := reExecCreate.FindStringSubmatch(p); m != nil {
			return decision{action: "ownedExecCreate", id: unesc(m[1])}
		}
		if m := reExecOp.FindStringSubmatch(p); m != nil {
			return decision{action: "ownedExec", id: m[1], hijack: m[2] == "start"}
		}
		if p == "/build" {
			return allow
		}
		if p == "/session" {
			// BuildKit gRPC session (hijacked): required for `docker build`.
			return decision{action: "allow", hijack: true}
		}
		if p == "/commit" {
			return decision{action: "ownedQuery", id: u.Query().Get("container")}
		}
		if p == "/images/create" || p == "/images/create/" {
			return allow // pull
		}
		if reImageOp.MatchString(p) {
			return allow
		}
		if p == "/volumes/create" {
			return decision{action: "validate", kind: "volume"}
		}
		if strings.HasPrefix(p, "/networks/") {
			return allow
		}
	case "DELETE":
		if m := reContainerDelete.FindStringSubmatch(p); m != nil {
			return decision{action: "owned", id: unesc(m[1])}
		}
		if reImageDelete.MatchString(p) || reVolumeAny.MatchString(p) && p != "/volumes" {
			return allow
		}
		if strings.HasPrefix(p, "/networks/") {
			return allow
		}
	case "PUT":
		if m := reArchive.FindStringSubmatch(p); m != nil { // docker cp
			return decision{action: "owned", id: unesc(m[1])}
		}
	}
	return decision{action: "deny", reason: fmt.Sprintf("route not allowed: %s %s", method, p)}
}

func unesc(s string) string {
	if out, err := url.PathUnescape(s); err == nil {
		return out
	}
	return s
}

/* ---------------- body policy ---------------- */

type mountSpec struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	BindOptions *struct {
		Propagation string `json:"Propagation"`
	} `json:"BindOptions"`
}

type hostConfig struct {
	Privileged   bool            `json:"Privileged"`
	PidMode      string          `json:"PidMode"`
	IpcMode      string          `json:"IpcMode"`
	UtsMode      string          `json:"UtsMode"`
	UsernsMode   string          `json:"UsernsMode"`
	CgroupnsMode string          `json:"CgroupnsMode"`
	NetworkMode  string          `json:"NetworkMode"`
	Runtime      string          `json:"Runtime"`
	Devices      []json.RawMessage `json:"Devices"`
	Links        []string        `json:"Links"`
	CapAdd       []string        `json:"CapAdd"`
	SecurityOpt  []string        `json:"SecurityOpt"`
	Memory       int64           `json:"Memory"`
	PidsLimit    *int64          `json:"PidsLimit"`
	Binds        []string        `json:"Binds"`
	Mounts       []mountSpec     `json:"Mounts"`
}

type createBody struct {
	HostConfig *hostConfig `json:"HostConfig"`
	Mounts     []mountSpec `json:"Mounts"`
}

type volumeBody struct {
	Driver     string            `json:"Driver"`
	DriverOpts map[string]string `json:"DriverOpts"`
}

func (g *guard) validateCreate(b *createBody) string {
	hc := b.HostConfig
	if hc == nil {
		hc = &hostConfig{}
	}
	if hc.Privileged {
		return "privileged containers are denied"
	}
	ns := []struct{ k, v string }{
		{"PidMode", hc.PidMode}, {"IpcMode", hc.IpcMode}, {"UtsMode", hc.UtsMode},
		{"UsernsMode", hc.UsernsMode}, {"CgroupnsMode", hc.CgroupnsMode},
	}
	for _, n := range ns {
		if n.v == "host" {
			return n.k + "=host is denied"
		}
		if strings.HasPrefix(n.v, "container:") && !g.isOwned(strings.TrimPrefix(n.v, "container:")) {
			return n.k + "=container:<foreign> is denied"
		}
	}
	if hc.NetworkMode == "host" {
		return "network=host is denied"
	}
	if len(hc.Devices) > 0 {
		return "device passthrough (--device) is denied"
	}
	if len(hc.Links) > 0 {
		return "links to other containers are denied"
	}
	for _, c := range hc.CapAdd {
		n := strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		if dangerousCaps[n] {
			return "cap-add " + c + " is denied"
		}
	}
	for _, s := range hc.SecurityOpt {
		t := strings.ToLower(s)
		if strings.Contains(t, "unconfined") || strings.HasPrefix(t, "label=") {
			return "security-opt " + s + " is denied"
		}
	}
	want := g.cfg.ForceRuntime
	if want == "" {
		want = "runc"
	}
	rt := hc.Runtime
	if rt == "" {
		rt = "runc"
	}
	if rt != want {
		return fmt.Sprintf("runtime must be %s", want)
	}
	if g.cfg.MaxMemoryBytes > 0 && hc.Memory > g.cfg.MaxMemoryBytes {
		return fmt.Sprintf("memory %d exceeds cap %d", hc.Memory, g.cfg.MaxMemoryBytes)
	}
	if g.cfg.MaxPids > 0 && hc.PidsLimit != nil && *hc.PidsLimit > g.cfg.MaxPids {
		return fmt.Sprintf("pids-limit %d exceeds cap %d", *hc.PidsLimit, g.cfg.MaxPids)
	}
	for _, entry := range hc.Binds {
		src := strings.Split(entry, ":")[0]
		if src == "" {
			continue // anonymous volume
		}
		if strings.Contains(src, "://") {
			return "npipe bind denied: " + entry
		}
		if !strings.HasPrefix(src, "/") {
			continue // named volume (volume-create is validated separately)
		}
		full, ok := g.resolveUnder(src)
		if !ok {
			return fmt.Sprintf("bind source %s resolves to %s, outside allowed roots [%s]",
				src, full, strings.Join(g.roots, ", "))
		}
	}
	// Mounts can arrive top-level (docker CLI) or under HostConfig (raw API
	// variants); policies that check only one shape are bypassable.
	for _, list := range [][]mountSpec{b.Mounts, hc.Mounts} {
		if r := g.checkMountList(list); r != "" {
			return r
		}
	}
	return ""
}

func (g *guard) checkMountList(list []mountSpec) string {
	for _, m := range list {
		switch m.Type {
		case "bind":
			if _, ok := g.resolveUnder(m.Source); !ok {
				return fmt.Sprintf("bind source %s resolves outside allowed roots [%s]",
					m.Source, strings.Join(g.roots, ", "))
			}
			prop := ""
			if m.BindOptions != nil {
				prop = m.BindOptions.Propagation
			}
			if prop == "rshared" || prop == "rslave" || prop == "rbind" {
				return "bind propagation " + prop + " is denied"
			}
		case "npipe":
			return "npipe mounts are denied"
		}
		// volume / tmpfs mounts are daemon-managed and allowed
	}
	return ""
}

// collectBindSources gathers absolute bind sources from every request shape;
// they are re-checked at container start (create->start TOCTOU, moby#36020).
func collectBindSources(b *createBody) []string {
	out := []string{}
	if b.HostConfig != nil {
		for _, entry := range b.HostConfig.Binds {
			src := strings.Split(entry, ":")[0]
			if strings.HasPrefix(src, "/") {
				out = append(out, src)
			}
		}
		for _, m := range b.HostConfig.Mounts {
			if m.Type == "bind" && m.Source != "" {
				out = append(out, m.Source)
			}
		}
	}
	for _, m := range b.Mounts {
		if m.Type == "bind" && m.Source != "" {
			out = append(out, m.Source)
		}
	}
	return out
}

func validateVolume(b *volumeBody) string {
	if b.Driver != "" && b.Driver != "local" {
		return fmt.Sprintf("volume driver %s is denied", b.Driver)
	}
	if len(b.DriverOpts) > 0 {
		return "volume DriverOpts (device/type/o bind bypass) are denied"
	}
	return ""
}

/* ---------------- http plumbing ---------------- */

type requestHead struct {
	raw     []byte
	method  string
	rawurl  string
	headers map[string]string
}

func readHead(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		buf = append(buf, line...)
		if len(buf) > maxHead {
			return nil, errors.New("request head too large")
		}
		if bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
			return buf, nil
		}
	}
}

func parseHead(raw []byte) (*requestHead, error) {
	text := string(raw[:len(raw)-2]) // drop final CRLF of the CRLFCRLF
	lines := strings.Split(text, "\r\n")
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return nil, errors.New("malformed request line")
	}
	h := &requestHead{raw: raw, method: parts[0], rawurl: parts[1], headers: map[string]string{}}
	for _, l := range lines[1:] {
		if i := strings.Index(l, ":"); i > 0 {
			h.headers[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(l[i+1:])
		}
	}
	return h, nil
}

func denyConn(c net.Conn, reason string) {
	log.Printf("DENY: %s", reason)
	body := fmt.Sprintf(`{"message":"docker-guard: %s"}`, reason)
	fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

type intercept struct {
	kind        string // create | exec
	name        string
	containerID string
	sources     []string
}

/* ---------------- forwarding + splice ---------------- */

func spliceSyscall(fdIn int, offIn *int64, fdOut int, offOff *int64, size uint, flags uint) (int, error) {
	r1, _, e1 := syscall.Syscall6(syscall.SYS_SPLICE,
		uintptr(fdIn), uintptr(unsafe.Pointer(offIn)),
		uintptr(fdOut), uintptr(unsafe.Pointer(offOff)),
		uintptr(size), uintptr(flags))
	if e1 != 0 {
		return 0, e1
	}
	return int(r1), nil
}

func pollBoth(fdRead, fdWrite int) {
	var rs, ws syscall.FdSet
	rs.Bits[fdRead/64] |= 1 << (uint(fdRead) % 64)
	ws.Bits[fdWrite/64] |= 1 << (uint(fdWrite) % 64)
	_, _ = syscall.Select(fdRead+1, &rs, nil, nil, nil)
	_, _ = syscall.Select(fdWrite+1, nil, &ws, nil, nil)
}

// splicePump copies src -> dst via splice(2) through an anonymous pipe
// (zero-copy in kernel space). Falls back to io.Copy when unavailable.
func (g *guard) splicePump(dst, src net.Conn) {
	su, ok1 := src.(*net.UnixConn)
	du, ok2 := dst.(*net.UnixConn)
	if !ok1 || !ok2 || g.disableSplice {
		_, _ = io.Copy(dst, src)
		return
	}
	sf, err1 := su.File()
	df, err2 := du.File()
	if err1 != nil || err2 != nil {
		if sf != nil {
			_ = sf.Close()
		}
		if df != nil {
			_ = df.Close()
		}
		_, _ = io.Copy(dst, src)
		return
	}
	defer sf.Close()
	defer df.Close()
	sfd, dfd := int(sf.Fd()), int(df.Fd())
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		_, _ = io.Copy(dst, src)
		return
	}
	defer syscall.Close(p[0])
	defer syscall.Close(p[1])
	for {
		n, err := spliceSyscall(sfd, nil, p[1], nil, spliceChunk, 0)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			pollBoth(sfd, p[1])
			continue
		}
		if err != nil {
			return // connection teardown
		}
		if n == 0 {
			return // EOF from src
		}
		sent := 0
		for sent < n {
			m, err := spliceSyscall(p[0], nil, dfd, nil, uint(n-sent), 0)
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN {
				pollBoth(p[0], dfd)
				continue
			}
			if err != nil {
				return
			}
			sent += m
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// pumpPair relays both directions; buffered leftovers in br/dbr (already-read
// bytes beyond the parsed head) are flushed before switching to splice.
// clientIdle > 0 arms a client read deadline once the response has been fully
// relayed, so a client that keeps the socket open cannot pin a goroutine.
func (g *guard) pumpPair(c, daemon net.Conn, br, dbr *bufio.Reader, clientIdle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if br != nil {
			_, _ = io.Copy(daemon, br)
		}
		g.splicePump(daemon, c)
		closeWrite(daemon)
	}()
	go func() {
		defer wg.Done()
		if dbr != nil {
			_, _ = io.Copy(c, dbr)
		}
		g.splicePump(c, daemon)
		closeWrite(c)
		if clientIdle > 0 {
			_ = c.SetReadDeadline(time.Now().Add(clientIdle))
		}
	}()
	wg.Wait()
}

// hasUpgrade is intentionally NOT used to decide raw-piping: the header is
// client-controlled and could be forged to skip Connection: close injection.
// Hijack routes are decided by classify() from the route itself.

// respContentLength extracts the Content-Length header value from a response
// head (empty string when absent).
func respContentLength(head []byte) string {
	end := len(head)
	if end >= 2 {
		end -= 2 // strip trailing CRLF CRLF
	}
	for _, l := range strings.Split(string(head[:end]), "\r\n")[1:] {
		if i := strings.Index(l, ":"); i > 0 && strings.EqualFold(strings.TrimSpace(l[:i]), "content-length") {
			return strings.TrimSpace(l[i+1:])
		}
	}
	return ""
}

// injectClose strips any Connection header from the request head and forces
// "Connection: close", so the daemon terminates the connection after its
// response and the client must dial a fresh connection for the next request
// (which is then fully re-classified). Without this, keep-alive/pipelined
// follow-up requests are spliced raw to the daemon and bypass policy.
func injectClose(head []byte) []byte {
	sep := strings.Index(string(head), "\r\n\r\n")
	if sep < 0 {
		return head
	}
	var keep []string
	for _, l := range strings.Split(string(head[:sep]), "\r\n") {
		if i := strings.Index(l, ":"); i > 0 && strings.EqualFold(strings.TrimSpace(l[:i]), "connection") {
			continue
		}
		keep = append(keep, l)
	}
	keep = append(keep, "Connection: close")
	return []byte(strings.Join(keep, "\r\n") + "\r\n\r\n" + string(head)[sep+4:])
}

func (g *guard) forward(c net.Conn, br *bufio.Reader, head, body []byte, inter *intercept, hijack bool) {
	daemon, err := net.DialTimeout("unix", g.daemonSocket, 10*time.Second)
	if err != nil {
		log.Printf("daemon unreachable: %v", err)
		return
	}
	defer daemon.Close()
	// One request per connection for non-hijack traffic: force the daemon to
	// close after its response so every subsequent request arrives on a fresh
	// connection and is fully re-classified (keep-alive bypass fix).
	idle := 5 * time.Second
	if hijack {
		idle = 0
	} else {
		head = injectClose(head)
	}
	if _, err := daemon.Write(head); err != nil {
		return
	}
	if len(body) > 0 {
		if _, err := daemon.Write(body); err != nil {
			return
		}
	}
	c.SetReadDeadline(time.Time{})
	if hijack {
		// Flush already-buffered request bytes (e.g. the exec-start body)
		// BEFORE peeking the response: the daemon will not answer until it has
		// the full request. Only drain what is buffered — reading more from br
		// would block the peek on a keep-alive client.
		if br.Buffered() > 0 {
			buf := make([]byte, br.Buffered())
			if _, err := io.ReadFull(br, buf); err != nil {
				return
			}
			if _, err := daemon.Write(buf); err != nil {
				return
			}
		}
		// Peek the response head: only a real 101 upgrade may continue as a
		// raw stream. If the daemon refused the upgrade, relay the framed
		// response and hard-close both sides, so no pipelined follow-up
		// request can ride this connection past the guard.
		dbr := bufio.NewReader(daemon)
		_ = daemon.SetReadDeadline(time.Now().Add(headReadTimeout))
		respHead, err := readHead(dbr)
		_ = daemon.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		status := respHead
		if len(status) > 15 {
			status = status[:15]
		}
		if !strings.Contains(string(status), " 101 ") {
			var rb []byte
			if n, err := strconv.Atoi(respContentLength(respHead)); err == nil && n >= 0 && n <= maxValidatedBody {
				rb = make([]byte, n)
				if _, err := io.ReadFull(dbr, rb); err != nil {
					rb = nil
				}
			} else {
				_ = daemon.SetReadDeadline(time.Now().Add(10 * time.Second))
				rb, _ = io.ReadAll(io.LimitReader(dbr, maxValidatedBody))
			}
			_, _ = c.Write(respHead)
			if rb != nil {
				_, _ = c.Write(rb)
			}
			return // defer closes both sides
		}
		if _, err := c.Write(respHead); err != nil {
			return
		}
		g.pumpPair(c, daemon, br, dbr, 0)
		return
	}
	if inter == nil {
		g.pumpPair(c, daemon, br, nil, idle)
		return
	}
	// Intercept the (small, JSON) response to record ownership, then relay.
	dbr := bufio.NewReader(daemon)
	respHead, err := readHead(dbr)
	if err != nil {
		return
	}
	var respBody []byte
	cl := respContentLength(respHead)
	if n, err := strconv.Atoi(cl); err == nil && n >= 0 && n <= maxValidatedBody {
		respBody = make([]byte, n)
		if _, err := io.ReadFull(dbr, respBody); err != nil {
			respBody = nil
		}
	}
	g.record(inter, respBody)
	if _, err := c.Write(respHead); err != nil {
		return
	}
	if respBody != nil {
		if _, err := c.Write(respBody); err != nil {
			return
		}
	}
	g.pumpPair(c, daemon, br, dbr, idle)
}

func (g *guard) record(inter *intercept, body []byte) {
	if len(body) == 0 {
		return
	}
	var j struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(body, &j); err != nil || j.ID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch inter.kind {
	case "create":
		g.owned[j.ID] = true
		if inter.name != "" {
			g.names[inter.name] = true
			g.nameToID[inter.name] = j.ID
		}
		if len(inter.sources) > 0 {
			g.sources[j.ID] = inter.sources
		}
		id := j.ID
		if len(id) > 12 {
			id = id[:12]
		}
		log.Printf("CREATE ok: %s %s", id, inter.name)
	case "exec":
		g.execs[j.ID] = inter.containerID
	}
	g.saveState()
}

/* ---------------- connection handling ---------------- */

func (g *guard) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(headReadTimeout))
	br := bufio.NewReader(c)
	rawHead, err := readHead(br)
	if err != nil {
		return
	}
	h, err := parseHead(rawHead)
	if err != nil {
		return
	}
	d := classify(h.method, h.rawurl)
	switch d.action {
	case "deny":
		denyConn(c, d.reason)
	case "allow":
		g.forward(c, br, h.raw, nil, nil, false)
	case "owned":
		if !g.isOwned(d.id) {
			denyConn(c, fmt.Sprintf("container %s was not created through this guard", d.id))
			return
		}
		if d.revalidate {
			// TOCTOU: the daemon resolves bind sources at mount time, so a path
			// validated at create may have been swapped for a symlink since.
			if cid := g.resolveContainerID(d.id); cid != "" {
				for _, src := range g.sourcesOf(cid) {
					if _, ok := g.resolveUnder(src); !ok {
						denyConn(c, "start-time revalidation failed: bind source "+src+" resolves outside allowed roots")
						return
					}
				}
			}
		}
		g.forward(c, br, h.raw, nil, nil, d.hijack)
	case "ownedExec":
		cid, ok := g.execOwner(d.id)
		if !ok || !g.isOwned(cid) {
			denyConn(c, fmt.Sprintf("exec %s does not belong to a guard-created container", d.id))
			return
		}
		g.forward(c, br, h.raw, nil, nil, d.hijack)
	case "ownedQuery":
		if !g.isOwned(d.id) {
			denyConn(c, fmt.Sprintf("container %s was not created through this guard", d.id))
			return
		}
		g.forward(c, br, h.raw, nil, nil, false)
	case "ownedExecCreate":
		if !g.isOwned(d.id) {
			denyConn(c, fmt.Sprintf("container %s was not created through this guard", d.id))
			return
		}
		body, reason := readValidatedBody(br, h)
		if reason != "" {
			denyConn(c, reason)
			return
		}
		g.forward(c, br, h.raw, body, &intercept{kind: "exec", containerID: d.id}, false)
	case "validate":
		body, reason := readValidatedBody(br, h)
		if reason != "" {
			denyConn(c, reason)
			return
		}
		switch d.kind {
		case "create":
			var b createBody
			if err := json.Unmarshal(body, &b); err != nil {
				denyConn(c, "invalid JSON body on validated route")
				return
			}
			if r := g.validateCreate(&b); r != "" {
				denyConn(c, r)
				return
			}
			name := ""
			if u, err := url.Parse(h.rawurl); err == nil {
				name = u.Query().Get("name")
			}
			g.forward(c, br, h.raw, body, &intercept{kind: "create", name: name, sources: collectBindSources(&b)}, false)
		case "volume":
			var vb volumeBody
			if err := json.Unmarshal(body, &vb); err != nil {
				denyConn(c, "invalid JSON body on validated route")
				return
			}
			if r := validateVolume(&vb); r != "" {
				denyConn(c, r)
				return
			}
			g.forward(c, br, h.raw, body, nil, false)
		}
	}
}

func readValidatedBody(br *bufio.Reader, h *requestHead) ([]byte, string) {
	if strings.Contains(strings.ToLower(h.headers["transfer-encoding"]), "chunked") {
		return nil, "chunked bodies are not accepted on validated routes"
	}
	n := 0
	if cl := h.headers["content-length"]; cl != "" {
		v, err := strconv.Atoi(cl)
		if err != nil || v < 0 {
			return nil, "invalid content-length"
		}
		n = v
	}
	if n > maxValidatedBody {
		return nil, "request body too large"
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, "incomplete request body"
	}
	return body, ""
}

/* ---------------- main ---------------- */

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	// Config comes from guard.json (GUARD_CONFIG) and may be overridden per
	// field by environment variables, which is how docker-compose configures
	// the guard (compose cannot template absolute host paths into a file).
	//   GUARD_ALLOWED_BIND_ROOTS  comma-separated; empty string = deny all binds
	//   GUARD_FORCE_RUNTIME       e.g. "runsc"
	//   GUARD_MAX_MEMORY_BYTES    integer, 0 = no cap
	//   GUARD_MAX_PIDS            integer, 0 = no cap
	var cfg config
	cfgPath := env("GUARD_CONFIG", "/app/guard.json")
	if b, err := os.ReadFile(cfgPath); err != nil {
		if _, ok := os.LookupEnv("GUARD_ALLOWED_BIND_ROOTS"); !ok {
			log.Fatalf("cannot read config %s and GUARD_ALLOWED_BIND_ROOTS is unset: %v", cfgPath, err)
		}
		log.Printf("config %s absent; using environment only", cfgPath)
	} else if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	if v, ok := os.LookupEnv("GUARD_ALLOWED_BIND_ROOTS"); ok {
		cfg.AllowedBindRoots = nil
		for _, r := range strings.Split(v, ",") {
			if r = strings.TrimSpace(r); r != "" {
				cfg.AllowedBindRoots = append(cfg.AllowedBindRoots, r)
			}
		}
	}
	if v := os.Getenv("GUARD_FORCE_RUNTIME"); v != "" {
		cfg.ForceRuntime = v
	}
	if v := os.Getenv("GUARD_MAX_MEMORY_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxMemoryBytes = n
		}
	}
	if v := os.Getenv("GUARD_MAX_PIDS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxPids = n
		}
	}
	if cfg.AllowedBindRoots == nil {
		log.Fatal("allowedBindRoots unset (config file or GUARD_ALLOWED_BIND_ROOTS; empty env value denies all bind mounts)")
	}
	roots := make([]string, 0, len(cfg.AllowedBindRoots))
	for _, r := range cfg.AllowedBindRoots {
		abs, err := filepath.Abs(r)
		if err != nil {
			log.Fatalf("bad allowedBindRoots entry %q: %v", r, err)
		}
		roots = append(roots, filepath.Clean(abs))
	}
	g := &guard{
		cfg:           cfg,
		roots:         roots,
		daemonSocket:  env("DOCKER_DAEMON_SOCKET", "/var/run/docker.sock"),
		guardSocket:   env("GUARD_SOCKET", "/run/guard/guard.sock"),
		stateFile:     env("GUARD_STATE", "/var/lib/guard/state.json"),
		disableSplice: os.Getenv("GUARD_DISABLE_SPLICE") == "1",
		owned:         map[string]bool{},
		names:         map[string]bool{},
		execs:         map[string]string{},
		sources:       map[string][]string{},
		nameToID:      map[string]string{},
	}
	g.loadState()

	if err := os.MkdirAll(filepath.Dir(g.guardSocket), 0o755); err != nil {
		log.Fatalf("cannot create socket dir: %v", err)
	}
	for {
		_ = os.Remove(g.guardSocket)
		ln, err := net.Listen("unix", g.guardSocket)
		if err != nil {
			log.Printf("listen error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		_ = os.Chmod(g.guardSocket, 0o660)
		log.Printf("docker-guard listening on %s -> %s", g.guardSocket, g.daemonSocket)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				c, err := ln.Accept()
				if err != nil {
					return // listener closed -> rebind
				}
				go g.handle(c)
			}
		}()
		// keep the socket path alive even if something unlinks it
		rebind := false
		for !rebind {
			if _, err := os.Stat(g.guardSocket); os.IsNotExist(err) {
				log.Printf("socket path missing, rebinding")
				rebind = true
			}
			select {
			case <-done:
				rebind = true
			case <-time.After(2 * time.Second):
			}
		}
		_ = ln.Close()
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
