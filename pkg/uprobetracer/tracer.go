// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package uprobetracer handles how uprobe/uretprobe/USDT programs are attached
// to containers. It has two running modes: `pending` mode and `running` mode.
//
// Before `AttachProg` is called, uprobetracer runs in `pending` mode, only
// maintaining the container PIDs ready to attach to.
//
// When `AttachProg` is called, uprobetracer enters the `running` mode and
// attaches to all pending containers. After that, it will never get back to
// the `pending` mode.
//
// In `running` mode, uprobetracer holds fd(s) of the executables, so we can
// use `/proc/self/fd/$fd` for attaching, it is used to avoid fd-reusing.
//
// Uprobetracer doesn't maintain ebpf.collection or perf-ring buffer by itself,
// those are hold by the parent tracer.
//
// All interfaces should hold locks, while inner functions do not.
package uprobetracer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kfilefields"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/secureopen"
)

type ProgType uint32

const (
	ProgUprobe ProgType = iota
	ProgUretprobe
	ProgUSDT
)

// inodeKeeper holds a file object, with the counter representing its
// reference count. links is empty only when the file is not attached.
//
// counter and len(links) count different things and must not be conflated:
// counter is how many container PIDs reference this inode, links is how many
// probe sites are bound in it. One binary attached for three containers is
// counter=3 with one set of links, because the uprobe is on the inode and the
// dedup in attachOneOpenFile deliberately attaches only once. Decrementing the
// refcount therefore never closes an individual link -- links are closed all at
// once, when the last reference goes away.
type inodeKeeper struct {
	counter int
	file    *os.File
	links   []link.Link
}

// close releases every link and the file, returning the number of links closed
// so the caller can account for them. It is idempotent in the sense that it
// clears links after closing, so a double call cannot double-close.
func (t *inodeKeeper) close() int {
	// Counts what it releases, not what it dereferences: a nil entry is
	// released trivially and still has to balance the attach-side count.
	// Production never stores a nil link -- attachUprobe returns early on any
	// bind error -- so there the two readings coincide; test doubles cannot
	// build a real link.Link (its isLink method is unexported) and store nil.
	released := len(t.links)
	for _, l := range t.links {
		if l != nil {
			l.Close()
		}
	}
	// Clearing is what makes a second call a no-op rather than a double-close.
	t.links = nil
	t.file.Close()
	return released
}

type Tracer[Event any] struct {
	progName       string
	progType       ProgType
	attachFilePath string
	attachSymbol   string
	prog           *ebpf.Program

	// keeps the inodes for each attached container
	// when users write library names in ebpf section names, it's possible to
	// find multiple libraries of different archs within the same container,
	// making this a one-to-many mapping
	containerPid2Inodes map[uint32][]uint64
	// keeps the fd and refCount for each realInodePtr
	//
	// we are using `realInodePtr` (the address of real inode in kernel) to identify a file
	// instead of just the inode number.
	// Since overlayFS overwrites the FsID of files and provides its own inode implementation,
	// we cannot uniquely identify a file on disk using `<FsID, inode>` pairs.
	//
	// Meanwhile, uprobe is using kernel function `d_real_inode` to get the underlying inode,
	// and attaching onto it. That means if we are attaching to one container, other containers
	// sharing the same image will also be attached. If we are attaching to multiple containers,
	// the underlying inode might be attached multiple times, leading to duplicate records.
	//
	// To deduplicate, we need to identify the underlying inode hidden by overlayFS,
	// and use it as a unique identifier. For each realInodePtr, we only attach to it once.
	inodeRefCount map[uint64]*inodeKeeper
	// used as a set, keeps PIDs of the pending containers
	pendingContainerPids map[uint32]bool

	// keeps the OCI runtime config (verbatim config.json) per attached/pending
	// container PID, recorded at AttachContainer. Used to resolve a container's
	// intended executable (process.args[0]) when a targeted library is statically
	// linked into the binary rather than present as a shared object — see
	// searchForLibrary. Kept here so the pending-attach path (which only has PIDs)
	// can still resolve the executable once the program loads.
	containerPid2OciConfig map[uint32]string

	// containerPidSettled mirrors containercollection.Container.SettledAtDiscovery()
	// for each attached/pending container PID, recorded at AttachContainer. True
	// means the container was already running (its process had already execve'd)
	// when it was discovered, so /proc/<pid>/exe is the settled target executable
	// rather than the runtime shim -- the same distinction ReattachContainerPid
	// already exploits for exec-driven re-attach, here applied at the FIRST
	// attach instead of waiting for an exec event that, for a container
	// discovered post-exec, will never come. See attachSettled and
	// attachContainerWork.
	containerPidSettled map[uint32]bool

	// keeps the last /proc/<pid>/exe symlink target re-resolved for each PID by
	// ReattachContainerPid. Used as a cheap guard so an exec storm that does not
	// change the settled executable short-circuits before the open/inode work.
	containerPid2ExeTarget map[uint32]string

	// mappedLibAttached marks the PIDs for which reattachMappedLibraries has
	// credited at least one inode via the map_files path. It is the stop signal
	// for the Phase-3 self-sustaining retry loop (HasMappedLibForPid): once a pid
	// is in this set the timer can deregister it. Cleared in DetachContainer.
	mappedLibAttached map[uint32]bool

	logger logger.Logger

	// seams over the impure operations, so the refcount/attach bookkeeping can be
	// unit-tested without a kernel or live containers. They default to the real
	// implementations in NewTracer and are only overridden in tests.
	openInContainer func(ctx context.Context, containerPid uint32, filePath string) (*os.File, error)
	readRealInode   func(fd int) (uint64, error)
	// attachToFile attaches to an already-open candidate, returning one link per
	// bound probe site. offsets are the file offsets resolved during the
	// lock-free open phase, or empty to attach by symbol name.
	attachToFile func(file *os.File, offsets []uint64) ([]link.Link, error)
	// openMapFileFunc is the seam for opening a /proc/<pid>/map_files/<range>
	// entry. Its signature matches openMapFile in mapfiles.go. Tests inject a
	// mock to exercise reattachMappedLibraries bookkeeping without /proc access.
	openMapFileFunc func(containerPid uint32, rangeKey string, expectedMntns uint64) (*os.File, error)

	// attachOffsetsResolver, when registered (SetAttachOffsetResolver or
	// SetAttachOffsetsResolver), maps an open candidate to the file offsets for
	// attachSymbol, for stripped targets that export no symbol to attach by
	// name. Consulted ONLY from the lock-free open phase; see
	// resolveAttachOffsets. Write-once before any container is attached.
	attachOffsetsResolver AttachOffsetsResolver

	// muHold records how long commitOpenedTargets spends holding t.mu.
	//
	// This lock serializes the create-time attach that gates runc's create→start,
	// so its tail hold time is the quantity that decides whether an exec storm
	// stalls container starts on the node. It is recorded rather than merely
	// logged on breach because "did we stay inside budget" is not answerable from
	// breach logs alone -- those only appear once the damage is done.
	muHold histogram.Recorder

	// resolverFailOpen counts how many times a registered resolver declined a
	// candidate (error or no offsets) and the tracer fell back to symbol-name
	// attach. Non-zero is normal -- the resolver is consulted for every candidate
	// including ones it has no opinion on -- but a rate that tracks total attach
	// attempts means the resolver is effectively not working.
	resolverFailOpen atomic.Uint64

	// attachRollbacks counts multi-offset attaches abandoned partway: some
	// offsets bound, a later one failed, and the ones already bound were closed
	// again. Non-zero means a binary resolved offsets that could not all be
	// bound, which leaves that target uninstrumented rather than half-probed.
	attachRollbacks atomic.Uint64

	// linksAttached and linksClosed count every link this tracer has created and
	// released. They exist to make the invariant that this rework turns on --
	// every link created is eventually closed exactly once -- checkable rather
	// than assumed, both in tests and on a running agent. link.Link cannot be
	// implemented outside cilium/ebpf, so counting at the two sites that create
	// and destroy links is the only way to observe the lifecycle at all.
	linksAttached atomic.Uint64
	linksClosed   atomic.Uint64

	// linksRolledBack counts links bound and then immediately released because a
	// later offset in the same set failed to bind. They never reach an
	// inodeKeeper, so they are counted separately rather than muddling the
	// attached/closed pair whose equality is the leak check.
	linksRolledBack atomic.Uint64

	// createTimeAttachUnresolved counts create-time attaches via the
	// AttachProg pending-drain that bypassed the resolver entirely; see
	// attachOneFile. Since AttachProg now routes unsettled+resolver-backed
	// pids through attachContainerWork instead (see AttachProg's own
	// comment), this only increments for gadgets with NO resolver
	// registered -- it no longer signals lost resolver-backed coverage the
	// way it did before that fix. Retained (not removed) because
	// attachOneFile is still directly exercised by non-resolver gadgets
	// (e.g. SSL/P1) via this same pending-drain path.
	createTimeAttachUnresolved atomic.Uint64

	// Create-time attach (AttachContainer) is dispatched to bounded background
	// goroutines so it NEVER runs on the synchronous container-start (fanotify
	// FAN_ACCESS_PERM) path: the AddContainer callback that AttachContainer serves
	// is awaited before runc's create→start is unblocked, so a slow attach there
	// (e.g. ELF parse of a large statically-linked binary, or setns) wedges
	// container starts under a pod burst. attachSem caps how many of those attaches
	// run concurrently; attachWg lets Close join the in-flight ones. It defaults to
	// the process-wide globalAttachSem -- see maxConcurrentAttaches for why the
	// budget cannot be per-tracer -- and SetAttachSemaphore replaces it.
	attachSem chan struct{}
	attachWg  sync.WaitGroup
	// syncAttach makes AttachContainer run the attach INLINE instead of dispatching
	// it. Off in production; unit tests set it so create-time bookkeeping is
	// observable synchronously.
	syncAttach bool

	closed bool
	mu     sync.Mutex
}

// maxConcurrentAttaches caps concurrent background create-time attaches.
//
// The binding constraint is the MEMORY a slot holds, not its setns/syscall
// cost. A slot that reaches a registered AttachOffsetsResolver parses the
// target's full Go symbol table (gosym.NewTable over .gopclntab), which for the
// 100-150 MB statically-linked binaries that are routine in real images costs
// 60-115 MB of live heap for the duration of that one parse. Eight slots is a
// ~1 GB transient working set; on a node whose every already-running container
// reaches the settled-attach path at startup that is the OOM, not a spike.
const maxConcurrentAttaches = 2

// attachIOTimeout bounds ONE resolve+open I/O phase -- the ld.so.cache read
// plus every candidate's mount-namespace switch and openat2 -- for a single
// container attach or exec-driven re-attach.
//
// It does not, and cannot, reclaim the goroutine/OS thread a wedged setns/
// openat2 is blocked in (see secureopen.OpenInContainer); what it bounds is
// how long the CALLER'S gate stays held by one stuck target:
//   - attachContainerWork's caller holds an attachSem slot (2 process-wide) for
//     the duration -- past this bound, a single wedged container would
//     otherwise starve every other container's create-time attach behind the
//     same 2 slots forever (confirmed on a real cluster: 15 goroutines queued
//     318-526 minutes behind exactly this).
//   - ReattachContainerPid's caller runs inside the per-subscriber goroutine
//     that containercollection's pubsub.Publish spawns for the EventTypeExec-
//     Container notification, and Publish blocks synchronously in wg.Wait()
//     until that goroutine returns -- which in turn is called from the
//     SINGLE goroutine draining the kernel exec-events ringbuf
//     (watchExecEvents). Past this bound, one wedged exec-driven reattach
//     does not just leak a goroutine, it permanently stops the ringbuf from
//     ever being drained again, silently disabling exec-driven re-attach for
//     every container on the node from that moment on.
//
// Picked generously above any legitimate mount-namespace switch plus a small
// ld.so.cache read (normally sub-millisecond) so it only fires on a genuine
// kernel-level wedge, not ordinary contention. See armosec/private-node-agent#480.
//
// A var, not a const, solely so tests can shrink it around a simulated stuck
// open instead of a real multi-second sleep.
var attachIOTimeout = 15 * time.Second

// globalAttachSem is the default attach semaphore, shared PROCESS-WIDE by every
// Tracer built by NewTracer.
//
// Per-tracer semaphores do not bound anything useful here: one gadget creates
// one Tracer per uprobe program (four for gotls), each of which independently
// resolves the SAME binaries for the SAME containers, so a per-tracer cap of N
// is really a cap of N x programs x gadgets concurrent full-binary parses. The
// memory the cap exists to bound is a property of the process, so the budget is
// held by the process. SetAttachSemaphore overrides it for tests and for
// embedders that want a separate budget.
var globalAttachSem = make(chan struct{}, maxConcurrentAttaches)

// attachJob is the immutable snapshot a background create-time attach needs,
// captured under t.mu at dispatch so the worker reads no write-once tracer fields
// off-lock (race-free).
type attachJob struct {
	pid            uint32
	attachFilePath string
	attachSymbol   string
	progName       string
	ociConfig      string
	settled        bool
}

func NewTracer[Event any](logger logger.Logger) (*Tracer[Event], error) {
	t := &Tracer[Event]{
		containerPid2Inodes:    make(map[uint32][]uint64),
		inodeRefCount:          make(map[uint64]*inodeKeeper),
		pendingContainerPids:   make(map[uint32]bool),
		containerPid2OciConfig: make(map[uint32]string),
		containerPidSettled:    make(map[uint32]bool),
		containerPid2ExeTarget: make(map[uint32]string),
		mappedLibAttached:      make(map[uint32]bool),
		openInContainer:        secureopen.OpenInContainer,
		readRealInode:          kfilefields.ReadRealInodeFromFd,
		openMapFileFunc:        openMapFile,
		attachSem:              globalAttachSem,
		logger:                 logger,
		closed:                 false,
	}
	t.attachToFile = t.attachUprobe
	return t, nil
}

// SetAttachSemaphore replaces the process-wide attach budget this tracer draws
// from with sem. Call it before any container is attached; a nil sem is ignored
// so a caller cannot accidentally uncap the budget.
//
// Sharing one sem across a set of tracers makes that set share one budget; the
// default already shares one across the whole process (see globalAttachSem), so
// this exists for tests that need a deterministic cap of their own and for
// embedders isolating one gadget's attaches from another's.
func (t *Tracer[Event]) SetAttachSemaphore(sem chan struct{}) {
	if sem == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.attachSem = sem
}

// dedupPaths drops repeated attach candidates, keeping the first occurrence of
// each distinct cleaned path.
//
// The settled-attach path offers /proc/<pid>/exe first and the create-time
// resolution second, and for a statically-linked container those are USUALLY
// the same file: the OCI process.args[0] fallback names exactly the binary the
// entrypoint went on to exec. They are not always the same (a re-exec'd
// entrypoint genuinely differs), so this dedups rather than dropping one
// unconditionally. Left in, the duplicate is opened twice and -- far more
// expensively -- handed to the AttachOffsetsResolver twice, doubling the peak
// heap of the one operation the attach budget exists to bound.
func dedupPaths(paths []string) []string {
	if len(paths) < 2 {
		return paths
	}
	seen := make(map[string]bool, len(paths))
	out := paths[:0:0]
	for _, p := range paths {
		key := filepath.Clean(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// AttachProg loads the ebpf program, and try attaching if there are pending containers
func (t *Tracer[Event]) AttachProg(progName string, progType ProgType, attachTo string, prog *ebpf.Program) error {
	if progType != ProgUprobe && progType != ProgUretprobe && progType != ProgUSDT {
		return fmt.Errorf("unsupported uprobe prog type: %q", progType)
	}

	if prog == nil {
		return errors.New("prog does not exist")
	}
	if t.prog != nil {
		return errors.New("loading uprobe program twice")
	}

	parts := strings.SplitN(attachTo, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid section name %q", attachTo)
	}
	if !filepath.IsAbs(parts[0]) && strings.Contains(parts[0], "/") {
		return fmt.Errorf("section name must be either an absolute path or a library name: %q", parts[0])
	}
	if progType == ProgUSDT && len(strings.Split(parts[1], ":")) != 2 {
		return fmt.Errorf("invalid USDT section name: %q", attachTo)
	}

	t.mu.Lock()

	if t.closed {
		t.mu.Unlock()
		return errors.New("uprobetracer has been closed")
	}

	t.progName = progName
	t.progType = progType
	t.attachFilePath = parts[0]
	t.attachSymbol = parts[1]
	t.prog = prog

	// Attach to pending containers, then release the pending list.
	//
	// Settled containers (see Container.SettledAtDiscovery) are dispatched
	// through the SAME bounded async job mechanism as a normal create-time
	// attach (attachContainerWork, gated by attachSem) rather than run
	// synchronously in this loop, which is still holding t.mu at this point.
	// A settled attach does real work an unsettled one never did here -- an
	// ELF parse and, for a resolver-backed gadget, a full offset resolution
	// -- and on a long-running node EVERY already-running container reaches
	// this loop as settled. Left synchronous and unbounded, that is an
	// uncapped-concurrency burst sized to the node's ENTIRE container count
	// at once: confirmed on a real cluster to OOM node-agent on smaller
	// instance types within the first minute of startup. Unsettled
	// containers with NO resolver registered (e.g. SSL/P1) keep the
	// original synchronous path (attach/attachOneFile); unsettled
	// containers WITH a resolver registered (e.g. gotls) now also route
	// through the bounded async job dispatch below, since attach()
	// deliberately never consults a registered resolver -- see
	// attachOneFile's own doc comment for why.
	//
	// syncJobs defers the syncAttach (test-only) inline calls until AFTER
	// t.mu is released below -- attachContainerWork takes t.mu itself for its
	// commit phase, and that lock is not reentrant, so calling it inline
	// while still holding the lock here deadlocks. This mirrors
	// AttachContainer's own runInline branch, which unlocks before calling
	// attachContainerWork inline for the identical reason.
	var syncJobs []attachJob
	sem := t.attachSem
	for pid := range t.pendingContainerPids {
		// Resolver-backed gadgets (e.g. gotls) skip the cheap unsettled fast
		// path here: attach() bypasses t.attachOffsetsResolver by design
		// (see attachOneFile's doc comment), so an unsettled+resolver-backed
		// pid would otherwise never get a resolver-backed attach attempt at
		// all until a later exec-driven reattach. Route it through the same
		// bounded async job dispatch settled pids already use instead, with
		// settled explicitly carried as t.containerPidSettled[pid] (false in
		// this branch) -- NOT hardcoded true, which would let
		// attachContainerWork consult /proc/<pid>/exe for a pid that may
		// still be the pre-execve runc shim (see settledAtDiscovery's doc
		// comment in pkg/container-collection/containers.go for why that's
		// safety-critical). Non-resolver gadgets (SSL/P1) are unaffected --
		// they keep the fast synchronous path unchanged.
		if !t.containerPidSettled[pid] && t.attachOffsetsResolver == nil {
			t.attach(pid)
			continue
		}
		job := attachJob{
			pid:            pid,
			attachFilePath: t.attachFilePath,
			attachSymbol:   t.attachSymbol,
			progName:       t.progName,
			ociConfig:      t.containerPid2OciConfig[pid],
			settled:        t.containerPidSettled[pid],
		}
		// Reserve as tracked before dispatch, mirroring AttachContainer: a
		// concurrent Reattach/Detach must see this pid immediately, not only
		// once its (possibly still-queued) job runs.
		t.containerPid2Inodes[pid] = nil
		if t.syncAttach {
			syncJobs = append(syncJobs, job)
			continue
		}
		t.attachWg.Add(1)
		go func() {
			defer t.attachWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t.attachContainerWork(job)
		}()
	}
	t.pendingContainerPids = nil

	t.mu.Unlock()

	for _, job := range syncJobs {
		t.attachContainerWork(job)
	}

	return nil
}

// searchForLibrary resolves the attach target paths using the tracer's recorded
// state. Caller holds t.mu (it reads containerPid2OciConfig). The lock-free hot
// paths call resolveLibraryPaths directly with snapshotted inputs instead.
func (t *Tracer[Event]) searchForLibrary(ctx context.Context, containerPid uint32) ([]string, error) {
	return t.resolveLibraryPaths(ctx, containerPid, t.attachFilePath, t.containerPid2OciConfig[containerPid])
}

// resolveLibraryPaths resolves the in-container paths to open for the uprobe
// target from SNAPSHOTTED inputs (attachFilePath and the container's verbatim OCI
// config), reading no shared tracer state, so it can run WITHOUT holding t.mu.
// The ld.so.cache parse it performs is I/O that must not be done under the lock
// (an exec storm holding t.mu across this work starves the create-time
// AttachContainer that sits on the synchronous container-start path).
func (t *Tracer[Event]) resolveLibraryPaths(ctx context.Context, containerPid uint32, attachFilePath, ociConfig string) ([]string, error) {
	if filepath.IsAbs(attachFilePath) {
		return []string{attachFilePath}, nil
	}

	ldCachePath := "/etc/ld.so.cache"
	ldCachePaths, err := parseLdCache(ctx, containerPid, ldCachePath, attachFilePath)
	// A missing ld.so.cache is not a parse failure to report, it is the expected
	// state of any container with no glibc at all -- which is precisely the
	// "statically-linked runtime" case the OCI-config fallback below exists to
	// handle. Before this guard, that fallback was unreachable in the exact case
	// it was built for: a scratch/distroless Go binary has no /etc/ld.so.cache,
	// parseLdCache's os.ErrNotExist was treated the same as a real parse/I-O
	// failure, and the function returned early with every uprobe gadget on that
	// container (SSL and gotls alike) finding nothing to attach to and no error
	// surfaced anywhere above this call. Any OTHER error here (malformed cache,
	// permission denial, an I/O failure mid-read) still aborts: those describe a
	// real problem worth surfacing, not an absent file.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("parsing ld cache: %w", err)
	}
	if len(ldCachePaths) > 0 {
		return ldCachePaths, nil
	}

	// The requested library is not a shared object in this container's ld cache
	// (or the container has no ld cache at all -- see above). This is the common
	// case for statically-linked runtimes that embed the library into their main
	// executable (Node.js, and Go/Rust binaries that statically link
	// OpenSSL/BoringSSL, or Go's own crypto/tls), where a `libssl`- or
	// probe-ID-targeted uprobe gadget would otherwise find nothing to attach to.
	// Fall back to the container's intended executable: the symbol may be defined
	// there.
	//
	// The executable is resolved from the OCI runtime config (process.args[0]),
	// NOT from /proc/<pid>/exe: at container-create time (when AttachContainer
	// fires) the PID still points at the runtime shim, because runc execve's into
	// the entrypoint in-place slightly later and a uprobe binds an inode without
	// following execve. The OCI-spec value is the in-rootfs path of the settled
	// binary, opened via the same OpenInContainer mechanism as a shared library —
	// so ReadRealInodeFromFd dedup and per-image attach-once are preserved, and
	// attachUprobe skips (logged) any executable that does not export the symbol.
	exePath, ok := t.executableFromOCIConfig(containerPid, ociConfig)
	if !ok {
		return nil, nil
	}
	return []string{exePath}, nil
}

// settledExecutablePath returns the in-container absolute path of the binary the
// container's process is currently running, read from /proc/<pid>/exe. At exec
// time this is the settled executable (e.g. /usr/local/bin/node), which is the
// attach target for statically-linked runtimes whose TLS symbol lives in the
// main binary rather than a shared library. The /proc/<pid>/exe symlink resolves
// in the process's own mount namespace, so the path is directly usable with
// secureopen.OpenInContainer.
func (t *Tracer[Event]) settledExecutablePath(containerPid uint32) (string, bool) {
	exeLink := filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "exe")
	target, err := os.Readlink(exeLink)
	if err != nil {
		return "", false
	}
	// A binary replaced or removed after exec shows up as "<path> (deleted)".
	target = strings.TrimSuffix(target, " (deleted)")
	if !filepath.IsAbs(target) {
		return "", false
	}
	return target, true
}

// containerExecutableFromOCI resolves a container's intended executable to its
// in-container absolute path from the OCI config recorded at AttachContainer
// (process.args[0]). First cut: only absolute argv[0] is supported (covers
// Node.js and most images, whose runtime resolves the image Entrypoint/Cmd to an
// absolute path); a relative argv[0] resolved against PATH is a follow-up.
func (t *Tracer[Event]) containerExecutableFromOCI(containerPid uint32) (string, bool) {
	return t.executableFromOCIConfig(containerPid, t.containerPid2OciConfig[containerPid])
}

// executableFromOCIConfig is the snapshot-based core of containerExecutableFromOCI:
// it takes the container's verbatim OCI config as a parameter instead of reading
// containerPid2OciConfig, so it can run WITHOUT holding t.mu.
func (t *Tracer[Event]) executableFromOCIConfig(containerPid uint32, ociConfig string) (string, bool) {
	if ociConfig == "" {
		return "", false
	}
	args, err := containercollection.OCIConfigGetProcessArgs(ociConfig)
	if err != nil || len(args) == 0 {
		t.logger.Debugf("uprobetracer: container %d: cannot read process args from OCI config: %v", containerPid, err)
		return "", false
	}
	exe := args[0]
	if !filepath.IsAbs(exe) {
		t.logger.Debugf("uprobetracer: container %d: entrypoint %q is not absolute; PATH resolution not yet supported", containerPid, exe)
		return "", false
	}
	t.logger.Debugf("uprobetracer: %q not in ld cache for container %d; attaching to executable %q from OCI spec", t.attachFilePath, containerPid, exe)
	return exe, true
}

// attachUprobe attaches the uprobe program to the inode of the file passed in.
//
// +x gate mitigation (spike note finding): cilium link.OpenExecutable gates on
// info.Mode()&0111 != 0 ("file is not executable"). netty-tcnative extracts its
// .so at mode 0600 (no execute bit), so the normal path rejects it. The Linux
// kernel's uprobe PMU does NOT require the execute bit — bpftrace attaches fine
// without it (proven on the Phase-0 droplet). When the file lacks any execute
// bit, we add +x via unix.Fchmod on the already-open fd (mutates the
// deleted-inode safely; no path, no container-visible change), call
// OpenExecutable, then RESTORE the original mode. This is flagged for architect
// review; the alternative (a cilium fork without the userspace mode gate) avoids
// the mutation entirely but requires a larger diff.
//
// offset, when non-nil, is a file offset resolved during the lock-free open
// phase; the uprobe is then bound there instead of by symbol lookup. No ELF or
// pread work happens here — the caller holds t.mu.
func (t *Tracer[Event]) attachUprobe(file *os.File, offsets []uint64) ([]link.Link, error) {
	// Detect and temporarily add the execute bit if the file lacks it.
	fi, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat before attach: %w", err)
	}
	origMode := fi.Mode().Perm()
	needsExecFix := origMode&0o111 == 0
	if needsExecFix {
		if err := unix.Fchmod(int(file.Fd()), uint32(origMode)|0o111); err != nil {
			return nil, fmt.Errorf("fchmod +x on map_files fd (cilium mode gate): %w", err)
		}
		// Restore original mode after we are done with OpenExecutable, whether
		// or not the attach itself succeeds. Accepted: between the two fchmods the
		// (deleted, container-private) inode transiently carries +x — a sub-ms
		// window with no filesystem path, so it cannot be exec'd by name.
		defer func() {
			if err := unix.Fchmod(int(file.Fd()), uint32(origMode)); err != nil {
				t.logger.Debugf("uprobetracer: fchmod restore after attach: %v", err)
			}
		}()
	}

	attachPath := path.Join(host.HostProcFs, "self/fd/", fmt.Sprint(file.Fd()))
	ex, err := link.OpenExecutable(attachPath)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", attachPath, err)
	}

	// USDT takes its attach address from the note section, so a resolver's
	// offsets do not apply to it and it is always a single probe.
	//
	// KNOWN GAP (accepted, review-noted): this branch sits below the attachToFile
	// test seam and so is not covered -- a mutant returning a nil slice here
	// survives. Hoisting it the way bindSites was would need the USDT metadata
	// read parameterised too, which is not worth it for a single-probe path no
	// gadget in play uses. Revisit if a USDT gadget ships.
	if t.progType == ProgUSDT {
		attachInfo, err := getUsdtInfo(attachPath, t.attachSymbol)
		if err != nil {
			return nil, fmt.Errorf("reading USDT metadata: %w", err)
		}
		l, err := ex.Uprobe(t.attachSymbol, t.prog,
			&link.UprobeOptions{
				Address:      attachInfo.attachAddress,
				RefCtrOffset: attachInfo.semaphoreAddress,
			})
		if err != nil {
			return nil, err
		}
		return []link.Link{l}, nil
	}

	return t.bindSites(offsets, func(offset *uint64) (link.Link, error) {
		return t.bindProbe(ex, offset)
	})
}

// bindSites turns a resolved offset set into bound probes: one probe bound by
// symbol name when there are no offsets, otherwise one per offset, all or none.
//
// The empty case is the path every gadget that does not use offset attach takes
// -- ssl included -- so its single-element result is load-bearing rather than a
// formality. Returning a nil slice there would still bind the probe in the
// kernel, but nothing would hold the link, and the runtime finalizer would close
// it moments later: the probe detaches on its own with no error anywhere. The
// link counters would not catch it either, since an empty slice balances
// against itself on teardown.
//
// It takes bind as a parameter for the same reason bindAll does: everything
// below attachToFile is replaced wholesale by the test seam, so a branch that
// is not hoisted above it cannot be tested without a kernel. (Found in review;
// the empty-offsets branch previously sat below the seam and no test reached it.)
func (t *Tracer[Event]) bindSites(offsets []uint64, bind func(offset *uint64) (link.Link, error)) ([]link.Link, error) {
	if len(offsets) == 0 {
		l, err := bind(nil)
		if err != nil {
			return nil, err
		}
		return []link.Link{l}, nil
	}
	return t.bindAll(offsets, bind)
}

// bindAll binds every offset or none.
//
// A partially bound program is worse than an unbound one: for the Go crypto/tls
// read capture, binding the entry probe but not every return produces a stream
// of started-but-never-completed reads, which reads as data rather than as
// breakage. So a failure at any offset undoes the ones already bound and
// reports the error, leaving the caller to take no reference and skip the
// target entirely.
//
// bind is a parameter rather than called directly so this loop -- the one piece
// of the multi-link path that cannot be reached through the attachToFile test
// seam, since that seam replaces the whole binder -- is unit-testable.
func (t *Tracer[Event]) bindAll(offsets []uint64, bind func(offset *uint64) (link.Link, error)) ([]link.Link, error) {
	links := make([]link.Link, 0, len(offsets))
	for idx := range offsets {
		l, err := bind(&offsets[idx])
		if err != nil {
			for _, bound := range links {
				if bound != nil {
					bound.Close()
				}
			}
			t.linksRolledBack.Add(uint64(len(links)))
			t.attachRollbacks.Add(1)
			return nil, fmt.Errorf("binding offset %#x (%d of %d), rolled back %d already bound: %w",
				offsets[idx], idx+1, len(offsets), len(links), err)
		}
		links = append(links, l)
	}
	return links, nil
}

// bindProbe binds one probe, at a file offset when given or by symbol name when
// not.
func (t *Tracer[Event]) bindProbe(ex *link.Executable, offset *uint64) (link.Link, error) {
	switch t.progType {
	case ProgUprobe:
		return ex.Uprobe(t.attachSymbol, t.prog, uprobeOffsetOptions(offset))
	case ProgUretprobe:
		return ex.Uretprobe(t.attachSymbol, t.prog, uprobeOffsetOptions(offset))
	default:
		return nil, fmt.Errorf("attaching to inode: unsupported prog type: %q", t.progType)
	}
}

// attachOneOpenFile is the post-open core of the attach path: given an
// already-open file (opened by either openInContainer or openMapFile), it
// resolves the real inode, deduplicates via existing/inodeRefCount, and attaches
// the uprobe. It is the single implementation of the
//
//	readRealInode → existing/inodeRefCount check → attachToFile → containerPid2Inodes[pid] append
//
// discipline for BOTH the path-based (P1.5/P2a) and map_files-based (P2b) flows,
// satisfying Principle 2 (bookkeeping parity). Caller holds t.mu.
//
// Returns (realInodePtr, added, error):
//   - added=true: the inode was newly credited to THIS pid's set (either a fresh
//     attach or a refcount bump from another pid's already-existing attach).
//   - added=false + err=nil: the inode was already in `existing` (idempotent
//     no-op) or attachToFile failed with symbol-absent (non-fatal skip, no ref).
//   - err != nil: a hard failure (inode read failed); caller logs and skips.
func (t *Tracer[Event]) attachOneOpenFile(containerPid uint32, file *os.File, label string, offsets []uint64, existing map[uint64]bool) (uint64, bool, error) {
	realInodePtr, err := t.readRealInode(int(file.Fd()))
	if err != nil {
		file.Close()
		return 0, false, fmt.Errorf("getting inode info for %q: %w", label, err)
	}

	// Already counted for THIS pid: nothing to do.
	if existing[realInodePtr] {
		file.Close()
		return realInodePtr, false, nil
	}

	if keeper, exists := t.inodeRefCount[realInodePtr]; exists {
		// Already attached for another pid (or another path of this pid):
		// only bump the shared refcount.
		keeper.counter++
		file.Close()
		t.logger.Debugf("uprobe %q already attached for inode of %q; bumped refcount for container %d", t.progName, label, containerPid)
		return realInodePtr, true, nil
	}

	progLinks, err := t.attachToFile(file, offsets)
	if err != nil {
		// The target exists but does not export the symbol (e.g. runc, a wrapper
		// executable, or BoringSSL which omits SSL_read_ex/SSL_write_ex), or a
		// multi-offset attach was rolled back. Either way nothing is bound: skip
		// without taking a reference so DetachContainer stays balanced.
		file.Close()
		t.logger.Debugf("not attaching uprobe %q to %q for container %d: %s", t.progName, label, containerPid, err.Error())
		return realInodePtr, false, nil
	}
	t.logger.Debugf("attaching uprobe %q to container %d: %q (%d probe sites)", t.progName, containerPid, label, len(progLinks))
	t.linksAttached.Add(uint64(len(progLinks)))
	t.inodeRefCount[realInodePtr] = &inodeKeeper{counter: 1, file: file, links: progLinks}
	return realInodePtr, true, nil
}

// attachOneFile opens filePath inside the container of containerPid and then
// calls attachOneOpenFile. It is the path-based attach entry point used by the
// P1.5 (dynamic libssl) and P2a (settled-exe) flows; its behaviour is unchanged
// by the Phase-2 refactor — attachOneOpenFile carries the identical bookkeeping.
// Caller holds t.mu.
//
// This path deliberately does NOT consult the AttachOffsetResolver. Its only
// caller today (attach(), via AttachProg's pending-drain) is now itself gated
// to the case where NO resolver is registered — a resolver-backed gadget's
// unsettled pending pids route through attachContainerWork instead (see
// AttachProg's own comment), where a real ELF parse and offset resolution
// does run. For the no-resolver population that still reaches this function,
// the omission remains correct: it already bails before reaching a
// statically-linked target (at create time the library is not in the
// container's ld.so.cache, so nothing resolves).
func (t *Tracer[Event]) attachOneFile(ctx context.Context, containerPid uint32, filePath string, existing map[uint64]bool) (uint64, bool, error) {
	// OpenInContainer returns a fd without O_PATH. This is necessary because
	// ReadRealInodeFromFd needs the private_data field in kernel "struct file"
	// to reach the underlying inode through overlayFS; O_PATH zeroes that field.
	file, err := t.openInContainer(ctx, containerPid, filePath)
	if err != nil {
		return 0, false, fmt.Errorf("opening file %q for uprobe: %w", filePath, err)
	}
	// Counted, not just commented. Post-fix, attach() (this function's sole
	// caller) is only reached when t.attachOffsetsResolver == nil for the
	// unsettled case, so in normal operation this branch should never fire
	// in practice for the AttachProg pending-drain path -- it stays as a
	// defensive counter for any other caller of attachOneFile that might
	// still have a resolver registered (there are none today; retained as
	// a tripwire, not deleted, since it costs nothing and the callers of
	// this function are not sealed against future additions).
	if t.attachOffsetsResolver != nil {
		t.createTimeAttachUnresolved.Add(1)
		t.logger.Debugf("uprobetracer: %q create-time attach to %q for container %d bypassed the offset resolver (count=%d)",
			t.progName, filePath, containerPid, t.createTimeAttachUnresolved.Load())
	}
	return t.attachOneOpenFile(containerPid, file, filePath, nil, existing)
}

// openedTarget is an opened, not-yet-committed attach candidate produced by the
// lock-free resolve+open phase of the hot reattach paths. Whoever holds the
// openedTarget owns its file: commitOpenedTargets consumes it (attachOneOpenFile
// closes it), and closeOpened releases any dropped on bail.
type openedTarget struct {
	file  *os.File
	label string
	// offsets are the file offsets resolved by the AttachOffsetsResolver during
	// the open phase, or empty to attach by symbol name. Carried to the commit
	// phase so no ELF/pread work is needed under t.mu.
	offsets []uint64
}

// openTargets opens each resolved in-container path WITHOUT holding t.mu — the
// secureopen.OpenInContainer call (a mount-namespace switch) is the expensive I/O
// that must stay off the lock, as is the AttachOffsetResolver's ELF parse and
// pread work, which runs here for the same reason. It returns the opened files
// plus whether any open failed, so a caller's retry guard (e.g.
// ReattachContainerPid's exe-target record) can avoid latching a target that was
// not fully attached.
func (t *Tracer[Event]) openTargets(ctx context.Context, containerPid uint32, paths []string) ([]openedTarget, bool) {
	var opened []openedTarget
	openFailed := false
	for _, filePath := range paths {
		// OpenInContainer returns a fd without O_PATH: ReadRealInodeFromFd needs the
		// kernel "struct file" private_data to reach the overlay's real inode.
		file, err := t.openInContainer(ctx, containerPid, filePath)
		if err != nil {
			t.logger.Debugf("opening file %q for uprobe: %v", filePath, err)
			openFailed = true
			continue
		}
		opened = append(opened, openedTarget{file: file, label: filePath, offsets: t.resolveAttachOffsets(file, containerPid)})
	}
	return opened, openFailed
}

// closeOpened releases opened candidates that will not be committed (e.g. the pid
// was detached during the lock-free I/O window). Safe on a nil/empty slice.
func closeOpened(opened []openedTarget) {
	for _, ot := range opened {
		ot.file.Close()
	}
}

// TracerStats is a point-in-time view of the attach path's cost and of the
// offset resolver's effectiveness, for embedders holding the attach path to a
// latency budget.
type TracerStats struct {
	// MuHold describes how long commitOpenedTargets held t.mu. This is the
	// budgeted quantity: t.mu serializes the attach that gates container starts.
	MuHold histogram.Stats
	// ResolverFailOpen counts fall-backs to symbol-name attach after a resolver
	// declined a candidate.
	ResolverFailOpen uint64
	// AttachRollbacks counts multi-offset attaches abandoned partway, with the
	// already-bound offsets closed again.
	AttachRollbacks uint64
	// LinksAttached and LinksClosed track link lifecycle. While a tracer has
	// live attachments LinksAttached exceeds LinksClosed; after Close they must
	// be equal, and any gap is a leaked link.
	LinksAttached uint64
	LinksClosed   uint64
	// LinksRolledBack counts links released by an abandoned multi-offset bind.
	// These never reached a keeper, so they are outside the Attached/Closed
	// balance.
	LinksRolledBack uint64
	// CreateTimeAttachUnresolved counts create-time (pending-drain) attaches
	// via a no-resolver-registered gadget's fast path that bypassed the
	// resolver.
	CreateTimeAttachUnresolved uint64
}

// Stats returns a snapshot. It takes no lock -- deliberately, since a stats read
// that waited on t.mu could not be used to diagnose t.mu being held too long.
func (t *Tracer[Event]) Stats() TracerStats {
	return TracerStats{
		MuHold:                     t.muHold.Stats(),
		ResolverFailOpen:           t.resolverFailOpen.Load(),
		AttachRollbacks:            t.attachRollbacks.Load(),
		LinksAttached:              t.linksAttached.Load(),
		LinksClosed:                t.linksClosed.Load(),
		LinksRolledBack:            t.linksRolledBack.Load(),
		CreateTimeAttachUnresolved: t.createTimeAttachUnresolved.Load(),
	}
}

// commitOpenedTargets attaches each already-open candidate under t.mu, applying the
// standard readRealInode → inodeRefCount dedup → containerPid2Inodes bookkeeping via
// attachOneOpenFile (which consumes/closes every file). Caller holds t.mu and has
// already re-validated that containerPid is still tracked. Returns whether any
// candidate hit a hard attach error (for the caller's retry guard).
func (t *Tracer[Event]) commitOpenedTargets(containerPid uint32, opened []openedTarget) bool {
	defer t.muHold.ObserveSince(time.Now())

	attachedRealInodes := t.containerPid2Inodes[containerPid]
	existing := make(map[uint64]bool, len(attachedRealInodes))
	for _, inode := range attachedRealInodes {
		existing[inode] = true
	}
	attachFailed := false
	for _, ot := range opened {
		realInodePtr, added, err := t.attachOneOpenFile(containerPid, ot.file, ot.label, ot.offsets, existing)
		if err != nil {
			t.logger.Debugf("%s", err.Error())
			attachFailed = true
			continue
		}
		if added {
			existing[realInodePtr] = true
			attachedRealInodes = append(attachedRealInodes, realInodePtr)
		}
	}
	t.containerPid2Inodes[containerPid] = attachedRealInodes
	return attachFailed
}

// try attaching to a container, will update `containerPid2Inodes`.
//
// Callers must not reach this for a settled container (see
// Container.SettledAtDiscovery) — AttachProg's pending-drain loop routes
// those through the bounded async job dispatch (attachContainerWork) instead,
// specifically so a settled attach's extra work (a real ELF parse and, for a
// resolver-backed gadget, full offset resolution) never runs synchronously
// for every already-running container on the node at once. See AttachProg's
// doc comment on that loop for why: run here unbounded, that burst OOM'd
// node-agent on smaller instance types within a minute of startup on a real
// cluster.
func (t *Tracer[Event]) attach(containerPid uint32) {
	ctx, cancel := context.WithTimeout(context.Background(), attachIOTimeout)
	defer cancel()

	unsecuredAttachFilePaths, err := t.searchForLibrary(ctx, containerPid)
	if err != nil {
		t.logger.Debugf("attaching to container %d: %s", containerPid, err.Error())
	}

	if len(unsecuredAttachFilePaths) == 0 {
		t.logger.Debugf("cannot find file to attach in container %d for symbol %q", containerPid, t.attachSymbol)
		// Info-level attach signal (diagnostic): the symbol has no resolvable
		// target in this container — not a shared object in its ld.so.cache and
		// no absolute OCI argv[0] to fall back to. Emitted at info so SSL uprobe
		// attachment can be confirmed from normal (non-debug) logs.
		t.logger.Infof("uprobetracer: %q NOT attached to container pid %d: no attach target for symbol %q (searchForLibrary err: %v)", t.progName, containerPid, t.attachSymbol, err)
		t.containerPid2Inodes[containerPid] = nil
		return
	}

	// Fresh attach: the existing set starts empty, so this is union-from-empty.
	existing := make(map[uint64]bool)
	var attachedRealInodes []uint64
	var lastErr error
	for _, filePath := range unsecuredAttachFilePaths {
		realInodePtr, added, err := t.attachOneFile(ctx, containerPid, filePath, existing)
		if err != nil {
			t.logger.Debugf("%s", err.Error())
			lastErr = err
			continue
		}
		if added {
			existing[realInodePtr] = true
			attachedRealInodes = append(attachedRealInodes, realInodePtr)
		}
	}

	t.containerPid2Inodes[containerPid] = attachedRealInodes

	// Info-level attach signal (diagnostic): one line per (program, container)
	// recording whether the uprobe actually bound. This is the operational signal
	// that distinguishes a silent attach failure (e.g. opening libssl in the
	// container's rootfs failing under a given runtime) from a downstream capture
	// gap — both otherwise present identically as zero events.
	if len(attachedRealInodes) > 0 {
		t.logger.Infof("uprobetracer: attached %q to container pid %d at %v", t.progName, containerPid, unsecuredAttachFilePaths)
	} else {
		t.logger.Infof("uprobetracer: %q NOT attached to container pid %d: resolved %v but bound 0 (symbol absent, or open/link failed: %v)", t.progName, containerPid, unsecuredAttachFilePaths, lastErr)
	}
}

// ReattachContainerPid re-resolves the attach target for a container PID and
// attaches the uprobe to any newly-settled executable. It is a thin wrapper
// over ReattachContainerExecPid for the in-place-exec case, where the process
// that execve'd IS the tracked container pid (see that function's doc comment
// for the general case and for why the two pids can differ).
func (t *Tracer[Event]) ReattachContainerPid(containerPid uint32) error {
	return t.ReattachContainerExecPid(containerPid, containerPid)
}

// ReattachContainerExecPid re-resolves the attach target for a tracked
// container and attaches the uprobe to any newly-settled executable. It is the
// load-bearing addition for statically-linked runtimes (Node.js, and Go/Rust
// binaries that embed OpenSSL/BoringSSL): at container-create time
// /proc/<pid>/exe still points at the runtime shim (runc), so the create-time
// attach binds the wrong inode. Calling this after a process inside the
// container has execve'd into its final binary re-resolves the executable and
// attaches to the settled inode.
//
// containerPid is the container's ORIGINAL tracked pid, as recorded by
// AttachContainer — this is what all bookkeeping (containerPid2Inodes,
// containerPid2ExeTarget, ...) stays keyed to, and it is also whose mount
// namespace resolveLibraryPaths/openTargets use to open the settled
// executable. execPid is the pid that ACTUALLY execve'd, per
// PubSubEvent.ExecPid: for an in-place wrapper exec (e.g. node:20-slim's
// docker-entrypoint.sh execve'ing into node) these are the same pid, but for a
// container's tracked process forking a child that then execve's (e.g. a
// `while true; do <bin>; done` wrapper loop) they differ — containerPid's own
// /proc/<pid>/exe never changes in that case (it still names the long-lived
// wrapper), so only /proc/<execPid>/exe can ever reveal the settled binary.
//
// execPid is used ONLY to read /proc/<execPid>/exe (a single, fast procfs
// readlink) — never to open files or hold any reference — so it is fine for
// execPid to be short-lived and to have already exited by the time this
// returns; it need only still exist at the moment the readlink runs. This
// deliberately creates NO new per-execPid bookkeeping entry: a forked child's
// exec is credited entirely to containerPid, exactly as if containerPid's own
// process had settled into that binary, which keeps DetachContainer's existing
// decrement-once-per-inode cleanup correct with no separate "pid exited"
// signal needed for the forked child (it shares containerPid's mount
// namespace via fork, which is why opening the resolved path through
// containerPid still resolves the same file the forked child sees).
//
// It is idempotent and safe to call repeatedly:
//   - an inode already counted for containerPid is a no-op;
//   - an inode already counted for another pid only bumps the shared refcount;
//   - a containerPid that AttachContainer never recorded (or that
//     DetachContainer has already cleaned up) is a no-op — fresh-attaching
//     would install a uprobe link with no DetachContainer to ever release it.
//
// containerPid2Inodes[containerPid] is treated as a SET — each (pid, realInode)
// holds exactly one reference — so DetachContainer's decrement-once-per-inode
// logic stays correct across the create-time attach plus N re-attaches, no
// matter how many distinct execPids fed into them.
func (t *Tracer[Event]) ReattachContainerExecPid(containerPid, execPid uint32) error {
	// Phase 0 (lock): cheap guards + snapshot the inputs the lock-free resolve
	// needs. The heavy resolve/open I/O below MUST NOT run under t.mu: an exec
	// storm holding the lock across it starves the create-time AttachContainer
	// that sits on the synchronous container-start (fanotify) path and wedges
	// container starts.
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("uprobetracer has been closed")
	}
	if t.prog == nil {
		// Pending mode: AttachContainer recorded the pid; the create-time attach
		// path will run searchForLibrary once AttachProg loads the program.
		t.mu.Unlock()
		return nil
	}
	// Tracked-pid guard: AttachContainer keys every live container's init pid in
	// containerPid2Inodes (even with an empty inode slice when the create-time
	// attach found no symbol). A Reattach for a pid not in the map means either
	// DetachContainer has already cleaned up — the exec event raced teardown —
	// or the pid was never an AttachContainer target. Either way, fresh-attaching
	// here would install a uprobe link with no DetachContainer to ever release it.
	if _, tracked := t.containerPid2Inodes[containerPid]; !tracked {
		t.mu.Unlock()
		return nil
	}
	attachFilePath := t.attachFilePath
	ociConfig := t.containerPid2OciConfig[containerPid]
	lastExeTarget, haveLastExeTarget := t.containerPid2ExeTarget[containerPid]
	t.mu.Unlock()

	// Phase 1 (NO lock): resolve + open the I/O-heavy attach targets.
	//
	// exe-inode-change guard: if /proc/<execPid>/exe still points at the target
	// we last *successfully* re-attached for this container, there is nothing
	// new to attach. Comparing by resolved PATH (not by pid) is what makes this
	// work across repeated fork+exec of the same binary — execPid is a fresh
	// pid every loop iteration, but the path it resolves to is unchanged. The
	// target is recorded only after a clean pass below, so a transient failure
	// (e.g. racing an overlayfs mount) is retried on the next exec instead of
	// being permanently short-circuited.
	exeLink := filepath.Join(host.HostProcFs, fmt.Sprint(execPid), "exe")
	exeTarget, _ := os.Readlink(exeLink)
	if exeTarget != "" && haveLastExeTarget && lastExeTarget == exeTarget {
		return nil
	}

	// This call is reached from the single goroutine that drains the kernel
	// exec-events ringbuf (via a synchronous PubSub.Publish that blocks on it) --
	// see attachIOTimeout's doc comment. Bounding it here is what keeps one
	// wedged setns/openat2 from permanently stopping exec-driven re-attach for
	// every container on the node.
	ctx, cancel := context.WithTimeout(context.Background(), attachIOTimeout)
	defer cancel()

	// At exec time the settled binary is /proc/<execPid>/exe: for
	// statically-linked runtimes the target symbol lives there, not in a shared
	// library. Resolve it first, then fall back to the normal create-time
	// resolution (absolute path, ld cache, or OCI process.args[0]) so
	// dynamic-libssl containers keep working. The library-path fallback and the
	// open below both use containerPid, not execPid: they need a pid whose
	// mount namespace stays valid for the duration of this call, and execPid
	// (a possibly-already-exited forked child) does not promise that, while
	// containerPid (the container's own long-lived tracked process) does — and
	// shares the same mount namespace via fork inheritance, so the resolved
	// path opens identically either way.
	var unsecuredAttachFilePaths []string
	if exe, ok := t.settledExecutablePath(execPid); ok {
		unsecuredAttachFilePaths = append(unsecuredAttachFilePaths, exe)
	}
	libPaths, err := t.resolveLibraryPaths(ctx, containerPid, attachFilePath, ociConfig)
	if err != nil {
		t.logger.Debugf("re-attaching to container %d (exec pid %d): %s", containerPid, execPid, err.Error())
	}
	unsecuredAttachFilePaths = dedupPaths(append(unsecuredAttachFilePaths, libPaths...))

	opened, openFailed := t.openTargets(ctx, containerPid, unsecuredAttachFilePaths)

	// Phase 2 (lock): re-validate the pid is still tracked — it may have been
	// detached during the lock-free window, and committing then would leak a uprobe
	// link with no DetachContainer to release it — then commit the dedup/attach
	// bookkeeping under the lock.
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		closeOpened(opened)
		return nil
	}
	if _, tracked := t.containerPid2Inodes[containerPid]; !tracked {
		closeOpened(opened)
		return nil
	}
	attachFailed := t.commitOpenedTargets(containerPid, opened)

	// Record the settled exe target only after a clean pass (no open or attach
	// failure) so the guard above does not permanently skip a pid whose attach
	// failed transiently.
	if exeTarget != "" && !openFailed && !attachFailed {
		t.containerPid2ExeTarget[containerPid] = exeTarget
	}
	return nil
}

// reattachMappedLibraries discovers file-backed mappings in
// /proc/<containerPid>/maps whose basename matches pattern, opens each via
// /proc/<containerPid>/map_files/<range> (the ONLY route to a deleted, mmap-only
// inode), and attaches the uprobe using the identical
// readRealInode → inodeRefCount → containerPid2Inodes bookkeeping as
// attachOneFile (Principle 2). It is the Phase-2 entry point called by the
// Phase-3 self-sustaining retry loop.
//
// Design invariants (mirror ReattachContainerPid):
//   - Tracked-pid guard: a pid not in containerPid2Inodes is a no-op (race with
//     DetachContainer or an event that pre-dates AttachContainer).
//   - Union-with-delta: existing inodes seeded from containerPid2Inodes[pid] so
//     a second call for an already-attached inode is a no-op.
//   - Per-file non-fatal: openMapFile / elfMachineMatchesProcess / inode errors
//     are logged-and-skipped; only a complete discovery failure is returned.
//   - Pattern is CALLER-SUPPLIED: the tcnative regex lives in the caller
//     (node-agent / Phase-3 wiring), not here.
//
// Caller holds t.mu.
func (t *Tracer[Event]) reattachMappedLibraries(containerPid uint32, pattern *regexp.Regexp) error {
	if t.closed {
		return errors.New("uprobetracer has been closed")
	}
	if t.prog == nil {
		// Pending mode: no program loaded yet; the create-time attach path
		// will run once AttachProg fires -- attachOneFile via attach() for
		// no-resolver gadgets, or attachContainerWork's bounded async job
		// for resolver-backed gadgets.
		return nil
	}

	// Tracked-pid guard: mirrors ReattachContainerPid's identical check.
	if _, tracked := t.containerPid2Inodes[containerPid]; !tracked {
		return nil
	}

	// Discover + open under the held lock here (this is the test/integration entry
	// point; lock-hold time is irrelevant). The production path
	// (ReattachContainerMappedLibsPid) runs the same discovery OFF the lock.
	opened, err := t.discoverAndOpenMappedLibraries(containerPid, pattern)
	if err != nil {
		closeMappedOpen(opened) // empty today (error precedes the open loop); defensive against future partial-result edits
		return err
	}
	t.commitMappedLibraries(containerPid, opened)
	return nil
}

// mappedOpen is an opened, not-yet-committed map_files attach candidate produced by
// the lock-free discoverAndOpenMappedLibraries. Whoever holds it owns the file:
// commitMappedLibraries consumes it (attachOneOpenFile closes it), closeMappedOpen
// releases any dropped on bail.
type mappedOpen struct {
	file     *os.File
	path     string
	rangeKey string
	// offsets mirrors openedTarget.offsets: resolved in the open phase, consumed
	// in the commit phase.
	offsets []uint64
}

// discoverAndOpenMappedLibraries performs the I/O-heavy half of the map_files
// reattach: it captures the container's mount namespace, walks /proc/<pid>/maps for
// file-backed mappings matching pattern, opens each via map_files, and applies the
// ELF e_machine arch guard. It reads NO shared tracer state (only the openMapFileFunc
// seam and the logger), so it runs WITHOUT t.mu — keeping the procfs/ELF I/O off the
// lock that the create-time AttachContainer path contends for. Returns the opened
// candidates; the caller commits them (commitMappedLibraries) or releases them
// (closeMappedOpen) on bail. A complete discovery failure is returned as an error;
// a teardown race (pid gone) returns (nil, nil).
func (t *Tracer[Event]) discoverAndOpenMappedLibraries(containerPid uint32, pattern *regexp.Regexp) ([]mappedOpen, error) {
	// Capture the mount namespace BEFORE walking maps so we can pass it to
	// openMapFile for the post-open PID-recycle validation.
	expectedMntns, err := readProcMntns(containerPid)
	if err != nil {
		// PID already gone: not an error, just a teardown race.
		t.logger.Debugf("uprobetracer: reattachMappedLibraries pid %d: mntns read failed (pid gone?): %v", containerPid, err)
		return nil, nil
	}

	libs, err := discoverMappedLibraries(containerPid, pattern)
	if err != nil {
		return nil, fmt.Errorf("discovering mapped libraries for pid %d: %w", containerPid, err)
	}

	var opened []mappedOpen
	for _, lib := range libs {
		file, err := t.openMapFileFunc(containerPid, lib.rangeKey, expectedMntns)
		if err != nil {
			// EACCES/EPERM/ENOENT / mntns mismatch / PID race: log and skip.
			t.logger.Debugf("uprobetracer: reattachMappedLibraries pid %d %q: open failed: %v", containerPid, lib.path, err)
			continue
		}

		// Arch guard: skip .so files whose ELF e_machine does not match the
		// container process. Non-fatal if the check itself fails (e.g. the
		// process exe is gone): still try to attach (worst case: symbol absent).
		if matches, err := elfMachineMatchesProcess(file, containerPid); err != nil {
			t.logger.Debugf("uprobetracer: reattachMappedLibraries pid %d %q: arch check failed: %v", containerPid, lib.path, err)
		} else if !matches {
			t.logger.Debugf("uprobetracer: reattachMappedLibraries pid %d %q: ELF e_machine mismatch, skipping", containerPid, lib.path)
			file.Close()
			continue
		}

		opened = append(opened, mappedOpen{file: file, path: lib.path, rangeKey: lib.rangeKey, offsets: t.resolveAttachOffsets(file, containerPid)})
	}
	return opened, nil
}

// closeMappedOpen releases opened map_files candidates that will not be committed
// (e.g. the pid was detached during the lock-free window). Safe on nil/empty.
func closeMappedOpen(opened []mappedOpen) {
	for _, mo := range opened {
		mo.file.Close()
	}
}

// commitMappedLibraries attaches each already-open map_files candidate under t.mu,
// applying the standard readRealInode → inodeRefCount dedup → containerPid2Inodes
// bookkeeping (via attachOneOpenFile, which consumes/closes every file) and marking
// mappedLibAttached so HasMappedLibForPid can stop the retry loop. Caller holds t.mu
// and has re-validated that containerPid is still tracked.
func (t *Tracer[Event]) commitMappedLibraries(containerPid uint32, opened []mappedOpen) {
	attachedRealInodes := t.containerPid2Inodes[containerPid]
	existing := make(map[uint64]bool, len(attachedRealInodes))
	for _, inode := range attachedRealInodes {
		existing[inode] = true
	}

	for _, mo := range opened {
		realInodePtr, added, err := t.attachOneOpenFile(containerPid, mo.file, mo.path, mo.offsets, existing)
		if err != nil {
			t.logger.Debugf("uprobetracer: reattachMappedLibraries pid %d %q: attach failed: %v", containerPid, mo.path, err)
			continue
		}
		if added {
			existing[realInodePtr] = true
			attachedRealInodes = append(attachedRealInodes, realInodePtr)
			// Mark the pid as having a map_files-credited inode so HasMappedLibForPid
			// reports success and the Phase-3 retry loop can stop. Set on a real
			// attach OR a refcount bump (added==true), since either means the
			// targeted library is now covered for this pid.
			t.mappedLibAttached[containerPid] = true
			t.logger.Infof("uprobetracer: reattachMappedLibraries: attached %q to container pid %d via map_files/%s", t.progName, containerPid, mo.rangeKey)
		}
	}

	t.containerPid2Inodes[containerPid] = attachedRealInodes
}

// ReattachContainerMappedLibsPid is the public, lock-taking entry point to the
// map_files discovery + attach path (reattachMappedLibraries). It mirrors
// ReattachContainerPid's locking: it acquires t.mu for the whole read-modify-write
// so the per-pid inode set and the shared refcount stay consistent. The matcher
// is CALLER-SUPPLIED (P2b passes the tcnative regex); a nil pattern is a no-op.
//
// It is driven by the Phase-3 fork-internal retry timer (ebpfInstance.ReattachContainer)
// and is safe to call repeatedly: it is idempotent via the union-with-delta
// existing-set seeding inside reattachMappedLibraries.
func (t *Tracer[Event]) ReattachContainerMappedLibsPid(containerPid uint32, pattern *regexp.Regexp) error {
	if pattern == nil {
		return nil
	}

	// Phase 0 (lock): cheap guards. Same rationale as ReattachContainerPid — the
	// discover/open I/O below must not hold t.mu, or an exec storm of retry-timer
	// goroutines starves the create-time AttachContainer on the container-start path.
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("uprobetracer has been closed")
	}
	if t.prog == nil {
		t.mu.Unlock()
		return nil
	}
	if _, tracked := t.containerPid2Inodes[containerPid]; !tracked {
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()

	// Phase 1 (NO lock): discover + open the map_files candidates.
	opened, err := t.discoverAndOpenMappedLibraries(containerPid, pattern)
	if err != nil {
		closeMappedOpen(opened) // empty today (error precedes the open loop); defensive against future partial-result edits
		return err
	}

	// Phase 2 (lock): re-validate the pid is still tracked (else committing would
	// leak a uprobe link with no DetachContainer to release it), then commit.
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		closeMappedOpen(opened)
		return nil
	}
	if _, tracked := t.containerPid2Inodes[containerPid]; !tracked {
		closeMappedOpen(opened)
		return nil
	}
	t.commitMappedLibraries(containerPid, opened)
	return nil
}

// HasMappedLibForPid reports whether reattachMappedLibraries has already credited
// at least one inode via the map_files path for containerPid. The Phase-3 retry
// timer polls this to stop once the targeted library (e.g. netty-tcnative) is
// attached, instead of running to the cap. It is lock-safe.
func (t *Tracer[Event]) HasMappedLibForPid(containerPid uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mappedLibAttached[containerPid]
}

// AttachContainer will attach now if the prog is ready, otherwise it will add container into the pending list.
//
// When the program is loaded, the actual resolve/open/attach is dispatched to a
// bounded background goroutine (attachContainerWork) rather than run inline: this
// callback is awaited on the synchronous container-start (fanotify) path, so doing
// the I/O here would block runc's create→start under load. AttachContainer instead
// reserves the pid as tracked and returns immediately. Tests set syncAttach to run
// the attach inline for deterministic bookkeeping.
func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	pid := container.ContainerPid()

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("uprobetracer has been closed")
	}
	// Record the OCI config so the attach can resolve a statically-linked symbol to
	// the container's executable via the OCI spec.
	t.containerPid2OciConfig[pid] = container.OciConfig
	settled := container.SettledAtDiscovery()
	t.containerPidSettled[pid] = settled
	if t.prog == nil {
		_, exist := t.pendingContainerPids[pid]
		if exist {
			t.mu.Unlock()
			return fmt.Errorf("container PID already exists: %d", pid)
		}
		t.pendingContainerPids[pid] = true
		t.mu.Unlock()
		return nil
	}
	if _, exist := t.containerPid2Inodes[pid]; exist {
		t.mu.Unlock()
		return fmt.Errorf("container PID already exists: %d", pid)
	}
	// Reserve the pid as tracked synchronously so a concurrent Reattach/Detach sees
	// it and the dup-check above stays authoritative; the attach itself runs off
	// this path.
	t.containerPid2Inodes[pid] = nil
	job := attachJob{pid: pid, attachFilePath: t.attachFilePath, attachSymbol: t.attachSymbol, progName: t.progName, ociConfig: container.OciConfig, settled: settled}
	runInline := t.syncAttach
	// Snapshot the semaphore under the lock so the worker never reads the field
	// concurrently with SetAttachSemaphore.
	sem := t.attachSem
	if !runInline {
		// Add UNDER the lock so it orders with Close (which sets closed under the
		// lock before joining attachWg): Close can never miss this attach.
		t.attachWg.Add(1)
	}
	t.mu.Unlock()

	if runInline {
		t.attachContainerWork(job)
	} else {
		// One goroutine per container; attachSem bounds how many run the heavy
		// resolve/open concurrently. Under a burst the excess goroutines briefly
		// park on the sem — cheap, bounded by the container-start rate, and never
		// on the container-start path. They bail fast on Close.
		go func() {
			defer t.attachWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t.attachContainerWork(job)
		}()
	}
	return nil
}

// attachContainerWork performs the create-time attach off the container-start path,
// reusing the optimistic resolve→open (no lock) then re-validate→commit (lock)
// discipline. It bails if the tracer closed or the pid was detached during the
// window (closing any opened files), so it can never install a uprobe link with no
// DetachContainer to release it.
func (t *Tracer[Event]) attachContainerWork(job attachJob) {
	t.mu.Lock()
	if t.closed || t.prog == nil {
		t.mu.Unlock()
		return
	}
	if _, tracked := t.containerPid2Inodes[job.pid]; !tracked {
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()

	// Bounds this job's resolve+open phase so a wedged setns/openat2 releases
	// its attachSem slot instead of starving every other container queued
	// behind the same process-wide budget forever; see attachIOTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), attachIOTimeout)
	defer cancel()

	// job.settled means containercollection observed this container AFTER its
	// entrypoint had already execve'd (see Container.SettledAtDiscovery), so
	// unlike the general create-time case /proc/<pid>/exe already names the
	// settled executable rather than the runtime shim. Try it first, exactly
	// as ReattachContainerPid does for the exec-driven case -- this is the
	// same distinction, just recognised at first attach instead of waiting for
	// an exec event that a pre-existing container will never generate.
	var paths []string
	if job.settled {
		if exe, ok := t.settledExecutablePath(job.pid); ok {
			paths = append(paths, exe)
		}
	}
	libPaths, err := t.resolveLibraryPaths(ctx, job.pid, job.attachFilePath, job.ociConfig)
	if err != nil {
		t.logger.Debugf("attaching to container %d: %s", job.pid, err.Error())
	}
	paths = dedupPaths(append(paths, libPaths...))
	if len(paths) == 0 {
		t.logger.Infof("uprobetracer: %q NOT attached to container pid %d: no attach target for symbol %q", job.progName, job.pid, job.attachSymbol)
		return
	}
	opened, _ := t.openTargets(ctx, job.pid, paths)

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		closeOpened(opened)
		return
	}
	if _, tracked := t.containerPid2Inodes[job.pid]; !tracked {
		closeOpened(opened)
		return
	}
	t.commitOpenedTargets(job.pid, opened)
	if inodes := t.containerPid2Inodes[job.pid]; len(inodes) > 0 {
		t.logger.Infof("uprobetracer: attached %q to container pid %d at %v", job.progName, job.pid, paths)
	} else {
		t.logger.Infof("uprobetracer: %q NOT attached to container pid %d: resolved %v but bound 0 (symbol absent, or open/link failed)", job.progName, job.pid, paths)
	}
}

func (t *Tracer[Event]) DetachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	pid := container.ContainerPid()
	delete(t.containerPid2OciConfig, pid)
	delete(t.containerPidSettled, pid)
	delete(t.containerPid2ExeTarget, pid)
	delete(t.mappedLibAttached, pid)
	if t.prog == nil {
		// remove from pending list
		_, exist := t.pendingContainerPids[pid]
		if !exist {
			return errors.New("container has not been attached")
		}
		delete(t.pendingContainerPids, pid)
	} else {
		// detach from container if attached
		attachedRealInodes, exist := t.containerPid2Inodes[pid]
		if !exist {
			return errors.New("container has not been attached")
		}
		delete(t.containerPid2Inodes, pid)

		for _, realInodePtr := range attachedRealInodes {
			keeper, exist := t.inodeRefCount[realInodePtr]
			if !exist {
				return errors.New("internal error: finding inodeKeeper with realInodePtr")
			}
			keeper.counter--
			if keeper.counter == 0 {
				// Only the LAST reference closes the links. A decrement that
				// leaves other PIDs referencing this inode must not touch them,
				// or those containers silently lose instrumentation.
				t.linksClosed.Add(uint64(keeper.close()))
				delete(t.inodeRefCount, realInodePtr)
			}
		}
	}

	return nil
}

func (t *Tracer[Event]) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()

	// Join in-flight background create-time attaches WITHOUT holding t.mu: their
	// commit phase takes t.mu, so holding it here would deadlock. They observe
	// closed==true and bail, closing any files they opened.
	t.attachWg.Wait()

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, keeper := range t.inodeRefCount {
		t.linksClosed.Add(uint64(keeper.close()))
	}
	t.containerPid2Inodes = nil
	t.inodeRefCount = nil
	t.containerPid2ExeTarget = nil
	t.mappedLibAttached = nil
}
