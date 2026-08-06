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
// reference count. The link is not nil only when the file is attached.
type inodeKeeper struct {
	counter int
	file    *os.File
	link    link.Link
}

func (t *inodeKeeper) close() {
	if t.link != nil {
		t.link.Close()
	}
	t.file.Close()
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
	openInContainer func(containerPid uint32, filePath string) (*os.File, error)
	readRealInode   func(fd int) (uint64, error)
	// attachToFile attaches to an already-open candidate. offset is the file
	// offset resolved during the lock-free open phase, or nil to attach by
	// symbol name (today's path).
	attachToFile func(file *os.File, offset *uint64) (link.Link, error)
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

	// multiOffsetUnsupported counts candidates skipped because the resolver
	// returned more than one offset, which the single-link inodeKeeper cannot
	// represent yet. See attachOffsets.
	multiOffsetUnsupported atomic.Uint64

	// createTimeAttachUnresolved counts create-time (AttachContainer) attaches
	// that bypassed the resolver entirely; see attachOneFile.
	createTimeAttachUnresolved atomic.Uint64

	// Create-time attach (AttachContainer) is dispatched to bounded background
	// goroutines so it NEVER runs on the synchronous container-start (fanotify
	// FAN_ACCESS_PERM) path: the AddContainer callback that AttachContainer serves
	// is awaited before runc's create→start is unblocked, so a slow attach there
	// (e.g. ELF parse of a large statically-linked binary, or setns) wedges
	// container starts under a pod burst. attachSem caps how many of those attaches
	// run concurrently; attachWg lets Close join the in-flight ones.
	attachSem chan struct{}
	attachWg  sync.WaitGroup
	// syncAttach makes AttachContainer run the attach INLINE instead of dispatching
	// it. Off in production; unit tests set it so create-time bookkeeping is
	// observable synchronously.
	syncAttach bool

	closed bool
	mu     sync.Mutex
}

// maxConcurrentAttaches caps concurrent background create-time attaches so a
// pod-burst cannot spawn an unbounded number of simultaneous setns/ELF-parse
// operations (the resource spike seen in the original wedge incident).
const maxConcurrentAttaches = 8

// attachJob is the immutable snapshot a background create-time attach needs,
// captured under t.mu at dispatch so the worker reads no write-once tracer fields
// off-lock (race-free).
type attachJob struct {
	pid            uint32
	attachFilePath string
	attachSymbol   string
	progName       string
	ociConfig      string
}

func NewTracer[Event any](logger logger.Logger) (*Tracer[Event], error) {
	t := &Tracer[Event]{
		containerPid2Inodes:    make(map[uint32][]uint64),
		inodeRefCount:          make(map[uint64]*inodeKeeper),
		pendingContainerPids:   make(map[uint32]bool),
		containerPid2OciConfig: make(map[uint32]string),
		containerPid2ExeTarget: make(map[uint32]string),
		mappedLibAttached:      make(map[uint32]bool),
		openInContainer:        secureopen.OpenInContainer,
		readRealInode:          kfilefields.ReadRealInodeFromFd,
		openMapFileFunc:        openMapFile,
		attachSem:              make(chan struct{}, maxConcurrentAttaches),
		logger:                 logger,
		closed:                 false,
	}
	t.attachToFile = t.attachUprobe
	return t, nil
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
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("uprobetracer has been closed")
	}

	t.progName = progName
	t.progType = progType
	t.attachFilePath = parts[0]
	t.attachSymbol = parts[1]
	t.prog = prog

	// attach to pending containers, then release the pending list
	for pid := range t.pendingContainerPids {
		t.attach(pid)
	}
	t.pendingContainerPids = nil

	return nil
}

// searchForLibrary resolves the attach target paths using the tracer's recorded
// state. Caller holds t.mu (it reads containerPid2OciConfig). The lock-free hot
// paths call resolveLibraryPaths directly with snapshotted inputs instead.
func (t *Tracer[Event]) searchForLibrary(containerPid uint32) ([]string, error) {
	return t.resolveLibraryPaths(containerPid, t.attachFilePath, t.containerPid2OciConfig[containerPid])
}

// resolveLibraryPaths resolves the in-container paths to open for the uprobe
// target from SNAPSHOTTED inputs (attachFilePath and the container's verbatim OCI
// config), reading no shared tracer state, so it can run WITHOUT holding t.mu.
// The ld.so.cache parse it performs is I/O that must not be done under the lock
// (an exec storm holding t.mu across this work starves the create-time
// AttachContainer that sits on the synchronous container-start path).
func (t *Tracer[Event]) resolveLibraryPaths(containerPid uint32, attachFilePath, ociConfig string) ([]string, error) {
	if filepath.IsAbs(attachFilePath) {
		return []string{attachFilePath}, nil
	}

	ldCachePath := "/etc/ld.so.cache"
	ldCachePaths, err := parseLdCache(containerPid, ldCachePath, attachFilePath)
	if err != nil {
		return nil, fmt.Errorf("parsing ld cache: %w", err)
	}
	if len(ldCachePaths) > 0 {
		return ldCachePaths, nil
	}

	// The requested library is not a shared object in this container's ld cache.
	// This is the common case for statically-linked runtimes that embed the
	// library into their main executable (Node.js, and Go/Rust binaries that
	// statically link OpenSSL/BoringSSL), where a `libssl`-targeted uprobe gadget
	// would otherwise find nothing to attach to. Fall back to the container's
	// intended executable: the symbol may be defined there.
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
func (t *Tracer[Event]) attachUprobe(file *os.File, offset *uint64) (link.Link, error) {
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
	switch t.progType {
	case ProgUprobe:
		return ex.Uprobe(t.attachSymbol, t.prog, uprobeOffsetOptions(offset))
	case ProgUretprobe:
		return ex.Uretprobe(t.attachSymbol, t.prog, uprobeOffsetOptions(offset))
	case ProgUSDT:
		attachInfo, err := getUsdtInfo(attachPath, t.attachSymbol)
		if err != nil {
			return nil, fmt.Errorf("reading USDT metadata: %w", err)
		}
		return ex.Uprobe(t.attachSymbol, t.prog,
			&link.UprobeOptions{
				Address:      attachInfo.attachAddress,
				RefCtrOffset: attachInfo.semaphoreAddress,
			})
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
func (t *Tracer[Event]) attachOneOpenFile(containerPid uint32, file *os.File, label string, offset *uint64, existing map[uint64]bool) (uint64, bool, error) {
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

	progLink, err := t.attachToFile(file, offset)
	if err != nil {
		// The target exists but does not export the symbol (e.g. runc, a wrapper
		// executable, or BoringSSL which omits SSL_read_ex/SSL_write_ex). Skip
		// without taking a reference so DetachContainer stays balanced.
		file.Close()
		t.logger.Debugf("not attaching uprobe %q to %q for container %d: %s", t.progName, label, containerPid, err.Error())
		return realInodePtr, false, nil
	}
	t.logger.Debugf("attaching uprobe %q to container %d: %q", t.progName, containerPid, label)
	t.inodeRefCount[realInodePtr] = &inodeKeeper{1, file, progLink}
	return realInodePtr, true, nil
}

// attachOneFile opens filePath inside the container of containerPid and then
// calls attachOneOpenFile. It is the path-based attach entry point used by the
// P1.5 (dynamic libssl) and P2a (settled-exe) flows; its behaviour is unchanged
// by the Phase-2 refactor — attachOneOpenFile carries the identical bookkeeping.
// Caller holds t.mu.
//
// This path deliberately does NOT consult the AttachOffsetResolver: it is the
// only remaining caller that opens under t.mu, and it already bails before
// reaching a statically-linked target (at create time the library is not in the
// container's ld.so.cache, so nothing resolves). The omission is a deliberate
// no-op, not an oversight — revisit only if that bail-out condition changes.
func (t *Tracer[Event]) attachOneFile(containerPid uint32, filePath string, existing map[uint64]bool) (uint64, bool, error) {
	// OpenInContainer returns a fd without O_PATH. This is necessary because
	// ReadRealInodeFromFd needs the private_data field in kernel "struct file"
	// to reach the underlying inode through overlayFS; O_PATH zeroes that field.
	file, err := t.openInContainer(containerPid, filePath)
	if err != nil {
		return 0, false, fmt.Errorf("opening file %q for uprobe: %w", filePath, err)
	}
	// Counted, not just commented: the claim that this path never meets a target
	// needing an offset is an assumption about what is reachable at create time,
	// and an assumption on a fail-open path is exactly the kind that stops being
	// true quietly. A registered resolver plus a rising count here is the signal
	// that the omission has started costing coverage.
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
func (t *Tracer[Event]) openTargets(containerPid uint32, paths []string) ([]openedTarget, bool) {
	var opened []openedTarget
	openFailed := false
	for _, filePath := range paths {
		// OpenInContainer returns a fd without O_PATH: ReadRealInodeFromFd needs the
		// kernel "struct file" private_data to reach the overlay's real inode.
		file, err := t.openInContainer(containerPid, filePath)
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
	// MultiOffsetUnsupported counts candidates left uninstrumented because the
	// resolver returned more than one offset.
	MultiOffsetUnsupported uint64
	// CreateTimeAttachUnresolved counts create-time attaches that bypassed the
	// resolver.
	CreateTimeAttachUnresolved uint64
}

// Stats returns a snapshot. It takes no lock -- deliberately, since a stats read
// that waited on t.mu could not be used to diagnose t.mu being held too long.
func (t *Tracer[Event]) Stats() TracerStats {
	return TracerStats{
		MuHold:                     t.muHold.Stats(),
		ResolverFailOpen:           t.resolverFailOpen.Load(),
		MultiOffsetUnsupported:     t.multiOffsetUnsupported.Load(),
		CreateTimeAttachUnresolved: t.createTimeAttachUnresolved.Load(),
	}
}

// attachOffsets narrows a resolved offset slice to the single offset the
// current inodeKeeper can hold, reporting whether the candidate may be attached
// at all.
//
// An empty slice means "attach by symbol name", today's unchanged behaviour.
// More than one offset is refused rather than truncated: inodeKeeper carries one
// link.Link per inode, so attaching only the first would bind some of a
// program's probe sites and silently drop the rest -- for the Go crypto/tls
// Read capture that is an entry probe with no returns, which produces a stream
// of started-but-never-completed reads rather than an obvious failure. Refusing
// loudly leaves the target uninstrumented, which is recoverable; a half-attached
// program is not.
//
// Multi-offset attach lands with the multi-link inodeKeeper rework, at which
// point this narrowing disappears rather than being extended.
func (t *Tracer[Event]) attachOffsets(offsets []uint64, label string) (*uint64, bool) {
	switch len(offsets) {
	case 0:
		return nil, true
	case 1:
		return &offsets[0], true
	default:
		t.multiOffsetUnsupported.Add(1)
		t.logger.Warnf("uprobetracer: %q NOT attached to %q: resolver returned %d offsets but only one link per inode is supported yet; leaving the target uninstrumented rather than attaching a subset",
			t.progName, label, len(offsets))
		return nil, false
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
		offset, ok := t.attachOffsets(ot.offsets, ot.label)
		if !ok {
			// attachOneOpenFile would have consumed the file; this path must.
			ot.file.Close()
			continue
		}
		realInodePtr, added, err := t.attachOneOpenFile(containerPid, ot.file, ot.label, offset, existing)
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

// try attaching to a container, will update `containerPid2Inodes`
func (t *Tracer[Event]) attach(containerPid uint32) {
	unsecuredAttachFilePaths, err := t.searchForLibrary(containerPid)
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
		realInodePtr, added, err := t.attachOneFile(containerPid, filePath, existing)
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
// attaches the uprobe to any newly-settled executable. It is the load-bearing
// addition for statically-linked runtimes (Node.js, and Go/Rust binaries that
// embed OpenSSL/BoringSSL): at container-create time /proc/<pid>/exe still
// points at the runtime shim (runc), so the create-time attach binds the wrong
// inode. Calling this after the container's process has execve'd into its final
// binary re-resolves the executable and attaches to the settled inode.
//
// It is idempotent and safe to call repeatedly:
//   - an inode already counted for this pid is a no-op;
//   - an inode already counted for another pid only bumps the shared refcount;
//   - a pid that AttachContainer never recorded (or that DetachContainer has
//     already cleaned up) is a no-op — fresh-attaching would install a uprobe
//     link with no DetachContainer to ever release it.
//
// containerPid2Inodes[pid] is treated as a SET — each (pid, realInode) holds
// exactly one reference — so DetachContainer's decrement-once-per-inode logic
// stays correct across the create-time attach plus N re-attaches.
func (t *Tracer[Event]) ReattachContainerPid(containerPid uint32) error {
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
	// exe-inode-change guard: if /proc/<pid>/exe still points at the target we last
	// *successfully* re-attached for this pid, there is nothing new to attach. The
	// target is recorded only after a clean pass below, so a transient failure
	// (e.g. racing an overlayfs mount) is retried on the next exec instead of being
	// permanently short-circuited.
	exeLink := filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "exe")
	exeTarget, _ := os.Readlink(exeLink)
	if exeTarget != "" && haveLastExeTarget && lastExeTarget == exeTarget {
		return nil
	}

	// At exec time the settled binary is /proc/<pid>/exe: for statically-linked
	// runtimes the target symbol lives there, not in a shared library. Resolve it
	// first, then fall back to the normal create-time resolution (absolute path,
	// ld cache, or OCI process.args[0]) so dynamic-libssl containers keep working.
	var unsecuredAttachFilePaths []string
	if exe, ok := t.settledExecutablePath(containerPid); ok {
		unsecuredAttachFilePaths = append(unsecuredAttachFilePaths, exe)
	}
	libPaths, err := t.resolveLibraryPaths(containerPid, attachFilePath, ociConfig)
	if err != nil {
		t.logger.Debugf("re-attaching to container %d: %s", containerPid, err.Error())
	}
	unsecuredAttachFilePaths = append(unsecuredAttachFilePaths, libPaths...)

	opened, openFailed := t.openTargets(containerPid, unsecuredAttachFilePaths)

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
		// (attachOneFile via attach) will run once AttachProg fires.
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
		offset, ok := t.attachOffsets(mo.offsets, mo.path)
		if !ok {
			mo.file.Close()
			continue
		}
		realInodePtr, added, err := t.attachOneOpenFile(containerPid, mo.file, mo.path, offset, existing)
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
	job := attachJob{pid: pid, attachFilePath: t.attachFilePath, attachSymbol: t.attachSymbol, progName: t.progName, ociConfig: container.OciConfig}
	runInline := t.syncAttach
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
			t.attachSem <- struct{}{}
			defer func() { <-t.attachSem }()
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

	paths, err := t.resolveLibraryPaths(job.pid, job.attachFilePath, job.ociConfig)
	if err != nil {
		t.logger.Debugf("attaching to container %d: %s", job.pid, err.Error())
	}
	if len(paths) == 0 {
		t.logger.Infof("uprobetracer: %q NOT attached to container pid %d: no attach target for symbol %q", job.progName, job.pid, job.attachSymbol)
		return
	}
	opened, _ := t.openTargets(job.pid, paths)

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
				keeper.close()
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
		keeper.close()
	}
	t.containerPid2Inodes = nil
	t.inodeRefCount = nil
	t.containerPid2ExeTarget = nil
	t.mappedLibAttached = nil
}
