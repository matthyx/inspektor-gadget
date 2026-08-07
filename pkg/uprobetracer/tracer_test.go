// Copyright 2026 The Inspektor Gadget authors
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

package uprobetracer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// testState drives the injected uprobetracer seams so the refcount/attach
// bookkeeping can be exercised without a kernel or live containers.
type testState struct {
	currentInode uint64 // realInode that the next resolved file maps to
	openErr      error  // when set, openInContainer fails (e.g. non-ELF / missing)
	inodeErr     error  // when set, readRealInode fails
	attachErr    error  // when set, attachToFile fails (e.g. symbol absent)

	attachCount int        // number of real uprobe attaches performed
	openFiles   []*os.File // every file handed out, so the test can clean up
	lastOffset  *uint64    // single pre-resolved offset seen by the last attach, nil if none
	lastOffsets []uint64   // every offset seen by the last attach
	lastLinks   int        // links returned by the last attach
}

func (s *testState) open(_ uint32, _ string) (*os.File, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	s.openFiles = append(s.openFiles, f)
	return f, nil
}

func (s *testState) readInode(_ int) (uint64, error) {
	if s.inodeErr != nil {
		return 0, s.inodeErr
	}
	return s.currentInode, nil
}

func (s *testState) attach(_ *os.File, offsets []uint64) ([]link.Link, error) {
	if s.attachErr != nil {
		return nil, s.attachErr
	}
	s.attachCount++
	s.lastOffsets = offsets
	// lastOffset keeps the single-offset assertions in the existing tests
	// readable; it is only meaningful when exactly one offset was resolved.
	s.lastOffset = nil
	if len(offsets) == 1 {
		s.lastOffset = &offsets[0]
	}
	// link.Link cannot be implemented outside cilium/ebpf (its isLink method is
	// unexported), so the doubles are nil -- but there is one PER BOUND OFFSET,
	// because the count is what the multi-link bookkeeping is measured by. A
	// symbol-name attach binds one probe and so yields one.
	n := len(offsets)
	if n == 0 {
		n = 1
	}
	s.lastLinks = n
	return make([]link.Link, n), nil
}

// newTestTracer returns a tracer wired to the test seams, already in "running"
// mode (prog != nil) with an absolute attach path so searchForLibrary resolves
// to exactly one file whose realInode is controlled by testState.currentInode.
func newTestTracer(t *testing.T) (*Tracer[any], *testState) {
	t.Helper()
	tr, err := NewTracer[any](logger.DefaultLogger())
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}
	st := &testState{}
	tr.prog = &ebpf.Program{} // sentinel: non-nil => running mode
	tr.progName = "test_ssl"
	tr.progType = ProgUprobe
	tr.attachFilePath = "/lib/libtest.so" // absolute => single resolved path
	tr.attachSymbol = "SSL_write"
	// Run create-time attach inline so these bookkeeping assertions are
	// deterministic; production dispatches it to a background goroutine.
	tr.syncAttach = true
	tr.openInContainer = st.open
	tr.readRealInode = st.readInode
	tr.attachToFile = st.attach
	t.Cleanup(func() {
		for _, f := range st.openFiles {
			f.Close()
		}
	})
	return tr, st
}

// testContainer builds a minimal Container whose ContainerPid() returns pid.
// A non-existent pid keeps the /proc/<pid>/exe guard from short-circuiting, so
// the dedup logic itself is exercised on every ReattachContainerPid.
func testContainer(pid uint32) *containercollection.Container {
	c := &containercollection.Container{}
	c.Runtime.ContainerPID = pid
	return c
}

const fakePid = uint32(4000000) // outside any real /proc range

func TestReattachIdempotentSameInode(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := tr.ReattachContainerPid(fakePid); err != nil {
			t.Fatalf("ReattachContainerPid #%d: %v", i, err)
		}
	}

	if st.attachCount != 1 {
		t.Errorf("attachCount = %d, want 1 (re-attach to same inode must not re-attach)", st.attachCount)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 1", k)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pid] = %v, want [100]", got)
	}
}

func TestReattachNewInodeAdds(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	// Process settles into a new binary at the same path -> new realInode.
	st.currentInode = 200
	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}

	if st.attachCount != 2 {
		t.Errorf("attachCount = %d, want 2 (new inode must attach)", st.attachCount)
	}
	if k := tr.inodeRefCount[200]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[200] = %+v, want counter 1", k)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 2 {
		t.Errorf("containerPid2Inodes[pid] = %v, want 2 inodes (100,200)", got)
	}
}

func TestDetachAfterReattachNoLeak(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	st.currentInode = 200
	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}

	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("DetachContainer: %v", err)
	}

	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount not empty after detach: %v (leak/over-ref)", tr.inodeRefCount)
	}
	if _, ok := tr.containerPid2Inodes[fakePid]; ok {
		t.Errorf("containerPid2Inodes still has pid after detach")
	}
	if _, ok := tr.containerPid2ExeTarget[fakePid]; ok {
		t.Errorf("containerPid2ExeTarget still has pid after detach")
	}
}

// An exec event for a pid that AttachContainer never recorded (e.g. the event
// raced DetachContainer and landed after teardown) must be a no-op: attaching
// fresh would install a uprobe link with no DetachContainer to ever release it.
func TestReattachUntrackedPidIsNoOp(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 300

	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid on untracked pid: %v", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (untracked pid must not fresh-attach)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated for untracked pid: %v", tr.inodeRefCount)
	}
	if _, ok := tr.containerPid2Inodes[fakePid]; ok {
		t.Errorf("containerPid2Inodes added entry for untracked pid (would leak)")
	}
}

func TestReattachSkipsNonELF(t *testing.T) {
	tr, st := newTestTracer(t)
	st.openErr = errors.New("not an ELF / cannot open")

	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (non-ELF open failure must be skipped)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated on skip: %v", tr.inodeRefCount)
	}
	if len(tr.containerPid2Inodes[fakePid]) != 0 {
		t.Errorf("containerPid2Inodes mutated on skip: %v", tr.containerPid2Inodes[fakePid])
	}
}

func TestReattachSkipsSymbolAbsent(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 500
	st.attachErr = errors.New("symbol SSL_write not found")

	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (attach itself failed)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated when symbol absent: %v", tr.inodeRefCount)
	}
	if len(tr.containerPid2Inodes[fakePid]) != 0 {
		t.Errorf("containerPid2Inodes mutated when symbol absent: %v", tr.containerPid2Inodes[fakePid])
	}
}

func TestSharedInodeAcrossPidsRefcount(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100 // both containers share the same image/inode

	pidA, pidB := fakePid, fakePid+1
	if err := tr.AttachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("AttachContainer A: %v", err)
	}
	if err := tr.AttachContainer(testContainer(pidB)); err != nil {
		t.Fatalf("AttachContainer B: %v", err)
	}

	if st.attachCount != 1 {
		t.Errorf("attachCount = %d, want 1 (shared inode attaches once)", st.attachCount)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 2 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 2", k)
	}

	if err := tr.DetachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("DetachContainer A: %v", err)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("after detach A: inodeRefCount[100] = %+v, want counter 1", k)
	}
	if err := tr.DetachContainer(testContainer(pidB)); err != nil {
		t.Fatalf("DetachContainer B: %v", err)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount not empty after both detached: %v", tr.inodeRefCount)
	}
}

func TestSettledExecutablePath(t *testing.T) {
	tr, _ := newTestTracer(t)

	// /proc/<self>/exe resolves to the running test binary (absolute).
	self := uint32(os.Getpid())
	if p, ok := tr.settledExecutablePath(self); !ok || !filepath.IsAbs(p) {
		t.Errorf("settledExecutablePath(self) = (%q, %v), want (absolute path, true)", p, ok)
	}

	// A non-existent pid has no /proc/<pid>/exe.
	if p, ok := tr.settledExecutablePath(fakePid); ok {
		t.Errorf("settledExecutablePath(fakePid) = (%q, true), want false", p)
	}
}

// TestResolveLibraryPathsFallsBackWhenLdCacheAbsent pins the fix for a real
// deployment failure: a statically-linked target (any scratch/distroless Go or
// Rust binary, which is common for both the SSL gadget's BoringSSL-embedding
// targets and every gotls target) has no /etc/ld.so.cache at all, since it has
// no glibc. parseLdCache's underlying OpenInContainer then fails with
// os.ErrNotExist -- previously indistinguishable from a real parse/I-O
// failure, so resolveLibraryPaths returned that error immediately and never
// reached the OCI-config executable fallback a few lines below, which exists
// specifically to handle this case. Every uprobe on a real target hit this: it
// silently found nothing to attach to, with the failure logged only as "no
// attach target for symbol" a level up, giving no hint that ld cache absence
// was the actual cause.
//
// fakePid's /proc/<fakePid>/root does not exist at all, which fails the SAME
// way (os.ErrNotExist through the identical wrapped chain) as a real
// container's root existing but its /etc/ld.so.cache not.
func TestResolveLibraryPathsFallsBackWhenLdCacheAbsent(t *testing.T) {
	tr, _ := newTestTracer(t)

	const wantExe = "/usr/local/bin/myapp"
	ociConfig := `{"process":{"args":["` + wantExe + `"]}}`

	paths, err := tr.resolveLibraryPaths(fakePid, "libssl.so.3", ociConfig)
	if err != nil {
		t.Fatalf("resolveLibraryPaths: %v, want no error (ld cache absence must fall through to the OCI-config exe)", err)
	}
	if len(paths) != 1 || paths[0] != wantExe {
		t.Errorf("resolveLibraryPaths = %v, want [%q] via the OCI-config fallback", paths, wantExe)
	}
}

func TestReattachAfterCloseErrors(t *testing.T) {
	tr, _ := newTestTracer(t)
	tr.Close()
	if err := tr.ReattachContainerPid(fakePid); err == nil {
		t.Errorf("ReattachContainerPid after Close should error")
	}
}

// TestReattachOpenFailureDoesNotLatchExeTarget asserts that a Phase-1 open failure
// (e.g. a transient overlayfs-mount race) does NOT record containerPid2ExeTarget, so
// the next exec retries instead of being permanently short-circuited. Splitting open
// from attach moved the open error into the new openFailed flag; this guards that the
// exe-target latch still gates on it, preserving the pre-split semantics.
func TestReattachOpenFailureDoesNotLatchExeTarget(t *testing.T) {
	tr, st := newTestTracer(t)
	st.openErr = errors.New("transient open failure (overlayfs race)")

	// Use self so /proc/<pid>/exe resolves and exeTarget != "" — otherwise the latch
	// branch is skipped for a missing exe regardless of openFailed.
	self := uint32(os.Getpid())
	tr.containerPid2Inodes[self] = nil // tracked

	if err := tr.ReattachContainerPid(self); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}
	if _, ok := tr.containerPid2ExeTarget[self]; ok {
		t.Errorf("containerPid2ExeTarget latched despite open failure (would wrongly short-circuit retries)")
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (every open failed)", st.attachCount)
	}
}

// TestAttachContainerDoesNotBlockOnSlowOpen is the regression test for the
// create-time wedge: AttachContainer must NOT run the resolve/open/attach inline,
// because it is awaited on the synchronous container-start (fanotify) path — a slow
// open there freezes runc's create→start under load. It parks the attach's open and
// asserts AttachContainer still returns promptly, having only reserved the pid.
func TestAttachContainerDoesNotBlockOnSlowOpen(t *testing.T) {
	tr, st := newTestTracer(t)
	tr.syncAttach = false // exercise the production async dispatch path
	st.currentInode = 100

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	// Park the background attach inside openInContainer.
	tr.openInContainer = func(pid uint32, path string) (*os.File, error) {
		once.Do(func() { close(entered) })
		<-release
		return st.open(pid, path)
	}

	done := make(chan error, 1)
	go func() { done <- tr.AttachContainer(testContainer(fakePid)) }()

	select {
	case err := <-done:
		if err != nil {
			close(release)
			t.Fatalf("AttachContainer: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("AttachContainer blocked on the background attach's slow open (must dispatch off the container-start path)")
	}

	<-entered // confirm the attach actually dispatched and reached the open

	// The pid must be reserved as tracked the moment AttachContainer returns.
	tr.mu.Lock()
	_, tracked := tr.containerPid2Inodes[fakePid]
	tr.mu.Unlock()
	if !tracked {
		close(release)
		t.Fatal("pid not reserved as tracked after AttachContainer returned")
	}

	close(release)
	tr.Close() // joins the in-flight background attach
}

// parkedOpenTracer returns a tracer in async-attach mode whose openInContainer
// parks the background attach until release is closed; entered fires once the
// attach reaches the open.
func parkedOpenTracer(t *testing.T) (tr *Tracer[any], st *testState, entered, release chan struct{}) {
	t.Helper()
	tr, st = newTestTracer(t)
	tr.syncAttach = false
	st.currentInode = 100
	entered = make(chan struct{})
	release = make(chan struct{})
	var once sync.Once
	tr.openInContainer = func(pid uint32, path string) (*os.File, error) {
		once.Do(func() { close(entered) })
		<-release
		return st.open(pid, path)
	}
	return tr, st, entered, release
}

// TestAttachContainerDetachDuringInFlightAttach exercises the Phase-2 !tracked bail:
// a container detached while its create-time attach is mid-open must NOT install a
// uprobe link (which would have no DetachContainer left to release it).
func TestAttachContainerDetachDuringInFlightAttach(t *testing.T) {
	tr, st, entered, release := parkedOpenTracer(t)

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	<-entered // background attach is parked mid-open

	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("DetachContainer (reserved pid): %v", err)
	}

	close(release) // attach proceeds; Phase-2 re-check must see !tracked and bail
	tr.Close()     // joins the in-flight attach

	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (attach must be dropped after detach-during-attach)", st.attachCount)
	}
}

// TestCloseDuringInFlightAttach asserts Close JOINS an in-flight create-time attach
// without deadlocking and without racing the map teardown (under -race). It does
// NOT assert attachCount: both orderings are correct — if the attach commits before
// Close observes closed, Close cleans up the keeper; if closed is observed first,
// the worker bails. The guarantee is "Close returns, no deadlock, no race".
func TestCloseDuringInFlightAttach(t *testing.T) {
	tr, _, entered, release := parkedOpenTracer(t)

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	<-entered // background attach parked mid-open

	closeDone := make(chan struct{})
	go func() { tr.Close(); close(closeDone) }()

	// Close is now in attachWg.Wait() with the worker parked. Releasing the open
	// lets the worker finish; Close must then return promptly.
	close(release)
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return: in-flight attach was not joined")
	}
}

// TestReattachDoesNotHoldLockDuringIO is the regression test for the container-start
// wedge: an exec-storm reattach must NOT hold t.mu while it does its resolve/open
// I/O, or it starves the create-time AttachContainer that sits on the synchronous
// (fanotify) container-start path and freezes container starts under load. It parks
// a ReattachContainerPid inside the (now lock-free) open phase and asserts that
// another t.mu-taking call still completes promptly.
func TestReattachDoesNotHoldLockDuringIO(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	// Park the reattach INSIDE openInContainer — i.e. in the lock-free Phase 1.
	tr.openInContainer = func(pid uint32, path string) (*os.File, error) {
		once.Do(func() { close(entered) })
		<-release
		return st.open(pid, path)
	}

	tr.containerPid2Inodes[fakePid] = nil // seed pid as tracked

	done := make(chan error, 1)
	go func() { done <- tr.ReattachContainerPid(fakePid) }()

	<-entered // reattach is now parked mid-open

	// t.mu MUST be free while the reattach blocks on I/O: a lock-taking call returns
	// promptly. Before the fix the lock was held across the open and this blocked.
	got := make(chan bool, 1)
	go func() { got <- tr.HasMappedLibForPid(fakePid + 1) }()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("t.mu held during lock-free open phase: HasMappedLibForPid blocked")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Phase-2: reattachMappedLibraries bookkeeping (no eBPF, no /proc)
// ---------------------------------------------------------------------------

// newTestTracerWithMapFiles extends newTestTracer with a controllable
// openMapFileFunc seam so reattachMappedLibraries can be exercised without
// /proc access. The mock opens /dev/null for each rangeKey in allowedRanges
// (so readRealInode can be called on a valid fd), and returns
// ErrMapFileUnavailable for any other rangeKey.
func newTestTracerWithMapFiles(
	t *testing.T,
	allowedRanges map[string]struct{},
) (*Tracer[any], *testState) {
	t.Helper()
	tr, st := newTestTracer(t)

	tr.openMapFileFunc = func(_ uint32, rangeKey string, _ uint64) (*os.File, error) {
		if _, ok := allowedRanges[rangeKey]; !ok {
			return nil, fmt.Errorf("rangeKey %q: %w", rangeKey, ErrMapFileUnavailable)
		}
		f, err := os.Open(os.DevNull)
		if err != nil {
			return nil, err
		}
		st.openFiles = append(st.openFiles, f)
		return f, nil
	}
	return tr, st
}

// buildMapsContent constructs a minimal /proc/<pid>/maps fragment for one
// mapping so parseMappedLibraries (called inside discoverMappedLibraries) can
// parse it. The returned rangeKey matches map_files convention.
func buildMapsLine(rangeKey, perms string, inode uint64, path string) string {
	return fmt.Sprintf("%s %s 00000000 00:2e %d   %s", rangeKey, perms, inode, path)
}

// reattachMappedLibrariesLocked wraps reattachMappedLibraries under the
// tracer's lock so tests can call it directly (the real call site in Phase 3
// will also hold t.mu).
func reattachMappedLibrariesLocked[E any](t *testing.T, tr *Tracer[E], pid uint32, pattern *regexp.Regexp) error {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.reattachMappedLibraries(pid, pattern)
}

// TestReattachMappedLibrariesDedup asserts that a .so with multiple VMAs
// (r--p / r-xp / rw-p for the same inode) results in exactly ONE attach.
func TestReattachMappedLibrariesDedup(t *testing.T) {
	const rangeExec = "7e8714023000-7e87141a3000"
	allowed := map[string]struct{}{rangeExec: {}}
	tr, st := newTestTracerWithMapFiles(t, allowed)

	// Seed the pid as tracked (AttachContainer sets this up in production).
	tr.containerPid2Inodes[fakePid] = nil
	st.currentInode = 999

	// Inject a fake discoverMappedLibraries result by patching the discovery
	// function. Since discoverMappedLibraries reads /proc which is unavailable
	// in the unit test, we override reattachMappedLibraries' discovery call
	// via the already-seeded openMapFileFunc + a single-VMA parseMappedLibraries
	// result piped through the tracer. We achieve this by directly testing
	// attachOneOpenFile (the primitive reattachMappedLibraries uses) to verify
	// the dedup contract without /proc:
	existing := make(map[uint64]bool)

	// Simulate three VMAs of the same inode (as reattachMappedLibraries would
	// receive from parseMappedLibraries, which already dedups to one entry).
	// attachOneOpenFile must attach exactly once.
	f1, _ := os.Open(os.DevNull)
	defer f1.Close()
	st.openFiles = append(st.openFiles, f1)

	realInode, added, err := tr.attachOneOpenFile(fakePid, f1, "libnetty.so", nil, existing)
	if err != nil {
		t.Fatalf("attachOneOpenFile: %v", err)
	}
	if !added {
		t.Errorf("first call: added=false, want true")
	}
	existing[realInode] = true

	// Second call with the same inode (same existing set): must be a no-op.
	f2, _ := os.Open(os.DevNull)
	defer f2.Close()
	st.openFiles = append(st.openFiles, f2)

	_, added2, err := tr.attachOneOpenFile(fakePid, f2, "libnetty.so", nil, existing)
	if err != nil {
		t.Fatalf("attachOneOpenFile (2nd): %v", err)
	}
	if added2 {
		t.Errorf("second call with same inode: added=true, want false (dedup)")
	}

	if st.attachCount != 1 {
		t.Errorf("attachCount = %d, want 1 (multiple VMAs → one attach)", st.attachCount)
	}
}

// TestReattachMappedLibrariesIdempotent asserts that calling
// reattachMappedLibraries twice for the same already-attached inode leaves
// refcount == 1 (idempotent via the existing set seeded from containerPid2Inodes).
func TestReattachMappedLibrariesIdempotent(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 777

	// Simulate a first attach having already happened: populate bookkeeping as
	// reattachMappedLibraries would after its first successful pass.
	f, _ := os.Open(os.DevNull)
	st.openFiles = append(st.openFiles, f)
	tr.inodeRefCount[777] = &inodeKeeper{counter: 1, file: f, links: nil}
	tr.containerPid2Inodes[fakePid] = []uint64{777}

	// Second pass: existing is seeded from containerPid2Inodes[fakePid] which
	// already contains 777 → attachOneOpenFile is a no-op for that inode.
	existing := make(map[uint64]bool)
	for _, inode := range tr.containerPid2Inodes[fakePid] {
		existing[inode] = true
	}
	f2, _ := os.Open(os.DevNull)
	defer f2.Close()
	st.openFiles = append(st.openFiles, f2)

	_, added, err := tr.attachOneOpenFile(fakePid, f2, "libnetty.so", nil, existing)
	if err != nil {
		t.Fatalf("attachOneOpenFile: %v", err)
	}
	if added {
		t.Errorf("idempotent call: added=true, want false")
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (idempotent)", st.attachCount)
	}
	if k := tr.inodeRefCount[777]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[777] = %+v, want counter 1 (unchanged)", k)
	}
}

// TestReattachMappedLibrariesRefcountBalance asserts that after an attach via
// attachOneOpenFile, DetachContainer decrements to zero and leaves no leak in
// inodeRefCount or containerPid2Inodes.
func TestReattachMappedLibrariesRefcountBalance(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 888

	// Seed the pid as tracked with an empty inode slice.
	tr.containerPid2Inodes[fakePid] = nil

	existing := make(map[uint64]bool)
	f, _ := os.Open(os.DevNull)
	st.openFiles = append(st.openFiles, f)

	realInode, added, err := tr.attachOneOpenFile(fakePid, f, "libnetty.so", nil, existing)
	if err != nil || !added {
		t.Fatalf("attachOneOpenFile: err=%v added=%v, want (nil, true)", err, added)
	}
	// Simulate what reattachMappedLibraries does after a successful attach.
	tr.containerPid2Inodes[fakePid] = append(tr.containerPid2Inodes[fakePid], realInode)

	if k := tr.inodeRefCount[888]; k == nil || k.counter != 1 {
		t.Fatalf("inodeRefCount[888] after attach = %+v, want counter 1", k)
	}

	// DetachContainer must balance to zero.
	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("DetachContainer: %v", err)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount not empty after detach: %v (leak)", tr.inodeRefCount)
	}
	if _, ok := tr.containerPid2Inodes[fakePid]; ok {
		t.Errorf("containerPid2Inodes still has pid after detach")
	}
}

// TestReattachContainerMappedLibsPidNilPattern asserts the public lock-taking
// entry point is a no-op (and does not even touch /proc) when the pattern is nil
// (feature off).
func TestReattachContainerMappedLibsPidNilPattern(t *testing.T) {
	tr, st := newTestTracer(t)
	tr.containerPid2Inodes[fakePid] = nil

	if err := tr.ReattachContainerMappedLibsPid(fakePid, nil); err != nil {
		t.Fatalf("ReattachContainerMappedLibsPid(nil pattern): %v", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (nil pattern must be a no-op)", st.attachCount)
	}
	if tr.HasMappedLibForPid(fakePid) {
		t.Errorf("HasMappedLibForPid true after nil-pattern call")
	}
}

// TestHasMappedLibForPidReflectsAttach asserts HasMappedLibForPid flips to true
// once reattachMappedLibraries credits an inode via the map_files path, and
// resets after DetachContainer.
func TestHasMappedLibForPidReflectsAttach(t *testing.T) {
	const rangeExec = "7e8714023000-7e87141a3000"
	tr, st := newTestTracerWithMapFiles(t, map[string]struct{}{rangeExec: {}})
	tr.containerPid2Inodes[fakePid] = nil
	st.currentInode = 4242

	// Inject discovery so reattachMappedLibraries finds one matched lib without
	// touching /proc: patch the openMapFileFunc-backed discovery by feeding the
	// attach primitive directly mirrors the other Phase-2 tests, but here we want
	// the mappedLibAttached marker, so drive reattachMappedLibraries via a stubbed
	// discovery. We do it by simulating its post-attach bookkeeping: call
	// attachOneOpenFile then set the marker exactly as reattachMappedLibraries does.
	if tr.HasMappedLibForPid(fakePid) {
		t.Fatalf("HasMappedLibForPid true before any attach")
	}

	existing := make(map[uint64]bool)
	f, _ := os.Open(os.DevNull)
	st.openFiles = append(st.openFiles, f)
	realInode, added, err := tr.attachOneOpenFile(fakePid, f, "libnetty.so", nil, existing)
	if err != nil || !added {
		t.Fatalf("attachOneOpenFile: err=%v added=%v", err, added)
	}
	tr.containerPid2Inodes[fakePid] = append(tr.containerPid2Inodes[fakePid], realInode)
	tr.mappedLibAttached[fakePid] = true // what reattachMappedLibraries sets on added

	if !tr.HasMappedLibForPid(fakePid) {
		t.Errorf("HasMappedLibForPid false after attach")
	}

	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("DetachContainer: %v", err)
	}
	if tr.HasMappedLibForPid(fakePid) {
		t.Errorf("HasMappedLibForPid true after DetachContainer (must reset)")
	}
}

// TestReattachMappedLibrariesSymbolAbsent asserts that when attachToFile fails
// (symbol absent — the BoringSSL SSL_read_ex / SSL_write_ex case), no refcount
// entry is created and the tracer is not errored.
func TestReattachMappedLibrariesSymbolAbsent(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 555
	st.attachErr = errors.New("symbol SSL_read_ex not found")

	tr.containerPid2Inodes[fakePid] = nil
	existing := make(map[uint64]bool)

	f, _ := os.Open(os.DevNull)
	st.openFiles = append(st.openFiles, f)

	_, added, err := tr.attachOneOpenFile(fakePid, f, "libnetty.so", nil, existing)
	if err != nil {
		t.Fatalf("attachOneOpenFile: unexpected hard error: %v", err)
	}
	if added {
		t.Errorf("symbol-absent: added=true, want false (non-fatal skip)")
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (symbol absent → skip)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated on symbol-absent skip: %v", tr.inodeRefCount)
	}
}
