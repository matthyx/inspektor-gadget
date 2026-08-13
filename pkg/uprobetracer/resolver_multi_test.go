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
	"context"
	"debug/elf"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf/link"
)

// TestAttachOffsetsResolverFromVarAcceptsEveryShape is the most load-bearing
// test in this file.
//
// The resolver arrives through an untyped GadgetContext variable set by a
// different module. A shape this function fails to recognise is not a compile
// error and not a runtime error — the value is dropped and the tracer quietly
// reverts to symbol-name attach, which on the stripped static targets this
// mechanism exists for cannot bind at all. The embedder's feature would stop
// working with nothing logged anywhere to say why.
//
// So the two legacy shapes are asserted here alongside the two new ones: if
// anyone later "tidies" them away, this fails loudly instead of the field
// failing silently.
func TestAttachOffsetsResolverFromVarAcceptsEveryShape(t *testing.T) {
	const wantOffset = uint64(0x1234)

	legacyFunc := func(_ *os.File, _ uint32, _ string, _ elf.Machine, _ string) (uint64, error) {
		return wantOffset, nil
	}
	multiFunc := func(_ AttachRequest) ([]uint64, error) {
		return []uint64{wantOffset}, nil
	}

	tests := []struct {
		name string
		v    any
	}{
		{"legacy named type", AttachOffsetResolver(legacyFunc)},
		{"legacy bare signature", legacyFunc},
		{"multi named type", AttachOffsetsResolver(multiFunc)},
		{"multi bare signature", multiFunc},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver, err := AttachOffsetsResolverFromVar(tc.v)
			if err != nil {
				t.Fatalf("AttachOffsetsResolverFromVar: %v", err)
			}
			offsets, err := resolver(AttachRequest{})
			if err != nil {
				t.Fatalf("resolver: %v", err)
			}
			if len(offsets) != 1 || offsets[0] != wantOffset {
				t.Errorf("offsets = %#x, want [%#x]", offsets, wantOffset)
			}
		})
	}
}

func TestAttachOffsetsResolverFromVarRejectsOtherTypes(t *testing.T) {
	for _, v := range []any{nil, 42, "resolver", func() {}} {
		if _, err := AttachOffsetsResolverFromVar(v); err == nil {
			t.Errorf("AttachOffsetsResolverFromVar(%T) accepted a value it cannot call", v)
		}
	}
}

// A legacy resolver's error must stay an error through the adapter rather than
// becoming an empty-but-successful result, which the caller would read as "no
// offsets" and treat identically — same outcome here, but it would hide the
// reason from the fail-open log line.
func TestAdaptSingleOffsetResolverPropagatesError(t *testing.T) {
	sentinel := errors.New("not covered")
	resolver := adaptSingleOffsetResolver(func(_ *os.File, _ uint32, _ string, _ elf.Machine, _ string) (uint64, error) {
		return 0, sentinel
	})
	if _, err := resolver(AttachRequest{}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want %v", err, sentinel)
	}
	if got := adaptSingleOffsetResolver(nil); got != nil {
		t.Error("adaptSingleOffsetResolver(nil) returned a non-nil resolver")
	}
}

// TestMultiOffsetResolverReceivesProgName covers the field that makes the Go
// crypto/tls capture possible at all: two tracers share the symbol
// crypto/tls.(*Conn).Read — one probing the entry, one probing each RET — so
// without ProgName a resolver sees identical requests and cannot tell which
// offsets to hand back.
func TestMultiOffsetResolverReceivesProgName(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "crypto/tls.(*Conn).Read")
	tr.progName = "gotls_read_entry"
	st.currentInode = 610

	var got AttachRequest
	tr.SetAttachOffsetsResolver(func(req AttachRequest) ([]uint64, error) {
		got = req
		return []uint64{0x9000}, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	if got.ProgName != "gotls_read_entry" {
		t.Errorf("ProgName = %q, want %q", got.ProgName, "gotls_read_entry")
	}
	if got.Symbol != "crypto/tls.(*Conn).Read" {
		t.Errorf("Symbol = %q, want the tracer's attach symbol", got.Symbol)
	}
	if got.File == nil {
		t.Error("File was not populated")
	}
	if got.BuildID == "" {
		t.Error("BuildID was not populated")
	}
	if st.lastOffset == nil || *st.lastOffset != 0x9000 {
		t.Errorf("attach offset = %v, want 0x9000", st.lastOffset)
	}
}

// TestMultiOffsetBindsEveryOffset is the seam test for the multi-link rework:
// N resolved offsets must become exactly N bound probes on ONE inode, and the
// whole set must be released exactly once on teardown.
//
// Seven is not arbitrary -- it is the number of RET instructions in
// crypto/tls.(*Conn).Read in a real go1.25.0/amd64 binary, which is the case
// this rework exists for. Go's moving stacks rule out a uretprobe, so each
// return needs its own entry probe.
func TestMultiOffsetBindsEveryOffset(t *testing.T) {
	const wantLinks = 7
	offsets := []uint64{0x9000, 0x9100, 0x9200, 0x9300, 0x9400, 0x9500, 0x9600}

	tr, st, _ := newResolverTracer(t, ProgUprobe, "crypto/tls.(*Conn).Read")
	st.currentInode = 611
	tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) {
		return offsets, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	// One inode, one attach call, seven links -- not seven attach calls.
	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1", st.attachCount)
	}
	if len(st.lastOffsets) != wantLinks {
		t.Errorf("resolver offsets reaching the attach = %d, want %d", len(st.lastOffsets), wantLinks)
	}
	keeper, ok := tr.inodeRefCount[st.currentInode]
	if !ok {
		t.Fatal("no inodeKeeper was created")
	}
	if got := len(keeper.links); got != wantLinks {
		t.Errorf("keeper holds %d links, want %d", got, wantLinks)
	}
	if keeper.counter != 1 {
		t.Errorf("keeper.counter = %d, want 1 -- the refcount counts PIDs, not links", keeper.counter)
	}
	if got := tr.Stats().LinksAttached; got != wantLinks {
		t.Errorf("LinksAttached = %d, want %d", got, wantLinks)
	}
	if got := tr.Stats().LinksClosed; got != 0 {
		t.Errorf("LinksClosed = %d before teardown, want 0", got)
	}

	// Teardown must release all seven, exactly once, and drop the keeper.
	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("DetachContainer: %v", err)
	}
	stats := tr.Stats()
	if stats.LinksClosed != wantLinks {
		t.Errorf("LinksClosed = %d after detach, want %d", stats.LinksClosed, wantLinks)
	}
	if stats.LinksAttached != stats.LinksClosed {
		t.Errorf("link leak: attached %d, closed %d", stats.LinksAttached, stats.LinksClosed)
	}
	if _, still := tr.inodeRefCount[st.currentInode]; still {
		t.Error("the keeper survived the last reference being dropped")
	}

	// Close after a full detach must not double-close what detach released.
	tr.Close()
	if got := tr.Stats().LinksClosed; got != wantLinks {
		t.Errorf("LinksClosed = %d after Close following detach, want %d (no double-close)", got, wantLinks)
	}
}

// The refcount counts PIDs and the links count probe sites; a second container
// sharing the inode must bump the former without binding more of the latter,
// and must not release anything while the first container still references it.
func TestMultiOffsetRefcountIsPerPidNotPerLink(t *testing.T) {
	const wantLinks = 7
	const secondPid = fakePid + 1

	tr, st, _ := newResolverTracer(t, ProgUprobe, "crypto/tls.(*Conn).Read")
	st.currentInode = 612
	tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) {
		return []uint64{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, nil
	})

	for _, pid := range []uint32{fakePid, secondPid} {
		if err := tr.AttachContainer(testContainer(pid)); err != nil {
			t.Fatalf("AttachContainer(%d): %v", pid, err)
		}
	}

	keeper := tr.inodeRefCount[st.currentInode]
	if keeper == nil {
		t.Fatal("no inodeKeeper was created")
	}
	if keeper.counter != 2 {
		t.Errorf("keeper.counter = %d after two containers, want 2", keeper.counter)
	}
	if got := len(keeper.links); got != wantLinks {
		t.Errorf("keeper holds %d links after two containers, want %d -- the second must not re-bind", got, wantLinks)
	}
	if got := tr.Stats().LinksAttached; got != wantLinks {
		t.Errorf("LinksAttached = %d, want %d -- the inode is probed once regardless of PID count", got, wantLinks)
	}

	// First detach drops a reference but must release nothing.
	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("DetachContainer(first): %v", err)
	}
	if got := tr.Stats().LinksClosed; got != 0 {
		t.Fatalf("LinksClosed = %d after the first of two detaches, want 0 -- the other container is still instrumented", got)
	}

	// Last detach releases the whole set.
	if err := tr.DetachContainer(testContainer(secondPid)); err != nil {
		t.Fatalf("DetachContainer(second): %v", err)
	}
	stats := tr.Stats()
	if stats.LinksClosed != wantLinks {
		t.Errorf("LinksClosed = %d after the last detach, want %d", stats.LinksClosed, wantLinks)
	}
	if stats.LinksAttached != stats.LinksClosed {
		t.Errorf("link leak: attached %d, closed %d", stats.LinksAttached, stats.LinksClosed)
	}
}

// A failed bind must leave no keeper, no reference, and no leaked descriptor.
// This is the wholesale-failure case -- the test seam replaces the whole binder,
// so the attach either succeeds or fails as a unit here; the genuinely partial
// case lives in TestBindAllRollsBackOnPartialFailure, which reaches the loop
// directly.
func TestFailedBindTakesNoReference(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "crypto/tls.(*Conn).Read")
	st.currentInode = 613
	st.attachErr = errors.New("symbol absent")
	tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) {
		return []uint64{0x1, 0x2, 0x3}, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	if _, ok := tr.inodeRefCount[st.currentInode]; ok {
		t.Error("a keeper was created for an attach that failed")
	}
	stats := tr.Stats()
	if stats.LinksAttached != 0 {
		t.Errorf("LinksAttached = %d after a failed attach, want 0", stats.LinksAttached)
	}
	if stats.LinksAttached != stats.LinksClosed {
		t.Errorf("link leak on the failure path: attached %d, closed %d", stats.LinksAttached, stats.LinksClosed)
	}
}

// TestBindAllRollsBackOnPartialFailure exercises the rollback loop directly.
//
// It cannot be reached through the attachToFile test seam -- that seam replaces
// the entire binder, so a mocked attach either succeeds or fails as a whole and
// never binds three of seven. bindAll takes its bind function as a parameter
// precisely so this case is reachable without a kernel.
func TestBindAllRollsBackOnPartialFailure(t *testing.T) {
	tests := []struct {
		name         string
		failAt       int
		wantRollback uint64
	}{
		{"fails on the first offset", 0, 0},
		{"fails midway", 3, 3},
		{"fails on the last offset", 6, 6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, _ := newTestTracer(t)
			offsets := []uint64{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}

			calls := 0
			links, err := tr.bindAll(offsets, func(_ *uint64) (link.Link, error) {
				defer func() { calls++ }()
				if calls == tc.failAt {
					return nil, errors.New("bind refused")
				}
				return nil, nil
			})

			if err == nil {
				t.Fatal("bindAll succeeded despite a failing bind")
			}
			if links != nil {
				t.Errorf("bindAll returned %d links on failure, want none", len(links))
			}
			if calls != tc.failAt+1 {
				t.Errorf("bind called %d times, want %d -- it must stop at the failure", calls, tc.failAt+1)
			}
			stats := tr.Stats()
			if stats.LinksRolledBack != tc.wantRollback {
				t.Errorf("LinksRolledBack = %d, want %d", stats.LinksRolledBack, tc.wantRollback)
			}
			if stats.AttachRollbacks != 1 {
				t.Errorf("AttachRollbacks = %d, want 1", stats.AttachRollbacks)
			}
			if stats.LinksAttached != 0 {
				t.Errorf("LinksAttached = %d after a rolled-back bind, want 0 -- nothing reached a keeper", stats.LinksAttached)
			}
		})
	}
}

// TestBindSitesWithoutOffsetsBindsExactlyOneProbe covers the path every gadget
// that does NOT use offset attach takes, ssl included.
//
// The single-element result is load-bearing, not a formality. Returning a nil
// slice would still bind the probe in the kernel, but nothing would hold the
// link and the runtime finalizer would close it moments later -- the probe
// detaches by itself, silently, with no error anywhere. The link counters would
// not notice either: an empty slice balances against itself on teardown, so
// LinksAttached == LinksClosed stays true while nothing is actually attached.
//
// Found in review: this branch previously sat below the attachToFile seam,
// which every test replaces wholesale, so nothing reached it.
func TestBindSitesWithoutOffsetsBindsExactlyOneProbe(t *testing.T) {
	tr, _ := newTestTracer(t)

	calls := 0
	var sawOffset *uint64
	sawOffsetSet := false
	links, err := tr.bindSites(nil, func(offset *uint64) (link.Link, error) {
		calls++
		sawOffset = offset
		sawOffsetSet = true
		return nil, nil
	})
	if err != nil {
		t.Fatalf("bindSites: %v", err)
	}
	if calls != 1 {
		t.Errorf("bind called %d times, want 1", calls)
	}
	if !sawOffsetSet || sawOffset != nil {
		t.Errorf("bind received offset %v, want nil -- symbol-name attach passes no offset", sawOffset)
	}
	if len(links) != 1 {
		t.Fatalf("bindSites returned %d links, want exactly 1 -- a nil slice would let the finalizer silently detach the probe", len(links))
	}
	if got := tr.Stats().AttachRollbacks; got != 0 {
		t.Errorf("AttachRollbacks = %d, want 0", got)
	}
}

// An empty offset set propagates a bind failure rather than reporting success
// with nothing bound.
func TestBindSitesWithoutOffsetsPropagatesFailure(t *testing.T) {
	tr, _ := newTestTracer(t)
	links, err := tr.bindSites(nil, func(_ *uint64) (link.Link, error) {
		return nil, errors.New("symbol absent")
	})
	if err == nil {
		t.Fatal("bindSites succeeded despite a failing bind")
	}
	if links != nil {
		t.Errorf("bindSites returned %d links on failure, want none", len(links))
	}
}

// With offsets, bindSites delegates to the all-or-nothing loop.
func TestBindSitesWithOffsetsBindsEachOne(t *testing.T) {
	tr, _ := newTestTracer(t)
	offsets := []uint64{0x10, 0x20, 0x30}

	calls := 0
	links, err := tr.bindSites(offsets, func(offset *uint64) (link.Link, error) {
		calls++
		if offset == nil {
			t.Error("bind received a nil offset while offsets were supplied")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("bindSites: %v", err)
	}
	if calls != len(offsets) || len(links) != len(offsets) {
		t.Errorf("bind called %d times returning %d links, want %d of each", calls, len(links), len(offsets))
	}
}

// The success path binds every offset, in order, and reports no rollback.
func TestBindAllBindsEveryOffsetInOrder(t *testing.T) {
	tr, _ := newTestTracer(t)
	offsets := []uint64{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70}

	var seen []uint64
	links, err := tr.bindAll(offsets, func(offset *uint64) (link.Link, error) {
		seen = append(seen, *offset)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("bindAll: %v", err)
	}
	if len(links) != len(offsets) {
		t.Errorf("bindAll returned %d links, want %d", len(links), len(offsets))
	}
	for i := range offsets {
		if seen[i] != offsets[i] {
			t.Errorf("bind %d saw offset %#x, want %#x", i, seen[i], offsets[i])
		}
	}
	if got := tr.Stats().AttachRollbacks; got != 0 {
		t.Errorf("AttachRollbacks = %d on the success path, want 0", got)
	}
}

// close() must be safe to call twice: the second call releases nothing rather
// than closing the same links again. DetachContainer followed by Close is the
// ordinary way this happens.
func TestKeeperCloseIsIdempotent(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	keeper := &inodeKeeper{counter: 1, file: f, links: make([]link.Link, 4)}

	if got := keeper.close(); got != 4 {
		t.Errorf("first close released %d links, want 4", got)
	}
	if got := keeper.close(); got != 0 {
		t.Errorf("second close released %d links, want 0 -- a double-close", got)
	}
}

// An empty slice and an error both mean "no opinion on this candidate", and
// both must fall back to symbol-name attach rather than skipping the target.
func TestResolverDeclineFallsBackToSymbolName(t *testing.T) {
	tests := []struct {
		name     string
		resolver AttachOffsetsResolver
	}{
		{"error", func(_ AttachRequest) ([]uint64, error) { return nil, errors.New("not covered") }},
		{"no offsets", func(_ AttachRequest) ([]uint64, error) { return nil, nil }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_read")
			st.currentInode = 612
			tr.SetAttachOffsetsResolver(tc.resolver)

			if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
				t.Fatalf("AttachContainer: %v", err)
			}
			if st.attachCount != 1 {
				t.Fatalf("attachCount = %d, want 1 (symbol-name attach)", st.attachCount)
			}
			if st.lastOffset != nil {
				t.Errorf("attach offset = %v, want nil (attach by symbol name)", st.lastOffset)
			}
			if got := tr.Stats().ResolverFailOpen; got != 1 {
				t.Errorf("ResolverFailOpen = %d, want 1", got)
			}
		})
	}
}

// commitOpenedTargets is the section of the attach path that runs under t.mu,
// the lock that gates container starts. Its hold time is the budgeted quantity,
// so it has to actually be recorded.
func TestCommitOpenedTargetsRecordsMuHold(t *testing.T) {
	tr, st, elfFile := newResolverTracer(t, ProgUprobe, "SSL_read")
	st.currentInode = 613

	f, err := os.Open(elfFile.Name())
	if err != nil {
		t.Fatalf("opening synthetic ELF: %v", err)
	}
	st.openFiles = append(st.openFiles, f)

	if got := tr.Stats().MuHold.Count; got != 0 {
		t.Fatalf("MuHold.Count = %d before any commit, want 0", got)
	}

	tr.mu.Lock()
	tr.containerPid2Inodes[fakePid] = nil
	tr.commitOpenedTargets(fakePid, []openedTarget{{file: f, label: "/lib/libtest.so"}})
	tr.mu.Unlock()

	if got := tr.Stats().MuHold.Count; got != 1 {
		t.Errorf("MuHold.Count = %d after one commit, want 1", got)
	}
}

// The create-time attach path deliberately does not consult the resolver. That
// omission rests on an assumption about what is reachable at create time, and
// an unchecked assumption on a fail-open path is how coverage disappears
// quietly — so it is counted whenever a resolver is registered.
func TestCreateTimeAttachCountsResolverBypass(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_read")
	st.currentInode = 614

	tr.mu.Lock()
	_, _, err := tr.attachOneFile(context.Background(), fakePid, "/lib/libtest.so", map[uint64]bool{})
	tr.mu.Unlock()
	if err != nil {
		t.Fatalf("attachOneFile: %v", err)
	}
	if got := tr.Stats().CreateTimeAttachUnresolved; got != 0 {
		t.Errorf("CreateTimeAttachUnresolved = %d with no resolver registered, want 0", got)
	}

	tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) { return []uint64{0x10}, nil })
	st.currentInode = 615

	tr.mu.Lock()
	_, _, err = tr.attachOneFile(context.Background(), fakePid, "/lib/libtest.so", map[uint64]bool{})
	tr.mu.Unlock()
	if err != nil {
		t.Fatalf("attachOneFile: %v", err)
	}
	if got := tr.Stats().CreateTimeAttachUnresolved; got != 1 {
		t.Errorf("CreateTimeAttachUnresolved = %d, want 1", got)
	}
}

// openFDCount reports how many file descriptors this process holds. It is the
// only way to observe the *os.File ownership rule from outside: the rule is
// "whoever receives the file closes it, exactly once", and a violation shows up
// as a descriptor that outlives the attach or as a close of one already closed.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestFileOwnershipIsSingularAcrossEveryBranch pins the invariant that made the
// multi-link rework risky: an opened candidate has exactly ONE owner on every
// path through the attach.
//
// Before this rework the ownership was split -- attachOneOpenFile closed the
// file on its own paths, while the caller closed it on the multi-offset refusal
// branch. Both failure modes of that split are silent: a double close returns a
// descriptor to the pool that something else then reuses, surfacing much later
// as an operation on the wrong inode; a missed close leaks a descriptor on the
// container-attach path. Neither raises an error where it happens.
//
// So this measures descriptors rather than trusting the code to be consistent.
func TestFileOwnershipIsSingularAcrossEveryBranch(t *testing.T) {
	sevenOffsets := []uint64{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}

	tests := []struct {
		name string
		run  func(t *testing.T, tr *Tracer[any], st *testState)
	}{
		{
			name: "multi-offset attach succeeds, released on Close",
			run: func(t *testing.T, tr *Tracer[any], st *testState) {
				st.currentInode = 900
				if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
					t.Fatalf("AttachContainer: %v", err)
				}
			},
		},
		{
			name: "attach fails, file released immediately",
			run: func(t *testing.T, tr *Tracer[any], st *testState) {
				st.currentInode = 901
				st.attachErr = errors.New("symbol absent")
				if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
					t.Fatalf("AttachContainer: %v", err)
				}
			},
		},
		{
			name: "inode dedup bumps the refcount and releases the extra file",
			run: func(t *testing.T, tr *Tracer[any], st *testState) {
				st.currentInode = 902
				for _, pid := range []uint32{fakePid, fakePid + 1} {
					if err := tr.AttachContainer(testContainer(pid)); err != nil {
						t.Fatalf("AttachContainer(%d): %v", pid, err)
					}
				}
			},
		},
		{
			name: "inode read fails, file released immediately",
			run: func(t *testing.T, tr *Tracer[any], st *testState) {
				st.inodeErr = errors.New("no inode")
				if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
					t.Fatalf("AttachContainer: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, st, _ := newResolverTracer(t, ProgUprobe, "crypto/tls.(*Conn).Read")
			tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) {
				return sevenOffsets, nil
			})

			before := openFDCount(t)
			tc.run(t, tr, st)
			// Close is the only teardown that must release everything still
			// held; every other branch has to have released as it went.
			tr.Close()
			after := openFDCount(t)

			if after != before {
				t.Errorf("descriptor count %d -> %d: %d not released", before, after, after-before)
			}
			stats := tr.Stats()
			if stats.LinksAttached != stats.LinksClosed {
				t.Errorf("link leak: attached %d, closed %d", stats.LinksAttached, stats.LinksClosed)
			}
		})
	}
}
