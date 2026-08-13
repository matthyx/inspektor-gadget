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
	"os"
	"testing"
	"time"
)

// withShortAttachIOTimeout shrinks the package's attachIOTimeout for the
// duration of the test, restoring it on cleanup, so these tests exercise the
// real deadline-wiring instead of waiting out the multi-second production
// value.
func withShortAttachIOTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := attachIOTimeout
	attachIOTimeout = d
	t.Cleanup(func() { attachIOTimeout = orig })
}

// stuckOpener returns an openInContainer double that blocks until release is
// closed, exactly like the fork's existing "parked open" doubles (see
// parkedOpenTracer in tracer_test.go) -- except it ALSO selects on ctx.Done(),
// mirroring what secureopen.OpenInContainer itself does internally when its
// own background goroutine is still stuck in the real, uninterruptible
// setns/openat2 syscalls. That is the actual contract under test: the tracer
// must hand every I/O call a ctx with a real deadline, and must treat that
// deadline firing as an ordinary (non-fatal) open failure, not a hang.
func stuckOpener(release <-chan struct{}) func(context.Context, uint32, string) (*os.File, error) {
	return func(ctx context.Context, _ uint32, _ string) (*os.File, error) {
		select {
		case <-release:
			return nil, errNeverReleased
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// errNeverReleased is unreachable in these tests (release is never closed);
// it exists only so stuckOpener type-checks as a real openInContainer double.
var errNeverReleased = context.Canceled

// runWithSafetyNet runs fn in a goroutine and fails the test if it does not
// return within bound. bound must be well above attachIOTimeout so a passing
// run never races it; a hang means the deadline wiring under test is broken.
func runWithSafetyNet(t *testing.T, bound time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(bound):
		t.Fatal("did not return within the safety-net bound -- the attachIOTimeout deadline was not honored (permanent hang)")
	}
}

// TestReattachContainerPidTimesOutOnStuckOpen is the regression test for
// issue #480: ReattachContainerPid's resolve/open phase previously had no
// deadline at all, so a stuck setns/openat2 parked the calling goroutine (and
// its OS thread) for the container's entire uptime. Because that goroutine is
// the one containercollection's pubsub.Publish blocks on synchronously
// (wg.Wait()), and Publish is invoked from the SINGLE goroutine draining the
// kernel exec-events ringbuf, a single wedge here did not just leak one
// goroutine: it permanently stopped exec-driven re-attach for every container
// on the node. This asserts ReattachContainerPid returns promptly once
// attachIOTimeout elapses, with no partial bookkeeping left behind.
func TestReattachContainerPidTimesOutOnStuckOpen(t *testing.T) {
	withShortAttachIOTimeout(t, 30*time.Millisecond)
	tr, st := newTestTracer(t)

	release := make(chan struct{}) // never closed: the open is permanently stuck
	tr.openInContainer = stuckOpener(release)

	tr.containerPid2Inodes[fakePid] = nil // seed as tracked, mirroring AttachContainer

	var err error
	runWithSafetyNet(t, 5*time.Second, func() {
		err = tr.ReattachContainerPid(fakePid)
	})

	// A timed-out open is treated exactly like any other open failure (e.g.
	// TestReattachSkipsNonELF): non-fatal, no error surfaced to the exec-event
	// caller.
	if err != nil {
		t.Errorf("ReattachContainerPid: %v, want nil (a timed-out open is a non-fatal skip)", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (nothing was ever actually opened)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated by a timed-out attach: %v", tr.inodeRefCount)
	}
	inodes, tracked := tr.containerPid2Inodes[fakePid]
	if !tracked {
		t.Fatal("pid no longer tracked after a timed-out reattach (would orphan a future DetachContainer)")
	}
	if len(inodes) != 0 {
		t.Errorf("containerPid2Inodes[pid] = %v, want empty (no partial attach survives a timeout)", inodes)
	}
	if _, latched := tr.containerPid2ExeTarget[fakePid]; latched {
		t.Error("containerPid2ExeTarget latched despite a timed-out open (would permanently skip retrying this pid)")
	}
}

// TestReattachContainerPidRecoversAfterTimeout asserts the timeout path is not
// a permanent wedge for the PID itself: once the stuck target clears (the
// process execs into something openable, or a later exec re-triggers
// resolution), a normal ReattachContainerPid call still attaches successfully
// using the exact bookkeeping a timeout run left behind.
func TestReattachContainerPidRecoversAfterTimeout(t *testing.T) {
	withShortAttachIOTimeout(t, 30*time.Millisecond)
	tr, st := newTestTracer(t)
	st.currentInode = 100

	release := make(chan struct{})
	tr.openInContainer = stuckOpener(release)
	tr.containerPid2Inodes[fakePid] = nil

	runWithSafetyNet(t, 5*time.Second, func() {
		if err := tr.ReattachContainerPid(fakePid); err != nil {
			t.Errorf("ReattachContainerPid (timeout run): %v", err)
		}
	})

	// Swap in a fast opener, as if the stuck target had since cleared.
	tr.openInContainer = st.open

	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid (recovery run): %v", err)
	}
	if st.attachCount != 1 {
		t.Errorf("attachCount = %d after recovery, want 1", st.attachCount)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pid] = %v after recovery, want [100]", got)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[100] = %+v after recovery, want counter 1", k)
	}
	close(release) // let the first (abandoned) goroutine's select exit; avoids a t.Cleanup leak warning
}

// TestAttachContainerWorkTimesOutOnStuckOpen is the create-time counterpart:
// attachContainerWork's caller (AttachContainer's dispatch goroutine, or the
// AttachProg pending-drain path in inline/test mode) holds a slot in the
// process-wide 2-slot attachSem for the duration of this call. Before this
// fix, a single wedged container's create-time attach would occupy that slot
// forever, and since only 2 slots exist process-wide, EVERY subsequent
// container's create-time attach queues behind it permanently (this is
// exactly what the issue's SIGQUIT dump found: 15 goroutines parked on the
// semaphore for 318-526 minutes). Run with syncAttach=true so
// attachContainerWork executes inline and AttachContainer's own return can be
// asserted to happen within the bound.
func TestAttachContainerWorkTimesOutOnStuckOpen(t *testing.T) {
	withShortAttachIOTimeout(t, 30*time.Millisecond)
	tr, st := newTestTracer(t)

	release := make(chan struct{})
	tr.openInContainer = stuckOpener(release)

	var attachErr error
	runWithSafetyNet(t, 5*time.Second, func() {
		attachErr = tr.AttachContainer(testContainer(fakePid))
	})
	if attachErr != nil {
		t.Fatalf("AttachContainer: %v", attachErr)
	}

	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (open never completed)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated by a timed-out create-time attach: %v", tr.inodeRefCount)
	}
	inodes, tracked := tr.containerPid2Inodes[fakePid]
	if !tracked {
		t.Fatal("pid not tracked after a timed-out create-time attach (DetachContainer would error as \"not attached\")")
	}
	if len(inodes) != 0 {
		t.Errorf("containerPid2Inodes[pid] = %v, want empty", inodes)
	}

	// DetachContainer must still balance cleanly: this is the concrete shape
	// of "no leaked/inconsistent state" for a pid whose only attach attempt
	// timed out.
	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Errorf("DetachContainer after timed-out attach: %v", err)
	}
	close(release)
}
