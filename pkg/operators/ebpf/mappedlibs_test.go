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

package ebpfoperator

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// shrinkBackoff replaces the production backoff schedule with near-zero delays
// for the duration of a test, so the cap-reached path does not wait ~20s.
func shrinkBackoff(t *testing.T) {
	t.Helper()
	orig := mappedLibBackoffSchedule
	mappedLibBackoffSchedule = func() []time.Duration {
		d := make([]time.Duration, mappedLibRetryAttempts-1)
		for i := range d {
			d[i] = time.Millisecond
		}
		return d
	}
	t.Cleanup(func() { mappedLibBackoffSchedule = orig })
}

// shrinkCeiling replaces the production wall-clock retry ceiling for the
// duration of a test, mirroring shrinkBackoff. mappedLibRetryCeiling is a plain
// package var, deliberately not an atomic: tests reassign it directly, and the
// ordering against the timer goroutine's reads is established by the test's own
// mutex/channel handshakes (see the ceiling sub-test below).
func shrinkCeiling(t *testing.T, d time.Duration) {
	t.Helper()
	orig := mappedLibRetryCeiling
	mappedLibRetryCeiling = d
	t.Cleanup(func() { mappedLibRetryCeiling = orig })
}

// newTimerInstance returns a minimal ebpfInstance wired for the retry-timer
// tests: a non-nil pattern (feature on), a fresh registry, a done channel, and
// an injected mappedLibPass mock.
func newTimerInstance(pass func(containerPid uint32, execPids []uint32, pattern *regexp.Regexp, deadline time.Time) (bool, []uint32)) *ebpfInstance {
	return &ebpfInstance{
		logger:           logger.DefaultLogger(),
		done:             make(chan struct{}),
		mappedLibPattern: regexp.MustCompile(`^libtest\.so$`),
		mappedLibTimers:  newMappedLibTimerRegistry(),
		mappedLibPass:    pass,
	}
}

// waitFor polls cond until true or the deadline; fails the test otherwise.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

// TestMappedLibTimerStopsOnSuccess: the timer fans out once, the pass reports
// attached, the goroutine exits immediately and retires the pid.
func TestMappedLibTimerStopsOnSuccess(t *testing.T) {
	shrinkBackoff(t)
	var calls atomic.Int32
	i := newTimerInstance(func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		calls.Add(1)
		return true, nil // attached on the first pass
	})

	i.armMappedLibTimer(42, 42)
	i.mappedLibTimers.wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("pass calls = %d, want 1 (stop on first success)", got)
	}
	// arm() on a live entry also refreshes that entry's scan target/generation
	// as a side effect; harmless here since this call is only a read-only
	// "is this still armed?" probe after the timer has already stopped.
	if _, armed := i.mappedLibTimers.arm(42, 42); !armed {
		t.Errorf("pid still armed after success; expected retired")
	}
}

// TestReattachContainerArmsTimerWithExecPid is a regression guard for the
// execPid-threading fix: ReattachContainer (the real production entry point,
// called from the container-hook exec path) must arm the mapped-lib retry
// timer with the settled execPid, not container.ContainerPid(). Every other
// test in this file calls armMappedLibTimer directly with containerPid ==
// execPid, so none of them would catch a regression that silently reverted
// ebpf.go's `i.armMappedLibTimer(container.ContainerPid(), execPid)` call
// back to `i.armMappedLibTimer(container.ContainerPid(), container.ContainerPid())`.
// This test uses distinct values for the two pids so such a revert fails it.
func TestReattachContainerArmsTimerWithExecPid(t *testing.T) {
	shrinkBackoff(t)
	var calls atomic.Int32
	var gotContainerPid uint32
	var gotExecPids []uint32
	i := newTimerInstance(func(containerPid uint32, execPids []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		calls.Add(1)
		gotContainerPid, gotExecPids = containerPid, slices.Clone(execPids)
		return true, nil // attached on the first pass
	})

	const containerPid, execPid uint32 = 100, 200
	container := &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{ContainerPID: containerPid},
		},
	}

	if err := i.ReattachContainer(container, execPid); err != nil {
		t.Fatalf("ReattachContainer: %v", err)
	}
	i.mappedLibTimers.wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("mappedLibPass calls = %d, want 1", got)
	}
	if gotContainerPid != containerPid {
		t.Errorf("mappedLibPass containerPid = %d, want %d", gotContainerPid, containerPid)
	}
	if want := []uint32{execPid}; !slices.Equal(gotExecPids, want) {
		t.Errorf("mappedLibPass execPids = %v, want %v (the settled exec pid, not container.ContainerPid())", gotExecPids, want)
	}
}

// TestMappedLibTimerStopsAtCap: the pass never reports attached, so the timer
// runs exactly mappedLibRetryAttempts passes then gives up and retires.
func TestMappedLibTimerStopsAtCap(t *testing.T) {
	shrinkBackoff(t)
	var calls atomic.Int32
	i := newTimerInstance(func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		calls.Add(1)
		return false, nil // never attaches
	})

	i.armMappedLibTimer(7, 7)
	i.mappedLibTimers.wg.Wait()

	if got := calls.Load(); got != mappedLibRetryAttempts {
		t.Errorf("pass calls = %d, want %d (cap)", got, mappedLibRetryAttempts)
	}
}

// TestMappedLibTimerDoubleArmDedup: arming twice for the same pid starts only one
// goroutine.
func TestMappedLibTimerDoubleArmDedup(t *testing.T) {
	shrinkBackoff(t)
	var calls atomic.Int32
	block := make(chan struct{})
	i := newTimerInstance(func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		calls.Add(1)
		<-block // hold the first goroutine so the second arm sees it active
		return true, nil
	})

	i.armMappedLibTimer(99, 99)
	waitFor(t, func() bool { return calls.Load() == 1 }, "first pass to start")
	i.armMappedLibTimer(99, 99) // must NOT arm a second goroutine

	close(block)
	i.mappedLibTimers.wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("pass calls = %d, want 1 (double-arm must dedup)", got)
	}
}

// TestMappedLibTimerCancelOnDetach: cancelling a pid mid-flight stops its
// goroutine without running to the cap.
func TestMappedLibTimerCancelOnDetach(t *testing.T) {
	shrinkBackoff(t)
	// Make the backoff long so cancel races ahead of the next pass.
	orig := mappedLibBackoffSchedule
	mappedLibBackoffSchedule = func() []time.Duration {
		d := make([]time.Duration, mappedLibRetryAttempts-1)
		for i := range d {
			d[i] = time.Hour
		}
		return d
	}
	t.Cleanup(func() { mappedLibBackoffSchedule = orig })

	var calls atomic.Int32
	i := newTimerInstance(func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		calls.Add(1)
		return false, nil // never attaches; would otherwise sleep 1h
	})

	i.armMappedLibTimer(5, 5)
	waitFor(t, func() bool { return calls.Load() == 1 }, "first pass")
	i.mappedLibTimers.cancel(5)
	i.mappedLibTimers.wg.Wait() // must return (goroutine exited via stop)

	if got := calls.Load(); got != 1 {
		t.Errorf("pass calls = %d, want 1 (cancel before 2nd pass)", got)
	}
}

// TestMappedLibTimerCancelAllNoLeak: Close-style cancelAll stops all goroutines
// and leaves no goroutine leak relative to baseline.
func TestMappedLibTimerCancelAllNoLeak(t *testing.T) {
	orig := mappedLibBackoffSchedule
	mappedLibBackoffSchedule = func() []time.Duration {
		d := make([]time.Duration, mappedLibRetryAttempts-1)
		for i := range d {
			d[i] = time.Hour
		}
		return d
	}
	t.Cleanup(func() { mappedLibBackoffSchedule = orig })

	var started sync.WaitGroup
	i := newTimerInstance(func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		started.Done()
		return false, nil
	})

	baseline := runtime.NumGoroutine()
	const n = 10
	started.Add(n)
	for pid := uint32(1); pid <= n; pid++ {
		i.armMappedLibTimer(pid, pid)
	}
	started.Wait() // all n goroutines reached their first pass

	i.mappedLibTimers.cancelAll() // closes all stops + joins

	waitFor(t, func() bool { return runtime.NumGoroutine() <= baseline+1 }, "goroutines to drain to baseline")
}

// TestMappedLibTimerNilPatternNoArm: with the feature off (nil pattern), no
// goroutine is ever armed.
func TestMappedLibTimerNilPatternNoArm(t *testing.T) {
	var calls atomic.Int32
	i := &ebpfInstance{
		logger:           logger.DefaultLogger(),
		done:             make(chan struct{}),
		mappedLibPattern: nil, // feature OFF
		mappedLibTimers:  newMappedLibTimerRegistry(),
		mappedLibPass: func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
			calls.Add(1)
			return false, nil
		},
	}

	i.armMappedLibTimer(1, 1)
	i.mappedLibTimers.wg.Wait() // returns immediately: nothing armed

	if got := calls.Load(); got != 0 {
		t.Errorf("pass calls = %d, want 0 (nil pattern must not arm)", got)
	}
	// arm() on a live entry also refreshes that entry's scan target/generation
	// as a side effect; harmless here since the feature is off and nothing was
	// ever armed, so this is only a read-only "is this still armed?" probe.
	if _, armed := i.mappedLibTimers.arm(1, 1); !armed {
		t.Errorf("pid armed despite nil pattern")
	}
}

// TestMappedLibTimerDoneChannelStops: closing i.done stops an in-flight timer.
func TestMappedLibTimerDoneChannelStops(t *testing.T) {
	orig := mappedLibBackoffSchedule
	mappedLibBackoffSchedule = func() []time.Duration {
		d := make([]time.Duration, mappedLibRetryAttempts-1)
		for i := range d {
			d[i] = time.Hour
		}
		return d
	}
	t.Cleanup(func() { mappedLibBackoffSchedule = orig })

	var calls atomic.Int32
	i := newTimerInstance(func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		calls.Add(1)
		return false, nil
	})

	i.armMappedLibTimer(3, 3)
	waitFor(t, func() bool { return calls.Load() == 1 }, "first pass")
	close(i.done)
	i.mappedLibTimers.wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("pass calls = %d, want 1 (done closes before 2nd pass)", got)
	}
}

// mappedLibPassCall records one mappedLibPass invocation's arguments, so a test
// can assert WHICH pids a given pass actually scanned (not just how many
// passes ran). execPids must be cloned by the caller (slices.Clone) before
// being stored here, since the mock's own execPids argument is a snapshot the
// caller may reuse.
type mappedLibPassCall struct {
	containerPid uint32
	execPids     []uint32
}

// sortedPids returns a sorted copy of pids, so a test can compare two tracked
// sets for set equality: snapshotPids builds its slice by ranging over a map,
// whose iteration order Go deliberately randomizes, so the arrival order of
// candidates is NOT preserved and must never be asserted on.
func sortedPids(pids []uint32) []uint32 {
	out := slices.Clone(pids)
	slices.Sort(out)
	return out
}

// TestMappedLibTimerRearm covers the re-arm semantics of the timer registry: a
// second exec for an already-armed container updates the LIVE tracked set
// instead of being dropped or starting a second goroutine, refreshes the
// attempt budget, and — when the wall-clock ceiling fires with a re-arm pending
// — still removes the registry entry rather than orphaning it.
func TestMappedLibTimerRearm(t *testing.T) {
	// A: a re-arm reaches the running goroutine's next pass ALONGSIDE the
	// candidate already tracked, and does not start a second goroutine.
	t.Run("tracks_both_candidates_and_dedups", func(t *testing.T) {
		shrinkBackoff(t)

		var (
			mu    sync.Mutex
			calls []mappedLibPassCall
			once  sync.Once
		)
		block := make(chan struct{})
		// Records BEFORE parking: the waitFor handshake below would otherwise
		// deadlock waiting for a record that only appears once block is released.
		i := newTimerInstance(func(containerPid uint32, execPids []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
			mu.Lock()
			calls = append(calls, mappedLibPassCall{containerPid, slices.Clone(execPids)})
			mu.Unlock()
			once.Do(func() { <-block }) // only the FIRST pass parks
			return false, nil           // never attaches
		})

		i.armMappedLibTimer(100, 200)
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) == 1 }, "first pass to record")
		mu.Lock()
		first := calls[0]
		mu.Unlock()
		if want := (mappedLibPassCall{100, []uint32{200}}); first.containerPid != want.containerPid || !slices.Equal(first.execPids, want.execPids) {
			t.Fatalf("calls[0] = %+v, want %+v", first, want)
		}

		i.armMappedLibTimer(100, 999) // re-arm while pass #1 is still parked

		// Dedup is a NEGATIVE assertion (nothing further happened), so there is
		// no positive event to waitFor on: a broken dedup would start a second
		// goroutine whose attempt-0 pass runs immediately and unparked (its
		// once.Do is already spent), growing calls past 1 within this window.
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		if n != 1 {
			t.Fatalf("pass calls = %d during re-arm settle, want 1 (re-arm must not start a 2nd goroutine)", n)
		}
		i.mappedLibTimers.mu.Lock()
		live := len(i.mappedLibTimers.timers)
		i.mappedLibTimers.mu.Unlock()
		if live != 1 {
			t.Errorf("live timers = %d, want 1", live)
		}

		close(block)
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) >= 2 }, "second pass after re-arm")
		mu.Lock()
		second := calls[1]
		mu.Unlock()
		// The tracked set RETAINS 200 and ADDS 999 — this is the assertion that
		// fails under the old single-slot design (which would report just
		// {999}) and passes under the set-based one. Compared set-equal, since
		// snapshotPids' order is map-iteration order, not arrival order.
		if want := []uint32{200, 999}; second.containerPid != 100 || !slices.Equal(sortedPids(second.execPids), want) {
			t.Errorf("calls[1] = %+v, want containerPid 100 and execPids set %v (the re-armed pid must reach the running goroutine WITHOUT evicting the earlier candidate)", second, want)
		}

		// Self-terminates: this test's own re-arm bumped gen to 1, so the second
		// cap-reached check observes gen == lastGen and retires.
		i.mappedLibTimers.wg.Wait()
	})

	// B: a re-arm landing on the final pre-cap pass refreshes the attempt budget
	// instead of the goroutine giving up.
	t.Run("resets_attempt_budget", func(t *testing.T) {
		shrinkBackoff(t) // required: at production rates the park below lands ~15s after arm, past waitFor's deadline

		var (
			mu    sync.Mutex
			calls []mappedLibPassCall
		)
		block := make(chan struct{})
		i := newTimerInstance(func(containerPid uint32, execPids []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
			mu.Lock()
			calls = append(calls, mappedLibPassCall{containerPid, slices.Clone(execPids)})
			n := len(calls)
			mu.Unlock()
			if n == mappedLibRetryAttempts {
				<-block // park the last pass before the cap-reached check
			}
			return false, nil
		})

		i.armMappedLibTimer(100, 200)
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) == mappedLibRetryAttempts },
			"final pre-cap pass to park")

		i.armMappedLibTimer(100, 999) // re-arm while that pass is parked
		close(block)

		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) > mappedLibRetryAttempts },
			"a pass beyond the original attempt cap")
		mu.Lock()
		afterReset := calls[mappedLibRetryAttempts]
		mu.Unlock()
		// The discriminating property is that the reset genuinely happened AND
		// reached the newly-armed candidate; the earlier candidate is still
		// tracked alongside it, so this is a containment check, not an exact
		// set match.
		if afterReset.containerPid != 100 || !slices.Contains(afterReset.execPids, uint32(999)) {
			t.Errorf("first post-reset pass = %+v, want containerPid 100 and execPids containing 999", afterReset)
		}

		// Self-terminates: the second cap-reached check sees no further re-arm.
		i.mappedLibTimers.wg.Wait()
	})

	// C: the ceiling path must retire the entry UNCONDITIONALLY. Forcing a
	// re-arm to land first is what makes this discriminating — without a bumped
	// gen, routing this path through rearmedOrRetire would pass too.
	t.Run("ceiling_retires_entry_despite_pending_rearm", func(t *testing.T) {
		shrinkBackoff(t)
		shrinkCeiling(t, time.Hour) // registers the restore; lowered mid-test below

		var (
			mu    sync.Mutex
			calls []mappedLibPassCall
			once  sync.Once
		)
		block := make(chan struct{})
		i := newTimerInstance(func(containerPid uint32, execPids []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
			mu.Lock()
			calls = append(calls, mappedLibPassCall{containerPid, slices.Clone(execPids)})
			mu.Unlock()
			once.Do(func() { <-block })
			return false, nil
		})

		i.armMappedLibTimer(100, 200)
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) == 1 }, "first pass to park")

		// Bumps entry.gen to 1 while the goroutine's lastGen is still 0, so the
		// ceiling check below runs with a re-arm pending.
		i.armMappedLibTimer(100, 999)

		// Plain assignment, deliberately not atomic: the goroutine's earlier read
		// (attempt 0) is ordered before this write through the mock's mutex and
		// the waitFor above; its later read (attempt 1) is ordered after it
		// through close(block).
		mappedLibRetryCeiling = time.Nanosecond

		close(block)
		i.mappedLibTimers.wg.Wait()

		mu.Lock()
		n := len(calls)
		mu.Unlock()
		if n != 1 {
			t.Errorf("pass calls = %d, want 1 (pass #2 must not run: the ceiling fired, not the attempt cap)", n)
		}
		i.mappedLibTimers.mu.Lock()
		live := len(i.mappedLibTimers.timers)
		i.mappedLibTimers.mu.Unlock()
		if live != 0 {
			t.Errorf("live timers = %d after the ceiling, want 0 (entry orphaned by the pending re-arm)", live)
		}

		// Discovery is not wedged: a later exec can arm a fresh timer. Do NOT add
		// a trailing wg.Wait()/cancelAll() — this probe's arm() does an unmatched
		// wg.Add(1) and either would hang.
		if _, armed := i.mappedLibTimers.arm(100, 100); !armed {
			t.Errorf("arm after the ceiling did not create a fresh timer; discovery is wedged")
		}
	})
}

// TestMappedLibTimerRetainsEarlierCandidateAfterEviction is the regression
// guard for the live-fire bug this design exists to fix: under Copilot CLI's
// own exec storm, the real target's exec event arrived EARLY and every later
// exec overwrote the single mutable scan target, permanently evicting it before
// any backoff-scheduled pass could recheck it. The tracked set must retain the
// earlier candidate across later re-arms.
//
// Discrimination rests on pass #1 deliberately NOT succeeding even though 200
// is present: only a LATER pass's success proves 200 SURVIVED the re-arms,
// rather than proving it merely matched before any re-arm could evict it.
func TestMappedLibTimerRetainsEarlierCandidateAfterEviction(t *testing.T) {
	shrinkBackoff(t)
	var (
		mu    sync.Mutex
		calls [][]uint32
		once  sync.Once
	)
	block := make(chan struct{})
	i := newTimerInstance(func(_ uint32, execPids []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		mu.Lock()
		calls = append(calls, slices.Clone(execPids))
		n := len(calls)
		mu.Unlock()
		once.Do(func() { <-block }) // park pass #1 only
		return n > 1 && slices.Contains(execPids, uint32(200)), nil
	})

	i.armMappedLibTimer(100, 200) // the real target arms first
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) == 1 }, "first pass to park")
	mu.Lock()
	first := calls[0]
	mu.Unlock()
	if want := []uint32{200}; !slices.Equal(first, want) {
		t.Fatalf("calls[0] = %v, want %v", first, want)
	}

	// While pass #1 is still parked, re-arm with several more pids — under the
	// old single-slot design each of these would have overwritten (not added
	// to) the scan target, permanently evicting 200.
	for p := uint32(201); p <= 205; p++ {
		i.armMappedLibTimer(100, p)
	}
	close(block)
	i.mappedLibTimers.wg.Wait()

	mu.Lock()
	later := calls[len(calls)-1]
	n := len(calls)
	mu.Unlock()
	if n < 2 {
		t.Fatalf("only %d pass(es) ran; need a pass after the re-arms to prove 200 survived", n)
	}
	if !slices.Contains(later, uint32(200)) {
		t.Errorf("later pass execPids = %v, does not contain 200 — the earlier candidate was evicted", later)
	}
}

// TestMappedLibTimerPrunesDeadCandidates proves the liveness-pruning mechanism
// actually removes a confirmed-dead candidate from the tracked set, rather than
// merely compiling: a pass reports 200 dead, and every later pass must scan the
// still-live 201 without 200.
func TestMappedLibTimerPrunesDeadCandidates(t *testing.T) {
	shrinkBackoff(t)
	var (
		mu    sync.Mutex
		calls [][]uint32
		once  sync.Once
	)
	block := make(chan struct{})
	i := newTimerInstance(func(_ uint32, execPids []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		mu.Lock()
		calls = append(calls, slices.Clone(execPids))
		n := len(calls)
		mu.Unlock()
		once.Do(func() { <-block }) // park pass #1 only
		if n == 1 {
			return false, []uint32{200} // 200 is confirmed gone
		}
		return false, nil
	})

	i.armMappedLibTimer(100, 200)
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) == 1 }, "first pass to park")

	i.armMappedLibTimer(100, 201) // a second, still-live candidate, added while parked
	close(block)
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(calls) >= 2 }, "a pass after the dead pid was reported")

	mu.Lock()
	second := calls[1]
	mu.Unlock()
	if !slices.Contains(second, uint32(201)) {
		t.Errorf("calls[1] = %v, does not contain the still-live 201", second)
	}
	if slices.Contains(second, uint32(200)) {
		t.Errorf("calls[1] = %v, still contains 200 — pruneDead did not remove the confirmed-dead candidate", second)
	}

	// Nothing ever attaches, so the goroutine runs to its cap and retires.
	i.mappedLibTimers.wg.Wait()
}

// TestMappedLibTimerTrackedPidsCapped proves the tracked set stays bounded: arm
// more distinct pids than the cap allows and no pass may ever scan more than
// mappedLibMaxTrackedPids candidates. The property is asserted over EVERY
// recorded pass, not one snapshot — an early pass may legitimately record a
// small length, so a single sample proves nothing.
func TestMappedLibTimerTrackedPidsCapped(t *testing.T) {
	shrinkBackoff(t)
	var (
		mu      sync.Mutex
		lengths []int
	)
	i := newTimerInstance(func(_ uint32, execPids []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		mu.Lock()
		lengths = append(lengths, len(execPids))
		mu.Unlock()
		return false, nil // never attaches
	})

	for p := uint32(1); p <= mappedLibMaxTrackedPids+5; p++ {
		i.armMappedLibTimer(100, p)
	}
	i.mappedLibTimers.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(lengths) == 0 {
		t.Fatalf("no passes ran")
	}
	for idx, n := range lengths {
		if n > mappedLibMaxTrackedPids {
			t.Errorf("pass %d scanned %d candidates, want at most %d", idx, n, mappedLibMaxTrackedPids)
		}
	}
}

// TestIsPidAlive unit-tests the liveness helper against a synthetic procfs
// root. host.HostProcFs is a process-global, so this test must NOT run
// t.Parallel() — same constraint the existing HostProcFs-overriding tests in
// pkg/uprobetracer already observe.
func TestIsPidAlive(t *testing.T) {
	dir := t.TempDir()
	prevProcFs := host.HostProcFs
	host.HostProcFs = dir
	t.Cleanup(func() { host.HostProcFs = prevProcFs })

	const livePid, deadPid uint32 = 4242, 4243
	if err := os.Mkdir(filepath.Join(dir, strconv.FormatUint(uint64(livePid), 10)), 0o755); err != nil {
		t.Fatalf("creating synthetic procfs entry: %v", err)
	}

	if !isPidAlive(livePid) {
		t.Errorf("isPidAlive(%d) = false, want true (its procfs directory exists)", livePid)
	}
	if isPidAlive(deadPid) {
		t.Errorf("isPidAlive(%d) = true, want false (no procfs directory)", deadPid)
	}
}

// TestSetMappedLibPattern round-trips through the package-global setter.
//
// NOTE: under the additive/union-regex design, SetMappedLibPattern(p) no longer
// stores p itself — mappedLibPatternGlobal.Load() returns a freshly-compiled
// union regex, not p by pointer identity. This test asserts source-string
// equivalence (the union of one source is exactly that source, wrapped) instead
// of pointer identity — see AddMappedLibPattern's doc comment for why.
func TestSetMappedLibPattern(t *testing.T) {
	t.Cleanup(func() { SetMappedLibPattern(nil) })

	if got := mappedLibPatternGlobal.Load(); got != nil {
		t.Fatalf("global pattern not nil at start: %v", got)
	}
	p := regexp.MustCompile(`^libnetty_tcnative_linux_(x86_64|aarch_64)\d+\.so$`)
	SetMappedLibPattern(p)
	if got := mappedLibPatternGlobal.Load(); got == nil || got.String() != "(?:"+p.String()+")" {
		t.Errorf("global pattern = %v, want union-wrapped %v", got, p)
	}
	SetMappedLibPattern(nil)
	if got := mappedLibPatternGlobal.Load(); got != nil {
		t.Errorf("global pattern = %v after clear, want nil", got)
	}
}

// TestAddMappedLibPattern_Union covers the additive registration API: two
// independently-registered patterns each keep matching their own basenames
// (test a), a nil pattern is a documented no-op (b, folded in here rather than
// a separate test since it's a one-line assertion), anchoring composes
// correctly across the union so a basename matching only the SECOND pattern
// still matches and one matching neither does not (test d), and
// SetMappedLibPattern after one or more AddMappedLibPattern calls resets to
// exactly the new single pattern (test b's "clears the set" half).
func TestAddMappedLibPattern_Union(t *testing.T) {
	t.Cleanup(func() { SetMappedLibPattern(nil) })

	if got := mappedLibPatternGlobal.Load(); got != nil {
		t.Fatalf("global pattern not nil at start: %v", got)
	}

	// (b) nil is a documented no-op, not a panic, and does not arm the feature.
	AddMappedLibPattern(nil)
	if got := mappedLibPatternGlobal.Load(); got != nil {
		t.Fatalf("AddMappedLibPattern(nil) armed the feature: %v", got)
	}

	nettyPattern := regexp.MustCompile(`^libnetty_tcnative_linux_(x86_64|aarch_64)\d+\.so$`)
	aeadPattern := regexp.MustCompile(`^runtime\.node$`)

	// (a) two distinct patterns registered additively both keep matching.
	AddMappedLibPattern(nettyPattern)
	AddMappedLibPattern(aeadPattern)

	union := mappedLibPatternGlobal.Load()
	if union == nil {
		t.Fatalf("global pattern nil after two AddMappedLibPattern calls")
	}
	cases := []struct {
		basename string
		want     bool
	}{
		{"libnetty_tcnative_linux_x86_64123.so", true},      // matches pattern 1 only
		{"libnetty_tcnative_linux_aarch_6499.so", true},     // matches pattern 1 only
		{"runtime.node", true},                              // (d) matches pattern 2 only — anchoring composes correctly across the join
		{"cli-native.node", false},                          // (d) matches neither — union must not over-match
		{"libnetty_tcnative_linux_x86_64123.so.bak", false}, // (d) trailing suffix must not match despite a prefix match — proves $ still anchors per-alternative
	}
	for _, c := range cases {
		if got := union.MatchString(c.basename); got != c.want {
			t.Errorf("union.MatchString(%q) = %v, want %v (union=%q)", c.basename, got, c.want, union.String())
		}
	}

	// (b) SetMappedLibPattern after Add calls DISCARDS the additive set and
	// leaves exactly the one new pattern — the netty and aead patterns above
	// must stop matching once Set replaces them.
	replacement := regexp.MustCompile(`^cli-native\.node$`)
	SetMappedLibPattern(replacement)
	afterSet := mappedLibPatternGlobal.Load()
	if afterSet == nil {
		t.Fatalf("global pattern nil after SetMappedLibPattern")
	}
	if afterSet.MatchString("libnetty_tcnative_linux_x86_64123.so") {
		t.Errorf("SetMappedLibPattern did not clear the previously-Added netty pattern")
	}
	if afterSet.MatchString("runtime.node") {
		t.Errorf("SetMappedLibPattern did not clear the previously-Added aead pattern")
	}
	if !afterSet.MatchString("cli-native.node") {
		t.Errorf("SetMappedLibPattern's own new pattern stopped matching: %q", afterSet.String())
	}
}

// TestAddMappedLibPattern_EmptyAfterClear covers (e): AddMappedLibPattern(p)
// then SetMappedLibPattern(nil) must leave the feature OFF (Load() == nil),
// never a compiled-and-stored empty-join "(?:)" — which would match every
// string, since strings.Join of a zero-length slice returns "".
func TestAddMappedLibPattern_EmptyAfterClear(t *testing.T) {
	t.Cleanup(func() { SetMappedLibPattern(nil) })

	AddMappedLibPattern(regexp.MustCompile(`^runtime\.node$`))
	if got := mappedLibPatternGlobal.Load(); got == nil {
		t.Fatalf("global pattern nil immediately after AddMappedLibPattern")
	}

	SetMappedLibPattern(nil)
	got := mappedLibPatternGlobal.Load()
	if got != nil {
		t.Fatalf("global pattern = %v after Add-then-Set(nil), want nil (empty-join match-everything bug)", got)
	}
}

// (c) fresh/zero-value state ⇒ feature OFF is already covered by the
// "not nil at start" preconditions asserted at the top of
// TestSetMappedLibPattern and TestAddMappedLibPattern_Union above — every test
// in this file cleans up via SetMappedLibPattern(nil), so a fresh run (or any
// run following cleanup) starts from mappedLibPatternGlobal == nil, matching
// today's unchanged zero-value behavior.

// fakeMappedLibHandler is a lightweight mappedLibHandler double: no eBPF, no
// procfs, just a call counter and a togglable "already attached" flag.
type fakeMappedLibHandler struct {
	mu           sync.Mutex
	calls        int
	hasMappedLib bool
}

func (f *fakeMappedLibHandler) HasMappedLibForPid(uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hasMappedLib
}

func (f *fakeMappedLibHandler) ReattachContainerMappedLibsPid(uint32, uint32, *regexp.Regexp) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return nil
}

// TestFanOutMappedLibPassGivesEveryHandlerAnAttemptOnDeadlineOverrun is the
// regression test for the AEAD-starvation bug: a resolver-backed handler (in
// production, AEAD's ELF-scanning ReattachContainerMappedLibsPid) that runs
// long enough to blow the shared deadline must not deny every OTHER handler
// their own first attempt for the pass. Before the fix, fanOutMappedLibPass's
// predecessor `return`ed on the FIRST deadline overrun encountered while
// iterating handlers in Go's randomized map order — so whichever handlers a
// given pass's iteration order happened to place after the slow one got ZERO
// calls, deterministically forever (a starved handler's HasMappedLibForPid
// never flips true, so it starves on every subsequent pass too).
//
// The deadline here is already elapsed before fanOutMappedLibPass is even
// called, so EVERY handler's first ReattachContainerMappedLibsPid call runs
// past it — this exercises the overrun path for all N handlers in one
// deterministic pass, independent of map iteration order.
func TestFanOutMappedLibPassGivesEveryHandlerAnAttemptOnDeadlineOverrun(t *testing.T) {
	const numHandlers = 8
	handlers := make(map[string]mappedLibHandler, numHandlers)
	fakes := make(map[string]*fakeMappedLibHandler, numHandlers)
	for i := 0; i < numHandlers; i++ {
		name := "handler-" + strconv.Itoa(i)
		f := &fakeMappedLibHandler{}
		fakes[name] = f
		handlers[name] = f
	}

	deadline := time.Now().Add(-time.Hour) // already elapsed
	live := []uint32{1234}

	anyAttached := fanOutMappedLibPass(handlers, 999, live, nil, deadline, func(uint32, error) {})
	if anyAttached {
		t.Fatalf("anyAttached = true, want false (no fake ever reports HasMappedLibForPid)")
	}

	for name, f := range fakes {
		f.mu.Lock()
		calls := f.calls
		f.mu.Unlock()
		if calls != 1 {
			t.Errorf("%s: ReattachContainerMappedLibsPid calls = %d, want exactly 1 (every handler must get at least one attempt even after the shared deadline has already elapsed)", name, calls)
		}
	}
}

// TestFanOutMappedLibPassSkipsAlreadySatisfiedHandlers confirms a handler that
// already reports HasMappedLibForPid==true is never called and still counts
// toward anyAttached, regardless of deadline state.
func TestFanOutMappedLibPassSkipsAlreadySatisfiedHandlers(t *testing.T) {
	satisfied := &fakeMappedLibHandler{hasMappedLib: true}
	pending := &fakeMappedLibHandler{}
	handlers := map[string]mappedLibHandler{"satisfied": satisfied, "pending": pending}

	anyAttached := fanOutMappedLibPass(handlers, 999, []uint32{1234}, nil, time.Now().Add(time.Hour), func(uint32, error) {})
	if !anyAttached {
		t.Fatalf("anyAttached = false, want true (satisfied handler already reports the lib attached)")
	}
	satisfied.mu.Lock()
	satisfiedCalls := satisfied.calls
	satisfied.mu.Unlock()
	if satisfiedCalls != 0 {
		t.Errorf("satisfied handler got %d ReattachContainerMappedLibsPid calls, want 0 (already-attached handlers must be skipped, not re-scanned)", satisfiedCalls)
	}
	pending.mu.Lock()
	pendingCalls := pending.calls
	pending.mu.Unlock()
	if pendingCalls != 1 {
		t.Errorf("pending handler got %d calls, want 1", pendingCalls)
	}
}
