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
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
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

// newTimerInstance returns a minimal ebpfInstance wired for the retry-timer
// tests: a non-nil pattern (feature on), a fresh registry, a done channel, and
// an injected mappedLibPass mock.
func newTimerInstance(pass func(pid uint32, pattern *regexp.Regexp) bool) *ebpfInstance {
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
// attached, the goroutine exits immediately and deregisters the pid.
func TestMappedLibTimerStopsOnSuccess(t *testing.T) {
	shrinkBackoff(t)
	var calls atomic.Int32
	i := newTimerInstance(func(_ uint32, _ *regexp.Regexp) bool {
		calls.Add(1)
		return true // attached on the first pass
	})

	i.armMappedLibTimer(42)
	i.mappedLibTimers.wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("pass calls = %d, want 1 (stop on first success)", got)
	}
	if _, armed := i.mappedLibTimers.arm(42); !armed {
		t.Errorf("pid still armed after success; expected deregistered")
	}
}

// TestMappedLibTimerStopsAtCap: the pass never reports attached, so the timer
// runs exactly mappedLibRetryAttempts passes then gives up and deregisters.
func TestMappedLibTimerStopsAtCap(t *testing.T) {
	shrinkBackoff(t)
	var calls atomic.Int32
	i := newTimerInstance(func(_ uint32, _ *regexp.Regexp) bool {
		calls.Add(1)
		return false // never attaches
	})

	i.armMappedLibTimer(7)
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
	i := newTimerInstance(func(_ uint32, _ *regexp.Regexp) bool {
		calls.Add(1)
		<-block // hold the first goroutine so the second arm sees it active
		return true
	})

	i.armMappedLibTimer(99)
	waitFor(t, func() bool { return calls.Load() == 1 }, "first pass to start")
	i.armMappedLibTimer(99) // must NOT arm a second goroutine

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
	i := newTimerInstance(func(_ uint32, _ *regexp.Regexp) bool {
		calls.Add(1)
		return false // never attaches; would otherwise sleep 1h
	})

	i.armMappedLibTimer(5)
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
	i := newTimerInstance(func(_ uint32, _ *regexp.Regexp) bool {
		started.Done()
		return false
	})

	baseline := runtime.NumGoroutine()
	const n = 10
	started.Add(n)
	for pid := uint32(1); pid <= n; pid++ {
		i.armMappedLibTimer(pid)
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
		mappedLibPass: func(_ uint32, _ *regexp.Regexp) bool {
			calls.Add(1)
			return false
		},
	}

	i.armMappedLibTimer(1)
	i.mappedLibTimers.wg.Wait() // returns immediately: nothing armed

	if got := calls.Load(); got != 0 {
		t.Errorf("pass calls = %d, want 0 (nil pattern must not arm)", got)
	}
	if _, armed := i.mappedLibTimers.arm(1); !armed {
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
	i := newTimerInstance(func(_ uint32, _ *regexp.Regexp) bool {
		calls.Add(1)
		return false
	})

	i.armMappedLibTimer(3)
	waitFor(t, func() bool { return calls.Load() == 1 }, "first pass")
	close(i.done)
	i.mappedLibTimers.wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("pass calls = %d, want 1 (done closes before 2nd pass)", got)
	}
}

// TestSetMappedLibPattern round-trips through the package-global setter.
func TestSetMappedLibPattern(t *testing.T) {
	t.Cleanup(func() { SetMappedLibPattern(nil) })

	if got := mappedLibPatternGlobal.Load(); got != nil {
		t.Fatalf("global pattern not nil at start: %v", got)
	}
	p := regexp.MustCompile(`^libnetty_tcnative_linux_(x86_64|aarch_64)\d+\.so$`)
	SetMappedLibPattern(p)
	if got := mappedLibPatternGlobal.Load(); got != p {
		t.Errorf("global pattern = %v, want %v", got, p)
	}
	SetMappedLibPattern(nil)
	if got := mappedLibPatternGlobal.Load(); got != nil {
		t.Errorf("global pattern = %v after clear, want nil", got)
	}
}
