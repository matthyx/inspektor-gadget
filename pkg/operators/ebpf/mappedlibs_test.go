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
