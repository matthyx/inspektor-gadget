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

// mappedlibs.go implements the Phase-3 (P2b) SELF-SUSTAINING bounded retry timer
// that drives the fork-internal map_files discovery + attach path
// (uprobetracer.ReattachContainerMappedLibsPid).
//
// Why a timer and not a one-shot scan: a library like netty-tcnative is dlopen'd
// AFTER the JVM's single execve, then unlinked. The container-hook exec ringbuf
// emits exactly ONE EventTypeExecContainer per execve and NOTHING at the later
// in-process dlopen, so the one and only exec event fires strictly BEFORE the lib
// is mapped. A one-shot reattach at the exec event therefore finds nothing — the
// bounded retry timer is REQUIRED to catch the late mapping.
//
// The matcher (mappedLibPattern) is CALLER-SUPPLIED via SetMappedLibPattern (a
// package-global setter mirroring container-hook.SetExecEventsCollection, which
// node-agent already calls): node-agent owns the tcnative regex and enables the
// feature. A nil pattern means the feature is OFF and NO timer is ever armed
// (zero behaviour change).
//
// Lock discipline (the one real footgun): the cancel-then-join on
// DetachContainer/Close MUST NOT happen while holding a uprobe tracer's t.mu. The
// timer is cancelled via a closed channel and joined via a per-timer WaitGroup,
// NEVER under t.mu. The timer goroutine only acquires t.mu transiently inside
// ReattachContainerMappedLibsPid / HasMappedLibForPid. The registry has its own
// dedicated mutex (mappedLibTimersMu), distinct from both i.mu and any t.mu.

import (
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Retry-window constants, derived from the Phase-0.1 droplet measurement of the
// exec-settle -> tcnative-dlopen delay (~0.3s for eager init, seconds for
// lazy-init apps). N attempts spread across roughly W with a 1s->5s backoff give
// the late mapping ample time to appear without unbounded polling.
const (
	// mappedLibRetryAttempts is the maximum number of discovery passes per pid (N).
	mappedLibRetryAttempts = 6
	// mappedLibRetryWindow is the soft upper bound on the total retry duration (W);
	// it is documentary — the actual schedule is mappedLibRetryBackoff, which sums
	// to this value.
	mappedLibRetryWindow = 30 * time.Second
	// mappedLibRetryBackoffMin / Max bound the per-tick backoff (1s -> 5s).
	mappedLibRetryBackoffMin = 1 * time.Second
	mappedLibRetryBackoffMax = 5 * time.Second
)

// mappedLibBackoffSchedule returns the per-attempt delays: 1s, 2s, 3s, 4s, 5s,
// 5s (capped), summing to ~20s of waiting across mappedLibRetryAttempts passes
// within the mappedLibRetryWindow envelope. The first pass runs immediately
// (before the first delay), so this slice has mappedLibRetryAttempts-1 entries.
//
// It is a package var so tests can shrink the delays without changing the
// production schedule; production never reassigns it.
var mappedLibBackoffSchedule = defaultMappedLibBackoffSchedule

func defaultMappedLibBackoffSchedule() []time.Duration {
	delays := make([]time.Duration, 0, mappedLibRetryAttempts-1)
	d := mappedLibRetryBackoffMin
	for i := 0; i < mappedLibRetryAttempts-1; i++ {
		delays = append(delays, d)
		if d < mappedLibRetryBackoffMax {
			d += time.Second
			if d > mappedLibRetryBackoffMax {
				d = mappedLibRetryBackoffMax
			}
		}
	}
	return delays
}

// mappedLibPatternGlobal is the package-global tcnative-or-other basename
// matcher, set by node-agent via SetMappedLibPattern/AddMappedLibPattern before
// any gadget is instantiated — exactly as node-agent calls
// container-hook.SetExecEventsCollection. A nil value (the default) means the
// feature is OFF. It is read once per ebpfInstance in newInstance into
// i.mappedLibPattern; the atomic pointer keeps the setter race-free relative to
// instance construction.
//
// SEAM DECISION (flagged for architect): the plan's preferred seam was a config
// setter propagated from localmanager/kubemanager down to ebpfInstance. That path
// is infeasible here because node-agent never constructs the ebpfInstance — it is
// created deep inside IG's InstantiateImageOperator from the gadget image, with a
// viper config node-agent does not populate with this field. The package-global
// setter is the EXISTING, proven precedent in this very re-attach chain
// (container-hook.SetExecEventsCollection), keeps the matcher node-agent-supplied
// (Principle 5), and defaults OFF (nil) for zero behaviour change.
//
// ADDITIVE REGISTRATION (union-regex synthesis): multiple node-agent-side callers
// (netty-tcnative, AEAD runtime.node, ...) each own a distinct basename pattern
// and must be able to register theirs without clobbering the others — the
// original single-pattern, last-writer-wins Store() made that impossible.
// mappedLibPatternSources holds each registered pattern's original source string
// (regexp.Regexp.String() — preserves anchors/flags exactly); every mutation
// recompiles their union ("(?:src1)|(?:src2)|...") and atomically republishes it
// into this SAME atomic.Pointer[regexp.Regexp]. This keeps every downstream
// reader (ebpf.go's Load(), mapfiles.go's MatchString, tracer.go's nil-gate)
// completely unaware that multiple source patterns exist — no type change, no
// second exported-signature break. Go's ^/$ are start/end-of-TEXT (not per-line)
// absent (?m), so per-alternative anchoring composes correctly across the join.
// Invariant: mappedLibPatternGlobal always holds either nil or a fully-formed,
// immutable, already-compiled regex — a reader never observes a
// partially-updated state, and len(sources)==0 always stores nil directly
// (never compiles+stores the empty-join "(?:)" ,  which would match every
// string).
//
// KNOWN LIMITATION (mappedLibAttached coverage, see uprobetracer/tracer.go's
// mappedLibAttached/HasMappedLibForPid): with N>1 registered patterns,
// "attached" means "at least one of N matched" — the Phase-3 retry loop
// (armMappedLibTimer) can stop for a pid once ANY registered pattern's library
// is discovered, before a SECOND, later-mapped library (matching a different
// registered pattern) is ever found. Unreachable today: netty-tcnative targets
// the JVM and the AEAD runtime.node pattern targets Node.js — disjoint runtimes,
// never co-mapped in the same container. Revisit if a third pattern is added, or
// if two registered patterns can ever match within the same container.
var (
	mappedLibPatternMu      sync.Mutex
	mappedLibPatternSources []string
	mappedLibPatternGlobal  atomic.Pointer[regexp.Regexp]
)

// recompileMappedLibPatternLocked rebuilds the union regex from
// mappedLibPatternSources and republishes it. Caller must hold
// mappedLibPatternMu. An empty source list always stores nil directly — it never
// compiles the empty join "(?:)", which would match every string. A compile
// error (not expected for sources drawn from already-valid *regexp.Regexp
// values, but handled defensively since this package has no logger dependency
// to report through) leaves the previously-published pattern in place and does
// not update sources with the offending value.
func recompileMappedLibPatternLocked() {
	if len(mappedLibPatternSources) == 0 {
		mappedLibPatternGlobal.Store(nil)
		return
	}
	union, err := regexp.Compile("(?:" + strings.Join(mappedLibPatternSources, ")|(?:") + ")")
	if err != nil {
		return
	}
	mappedLibPatternGlobal.Store(union)
}

// AddMappedLibPattern additively registers a basename matcher that arms the
// Phase-3 map_files retry timer, alongside any previously registered pattern(s)
// (from earlier AddMappedLibPattern or SetMappedLibPattern calls). Each
// registered pattern's matches are OR'd together — the retry timer fires for a
// candidate file matching ANY registered pattern. Call once per distinct
// pattern, before any gadget is instantiated, mirroring
// container-hook.SetExecEventsCollection. A nil pattern is a documented no-op
// (no current caller passes nil here; this avoids a panic on pattern.String()
// rather than silently accepting a meaningless call).
func AddMappedLibPattern(pattern *regexp.Regexp) {
	if pattern == nil {
		return
	}
	mappedLibPatternMu.Lock()
	defer mappedLibPatternMu.Unlock()
	mappedLibPatternSources = append(mappedLibPatternSources, pattern.String())
	recompileMappedLibPatternLocked()
}

// SetMappedLibPattern sets (or clears, with nil) the package-global basename
// matcher that arms the Phase-3 map_files retry timer, DISCARDING any patterns
// previously registered via AddMappedLibPattern or a prior SetMappedLibPattern
// call — this is the reset entry point, not an additive one (use
// AddMappedLibPattern to register alongside existing patterns). It mirrors
// container-hook.SetExecEventsCollection: node-agent calls it once at startup,
// before any gadget is instantiated. Passing nil disables the feature.
//
// Behaviorally equivalent to the pre-additive-API version for a single caller
// (same matching outcomes) — but NOT pointer-identical: Load() after Set(p) now
// returns a freshly-compiled regex, never p itself. This is a real, deliberate
// behavior change to this exported function, not an oversight.
func SetMappedLibPattern(pattern *regexp.Regexp) {
	mappedLibPatternMu.Lock()
	defer mappedLibPatternMu.Unlock()
	if pattern == nil {
		mappedLibPatternSources = nil
	} else {
		mappedLibPatternSources = []string{pattern.String()}
	}
	recompileMappedLibPatternLocked()
}

// mappedLibTimer is the per-pid retry-timer registry on the ebpfInstance. Its
// mutex is dedicated (NOT i.mu, NOT any uprobe tracer's t.mu) so cancelling a
// timer never contends with the attach path. cancel closes the stop channel;
// wg tracks the live goroutines so Close can join them WITHOUT holding any t.mu.
type mappedLibTimerRegistry struct {
	mu     sync.Mutex
	timers map[uint32]chan struct{} // pid -> stop channel
	wg     sync.WaitGroup
}

func newMappedLibTimerRegistry() *mappedLibTimerRegistry {
	return &mappedLibTimerRegistry{timers: make(map[uint32]chan struct{})}
}

// arm starts a retry goroutine for pid unless one is already armed (dedup). It
// returns the stop channel, or nil if the pid was already armed. The caller runs
// the goroutine body.
func (r *mappedLibTimerRegistry) arm(pid uint32) (chan struct{}, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.timers[pid]; exists {
		return nil, false
	}
	stop := make(chan struct{})
	r.timers[pid] = stop
	r.wg.Add(1)
	return stop, true
}

// deregister removes a pid's timer from the registry without closing the stop
// channel (the goroutine deregisters itself when it exits naturally). Idempotent.
func (r *mappedLibTimerRegistry) deregister(pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.timers, pid)
}

// cancel closes a pid's stop channel (signalling its goroutine to exit) and
// removes it from the registry. Idempotent: a pid whose goroutine already exited
// is a no-op. It does NOT wait for the goroutine — that join is the registry
// WaitGroup's job (cancelAll), which must run without any t.mu held.
func (r *mappedLibTimerRegistry) cancel(pid uint32) {
	r.mu.Lock()
	stop, exists := r.timers[pid]
	if exists {
		delete(r.timers, pid)
	}
	r.mu.Unlock()
	if exists {
		close(stop)
	}
}

// cancelAll closes every armed timer's stop channel and waits for all goroutines
// to exit. It MUST be called WITHOUT holding any uprobe tracer's t.mu, since the
// goroutines acquire t.mu transiently. Used by ebpfInstance.Close.
func (r *mappedLibTimerRegistry) cancelAll() {
	r.mu.Lock()
	for pid, stop := range r.timers {
		delete(r.timers, pid)
		close(stop)
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// armMappedLibTimer arms (once per pid) a bounded retry goroutine that fans out
// ReattachContainerMappedLibsPid across i.uprobeTracers until any tracer reports
// the library attached for that pid (HasMappedLibForPid) or the attempt cap is
// hit, then deregisters. It is a no-op when the feature is off (nil pattern).
//
// Lock order: the goroutine takes a uprobe tracer's t.mu only transiently inside
// the public Tracer methods. It NEVER holds t.mu across the stop-channel select.
// Cancellation (DetachContainer/Close) closes stop and joins via the registry
// WaitGroup, never under t.mu.
func (i *ebpfInstance) armMappedLibTimer(pid uint32) {
	pattern := i.mappedLibPattern
	if pattern == nil {
		return
	}
	stop, armed := i.mappedLibTimers.arm(pid)
	if !armed {
		// Already armed for this pid (a duplicate exec/reattach): do not double-arm.
		return
	}

	// pass is the per-attempt discovery work; a field so tests can inject a mock
	// without an eBPF tracer. Defaults to the real fan-out.
	pass := i.mappedLibPass
	if pass == nil {
		pass = i.runMappedLibPass
	}

	go func() {
		defer i.mappedLibTimers.wg.Done()
		defer i.mappedLibTimers.deregister(pid)

		schedule := mappedLibBackoffSchedule()
		for attempt := 0; attempt < mappedLibRetryAttempts; attempt++ {
			// Fan out a discovery+attach pass for pids still lacking the lib.
			attached := pass(pid, pattern)
			if attached {
				i.logger.Debugf("ebpf: mapped-lib retry timer for pid %d: attached on attempt %d", pid, attempt+1)
				return
			}
			if attempt >= len(schedule) {
				break
			}
			select {
			case <-stop:
				return
			case <-i.done:
				return
			case <-time.After(schedule[attempt]):
			}
		}
		i.logger.Debugf("ebpf: mapped-lib retry timer for pid %d: cap reached (%d attempts), giving up", pid, mappedLibRetryAttempts)
	}()
}

// runMappedLibPass runs one discovery+attach pass across all uprobe tracers for
// pid and reports whether the targeted library is now attached on any tracer.
// Re-scan is scoped to tracers that do NOT yet report the lib for this pid.
func (i *ebpfInstance) runMappedLibPass(pid uint32, pattern *regexp.Regexp) bool {
	anyAttached := false
	for _, handler := range i.uprobeTracers {
		if handler.HasMappedLibForPid(pid) {
			anyAttached = true
			continue
		}
		if err := handler.ReattachContainerMappedLibsPid(pid, pattern); err != nil {
			i.logger.Debugf("ebpf: mapped-lib reattach for pid %d: %v", pid, err)
		}
		if handler.HasMappedLibForPid(pid) {
			anyAttached = true
		}
	}
	return anyAttached
}
