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
	// mappedLibRetryWindow is the documentary envelope for the BACKOFF SCHEDULE's
	// nominal sum specifically — it is NOT the retry ceiling. Since a re-arm can
	// reset the attempt budget (see mappedLibTimerEntry.gen), the actual upper
	// bound on one timer goroutine's lifetime is mappedLibRetryCeiling, which is
	// deliberately longer than this value and IS enforced in code.
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

// mappedLibRetryCeiling is the hard wall-clock bound on a single retry
// goroutine's lifetime. Because a re-arm resets the attempt budget
// (mappedLibTimerEntry.gen), the attempt cap alone no longer bounds the
// goroutine: an unbounded exec storm would otherwise keep refreshing the budget
// forever. 3x the backoff schedule's nominal ~20s of waiting, leaving room for
// a real exec storm to resolve while still terminating. Hitting the ceiling does
// NOT wedge discovery for the container — the entry is removed, so the next
// exec's arm() creates a fresh timer with a full budget.
//
// A package var (mirroring mappedLibBackoffSchedule) so tests can shrink it;
// production never reassigns it.
var mappedLibRetryCeiling = 60 * time.Second

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

// mappedLibTimerEntry is one container's live retry timer. It is keyed in the
// registry on containerPid (the cancellation identity), but carries execPid as a
// MUTABLE scan target: a re-arm from a later exec updates the slot in place and
// the running goroutine re-reads it on every pass, rather than the target being
// frozen at arm time and a second exec's pid being silently discarded.
//
// Registry invariant: r.timers[cp] == e ⟹ exactly one live goroutine owns e. e
// leaves the map only via cancel/cancelAll, or via that goroutine immediately
// before it returns. A gen bump is guaranteed to be observed only on the retry
// (cap-reached) path; the terminal paths — success, detach (<-stop), shutdown
// (<-i.done), ceiling — drop a racing bump deliberately, which is safe because
// removal-then-return leaves the next arm() free to create a fresh entry rather
// than dedup against a dead one. (This clause concerns the generation/
// budget-reset signal only, not the mutable scan target — the re-armed
// e.execPid is re-read by the running goroutine on every pass regardless of
// gen; only the retry-budget-reset signal is disposition-gated as described
// here.) Every exit path in armMappedLibTimer is derived from this invariant,
// not patched independently.
type mappedLibTimerEntry struct {
	stop    chan struct{}
	execPid atomic.Uint32 // latest exec'd pid to scan; updated in place on re-arm
	gen     atomic.Uint64 // bumped on every re-arm; see rearmedOrRetire
}

// mappedLibTimer is the per-containerPid retry-timer registry on the
// ebpfInstance. Its mutex is dedicated (NOT i.mu, NOT any uprobe tracer's t.mu)
// so cancelling a timer never contends with the attach path. cancel closes the
// stop channel; wg tracks the live goroutines so Close can join them WITHOUT
// holding any t.mu.
type mappedLibTimerRegistry struct {
	mu     sync.Mutex
	timers map[uint32]*mappedLibTimerEntry // containerPid -> live timer
	wg     sync.WaitGroup
}

func newMappedLibTimerRegistry() *mappedLibTimerRegistry {
	return &mappedLibTimerRegistry{timers: make(map[uint32]*mappedLibTimerEntry)}
}

// arm starts a retry goroutine for containerPid unless one is already armed
// (dedup). It returns the new entry, or nil if one already existed — in which
// case the existing entry's scan target is refreshed to execPid and its
// generation bumped, so the already-running goroutine picks up the newer exec
// instead of the re-arm being dropped. The caller runs the goroutine body.
func (r *mappedLibTimerRegistry) arm(containerPid, execPid uint32) (*mappedLibTimerEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, exists := r.timers[containerPid]; exists {
		existing.execPid.Store(execPid)
		existing.gen.Add(1)
		return nil, false
	}
	entry := &mappedLibTimerEntry{stop: make(chan struct{})}
	entry.execPid.Store(execPid)
	r.timers[containerPid] = entry
	r.wg.Add(1)
	return entry, true
}

// retire removes e from the registry unconditionally, identity-checked so a
// newer entry installed by a concurrent arm() is never clobbered. Idempotent.
// Called by the success, shutdown, and ceiling paths. NOT called by the detach
// (<-stop) path, since cancel() already removed the entry before closing stop;
// NOT called by the cap-reached (retry) path, which uses rearmedOrRetire
// instead.
func (r *mappedLibTimerRegistry) retire(cp uint32, e *mappedLibTimerEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timers[cp] == e {
		delete(r.timers, cp)
	}
}

// rearmedOrRetire is used ONLY by the cap-reached path, which is the one exit
// path that may legitimately keep going instead of exiting. If a re-arm landed
// (gen != lastGen), the entry is NOT deleted and the caller must continue with
// the new generation. Otherwise this behaves exactly like retire. The gen check
// and the delete happen inside ONE lock hold, so a re-arm landing in the exit
// window cannot be lost between them.
func (r *mappedLibTimerRegistry) rearmedOrRetire(cp uint32, e *mappedLibTimerEntry, lastGen uint64) (newGen uint64, keepGoing bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g := e.gen.Load(); g != lastGen {
		return g, true // a re-arm landed; caller adopts the new generation and keeps going
	}
	if r.timers[cp] == e {
		delete(r.timers, cp)
	}
	return lastGen, false
}

// cancel closes a containerPid's stop channel (signalling its goroutine to exit)
// and removes it from the registry. Idempotent: a pid whose goroutine already
// exited is a no-op. It does NOT wait for the goroutine — that join is the
// registry WaitGroup's job (cancelAll), which must run without any t.mu held.
func (r *mappedLibTimerRegistry) cancel(containerPid uint32) {
	r.mu.Lock()
	entry, exists := r.timers[containerPid]
	if exists {
		delete(r.timers, containerPid)
	}
	r.mu.Unlock()
	if exists {
		close(entry.stop)
	}
}

// cancelAll closes every armed timer's stop channel and waits for all goroutines
// to exit. It MUST be called WITHOUT holding any uprobe tracer's t.mu, since the
// goroutines acquire t.mu transiently. Used by ebpfInstance.Close.
func (r *mappedLibTimerRegistry) cancelAll() {
	r.mu.Lock()
	for containerPid, entry := range r.timers {
		delete(r.timers, containerPid)
		close(entry.stop)
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// armMappedLibTimer arms (once per containerPid) a bounded retry goroutine that
// fans out ReattachContainerMappedLibsPid across i.uprobeTracers until any
// tracer reports the library attached for that container (HasMappedLibForPid),
// the attempt cap is hit, or the wall-clock ceiling expires. It is a no-op when
// the feature is off (nil pattern).
//
// containerPid is the dedup/cancellation key; execPid is the pid whose procfs
// the pass actually scans. A re-arm with a later execPid does not start a second
// goroutine — it updates the live entry's scan target and resets the running
// goroutine's attempt budget, so an exec storm cannot exhaust the budget on
// early short-lived execs before the real target settles.
//
// Lock order: the goroutine takes a uprobe tracer's t.mu only transiently inside
// the public Tracer methods. It NEVER holds t.mu across the stop-channel select.
// Cancellation (DetachContainer/Close) closes stop and joins via the registry
// WaitGroup, never under t.mu.
func (i *ebpfInstance) armMappedLibTimer(containerPid, execPid uint32) {
	pattern := i.mappedLibPattern
	if pattern == nil {
		return
	}
	entry, armed := i.mappedLibTimers.arm(containerPid, execPid)
	if !armed {
		// Already armed for this container (a duplicate exec/reattach): do not
		// double-arm. arm() has refreshed the existing entry's scan target and
		// bumped its generation, so the running goroutine picks up this exec.
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

		schedule := mappedLibBackoffSchedule() // len(schedule) >= 1 for both the production schedule and test overrides
		// delayIdx is deliberately decoupled from attempt and monotonically
		// non-decreasing: a re-arm refreshes the retry budget (attempt) without
		// rewinding backoff progression, so an exec storm cannot pin the poll
		// rate to the schedule's floor for its whole duration. Its explicit
		// clamp below is also what keeps schedule[delayIdx] in range now that
		// attempt can be reset — do NOT reintroduce an `attempt >= len(schedule)`
		// break guard, which has no re-arm-aware equivalent and would silently
		// break the reset-and-continue path. The other half of that guard's old
		// job is done by the cap-reached check returning or continuing BEFORE the
		// select that would have indexed the schedule.
		delayIdx, lastGen, start := 0, entry.gen.Load(), time.Now()
		for attempt := 0; attempt < mappedLibRetryAttempts; attempt++ {
			if time.Since(start) >= mappedLibRetryCeiling {
				i.mappedLibTimers.retire(containerPid, entry) // path 5: wall-clock ceiling
				return
			}
			// Fan out a discovery+attach pass, re-reading the scan target so a
			// re-arm that landed since the last pass is picked up.
			if pass(containerPid, entry.execPid.Load(), pattern) {
				// "attempt %d" is relative to the CURRENT generation: after a
				// budget reset a later pass can log a low attempt number.
				i.logger.Debugf("ebpf: mapped-lib retry timer for pid %d: attached on attempt %d", containerPid, attempt+1)
				i.mappedLibTimers.retire(containerPid, entry) // path 1: success
				return
			}
			if attempt+1 >= mappedLibRetryAttempts { // path 4: cap reached
				if g, keep := i.mappedLibTimers.rearmedOrRetire(containerPid, entry, lastGen); keep {
					lastGen, attempt = g, -1
					continue
				}
				i.logger.Debugf("ebpf: mapped-lib retry timer for pid %d: cap reached (%d attempts), giving up", containerPid, mappedLibRetryAttempts)
				return
			}
			select {
			case <-entry.stop:
				return // path 2: detached — cancel() already removed the entry
			case <-i.done:
				i.mappedLibTimers.retire(containerPid, entry) // path 3: agent shutdown
				return
			case <-time.After(schedule[delayIdx]):
				if delayIdx < len(schedule)-1 {
					delayIdx++
				}
			}
		}
		// Unreachable today: every loop exit above is an explicit return, and
		// mappedLibRetryAttempts is a positive const so the loop condition itself
		// never falls through. This is a defensive backstop only for a future
		// change that turns mappedLibRetryAttempts into a var (or 0), so a
		// fall-through can never leak this entry out of the registry.
		i.mappedLibTimers.retire(containerPid, entry)
	}()
}

// runMappedLibPass runs one discovery+attach pass across all uprobe tracers for
// containerPid, scanning execPid's procfs, and reports whether the targeted
// library is now attached on any tracer. Re-scan is scoped to tracers that do
// NOT yet report the lib for this container.
func (i *ebpfInstance) runMappedLibPass(containerPid, execPid uint32, pattern *regexp.Regexp) bool {
	anyAttached := false
	for _, handler := range i.uprobeTracers {
		if handler.HasMappedLibForPid(containerPid) {
			anyAttached = true
			continue
		}
		if err := handler.ReattachContainerMappedLibsPid(containerPid, execPid, pattern); err != nil {
			i.logger.Debugf("ebpf: mapped-lib reattach for containerPid %d execPid %d: %v", containerPid, execPid, err)
		}
		if handler.HasMappedLibForPid(containerPid) {
			anyAttached = true
		}
	}
	return anyAttached
}
