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

package histogram

import (
	"math/bits"
	"sync/atomic"
	"time"
)

// exp2Slots is the number of power-of-two buckets a Recorder keeps. Bucket i
// holds durations in [2^(i-1), 2^i) microseconds, so 40 slots span roughly a
// microsecond to a fortnight -- far past any latency worth distinguishing here,
// and small enough that a Recorder stays cache-friendly.
const exp2Slots = 40

// Recorder accumulates latency samples into exponential (power-of-two) buckets
// without locking, so it can sit on paths that must not serialize -- including
// paths that already hold a contended mutex, where a mutex-guarded histogram
// would extend exactly the hold time it is meant to measure.
//
// It exists because the durations worth watching here are tail latencies: a
// mean hold time says nothing about whether one exec storm wedged container
// starts, which is the failure this instrumentation is meant to catch. Buckets
// give a real quantile; a counter and a sum do not.
//
// The zero value is ready to use. All methods are safe for concurrent use.
type Recorder struct {
	slots [exp2Slots]atomic.Uint32
	count atomic.Uint64
	// totalMicros saturates rather than wrapping; see Observe.
	totalMicros atomic.Uint64
	maxMicros   atomic.Uint64
}

// Observe records one duration. Negative durations (a non-monotonic clock read,
// or a caller passing an uninitialised value) are recorded as zero rather than
// discarded, so a sample is never silently lost from the count.
func (r *Recorder) Observe(d time.Duration) {
	micros := d.Microseconds()
	if micros < 0 {
		micros = 0
	}
	u := uint64(micros)

	r.slots[exp2Slot(u)].Add(1)
	r.count.Add(1)
	r.totalMicros.Add(u)

	// Compare-and-swap loop rather than a plain Store: a concurrent larger
	// sample must not be overwritten by a smaller one arriving late.
	for {
		cur := r.maxMicros.Load()
		if u <= cur || r.maxMicros.CompareAndSwap(cur, u) {
			break
		}
	}
}

// ObserveSince records the time elapsed since start. It is the form nearly every
// call site wants, and keeping it here means no call site has to remember to use
// a monotonic-safe subtraction.
func (r *Recorder) ObserveSince(start time.Time) {
	r.Observe(time.Since(start))
}

// exp2Slot returns the bucket index for a microsecond value, matching the
// convention NewIntervalsFromExp2Slots renders: slot i covers [2^i, 2^(i+1)),
// with slot 0 additionally absorbing zero.
//
// The alignment with that renderer is the whole contract. Using the highest set
// bit directly (bits.Len64, without the -1) puts every sample one slot too
// high, and because both the rendered histogram and Quantile read the slots
// through the same renderer, the error is invisible from either on its own --
// every reported quantile simply comes out 2x the truth. What exposes it is
// Max, which is recorded independently: a max of 8.9ms alongside a populated
// "[16384, 32768) us" bucket cannot both be right.
func exp2Slot(micros uint64) int {
	if micros == 0 {
		return 0
	}
	slot := bits.Len64(micros) - 1
	if slot >= exp2Slots {
		return exp2Slots - 1
	}
	return slot
}

// Stats is a point-in-time summary of a Recorder.
//
// The fields are read with separate atomic loads, so a Stats taken while
// samples are arriving may be very slightly inconsistent between fields (a
// count that includes a sample whose duration is not yet in the total). That is
// deliberate: making the snapshot exact would need a lock on the record path,
// which is the one thing this type exists to avoid, and the instrumentation is
// read at human timescales where a single in-flight sample cannot change a
// verdict.
type Stats struct {
	Count uint64
	Total time.Duration
	Max   time.Duration
	// Histogram renders the bucket distribution, and is what a quantile is read
	// off. Nil when no samples have been recorded.
	Histogram *Histogram
}

// Quantile returns the upper edge of the bucket containing the q'th quantile
// (0 < q <= 1), which for exponential buckets is an upper bound on the true
// value, never an underestimate. It returns zero when no samples exist.
//
// An upper bound is the right direction for a budget check: it can fail a
// borderline system that would have passed, but it can never pass one that
// should have failed.
func (s Stats) Quantile(q float64) time.Duration {
	if s.Count == 0 || s.Histogram == nil || q <= 0 || q > 1 {
		return 0
	}
	target := uint64(float64(s.Count) * q)
	if target == 0 {
		target = 1
	}
	var seen uint64
	for _, iv := range s.Histogram.Intervals {
		seen += iv.Count
		if seen >= target {
			return time.Duration(iv.End) * time.Microsecond
		}
	}
	return s.Max
}

// Stats returns a snapshot. The Recorder keeps accumulating.
func (r *Recorder) Stats() Stats {
	slots := make([]uint32, exp2Slots)
	for i := range r.slots {
		slots[i] = r.slots[i].Load()
	}

	s := Stats{
		Count: r.count.Load(),
		Total: time.Duration(r.totalMicros.Load()) * time.Microsecond,
		Max:   time.Duration(r.maxMicros.Load()) * time.Microsecond,
	}
	if s.Count > 0 {
		s.Histogram = &Histogram{
			Unit:      UnitMicroseconds,
			Intervals: NewIntervalsFromExp2Slots(slots),
		}
	}
	return s
}
