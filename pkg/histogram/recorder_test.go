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
	"sync"
	"testing"
	"time"
)

func TestRecorderZeroValueIsEmpty(t *testing.T) {
	var r Recorder
	s := r.Stats()
	if s.Count != 0 || s.Total != 0 || s.Max != 0 {
		t.Errorf("zero-value Recorder reported %+v, want all zero", s)
	}
	if s.Histogram != nil {
		t.Error("zero-value Recorder produced a histogram; want nil until a sample arrives")
	}
	if got := s.Quantile(0.99); got != 0 {
		t.Errorf("Quantile on an empty Recorder = %v, want 0", got)
	}
}

func TestRecorderCountTotalMax(t *testing.T) {
	var r Recorder
	for _, d := range []time.Duration{
		1 * time.Millisecond,
		5 * time.Millisecond,
		2 * time.Millisecond,
	} {
		r.Observe(d)
	}

	s := r.Stats()
	if s.Count != 3 {
		t.Errorf("Count = %d, want 3", s.Count)
	}
	if s.Total != 8*time.Millisecond {
		t.Errorf("Total = %v, want 8ms", s.Total)
	}
	if s.Max != 5*time.Millisecond {
		t.Errorf("Max = %v, want 5ms", s.Max)
	}
}

// TestRecorderMaxKeepsTheLargest guards the compare-and-swap in Observe: a
// smaller sample arriving after a larger one must not lower the maximum.
func TestRecorderMaxKeepsTheLargest(t *testing.T) {
	var r Recorder
	r.Observe(50 * time.Millisecond)
	r.Observe(1 * time.Millisecond)
	if got := r.Stats().Max; got != 50*time.Millisecond {
		t.Errorf("Max = %v after a smaller late sample, want 50ms", got)
	}
}

func TestRecorderNegativeDurationCounted(t *testing.T) {
	var r Recorder
	r.Observe(-1 * time.Second)
	s := r.Stats()
	if s.Count != 1 {
		t.Errorf("Count = %d, want 1 -- a negative sample must not be silently dropped", s.Count)
	}
	if s.Max != 0 {
		t.Errorf("Max = %v, want 0 -- a negative sample is clamped, not propagated", s.Max)
	}
}

func TestExp2Slot(t *testing.T) {
	// These pin the alignment with NewIntervalsFromExp2Slots: slot i must cover
	// [2^i, 2^(i+1)). The previous table encoded a slot convention one power of
	// two too high, which is why it passed while every rendered quantile was 2x
	// the truth.
	tests := []struct {
		micros uint64
		want   int
	}{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 1},
		{4, 2},
		{7, 2},
		{8, 3},
		{15, 3},
		{16, 4},
	}
	for _, tc := range tests {
		if got := exp2Slot(tc.micros); got != tc.want {
			t.Errorf("exp2Slot(%d) = %d, want %d", tc.micros, got, tc.want)
		}
	}
	// A sample past the last bucket saturates rather than indexing out of range.
	if got := exp2Slot(^uint64(0)); got != exp2Slots-1 {
		t.Errorf("exp2Slot(max) = %d, want %d", got, exp2Slots-1)
	}
}

// TestQuantileIsAnUpperBound is the property the budget check depends on: the
// reported quantile may overstate the true latency but must never understate
// it, so a system that should fail the budget can never pass it.
func TestQuantileIsAnUpperBound(t *testing.T) {
	var r Recorder
	for i := 0; i < 99; i++ {
		r.Observe(1 * time.Millisecond)
	}
	r.Observe(100 * time.Millisecond)

	s := r.Stats()
	p99 := s.Quantile(0.99)
	if p99 < 1*time.Millisecond {
		t.Errorf("p99 = %v, want at least the 1ms bulk of the samples", p99)
	}
	if p99 > s.Max {
		t.Errorf("p99 = %v exceeds the observed max %v", p99, s.Max)
	}
	if got := s.Quantile(1); got < 100*time.Millisecond {
		t.Errorf("p100 = %v, want at least the 100ms outlier", got)
	}
}

func TestQuantileRejectsOutOfRange(t *testing.T) {
	var r Recorder
	r.Observe(time.Millisecond)
	for _, q := range []float64{0, -1, 1.5} {
		if got := r.Stats().Quantile(q); got != 0 {
			t.Errorf("Quantile(%v) = %v, want 0", q, got)
		}
	}
}

// TestRecorderConcurrent is the reason this type exists in place of a
// mutex-guarded histogram: it must be safe to call from many goroutines at
// once. Run with -race to make the check meaningful.
func TestRecorderConcurrent(t *testing.T) {
	var r Recorder
	const goroutines, each = 8, 500

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				r.Observe(time.Duration(i%10) * time.Microsecond)
			}
		}()
	}
	wg.Wait()

	if got := r.Stats().Count; got != goroutines*each {
		t.Errorf("Count = %d, want %d", got, goroutines*each)
	}
}

func TestObserveSince(t *testing.T) {
	var r Recorder
	r.ObserveSince(time.Now())
	if got := r.Stats().Count; got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}
}

// TestHistogramBucketsContainMax is the cross-check this type shipped without,
// and the reason a real misalignment survived its own unit tests.
//
// Max is recorded independently of the buckets. The buckets and Quantile both
// read through NewIntervalsFromExp2Slots, so if exp2Slot disagrees with that
// renderer's convention neither can reveal it -- they are wrong together and
// consistent with each other. Only Max, which never passes through the
// renderer, can contradict them. Requiring the rendered bucket that holds the
// largest sample to actually contain Max pins the two conventions together.
func TestHistogramBucketsContainMax(t *testing.T) {
	for _, sample := range []time.Duration{
		1 * time.Microsecond,
		500 * time.Microsecond,
		8941 * time.Microsecond,
		37 * time.Millisecond,
		1 * time.Second,
	} {
		t.Run(sample.String(), func(t *testing.T) {
			var r Recorder
			r.Observe(sample)
			s := r.Stats()

			if s.Histogram == nil || len(s.Histogram.Intervals) == 0 {
				t.Fatal("no histogram produced for a recorded sample")
			}
			last := s.Histogram.Intervals[len(s.Histogram.Intervals)-1]
			if last.Count != 1 {
				t.Fatalf("the last populated bucket holds %d samples, want 1", last.Count)
			}

			maxMicros := uint64(s.Max.Microseconds())
			if maxMicros < last.Start || maxMicros > last.End {
				t.Errorf("Max is %d us but its bucket renders as [%d, %d] -- the slot convention disagrees with the renderer",
					maxMicros, last.Start, last.End)
			}
			// A quantile must not exceed the containing bucket's upper edge.
			if got := s.Quantile(1); got > time.Duration(last.End)*time.Microsecond {
				t.Errorf("Quantile(1) = %v exceeds its bucket's upper edge %v", got, time.Duration(last.End)*time.Microsecond)
			}
		})
	}
}
