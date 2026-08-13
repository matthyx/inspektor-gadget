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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func TestDedupPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"single", []string{"/a"}, []string{"/a"}},
		{"identical", []string{"/a", "/a"}, []string{"/a"}},
		// The two candidates are produced by different resolvers (one readlinks
		// /proc/<pid>/exe, the other reads the OCI spec), so the same file can
		// arrive spelled differently.
		{"same file different spelling", []string{"/usr/bin/app", "/usr//bin/./app"}, []string{"/usr/bin/app"}},
		{"distinct kept in order", []string{"/b", "/a", "/b", "/c"}, []string{"/b", "/a", "/c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupPaths(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("dedupPaths(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("dedupPaths(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// TestSettledAttachOpensSameFileOnce is the end-to-end half of the dedup: a
// settled container offers /proc/<pid>/exe AND the create-time resolution, and
// for a statically-linked image those name the same file. Opening it twice also
// resolves its attach offsets twice, which for a resolver-backed gadget means
// parsing the whole binary twice at once.
func TestSettledAttachOpensSameFileOnce(t *testing.T) {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Skipf("cannot read own exe link: %v", err)
	}
	prevProcFs := host.HostProcFs
	host.HostProcFs = "/proc"
	t.Cleanup(func() { host.HostProcFs = prevProcFs })

	tr, st := newTestTracer(t)
	// Absolute => resolveLibraryPaths returns exactly this path, which is also
	// what settledExecutablePath readlinks for this pid.
	tr.attachFilePath = exe

	if err := tr.AttachContainer(settledTestContainer(uint32(os.Getpid()))); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	if len(st.openedPaths) != 1 {
		t.Fatalf("settled attach opened %v; the exe and the resolved candidate are the same file and must be opened once", st.openedPaths)
	}
}

func TestNewTracerSharesOneProcessWideAttachBudget(t *testing.T) {
	if maxConcurrentAttaches > 2 {
		t.Fatalf("maxConcurrentAttaches = %d; each slot holds a full Go symbol-table parse (60-115 MB), so the cap must stay small", maxConcurrentAttaches)
	}

	a, err := NewTracer[any](nil)
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}
	b, err := NewTracer[any](nil)
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}
	if a.attachSem != b.attachSem {
		t.Fatal("sibling tracers must draw from one attach budget; a per-tracer semaphore multiplies the cap by the number of uprobe programs")
	}
	if cap(a.attachSem) != maxConcurrentAttaches {
		t.Fatalf("attach semaphore cap = %d, want %d", cap(a.attachSem), maxConcurrentAttaches)
	}
}

// TestSharedAttachSemaphoreCapsSiblingTracers pins the property the whole fix
// rests on: the cap applies ACROSS the tracers of one gadget, not per tracer.
// The gotls gadget has four uprobe programs and so four tracers, each of which
// independently opens and fully parses the same container binaries.
func TestSharedAttachSemaphoreCapsSiblingTracers(t *testing.T) {
	const (
		siblings   = 4
		containers = 3
	)

	sem := make(chan struct{}, 1)

	var (
		live    atomic.Int64
		peak    atomic.Int64
		opens   sync.WaitGroup
		tracers []*Tracer[any]
	)
	opens.Add(siblings * containers)

	for i := 0; i < siblings; i++ {
		tr, st := newTestTracer(t)
		// Production dispatches the attach to a background goroutine gated by
		// attachSem; the inline test mode would hide the concurrency entirely.
		tr.syncAttach = false
		tr.SetAttachSemaphore(sem)

		var mu sync.Mutex
		inner := st.open
		tr.openInContainer = func(ctx context.Context, pid uint32, path string) (*os.File, error) {
			n := live.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			// Hold the slot long enough that an unshared budget would overlap.
			time.Sleep(10 * time.Millisecond)
			live.Add(-1)
			mu.Lock()
			f, err := inner(ctx, pid, path)
			mu.Unlock()
			opens.Done()
			return f, err
		}
		tracers = append(tracers, tr)
	}

	for _, tr := range tracers {
		for c := 0; c < containers; c++ {
			if err := tr.AttachContainer(testContainer(fakePid + uint32(c))); err != nil {
				t.Fatalf("AttachContainer: %v", err)
			}
		}
	}

	done := make(chan struct{})
	go func() {
		opens.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("attaches did not complete; a shared semaphore must serialise them, not deadlock")
	}

	for _, tr := range tracers {
		tr.Close()
	}

	if got := peak.Load(); got > int64(cap(sem)) {
		t.Fatalf("peak concurrent attaches = %d, want <= %d: the semaphore is not shared across sibling tracers", got, cap(sem))
	}
}
