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
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// These cover the seam between "this binary has no GNU build-id" and "the
// registered resolver gets a chance to look at it".
//
// That seam was closed. resolveAttachOffsets read the build-id before calling
// the resolver and gave up if there wasn't one, which the tracer treats as
// "attach by symbol name". For a gadget with no symbol-name fallback that is
// zero attach, zero error, and a resolver whose own gates and metrics never
// run -- a silent hole rather than a failure. Every test on either side passed,
// because neither side was wrong on its own.
//
// The condition is a linker property, not a Go-version one: Go began emitting
// the note by default only in go1.24, and -ldflags=-buildid= suppresses it on
// any version.

// TestResolverIsConsultedWithoutBuildID is the regression test for that hole.
// The assertion that matters is simply that the resolver RAN.
func TestResolverIsConsultedWithoutBuildID(t *testing.T) {
	const wantOffset = uint64(0x4100)
	tr, st, _ := newResolverTracerWithBuildID(t, ProgUprobe, "SSL_write", nil)
	st.currentInode = 700

	var called bool
	var sawBuildID string
	tr.SetAttachOffsetsResolver(func(req AttachRequest) ([]uint64, error) {
		called = true
		sawBuildID = req.BuildID
		return []uint64{wantOffset}, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	if !called {
		t.Fatal("the resolver was never consulted for a binary with no build-id")
	}
	if sawBuildID != "" {
		t.Errorf("resolver saw build-id %q, want empty -- the absence must be passed through, not faked", sawBuildID)
	}
	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1", st.attachCount)
	}
	if st.lastOffset == nil || *st.lastOffset != wantOffset {
		t.Errorf("attach offset = %v, want %#x -- the resolver's answer must reach the attach", st.lastOffset, wantOffset)
	}
}

// A resolver that declines a build-id-less binary must still fall open to
// symbol-name attach, exactly as it does for one that declines a binary it does
// have a build-id for. Passing the empty build-id through must not turn a
// decline into a failure.
func TestResolverMayDeclineWithoutBuildID(t *testing.T) {
	tr, st, _ := newResolverTracerWithBuildID(t, ProgUprobe, "SSL_write", nil)
	st.currentInode = 701

	tr.SetAttachOffsetsResolver(func(req AttachRequest) ([]uint64, error) {
		if req.BuildID == "" {
			return nil, errNoBuildID // stands in for a table-driven resolver's miss
		}
		return []uint64{0x1}, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1 (symbol-name attach)", st.attachCount)
	}
	if st.lastOffset != nil {
		t.Errorf("attach offset = %v, want nil -- a declined resolve attaches by symbol name", st.lastOffset)
	}
	if got := tr.Stats().ResolverFailOpen; got != 1 {
		t.Errorf("ResolverFailOpen = %d, want 1", got)
	}
}

// TestNoResolverWithoutBuildIDStillAttachesBySymbolName is the no-regression
// case for the shipped ssl path, which relies on symbol-name attach and
// registers no resolver at all.
//
// It is structurally safe -- resolveAttachOffsets returns before it ever reads
// a build-id when no resolver is registered -- but that ordering is exactly the
// kind of thing a later edit reshuffles without noticing, so it is pinned here
// rather than left to inspection.
func TestNoResolverWithoutBuildIDStillAttachesBySymbolName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		buildID []byte
	}{
		{"no build-id", nil},
		{"with build-id", testBuildID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, st, _ := newResolverTracerWithBuildID(t, ProgUprobe, "SSL_write", tc.buildID)
			st.currentInode = 702

			if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
				t.Fatalf("AttachContainer: %v", err)
			}
			if st.attachCount != 1 {
				t.Fatalf("attachCount = %d, want 1", st.attachCount)
			}
			if st.lastOffset != nil {
				t.Errorf("attach offset = %v, want nil (symbol-name attach)", st.lastOffset)
			}
			if got := tr.Stats().ResolverFailOpen; got != 0 {
				t.Errorf("ResolverFailOpen = %d, want 0 -- no resolver was registered to fail open", got)
			}
		})
	}
}

// The multi-offset shape must work without a build-id too: this is the Go
// crypto/tls case, where the binary is exactly the kind likely to lack the note
// and the resolver needs no build-id to do its job.
func TestMultiOffsetResolverWithoutBuildID(t *testing.T) {
	offsets := []uint64{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}
	tr, st, _ := newResolverTracerWithBuildID(t, ProgUprobe, "crypto/tls.(*Conn).Read", nil)
	st.currentInode = 703

	tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) {
		return offsets, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	keeper, ok := tr.inodeRefCount[st.currentInode]
	if !ok {
		t.Fatal("no inodeKeeper was created")
	}
	if got := len(keeper.links); got != len(offsets) {
		t.Errorf("keeper holds %d links, want %d", got, len(offsets))
	}
	if got := tr.Stats().LinksAttached; got != uint64(len(offsets)) {
		t.Errorf("LinksAttached = %d, want %d", got, len(offsets))
	}
}

// capturingLogger records every line the tracer emits. It implements only
// GenericLoggerWithLevelSetter; NewFromGenericLogger supplies the rest.
type capturingLogger struct {
	mu    sync.Mutex
	lines []string
	level logger.Level
}

func (c *capturingLogger) Log(_ logger.Level, params ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprint(params...))
}

func (c *capturingLogger) Logf(_ logger.Level, format string, params ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, params...))
}

func (c *capturingLogger) SetLevel(l logger.Level) { c.level = l }
func (c *capturingLogger) GetLevel() logger.Level  { return c.level }

func (c *capturingLogger) linesContaining(substr string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, l := range c.lines {
		if strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return out
}

// TestNoResolverDoesNoResolveWork pins the ORDER of the nil-resolver guard,
// which an outcome assertion cannot.
//
// The guard returns before the ELF is parsed and the build-id note walked. Move
// it below either and the outcome is unchanged -- still nil, still symbol-name
// attach -- so every test that checks the result keeps passing while every
// uprobe gadget with no resolver registered starts paying a full ELF parse and
// note walk per candidate per container, on the same container-attach path the
// attach-cost budget is measured against.
//
// Found in review: an earlier version of this file claimed to pin the ordering
// and did not, because it asserted the outcome. This asserts the WORK instead:
// every log line in resolveAttachOffsets shares the "offset resolve" prefix, so
// the absence of any such line is evidence the function returned before doing
// anything.
func TestNoResolverDoesNoResolveWork(t *testing.T) {
	cap := &capturingLogger{}
	tr, st, _ := newResolverTracerWithBuildID(t, ProgUprobe, "SSL_write", nil)
	tr.logger = logger.NewFromGenericLogger(cap)
	st.currentInode = 704

	// No resolver registered -- the shipped ssl shape.
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1 (symbol-name attach)", st.attachCount)
	}

	if got := cap.linesContaining("offset resolve"); len(got) != 0 {
		t.Errorf("resolveAttachOffsets did work with no resolver registered; it must return first.\nlines: %v", got)
	}
}

func TestLogBuildID(t *testing.T) {
	if got := logBuildID(""); got != "<none>" {
		t.Errorf("logBuildID(\"\") = %q, want \"<none>\"", got)
	}
	if got := logBuildID("abc123"); got != "abc123" {
		t.Errorf("logBuildID(\"abc123\") = %q, want it unchanged", got)
	}
}
