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
	"debug/elf"
	"errors"
	"os"
	"testing"
)

// TestAttachOffsetsResolverFromVarAcceptsEveryShape is the most load-bearing
// test in this file.
//
// The resolver arrives through an untyped GadgetContext variable set by a
// different module. A shape this function fails to recognise is not a compile
// error and not a runtime error — the value is dropped and the tracer quietly
// reverts to symbol-name attach, which on the stripped static targets this
// mechanism exists for cannot bind at all. The embedder's feature would stop
// working with nothing logged anywhere to say why.
//
// So the two legacy shapes are asserted here alongside the two new ones: if
// anyone later "tidies" them away, this fails loudly instead of the field
// failing silently.
func TestAttachOffsetsResolverFromVarAcceptsEveryShape(t *testing.T) {
	const wantOffset = uint64(0x1234)

	legacyFunc := func(_ *os.File, _ uint32, _ string, _ elf.Machine, _ string) (uint64, error) {
		return wantOffset, nil
	}
	multiFunc := func(_ AttachRequest) ([]uint64, error) {
		return []uint64{wantOffset}, nil
	}

	tests := []struct {
		name string
		v    any
	}{
		{"legacy named type", AttachOffsetResolver(legacyFunc)},
		{"legacy bare signature", legacyFunc},
		{"multi named type", AttachOffsetsResolver(multiFunc)},
		{"multi bare signature", multiFunc},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver, err := AttachOffsetsResolverFromVar(tc.v)
			if err != nil {
				t.Fatalf("AttachOffsetsResolverFromVar: %v", err)
			}
			offsets, err := resolver(AttachRequest{})
			if err != nil {
				t.Fatalf("resolver: %v", err)
			}
			if len(offsets) != 1 || offsets[0] != wantOffset {
				t.Errorf("offsets = %#x, want [%#x]", offsets, wantOffset)
			}
		})
	}
}

func TestAttachOffsetsResolverFromVarRejectsOtherTypes(t *testing.T) {
	for _, v := range []any{nil, 42, "resolver", func() {}} {
		if _, err := AttachOffsetsResolverFromVar(v); err == nil {
			t.Errorf("AttachOffsetsResolverFromVar(%T) accepted a value it cannot call", v)
		}
	}
}

// A legacy resolver's error must stay an error through the adapter rather than
// becoming an empty-but-successful result, which the caller would read as "no
// offsets" and treat identically — same outcome here, but it would hide the
// reason from the fail-open log line.
func TestAdaptSingleOffsetResolverPropagatesError(t *testing.T) {
	sentinel := errors.New("not covered")
	resolver := adaptSingleOffsetResolver(func(_ *os.File, _ uint32, _ string, _ elf.Machine, _ string) (uint64, error) {
		return 0, sentinel
	})
	if _, err := resolver(AttachRequest{}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want %v", err, sentinel)
	}
	if got := adaptSingleOffsetResolver(nil); got != nil {
		t.Error("adaptSingleOffsetResolver(nil) returned a non-nil resolver")
	}
}

// TestMultiOffsetResolverReceivesProgName covers the field that makes the Go
// crypto/tls capture possible at all: two tracers share the symbol
// crypto/tls.(*Conn).Read — one probing the entry, one probing each RET — so
// without ProgName a resolver sees identical requests and cannot tell which
// offsets to hand back.
func TestMultiOffsetResolverReceivesProgName(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "crypto/tls.(*Conn).Read")
	tr.progName = "gotls_read_entry"
	st.currentInode = 610

	var got AttachRequest
	tr.SetAttachOffsetsResolver(func(req AttachRequest) ([]uint64, error) {
		got = req
		return []uint64{0x9000}, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	if got.ProgName != "gotls_read_entry" {
		t.Errorf("ProgName = %q, want %q", got.ProgName, "gotls_read_entry")
	}
	if got.Symbol != "crypto/tls.(*Conn).Read" {
		t.Errorf("Symbol = %q, want the tracer's attach symbol", got.Symbol)
	}
	if got.File == nil {
		t.Error("File was not populated")
	}
	if got.BuildID == "" {
		t.Error("BuildID was not populated")
	}
	if st.lastOffset == nil || *st.lastOffset != 0x9000 {
		t.Errorf("attach offset = %v, want 0x9000", st.lastOffset)
	}
}

func TestAttachOffsetsNarrowing(t *testing.T) {
	tr, _ := newTestTracer(t)

	if offset, ok := tr.attachOffsets(nil, "lib"); !ok || offset != nil {
		t.Errorf("no offsets: got (%v, %v), want (nil, true) — attach by symbol name", offset, ok)
	}

	offsets := []uint64{0x40}
	offset, ok := tr.attachOffsets(offsets, "lib")
	if !ok || offset == nil || *offset != 0x40 {
		t.Errorf("one offset: got (%v, %v), want (&0x40, true)", offset, ok)
	}

	if offset, ok := tr.attachOffsets([]uint64{0x40, 0x80}, "lib"); ok || offset != nil {
		t.Errorf("many offsets: got (%v, %v), want (nil, false)", offset, ok)
	}
	if got := tr.Stats().MultiOffsetUnsupported; got != 1 {
		t.Errorf("MultiOffsetUnsupported = %d, want 1", got)
	}
}

// A resolver returning several offsets must leave the target UNINSTRUMENTED
// rather than attached at the first one. A partial attach of a multi-probe
// program is the worse failure: for the Read capture it binds the entry probe
// and none of the returns, producing a stream of started-but-never-completed
// reads that looks like data rather than like breakage.
func TestMultiOffsetLeavesTargetUninstrumented(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "crypto/tls.(*Conn).Read")
	st.currentInode = 611

	tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) {
		return []uint64{0x9000, 0x9100, 0x9200}, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 — a subset attach is worse than none", st.attachCount)
	}
	if got := tr.Stats().MultiOffsetUnsupported; got == 0 {
		t.Error("MultiOffsetUnsupported = 0; the refusal must be counted, not silent")
	}
}

// An empty slice and an error both mean "no opinion on this candidate", and
// both must fall back to symbol-name attach rather than skipping the target.
func TestResolverDeclineFallsBackToSymbolName(t *testing.T) {
	tests := []struct {
		name     string
		resolver AttachOffsetsResolver
	}{
		{"error", func(_ AttachRequest) ([]uint64, error) { return nil, errors.New("not covered") }},
		{"no offsets", func(_ AttachRequest) ([]uint64, error) { return nil, nil }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_read")
			st.currentInode = 612
			tr.SetAttachOffsetsResolver(tc.resolver)

			if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
				t.Fatalf("AttachContainer: %v", err)
			}
			if st.attachCount != 1 {
				t.Fatalf("attachCount = %d, want 1 (symbol-name attach)", st.attachCount)
			}
			if st.lastOffset != nil {
				t.Errorf("attach offset = %v, want nil (attach by symbol name)", st.lastOffset)
			}
			if got := tr.Stats().ResolverFailOpen; got != 1 {
				t.Errorf("ResolverFailOpen = %d, want 1", got)
			}
		})
	}
}

// commitOpenedTargets is the section of the attach path that runs under t.mu,
// the lock that gates container starts. Its hold time is the budgeted quantity,
// so it has to actually be recorded.
func TestCommitOpenedTargetsRecordsMuHold(t *testing.T) {
	tr, st, elfFile := newResolverTracer(t, ProgUprobe, "SSL_read")
	st.currentInode = 613

	f, err := os.Open(elfFile.Name())
	if err != nil {
		t.Fatalf("opening synthetic ELF: %v", err)
	}
	st.openFiles = append(st.openFiles, f)

	if got := tr.Stats().MuHold.Count; got != 0 {
		t.Fatalf("MuHold.Count = %d before any commit, want 0", got)
	}

	tr.mu.Lock()
	tr.containerPid2Inodes[fakePid] = nil
	tr.commitOpenedTargets(fakePid, []openedTarget{{file: f, label: "/lib/libtest.so"}})
	tr.mu.Unlock()

	if got := tr.Stats().MuHold.Count; got != 1 {
		t.Errorf("MuHold.Count = %d after one commit, want 1", got)
	}
}

// The create-time attach path deliberately does not consult the resolver. That
// omission rests on an assumption about what is reachable at create time, and
// an unchecked assumption on a fail-open path is how coverage disappears
// quietly — so it is counted whenever a resolver is registered.
func TestCreateTimeAttachCountsResolverBypass(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_read")
	st.currentInode = 614

	tr.mu.Lock()
	_, _, err := tr.attachOneFile(fakePid, "/lib/libtest.so", map[uint64]bool{})
	tr.mu.Unlock()
	if err != nil {
		t.Fatalf("attachOneFile: %v", err)
	}
	if got := tr.Stats().CreateTimeAttachUnresolved; got != 0 {
		t.Errorf("CreateTimeAttachUnresolved = %d with no resolver registered, want 0", got)
	}

	tr.SetAttachOffsetsResolver(func(_ AttachRequest) ([]uint64, error) { return []uint64{0x10}, nil })
	st.currentInode = 615

	tr.mu.Lock()
	_, _, err = tr.attachOneFile(fakePid, "/lib/libtest.so", map[uint64]bool{})
	tr.mu.Unlock()
	if err != nil {
		t.Fatalf("attachOneFile: %v", err)
	}
	if got := tr.Stats().CreateTimeAttachUnresolved; got != 1 {
		t.Errorf("CreateTimeAttachUnresolved = %d, want 1", got)
	}
}
