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
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

// testBuildID is the build-id baked into the synthetic ELF below.
var testBuildID = []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

// writeSyntheticELF writes a minimal ELF64 x86-64 ET_EXEC file carrying a GNU
// build-id in a PT_NOTE segment and NO section headers, then returns it open.
//
// The absent section table is the point: the binaries this resolver exists for
// are fully stripped, so elfBuildID's PT_NOTE fallback — not the
// .note.gnu.build-id section lookup — is what has to work on them.
func writeSyntheticELF(t *testing.T, buildID []byte) *os.File {
	t.Helper()

	note := new(bytes.Buffer)
	binary.Write(note, binary.LittleEndian, uint32(len(gnuNoteName)))
	binary.Write(note, binary.LittleEndian, uint32(len(buildID)))
	binary.Write(note, binary.LittleEndian, uint32(ntGNUBuildID))
	note.Write(gnuNoteName)
	note.Write(buildID)
	for note.Len()%4 != 0 {
		note.WriteByte(0)
	}

	const ehSize, phSize, phOff = 64, 56, 64
	noteOff := uint64(phOff + phSize)

	buf := new(bytes.Buffer)
	buf.Write([]byte{0x7f, 'E', 'L', 'F', 2 /*ELFCLASS64*/, 1 /*ELFDATA2LSB*/, 1 /*EV_CURRENT*/, 0})
	buf.Write(make([]byte, 8)) // e_ident padding
	le := binary.LittleEndian
	binary.Write(buf, le, uint16(elf.ET_EXEC))
	binary.Write(buf, le, uint16(elf.EM_X86_64))
	binary.Write(buf, le, uint32(elf.EV_CURRENT))
	binary.Write(buf, le, uint64(0))      // e_entry
	binary.Write(buf, le, uint64(phOff))  // e_phoff
	binary.Write(buf, le, uint64(0))      // e_shoff: no section headers
	binary.Write(buf, le, uint32(0))      // e_flags
	binary.Write(buf, le, uint16(ehSize)) // e_ehsize
	binary.Write(buf, le, uint16(phSize)) // e_phentsize
	binary.Write(buf, le, uint16(1))      // e_phnum
	binary.Write(buf, le, uint16(0))      // e_shentsize
	binary.Write(buf, le, uint16(0))      // e_shnum
	binary.Write(buf, le, uint16(0))      // e_shstrndx

	binary.Write(buf, le, uint32(elf.PT_NOTE))
	binary.Write(buf, le, uint32(elf.PF_R))
	binary.Write(buf, le, noteOff)            // p_offset
	binary.Write(buf, le, uint64(0))          // p_vaddr
	binary.Write(buf, le, uint64(0))          // p_paddr
	binary.Write(buf, le, uint64(note.Len())) // p_filesz
	binary.Write(buf, le, uint64(note.Len())) // p_memsz
	binary.Write(buf, le, uint64(4))          // p_align
	buf.Write(note.Bytes())

	path := filepath.Join(t.TempDir(), "synthetic.elf")
	if err := os.WriteFile(path, buf.Bytes(), 0o755); err != nil {
		t.Fatalf("writing synthetic ELF: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening synthetic ELF: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestElfBuildIDFromProgramHeaderNote(t *testing.T) {
	f := writeSyntheticELF(t, testBuildID)
	ef, err := elf.NewFile(f)
	if err != nil {
		t.Fatalf("elf.NewFile on synthetic ELF: %v", err)
	}
	defer ef.Close()

	got, err := elfBuildID(ef)
	if err != nil {
		t.Fatalf("elfBuildID: %v", err)
	}
	if want := hex.EncodeToString(testBuildID); got != want {
		t.Errorf("elfBuildID = %q, want %q", got, want)
	}
}

// uprobeOffsetOptions encodes AC11's hard requirement: Offset must be zero,
// because link's ex.address() returns Address+Offset and a non-zero Offset would
// silently shift the attach point off the verified instruction.
func TestUprobeOffsetOptions(t *testing.T) {
	if got := uprobeOffsetOptions(nil); got != nil {
		t.Errorf("uprobeOffsetOptions(nil) = %+v, want nil (attach by symbol name)", got)
	}

	off := uint64(0x1234)
	got := uprobeOffsetOptions(&off)
	if got == nil {
		t.Fatal("uprobeOffsetOptions(&off) = nil, want options")
	}
	if got.Address != off {
		t.Errorf("Address = %#x, want %#x", got.Address, off)
	}
	if got.Offset != 0 {
		t.Errorf("Offset = %#x, want 0 (link adds Address+Offset)", got.Offset)
	}
}

// newResolverTracer wires a tracer whose open seam always hands back the same
// synthetic ELF, so the resolve path runs on a parseable binary.
func newResolverTracer(t *testing.T, progType ProgType, symbol string) (*Tracer[any], *testState, *os.File) {
	t.Helper()
	return newResolverTracerWithBuildID(t, progType, symbol, testBuildID)
}

// newResolverTracerWithBuildID is newResolverTracer with the target's build-id
// under the caller's control. Passing nil yields an ELF whose note carries a
// zero-length descriptor, which is what a binary linked with -ldflags=-buildid=
// looks like to elfBuildID: no usable build-id.
func newResolverTracerWithBuildID(t *testing.T, progType ProgType, symbol string, buildID []byte) (*Tracer[any], *testState, *os.File) {
	t.Helper()
	tr, st := newTestTracer(t)
	tr.progType = progType
	tr.attachSymbol = symbol
	elfFile := writeSyntheticELF(t, buildID)
	tr.openInContainer = func(_ context.Context, _ uint32, _ string) (*os.File, error) {
		f, err := os.Open(elfFile.Name())
		if err != nil {
			return nil, err
		}
		st.openFiles = append(st.openFiles, f)
		return f, nil
	}
	return tr, st, elfFile
}

// A resolver hit must reach the commit-phase attach for a URETPROBE tracer, not
// only a uprobe one: both prog types bind by Address through the same link path,
// and the SSL gadget attaches each symbol with both.
func TestResolvedOffsetReachesUretprobeAttach(t *testing.T) {
	const wantOffset = uint64(0x2f100)
	tr, st, _ := newResolverTracer(t, ProgUretprobe, "SSL_read")
	st.currentInode = 500

	var sawBuildID, sawSymbol string
	var sawMachine elf.Machine
	var sawPid uint32
	tr.SetAttachOffsetResolver(func(_ *os.File, containerPID uint32, buildID string, machine elf.Machine, symbol string) (uint64, error) {
		sawPid, sawBuildID, sawMachine, sawSymbol = containerPID, buildID, machine, symbol
		return wantOffset, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1", st.attachCount)
	}
	if st.lastOffset == nil {
		t.Fatal("attach saw no pre-resolved offset; the resolve did not reach the commit phase")
	}
	if *st.lastOffset != wantOffset {
		t.Errorf("attach offset = %#x, want %#x", *st.lastOffset, wantOffset)
	}
	if tr.progType != ProgUretprobe {
		t.Errorf("progType = %v, want ProgUretprobe", tr.progType)
	}
	if want := hex.EncodeToString(testBuildID); sawBuildID != want {
		t.Errorf("resolver saw build-id %q, want %q", sawBuildID, want)
	}
	if sawMachine != elf.EM_X86_64 {
		t.Errorf("resolver saw machine %v, want EM_X86_64", sawMachine)
	}
	if sawSymbol != "SSL_read" {
		t.Errorf("resolver saw symbol %q, want SSL_read", sawSymbol)
	}
	if sawPid != fakePid {
		t.Errorf("resolver saw containerPID %d, want %d", sawPid, fakePid)
	}
}

// TestAttachProgPendingDrainInvokesResolver is split from
// TestAttachProgPendingDrainResolverBackedDoesNotTryProcExe (tracer_test.go)
// because that test's harness (newTestTracer) records openedPaths but its
// openInContainer never returns a real ELF, so a resolver registered against
// it is never actually invoked (elf.NewFile fails first) -- unassertable
// there regardless of the dispatch fix. This test uses the resolver harness
// (a real synthetic ELF) to positively prove the fix's actual point: an
// unsettled, resolver-backed pid queued before AttachProg loads the program
// now reaches the registered resolver and binds at its resolved offset,
// rather than being routed through attach()/attachOneFile (which would never
// invoke a resolver at all).
func TestAttachProgPendingDrainInvokesResolver(t *testing.T) {
	const wantOffset = uint64(0x3a000)
	tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_write")
	tr.prog = nil // force pending mode: AttachContainer only queues the pid
	st.currentInode = 700

	tr.SetAttachOffsetResolver(func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		return wantOffset, nil
	})

	self := uint32(os.Getpid())
	if err := tr.AttachContainer(testContainer(self)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if _, pending := tr.pendingContainerPids[self]; !pending {
		t.Fatalf("pid not recorded as pending (prog == nil should have deferred it)")
	}

	if err := tr.AttachProg(tr.progName, tr.progType, tr.attachFilePath+":"+tr.attachSymbol, &ebpf.Program{}); err != nil {
		t.Fatalf("AttachProg: %v", err)
	}

	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1 -- pending-drain must reach the resolver-backed attach for an unsettled resolver-registered pid", st.attachCount)
	}
	if st.lastOffset == nil || *st.lastOffset != wantOffset {
		t.Errorf("attach offset = %v, want %#x -- the registered resolver's answer must reach the pending-drain attach", st.lastOffset, wantOffset)
	}
}

// A resolver error must fall through to today's unchanged symbol-name attach —
// fail-open, never a skipped attach.
func TestResolverErrorFallsBackToSymbolAttach(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_write")
	st.currentInode = 501
	tr.SetAttachOffsetResolver(func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		return 0, errors.New("build-id not covered")
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1 (resolver failure must not block the attach)", st.attachCount)
	}
	if st.lastOffset != nil {
		t.Errorf("attach offset = %#x, want nil (symbol-name attach)", *st.lastOffset)
	}
}

// The resolve — an ELF parse plus the resolver's own pread work — must run in
// the lock-free open phase. Commits f4ef5cd8f and 7344ac379 moved slow I/O off
// t.mu precisely because holding it there wedges container starts under a pod
// burst; doing the resolve under the lock would reintroduce that class of bug.
func TestResolverRunsOffTheLock(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_write")
	st.currentInode = 502

	calls := 0
	tr.SetAttachOffsetResolver(func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		calls++
		if !tr.mu.TryLock() {
			t.Error("resolver ran with t.mu held: the resolve belongs in the lock-free open phase")
			return 0, errors.New("lock held")
		}
		tr.mu.Unlock()
		return 0x3000, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}
	if calls == 0 {
		t.Fatal("resolver was never called")
	}
}

// Once an offset is pre-resolved, the commit phase must do no further ELF or
// filesystem work: it only hands the carried offset to the attach.
func TestCommitPhaseDoesNoFileWorkWithPreResolvedOffset(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_write")
	st.currentInode = 503

	resolveCalls := 0
	tr.SetAttachOffsetResolver(func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		resolveCalls++
		return 0x4000, nil
	})

	f, err := tr.openInContainer(context.Background(), fakePid, "/lib/libtest.so")
	if err != nil {
		t.Fatalf("opening candidate: %v", err)
	}

	off := uint64(0x4000)
	tr.mu.Lock()
	tr.containerPid2Inodes[fakePid] = nil
	tr.commitOpenedTargets(fakePid, []openedTarget{{file: f, label: "/lib/libtest.so", offsets: []uint64{off}}})
	tr.mu.Unlock()

	if resolveCalls != 0 {
		t.Errorf("resolver called %d times from the commit phase, want 0", resolveCalls)
	}
	if st.lastOffset == nil || *st.lastOffset != off {
		t.Errorf("commit phase did not carry the pre-resolved offset through to the attach")
	}
}

// The map_files commit phase carries its candidate's offset to the attach the
// same way the path-based one does, so a deleted-inode target (netty-tcnative,
// Bun) is covered too. The open-phase half of this path needs /proc and is
// covered by TestMapFilesResolvesOffset.
func TestMappedLibrariesCarryResolvedOffset(t *testing.T) {
	tr, st, elfFile := newResolverTracer(t, ProgUretprobe, "SSL_read")
	st.currentInode = 504

	f, err := os.Open(elfFile.Name())
	if err != nil {
		t.Fatalf("opening synthetic ELF: %v", err)
	}
	st.openFiles = append(st.openFiles, f)

	wantOffset := uint64(0x5abc)
	tr.mu.Lock()
	tr.containerPid2Inodes[fakePid] = nil
	tr.commitMappedLibraries(fakePid, []mappedOpen{{
		file:     f,
		path:     "/tmp/libnetty.so",
		rangeKey: "7f0000000000-7f0000001000",
		offsets:  []uint64{wantOffset},
	}})
	tr.mu.Unlock()

	if st.lastOffset == nil || *st.lastOffset != wantOffset {
		t.Fatalf("map_files attach offset = %v, want %#x", st.lastOffset, wantOffset)
	}
}

// Without a registered resolver nothing changes: no ELF parse, symbol-name
// attach, exactly today's behaviour.
func TestNoResolverMeansSymbolAttach(t *testing.T) {
	tr, st, _ := newResolverTracer(t, ProgUprobe, "SSL_write")
	st.currentInode = 505

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if st.attachCount != 1 {
		t.Fatalf("attachCount = %d, want 1", st.attachCount)
	}
	if st.lastOffset != nil {
		t.Errorf("attach offset = %#x, want nil", *st.lastOffset)
	}
}

// A non-ELF target (the common case: /dev/null in these tests, a script or a
// truncated file in the field) must not fail the attach — it falls through to
// the symbol-name path.
func TestNonELFTargetFallsBackToSymbolAttach(t *testing.T) {
	tr, st := newTestTracer(t) // its open seam hands back /dev/null
	st.currentInode = 506
	called := false
	tr.SetAttachOffsetResolver(func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		called = true
		return 0x6000, nil
	})

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	if called {
		t.Error("resolver was called for an unparseable ELF")
	}
	if st.attachCount != 1 || st.lastOffset != nil {
		t.Errorf("attachCount = %d, offset = %v; want 1 and nil (symbol-name attach)", st.attachCount, st.lastOffset)
	}
}

func TestAttachOffsetResolverFromVar(t *testing.T) {
	var named AttachOffsetResolver = func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		return 1, nil
	}
	bare := func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		return 2, nil
	}

	for _, tc := range []struct {
		name string
		v    any
		want uint64
	}{
		{"named type", named, 1},
		// An embedder that stores a plain func literal must still be honoured: a
		// type assertion to the named type alone would silently drop it.
		{"bare func", bare, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := AttachOffsetResolverFromVar(tc.v)
			if err != nil {
				t.Fatalf("AttachOffsetResolverFromVar: %v", err)
			}
			got, _ := r(nil, 0, "", elf.EM_X86_64, "")
			if got != tc.want {
				t.Errorf("resolver returned %d, want %d", got, tc.want)
			}
		})
	}

	if _, err := AttachOffsetResolverFromVar("not a func"); err == nil {
		t.Error("AttachOffsetResolverFromVar on a wrong type: want error, got nil")
	}
}

// AC12: the resolver is registered on a GadgetContext, whose vars are
// per-instance, so a second gadget running alongside the SSL one never sees it.
func TestAttachOffsetResolverScopedToGadgetContext(t *testing.T) {
	sslCtx := gadgetcontext.New(context.Background(), "ghcr.io/armosec/ssl:latest")
	otherCtx := gadgetcontext.New(context.Background(), "ghcr.io/armosec/http:latest")

	var resolver AttachOffsetResolver = func(*os.File, uint32, string, elf.Machine, string) (uint64, error) {
		return 0x7000, nil
	}
	sslCtx.SetVar(AttachOffsetResolverVar, resolver)

	v, ok := sslCtx.GetVar(AttachOffsetResolverVar)
	if !ok {
		t.Fatal("resolver not readable from the gadget context that set it")
	}
	if _, err := AttachOffsetResolverFromVar(v); err != nil {
		t.Fatalf("AttachOffsetResolverFromVar: %v", err)
	}

	if _, ok := otherCtx.GetVar(AttachOffsetResolverVar); ok {
		t.Error("resolver leaked into an unrelated gadget's context")
	}
}
