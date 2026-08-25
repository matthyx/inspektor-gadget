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

// Kernel-level validation of attaching at a file offset. Requires root:
//
//	go test -exec sudo -v ./pkg/uprobetracer/ -run TestAttachAtFileOffset

package uprobetracer

import (
	"debug/elf"
	"fmt"
	"os"
	"path"
	"regexp"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// TestAttachAtFileOffset proves on a live kernel what the offset-attach design
// rests on: UprobeOptions.Address binds a probe without any symbol lookup, and
// does so identically for a uprobe and a uretprobe.
//
// The symbol passed is deliberately one the target binary does not export — it
// only names the tracefs event. If Address did not short-circuit symbol
// resolution, every case here would fail with ErrNoSymbol.
func TestAttachAtFileOffset(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (uprobe attach)")
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.Kprobe,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Fatalf("loading probe program: %v", err)
	}
	defer prog.Close()

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	file, err := os.Open(self)
	if err != nil {
		t.Fatalf("opening %q: %v", self, err)
	}
	defer file.Close()

	offset, err := entryFileOffset(file)
	if err != nil {
		t.Fatalf("locating entry point file offset: %v", err)
	}

	// Attach through the same /proc/self/fd path production uses, so this
	// exercises the real attach surface rather than a plain filesystem path.
	ex, err := link.OpenExecutable(path.Join(host.HostProcFs, "self/fd", fmt.Sprint(file.Fd())))
	if err != nil {
		t.Fatalf("OpenExecutable: %v", err)
	}

	const absentSymbol = "SSL_read_definitely_not_exported"
	for _, tc := range []struct {
		name   string
		attach func(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error)
	}{
		{"uprobe", ex.Uprobe},
		{"uretprobe", ex.Uretprobe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := tc.attach(absentSymbol, prog, uprobeOffsetOptions(&offset))
			if err != nil {
				t.Fatalf("attaching at file offset %#x: %v", offset, err)
			}
			l.Close()
		})
	}

	// Control: without an Address the same absent symbol must fail, confirming
	// the cases above passed because of Address and not by accident.
	if _, err := ex.Uretprobe(absentSymbol, prog, nil); err == nil {
		t.Error("uretprobe on an absent symbol without Address succeeded; the offset cases prove nothing")
	}
}

// TestMapFilesResolvesOffset covers the map_files open phase against real /proc:
// discoverAndOpenMappedLibraries must run the resolver on every candidate it
// opens and carry the result on the mappedOpen. The unit tests cannot reach this
// path (readProcMntns needs a live pid), which is exactly where a dropped
// resolver call would otherwise go unnoticed.
func TestMapFilesResolvesOffset(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (/proc/<pid>/map_files)")
	}

	tr, err := NewTracer[any](logger.DefaultLogger())
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}
	tr.attachSymbol = "SSL_read"

	const wantOffset = uint64(0x9abc)
	resolved := 0
	tr.SetAttachOffsetResolver(func(_ *os.File, _ uint32, buildID string, machine elf.Machine, symbol string) (uint64, error) {
		if buildID == "" {
			t.Errorf("resolver called with an empty build-id")
		}
		if symbol != "SSL_read" {
			t.Errorf("resolver saw symbol %q, want SSL_read", symbol)
		}
		resolved++
		return wantOffset, nil
	})

	self := uint32(os.Getpid())
	opened, err := tr.discoverAndOpenMappedLibraries(self, self, regexp.MustCompile(`^libc\.so`))
	if err != nil {
		t.Fatalf("discoverAndOpenMappedLibraries: %v", err)
	}
	defer closeMappedOpen(opened)
	if len(opened) == 0 {
		t.Skip("no libc.so mapping found in this test binary (static build?)")
	}
	if resolved == 0 {
		t.Fatal("resolver was never called from the map_files open phase")
	}
	for _, mo := range opened {
		if len(mo.offsets) != 1 || mo.offsets[0] != wantOffset {
			t.Errorf("mappedOpen %q offsets = %v, want [%#x]", mo.path, mo.offsets, wantOffset)
		}
	}
}

// entryFileOffset converts the ELF entry point vaddr to a file offset via the
// PT_LOAD segment that contains it — a real instruction boundary in the target,
// so the probe binds somewhere valid rather than mid-instruction.
func entryFileOffset(f *os.File) (uint64, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return 0, err
	}
	defer ef.Close()

	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if ef.Entry >= prog.Vaddr && ef.Entry < prog.Vaddr+prog.Memsz {
			return ef.Entry - prog.Vaddr + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("no PT_LOAD segment contains entry %#x", ef.Entry)
}
