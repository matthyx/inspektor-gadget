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
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf/link"
)

// AttachOffsetResolverVar is the GadgetContext variable name under which an
// embedder registers an AttachOffsetResolver. It is read once per uprobe tracer
// at tracer-construction time in the ebpf operator, so the resolver is scoped to
// the gadget instance that set it — an unrelated gadget running in another
// GadgetContext never sees it.
const AttachOffsetResolverVar = "attachOffsetResolver"

// AttachOffsetResolver maps an already-open attach candidate to the file offset
// at which symbol should be attached, bypassing symbol-table lookup. It exists
// for targets whose symbol table cannot be used — a fully stripped, statically
// linked TLS library (Bun/BoringSSL) exports no SSL_* symbols at all, so the
// normal ex.Uprobe(symbol, ...) path can never bind.
//
// fd is the open candidate (also the source of buildID and machine); it must not
// be closed or have its read offset consumed — use ReadAt. containerPID is
// carried for diagnostics only, not as an event-join key.
//
// Returning an error means "no offset for this target": the caller falls back to
// today's unchanged symbol-name attach. A resolver must never panic and must not
// block, because it runs on the uprobe attach path.
type AttachOffsetResolver func(fd *os.File, containerPID uint32, buildID string, machine elf.Machine, symbol string) (offset uint64, err error)

// SetAttachOffsetResolver registers the resolver consulted during the lock-free
// open phase. It is called once, right after NewTracer and before any container
// is attached, so it needs no lock.
func (t *Tracer[Event]) SetAttachOffsetResolver(resolver AttachOffsetResolver) {
	t.attachOffsetResolver = resolver
}

// resolveAttachOffset asks the registered resolver for a file offset for the
// tracer's attach symbol in the already-open candidate file.
//
// It MUST only be called from the lock-free open phase (openTargets,
// discoverAndOpenMappedLibraries). The ELF parse and the resolver's own pread
// work are exactly the kind of slow I/O that commits f4ef5cd8f and 7344ac379
// moved off t.mu: an exec storm holding the lock across it starves the
// create-time attach on the synchronous container-start path and wedges
// container starts.
//
// A nil return means "attach by symbol name", today's behaviour — this is the
// fail-open path taken for a missing resolver, an unparseable ELF, a binary with
// no build-id, and any resolver error.
//
// Reading t.attachSymbol off-lock is race-free: it is written once in AttachProg
// under t.mu, and every caller of this function has already observed
// t.prog != nil under t.mu, which orders that write before this read.
func (t *Tracer[Event]) resolveAttachOffset(file *os.File, containerPid uint32) *uint64 {
	resolver := t.attachOffsetResolver
	if resolver == nil {
		return nil
	}

	ef, err := elf.NewFile(file)
	if err != nil {
		t.logger.Debugf("uprobetracer: offset resolve for container %d: parsing ELF: %v", containerPid, err)
		return nil
	}
	defer ef.Close()

	buildID, err := elfBuildID(ef)
	if err != nil {
		t.logger.Debugf("uprobetracer: offset resolve for container %d: reading build-id: %v", containerPid, err)
		return nil
	}

	offset, err := resolver(file, containerPid, buildID, ef.Machine, t.attachSymbol)
	if err != nil {
		t.logger.Debugf("uprobetracer: offset resolve for container %d, build-id %s, symbol %q: %v", containerPid, buildID, t.attachSymbol, err)
		return nil
	}
	t.logger.Debugf("uprobetracer: offset resolve for container %d, build-id %s, symbol %q: attaching at file offset %#x", containerPid, buildID, t.attachSymbol, offset)
	return &offset
}

// uprobeOffsetOptions builds the link options that bind a uprobe at an
// already-resolved file offset, or nil to attach by symbol name.
//
// Offset is explicitly zero because link's ex.address() returns Address+Offset:
// a stray non-zero Offset would silently shift the attach point off the resolved
// instruction. A non-zero Address short-circuits symbol lookup entirely, so no
// symbol table is needed — identically for Uprobe and Uretprobe, which funnel
// through the same ex.uprobe() and differ only in the ret flag.
func uprobeOffsetOptions(offset *uint64) *link.UprobeOptions {
	if offset == nil {
		return nil
	}
	return &link.UprobeOptions{Address: *offset, Offset: 0}
}

var errNoBuildID = errors.New("no GNU build-id note")

// maxNoteSize bounds how much of a note region is read, so a corrupt or hostile
// header cannot make us allocate arbitrarily.
const maxNoteSize = 64 << 10

// elfBuildID returns the lowercase hex GNU build-id of ef.
//
// It tries the .note.gnu.build-id section first, then falls back to walking
// PT_NOTE program headers. The fallback is load-bearing rather than defensive:
// the targets this resolver exists for are stripped binaries, which may carry no
// section headers at all while still keeping the note in a mapped PT_NOTE
// segment.
func elfBuildID(ef *elf.File) (string, error) {
	if sec := ef.Section(".note.gnu.build-id"); sec != nil && sec.Type != elf.SHT_NOBITS && sec.Size <= maxNoteSize {
		if data, err := sec.Data(); err == nil {
			if id, ok := parseBuildIDNote(data, ef.ByteOrder); ok {
				return id, nil
			}
		}
	}

	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_NOTE || prog.Filesz == 0 || prog.Filesz > maxNoteSize {
			continue
		}
		data := make([]byte, prog.Filesz)
		if _, err := io.ReadFull(prog.Open(), data); err != nil {
			continue
		}
		if id, ok := parseBuildIDNote(data, ef.ByteOrder); ok {
			return id, nil
		}
	}

	return "", errNoBuildID
}

// ntGNUBuildID is NT_GNU_BUILD_ID, the note type carrying the build-id payload.
const ntGNUBuildID = 3

var gnuNoteName = []byte("GNU\x00")

// parseBuildIDNote walks a sequence of ELF notes and returns the payload of the
// first GNU/NT_GNU_BUILD_ID one, hex-encoded. Note layout: namesz, descsz, type
// (4 bytes each), then name and desc, each padded to a 4-byte boundary.
func parseBuildIDNote(data []byte, order binary.ByteOrder) (string, bool) {
	for len(data) >= 12 {
		nameSz := order.Uint32(data[0:4])
		descSz := order.Uint32(data[4:8])
		noteType := order.Uint32(data[8:12])

		namePad := align4(nameSz)
		descPad := align4(descSz)
		// Compare in uint64 so a hostile 32-bit size cannot overflow the sum.
		if 12+uint64(namePad)+uint64(descPad) > uint64(len(data)) {
			return "", false
		}

		name := data[12 : 12+nameSz]
		desc := data[12+namePad : 12+namePad+descSz]
		if noteType == ntGNUBuildID && bytes.Equal(name, gnuNoteName) && descSz > 0 {
			return hex.EncodeToString(desc), true
		}

		data = data[12+namePad+descPad:]
	}
	return "", false
}

func align4(n uint32) uint32 {
	return (n + 3) &^ 3
}

// AttachOffsetResolverFromVar type-checks a value read from a GadgetContext
// variable set via SetVar(AttachOffsetResolverVar, ...).
//
// Both the named type and the bare function signature are accepted because a Go
// type assertion demands an identical dynamic type: an embedder in another
// module that stores a plain func literal (rather than converting it to
// AttachOffsetResolver first) would otherwise be silently ignored.
func AttachOffsetResolverFromVar(v any) (AttachOffsetResolver, error) {
	switch r := v.(type) {
	case AttachOffsetResolver:
		return r, nil
	case func(*os.File, uint32, string, elf.Machine, string) (uint64, error):
		return r, nil
	default:
		return nil, fmt.Errorf("%q is a %T, want uprobetracer.AttachOffsetResolver", AttachOffsetResolverVar, v)
	}
}
