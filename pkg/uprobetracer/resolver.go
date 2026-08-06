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

// AttachRequest describes one attach candidate to an AttachOffsetsResolver.
//
// It is a struct rather than a parameter list so that later additions do not
// break embedders: this hook is implemented in a different module (the
// node-agent), reached through an untyped GadgetContext variable, and a
// signature change there fails by silently not matching the type assertion
// rather than by failing to compile. A struct makes growth additive.
type AttachRequest struct {
	// File is the open candidate, also the source of BuildID and Machine. It
	// must not be closed, and its read offset must not be consumed — use ReadAt.
	File *os.File
	// ContainerPID is carried for diagnostics only, never as an event-join key.
	ContainerPID uint32
	// BuildID is the target's GNU build-id, or EMPTY when it carries none --
	// measured at 45 of 97 real Go binaries, so the empty case is nearly half
	// the population rather than an edge case. Go began emitting the note by
	// default only in go1.24, and -ldflags=-buildid= suppresses it on any
	// version, so this is a property of the build and cannot be predicted from
	// the project or the toolchain version.
	//
	// It is a CACHE KEY, never a precondition for resolving. A resolver MUST
	// NOT key a cache on it without handling the empty case, or every
	// build-id-less binary aliases onto the first one's offsets -- a
	// wrong-offset attach, at roughly half of all binaries.
	BuildID string
	Machine elf.Machine
	// Symbol is the tracer's attach symbol, from the "path:symbol" section name.
	Symbol string
	// ProgName distinguishes tracers that share a Symbol. This is load-bearing
	// for Go's crypto/tls capture, where one symbol needs two different programs
	// at different offsets — an entry probe reading the buffer argument, and
	// probes at each RET reading the returned byte count, which Go's moving
	// stacks make unsafe to reach with a uretprobe. Without ProgName a resolver
	// receives identical requests for both and cannot tell them apart.
	ProgName string
}

// AttachOffsetsResolver maps an attach candidate to the file offsets at which
// its program should be attached. It is the multi-offset form of
// AttachOffsetResolver: returning several offsets attaches the same program at
// each of them.
//
// Returning an error, or an empty slice, means "no offsets for this target":
// the caller falls back to today's unchanged symbol-name attach. A resolver
// must never panic and must not block, because it runs on the uprobe attach
// path.
type AttachOffsetsResolver func(req AttachRequest) (offsets []uint64, err error)

// SetAttachOffsetResolver registers the single-offset resolver consulted during
// the lock-free open phase. It is called once, right after NewTracer and before
// any container is attached, so it needs no lock.
//
// Retained unchanged so existing embedders keep working untouched; it adapts to
// the multi-offset form internally.
func (t *Tracer[Event]) SetAttachOffsetResolver(resolver AttachOffsetResolver) {
	t.attachOffsetsResolver = adaptSingleOffsetResolver(resolver)
}

// SetAttachOffsetsResolver registers the multi-offset resolver. Same contract
// and same call-once timing as SetAttachOffsetResolver.
func (t *Tracer[Event]) SetAttachOffsetsResolver(resolver AttachOffsetsResolver) {
	t.attachOffsetsResolver = resolver
}

// HasAttachOffsetResolver reports whether a resolver is registered.
//
// It exists so the operator that wires the two together can be tested for
// having actually done so. Both halves of that wiring can be present and
// correct while nothing connects them -- which is not a hypothetical: the
// multi-offset resolver shipped with no call site, and every unit test on
// either side still passed, because each side was fine in isolation.
func (t *Tracer[Event]) HasAttachOffsetResolver() bool {
	return t.attachOffsetsResolver != nil
}

// adaptSingleOffsetResolver lifts a single-offset resolver into the
// multi-offset shape, so the tracer has exactly one internal code path and the
// older form cannot rot.
func adaptSingleOffsetResolver(resolver AttachOffsetResolver) AttachOffsetsResolver {
	if resolver == nil {
		return nil
	}
	return func(req AttachRequest) ([]uint64, error) {
		offset, err := resolver(req.File, req.ContainerPID, req.BuildID, req.Machine, req.Symbol)
		if err != nil {
			return nil, err
		}
		return []uint64{offset}, nil
	}
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
func (t *Tracer[Event]) resolveAttachOffsets(file *os.File, containerPid uint32) []uint64 {
	resolver := t.attachOffsetsResolver
	if resolver == nil {
		return nil
	}

	ef, err := elf.NewFile(file)
	if err != nil {
		t.logger.Debugf("uprobetracer: offset resolve for container %d: parsing ELF: %v", containerPid, err)
		return nil
	}
	defer ef.Close()

	// A missing build-id must NOT skip the resolver.
	//
	// The build-id is a CACHE KEY, not a precondition for resolution. A
	// structural resolver (.gopclntab) needs no build-id at all; a table-driven
	// one simply misses and declines. Returning nil here instead meant "attach
	// by symbol name" -- which a gadget that has no symbol-name fallback cannot
	// use -- so a binary with no .note.gnu.build-id produced zero attach, zero
	// error, and the resolver's own gates and metrics never ran at all.
	//
	// It is a LINKER property, not a Go-version one: Go only began emitting the
	// note by default in go1.24, and -ldflags=-buildid= (or a custom link, or a
	// vendor toolchain) suppresses it on any version including the newest.
	buildID, err := elfBuildID(ef)
	if err != nil {
		t.logger.Debugf("uprobetracer: offset resolve for container %d: no usable build-id (%v); consulting the resolver anyway", containerPid, err)
	}

	offsets, err := resolver(AttachRequest{
		File:         file,
		ContainerPID: containerPid,
		BuildID:      buildID,
		Machine:      ef.Machine,
		Symbol:       t.attachSymbol,
		ProgName:     t.progName,
	})
	if err != nil {
		t.resolverFailOpen.Add(1)
		t.logger.Debugf("uprobetracer: offset resolve for container %d, build-id %s, symbol %q: %v", containerPid, logBuildID(buildID), t.attachSymbol, err)
		return nil
	}
	if len(offsets) == 0 {
		t.resolverFailOpen.Add(1)
		t.logger.Debugf("uprobetracer: offset resolve for container %d, build-id %s, symbol %q: no offsets returned", containerPid, logBuildID(buildID), t.attachSymbol)
		return nil
	}
	t.logger.Debugf("uprobetracer: offset resolve for container %d, build-id %s, symbol %q: attaching at file offsets %#x", containerPid, logBuildID(buildID), t.attachSymbol, offsets)
	return offsets
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

// logBuildID renders a build-id for a decision log line, naming the empty case
// rather than printing nothing. The absence is precisely the condition worth
// being able to see: it is how the silent-zero-capture bug was diagnosed, and
// an empty %s in the middle of a log line reads as a formatting glitch.
func logBuildID(buildID string) string {
	if buildID == "" {
		return "<none>"
	}
	return buildID
}

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

// AttachOffsetsResolverFromVar type-checks a value read from a GadgetContext
// variable set via SetVar(AttachOffsetResolverVar, ...) and normalises it to the
// multi-offset form.
//
// FOUR shapes are accepted, and the two legacy ones are the reason this
// function is written this way rather than as a single assertion. An embedder
// registers through an untyped variable, so a shape this function does not
// recognise is not a compile error and not a runtime error either — the value is
// simply ignored and the tracer silently falls back to symbol-name attach. For
// a stripped, statically linked target that fallback cannot bind, so the
// embedder's feature stops working with no error anywhere. Dropping the legacy
// shapes here would do exactly that to any embedder still registering them.
func AttachOffsetsResolverFromVar(v any) (AttachOffsetsResolver, error) {
	switch r := v.(type) {
	case AttachOffsetsResolver:
		return r, nil
	case func(AttachRequest) ([]uint64, error):
		return r, nil
	case AttachOffsetResolver:
		return adaptSingleOffsetResolver(r), nil
	case func(*os.File, uint32, string, elf.Machine, string) (uint64, error):
		return adaptSingleOffsetResolver(r), nil
	default:
		return nil, fmt.Errorf("%q is a %T, want uprobetracer.AttachOffsetsResolver or uprobetracer.AttachOffsetResolver", AttachOffsetResolverVar, v)
	}
}
