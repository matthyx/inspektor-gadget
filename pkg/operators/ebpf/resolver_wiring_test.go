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

import (
	"context"
	"debug/elf"
	"os"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/uprobetracer"
)

// These tests cover the seam between an embedder registering a resolver and the
// tracer receiving it. That seam had both halves built and correct while
// nothing joined them: the multi-offset resolver shipped with no call site, and
// every test on either side passed, because each side was fine in isolation.
//
// So these assert the connection itself, not the pieces.

func newResolverGadgetCtx(t *testing.T, v any) *gadgetcontext.GadgetContext {
	t.Helper()
	gadgetCtx := gadgetcontext.New(context.Background(), "ghcr.io/armosec/gotls:latest")
	if v != nil {
		gadgetCtx.SetVar(uprobetracer.AttachOffsetResolverVar, v)
	}
	return gadgetCtx
}

// TestUprobeTracerReceivesEveryResolverShape is the regression test for the
// dead-plumbing bug. Every shape an embedder can legitimately register must
// reach the tracer through the operator, not merely be representable by the
// types in uprobetracer.
//
// The multi-offset shapes are the ones that were broken: the call site used the
// singular AttachOffsetResolverFromVar, whose type switch does not match them,
// and the resulting error propagates out of init -- so a gadget registering a
// multi-offset resolver failed to load at all rather than losing coverage.
func TestUprobeTracerReceivesEveryResolverShape(t *testing.T) {
	legacyFunc := func(_ *os.File, _ uint32, _ string, _ elf.Machine, _ string) (uint64, error) {
		return 0x1000, nil
	}
	multiFunc := func(_ uprobetracer.AttachRequest) ([]uint64, error) {
		return []uint64{0x1000, 0x2000}, nil
	}

	tests := []struct {
		name string
		v    any
	}{
		{"legacy named type", uprobetracer.AttachOffsetResolver(legacyFunc)},
		{"legacy bare signature", legacyFunc},
		{"multi named type", uprobetracer.AttachOffsetsResolver(multiFunc)},
		{"multi bare signature", multiFunc},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			i := &ebpfInstance{}
			tracer, err := i.newUprobeTracer(newResolverGadgetCtx(t, tc.v))
			if err != nil {
				t.Fatalf("newUprobeTracer: %v", err)
			}
			if tracer == nil {
				t.Fatal("newUprobeTracer returned no tracer")
			}
			if !tracer.HasAttachOffsetResolver() {
				t.Error("the registered resolver did not reach the tracer")
			}
		})
	}
}

// A gadget whose context carries no resolver must still get a tracer: offset
// attach is opt-in, and every uprobe gadget that does not use it goes through
// this same path.
func TestUprobeTracerWithoutResolver(t *testing.T) {
	i := &ebpfInstance{}
	tracer, err := i.newUprobeTracer(newResolverGadgetCtx(t, nil))
	if err != nil {
		t.Fatalf("newUprobeTracer: %v", err)
	}
	if tracer == nil {
		t.Fatal("newUprobeTracer returned no tracer")
	}
	if tracer.HasAttachOffsetResolver() {
		t.Error("a resolver was registered when the context carried none")
	}
}

// A registered-but-unusable value fails the gadget rather than being ignored.
// The embedder asked for offset attach; silently reverting to symbol-name
// attach would leave a target it cannot bind silently uninstrumented.
func TestUprobeTracerRejectsUnusableResolver(t *testing.T) {
	for _, v := range []any{42, "resolver", func() {}} {
		i := &ebpfInstance{}
		if _, err := i.newUprobeTracer(newResolverGadgetCtx(t, v)); err == nil {
			t.Errorf("newUprobeTracer accepted a %T as a resolver", v)
		}
	}
}

// The resolver must not leak between gadget instances. Vars are per-context, so
// a gadget that registered nothing must not inherit another's resolver.
func TestResolverDoesNotLeakAcrossGadgets(t *testing.T) {
	registered := newResolverGadgetCtx(t, uprobetracer.AttachOffsetsResolver(
		func(_ uprobetracer.AttachRequest) ([]uint64, error) { return []uint64{0x1000}, nil },
	))
	bare := newResolverGadgetCtx(t, nil)

	i := &ebpfInstance{}
	withResolver, err := i.newUprobeTracer(registered)
	if err != nil {
		t.Fatalf("newUprobeTracer (registered): %v", err)
	}
	withoutResolver, err := i.newUprobeTracer(bare)
	if err != nil {
		t.Fatalf("newUprobeTracer (bare): %v", err)
	}

	if !withResolver.HasAttachOffsetResolver() {
		t.Error("the registering gadget's tracer has no resolver")
	}
	if withoutResolver.HasAttachOffsetResolver() {
		t.Error("a resolver leaked into a gadget that registered none")
	}
}
