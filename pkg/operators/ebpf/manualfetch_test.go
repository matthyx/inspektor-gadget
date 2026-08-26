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
	"testing"
	"time"
)

func TestTriggerManualMapFetchNoSubscribers(t *testing.T) {
	// Must not panic or block when nothing is registered.
	TriggerManualMapFetch()
	TriggerManualMapFetch("syscalls")
}

func TestTriggerManualMapFetchUnfiltered(t *testing.T) {
	a := &mapIter{name: "a"}
	b := &mapIter{name: "b"}
	chA := registerManualFetch(a)
	defer unregisterManualFetch(a)
	chB := registerManualFetch(b)
	defer unregisterManualFetch(b)

	TriggerManualMapFetch()

	assertReceived(t, chA, "a")
	assertReceived(t, chB, "b")
}

func TestTriggerManualMapFetchFiltersByName(t *testing.T) {
	syscalls := &mapIter{name: "syscalls"}
	other := &mapIter{name: "other"}
	chSyscalls := registerManualFetch(syscalls)
	defer unregisterManualFetch(syscalls)
	chOther := registerManualFetch(other)
	defer unregisterManualFetch(other)

	TriggerManualMapFetch("syscalls")

	assertReceived(t, chSyscalls, "syscalls")
	assertNotReceived(t, chOther, "other")
}

func TestTriggerManualMapFetchCoalescesPendingTrigger(t *testing.T) {
	iter := &mapIter{name: "syscalls"}
	ch := registerManualFetch(iter)
	defer unregisterManualFetch(iter)

	// Two triggers before the subscriber ever reads must not block the second
	// call (the channel is buffered by 1 and the send is non-blocking).
	done := make(chan struct{})
	go func() {
		TriggerManualMapFetch("syscalls")
		TriggerManualMapFetch("syscalls")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TriggerManualMapFetch blocked on a full, unread subscriber channel")
	}

	assertReceived(t, ch, "syscalls")
}

func TestUnregisterManualFetchStopsDelivery(t *testing.T) {
	iter := &mapIter{name: "syscalls"}
	ch := registerManualFetch(iter)
	unregisterManualFetch(iter)

	TriggerManualMapFetch("syscalls")

	assertNotReceived(t, ch, "syscalls")
}

func assertReceived(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("expected a trigger on iterator %q, got none", name)
	}
}

func assertNotReceived(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("expected no trigger on iterator %q, but received one", name)
	case <-time.After(50 * time.Millisecond):
	}
}
