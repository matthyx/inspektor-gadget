// Copyright 2024-2025 The Inspektor Gadget authors
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

import "sync"

var (
	manualFetchMu   sync.Mutex
	manualFetchSubs = map[string]map[*mapIter]chan struct{}{}
)

// registerManualFetch makes iter eligible to receive TriggerManualMapFetch requests
// for the lifetime of its goroutine. The returned channel receives a value whenever
// a matching trigger fires; it is buffered by 1 so a trigger is never lost if it
// races with the iterator already being mid-fetch. Callers must call
// unregisterManualFetch(iter) when the goroutine returns.
func registerManualFetch(iter *mapIter) <-chan struct{} {
	ch := make(chan struct{}, 1)
	manualFetchMu.Lock()
	subs, ok := manualFetchSubs[iter.name]
	if !ok {
		subs = map[*mapIter]chan struct{}{}
		manualFetchSubs[iter.name] = subs
	}
	subs[iter] = ch
	manualFetchMu.Unlock()
	return ch
}

func unregisterManualFetch(iter *mapIter) {
	manualFetchMu.Lock()
	subs := manualFetchSubs[iter.name]
	delete(subs, iter)
	if len(subs) == 0 {
		delete(manualFetchSubs, iter.name)
	}
	manualFetchMu.Unlock()
}

// TriggerManualMapFetch requests an immediate, out-of-band fetch from every
// currently running eBPF map iterator (see ParamMapIterInterval/ParamMapIterCount)
// whose datasource name is in names, on top of its normal periodic/count-based
// schedule. With no names given, every map iterator running in the process is
// triggered.
//
// This exists for a long-running consumer of a periodically-polled map (such as
// node-agent's seccomp syscall tracer) to opportunistically recover data that
// would otherwise only surface on the iterator's next tick — for example, right
// before the consumer stops tracking whatever produced that data and any
// still-unfetched entries for it become unreachable.
//
// TriggerManualMapFetch does not block until the requested fetch(es) complete, and
// is a silent no-op for any name with no currently running iterator (e.g. its
// gadget instance isn't running, or hasn't reached the point of registering its
// iterators yet).
func TriggerManualMapFetch(names ...string) {
	manualFetchMu.Lock()
	var chans []chan struct{}
	if len(names) > 0 {
		for _, n := range names {
			for _, ch := range manualFetchSubs[n] {
				chans = append(chans, ch)
			}
		}
	} else {
		for _, subs := range manualFetchSubs {
			for _, ch := range subs {
				chans = append(chans, ch)
			}
		}
	}
	manualFetchMu.Unlock()

	for _, ch := range chans {
		select {
		case ch <- struct{}{}:
		default:
			// A trigger is already pending for this iterator; it will pick up
			// the map's current contents momentarily regardless.
		}
	}
}
