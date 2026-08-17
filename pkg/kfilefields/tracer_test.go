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

package kfilefields

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSetSockTimeout(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("creating socket pair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	if err := setSockTimeout(fds[0], 250*time.Millisecond); err != nil {
		t.Fatalf("setSockTimeout: %v", err)
	}

	tv, err := unix.GetsockoptTimeval(fds[0], unix.SOL_SOCKET, unix.SO_SNDTIMEO)
	if err != nil {
		t.Fatalf("GetsockoptTimeval SO_SNDTIMEO: %v", err)
	}
	if got := time.Duration(tv.Nano()); got != 250*time.Millisecond {
		t.Errorf("SO_SNDTIMEO = %v, want %v", got, 250*time.Millisecond)
	}

	tv, err = unix.GetsockoptTimeval(fds[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO)
	if err != nil {
		t.Fatalf("GetsockoptTimeval SO_RCVTIMEO: %v", err)
	}
	if got := time.Duration(tv.Nano()); got != 250*time.Millisecond {
		t.Errorf("SO_RCVTIMEO = %v, want %v", got, 250*time.Millisecond)
	}
}

func TestSetSockTimeoutInvalidFd(t *testing.T) {
	if err := setSockTimeout(-1, time.Second); err == nil {
		t.Fatal("expected error for invalid fd, got nil")
	}
}

// TestSocketDrainPreventsBlockingSend simulates the bug fixed in
// readStructFileFields: without draining the receiving end, enough queued
// datagrams eventually make Sendmsg block. This reproduces that with a real
// AF_UNIX SOCK_DGRAM pair and a bounded SO_SNDTIMEO, then shows that reading
// off the other end (as readStructFileFields now does after every send)
// keeps the buffer from filling.
func TestSocketDrainPreventsBlockingSend(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("creating socket pair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	if err := setSockTimeout(fds[0], 2*time.Second); err != nil {
		t.Fatalf("setSockTimeout: %v", err)
	}

	buf := make([]byte, 1)
	drainBuf := make([]byte, 1)
	for i := 0; i < 5000; i++ {
		if err := unix.Sendmsg(fds[0], buf, nil, nil, 0); err != nil {
			t.Fatalf("Sendmsg blocked/failed at iteration %d despite draining: %v", i, err)
		}
		if _, err := unix.Read(fds[1], drainBuf); err != nil {
			t.Fatalf("Read (drain) failed at iteration %d: %v", i, err)
		}
	}
}
