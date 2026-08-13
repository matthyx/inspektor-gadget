// Copyright 2024 The Inspektor Gadget authors
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

// Package secureopen provides a way to securely open a file in a container and
// checking that the path didn't move outside of the container rootfs.
package secureopen

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// OpenInContainer opens the given path in the given container referenced by
// containerPid in read-only mode.
//
// The resulting open file is guaranteed to be:
// - inside the provided container
// - a regular file
// - without following magic links from procfs
//
// It relies on openat2 with RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS flags.
//
// Requires Linux 5.6 for openat2:
// https://github.com/torvalds/linux/commit/fddb5d430ad9fa91b49b1d34d0202ffe2fa0e179
//
// ctx bounds how long the CALLER waits, not how long the underlying setns/
// openat2 syscalls run: those are raw blocking kernel calls with no
// cancellable variant, so a wedged one (a stuck mount namespace, a hung
// overlay/network filesystem) still burns its goroutine and OS thread for as
// long as the kernel call itself takes -- this cannot fix that. What it does
// is stop the caller from waiting on it forever: on ctx's deadline this
// returns ctx.Err() immediately and hands the still-running open off to a
// detached goroutine that closes the file if/when it eventually shows up, so
// a caller-side gate (an attach semaphore slot, or the single fanotify
// exec-event dispatch goroutine a synchronous PubSub.Publish blocks) is
// released instead of held forever by one wedged target. See
// armosec/private-node-agent#480.
func OpenInContainer(ctx context.Context, containerPid uint32, unsafePath string) (*os.File, error) {
	type result struct {
		file *os.File
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := openInContainer(containerPid, unsafePath)
		ch <- result{f, err}
	}()

	select {
	case r := <-ch:
		return r.file, r.err
	case <-ctx.Done():
		go func() {
			r := <-ch
			if r.file != nil {
				r.file.Close()
			}
		}()
		return nil, fmt.Errorf("open %q in container %d: %w", unsafePath, containerPid, ctx.Err())
	}
}

// openInContainer is the actual, uninterruptible open; see OpenInContainer's
// doc comment for why it is wrapped rather than made cancellable itself.
func openInContainer(containerPid uint32, unsafePath string) (*os.File, error) {
	root := filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root")
	rootDir, err := os.OpenFile(root, unix.O_PATH, 0)
	if err != nil {
		return nil, fmt.Errorf("open o_path %q: %w", root, err)
	}
	defer rootDir.Close()

	// Open with O_PATH first to avoid blocking on opening the file in case it
	// is a pipe.
	howOPath := unix.OpenHow{
		Flags:   unix.O_PATH,
		Mode:    0,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(int(rootDir.Fd()), unsafePath, &howOPath)
	if err != nil {
		return nil, fmt.Errorf("openat2 %q in %q: %w", unsafePath, root, err)
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err != nil {
		return nil, fmt.Errorf("fstat %q in %q: %w", unsafePath, root, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("procfd stat: not a regular file: expected %d, got %d",
			unix.S_IFREG, stat.Mode&unix.S_IFMT)
	}

	// Re-open in read-only mode (without O_PATH)
	procfd := filepath.Join("/proc/self/fd", strconv.Itoa(int(fd)))
	return os.Open(procfd)
}

// ReadFileInContainer reads the named file and returns the contents.
//
// This is similar to os.ReadFile() except the file is opened with
// OpenInContainer(). See OpenInContainer's doc comment for what ctx does and
// does not bound; the read phase gets the same treatment since a container
// rootfs can be backed by a filesystem whose regular-file reads block (e.g.
// a wedged overlay/network mount), not just its directory resolution.
func ReadFileInContainer(ctx context.Context, containerPid uint32, unsafePath string, limitBytes int64) ([]byte, error) {
	fh, err := OpenInContainer(ctx, containerPid, unsafePath)
	if err != nil {
		return nil, fmt.Errorf("secureopen: %w", err)
	}
	defer fh.Close()

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var data []byte
		var err error
		if limitBytes > 0 {
			data, err = io.ReadAll(io.LimitReader(fh, limitBytes))
		} else {
			data, err = io.ReadAll(fh)
		}
		ch <- result{data, err}
	}()

	select {
	case r := <-ch:
		return r.data, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("read %q in container %d: %w", unsafePath, containerPid, ctx.Err())
	}
}
