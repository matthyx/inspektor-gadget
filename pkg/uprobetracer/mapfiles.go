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

package uprobetracer

// mapfiles.go implements a GENERAL map_files-based discovery + open primitive,
// distinct from the path-based secureopen.OpenInContainer flow used elsewhere in
// this package.
//
// secureopen.OpenInContainer resolves an in-rootfs PATH with
// RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS, so it cannot reach a library that has
// been unlinked from the filesystem and lives only as a deleted, mmap-only inode
// (e.g. netty-tcnative, which is dlopen'd then unlinked). Such a library still
// has a stable handle through /proc/<pid>/map_files/<start-end>, which is a magic
// link secureopen deliberately refuses.
//
// The matcher is CALLER-SUPPLIED (a *regexp.Regexp over the mapping basename) so
// this stays a general primitive rather than a tcnative special-case; the
// concrete tcnative pattern lives in the caller (node-agent), not here.
//
// This file covers discovery + open ONLY. Attaching the resulting fd into the
// readRealInode -> inodeRefCount -> containerPid2Inodes bookkeeping is handled
// separately.

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// ErrMapFileUnavailable is a sentinel error returned by openMapFile for the
// expected, NON-FATAL failure modes (capability gap, PID/mapping race, container
// teardown). Callers should log-and-skip on this error and MUST NOT treat it as
// a tracer-fatal condition.
var ErrMapFileUnavailable = errors.New("map_files entry unavailable")

// mappedLib describes one file-backed mapping matched in /proc/<pid>/maps,
// deduplicated to a single entry per distinct backing inode.
type mappedLib struct {
	// rangeKey is the maps first field verbatim ("start-end"), which is also the
	// /proc/<pid>/map_files/<rangeKey> entry name used to open the mapping.
	rangeKey string
	// inode is the backing inode from the maps line; used as the dedup key and,
	// downstream, to align with readRealInode-based refcounting.
	inode uint64
	// path is the mapping pathname with any trailing " (deleted)" suffix stripped.
	path string
}

// discoverMappedLibraries parses /proc/<containerPid>/maps and returns one
// mappedLib per distinct file-backed inode whose basename matches
// basenamePattern. See parseMappedLibraries for the parsing/dedup contract.
func discoverMappedLibraries(containerPid uint32, basenamePattern *regexp.Regexp) ([]mappedLib, error) {
	mapsPath := filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "maps")
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", mapsPath, err)
	}
	defer f.Close()

	return parseMappedLibraries(f, basenamePattern)
}

// parseMappedLibraries is the unit-testable core of discoverMappedLibraries: it
// reads /proc/<pid>/maps-formatted content from r and returns one mappedLib per
// distinct file-backed inode whose basename matches basenamePattern.
//
// maps line layout: range perms offset dev inode pathname[ (deleted)]
// The pathname is everything after the 5th field and MAY end with " (deleted)";
// that suffix is stripped before basename matching (a naive last-field grab would
// otherwise yield "(deleted)").
//
// Selection: file-backed mappings only (inode != 0 and a non-empty path).
// Dedup: one entry per distinct inode. The executable (r-xp) VMA's rangeKey is
// preferred, but any VMA's rangeKey opens the whole file, so the first-seen VMA
// is used when no r-xp VMA is present.
//
// The parse is streaming (bufio.Scanner) and tolerant of malformed lines and of
// lines appearing/disappearing mid-read: a line it cannot parse is skipped, it
// does not fail the whole walk.
func parseMappedLibraries(r io.Reader, basenamePattern *regexp.Regexp) ([]mappedLib, error) {
	// Preserve first-seen order across inodes for deterministic output.
	order := []uint64{}
	byInode := map[uint64]mappedLib{}
	// Track whether the stored entry for an inode came from an r-xp VMA, so a
	// later r-xp VMA can upgrade a non-executable first hit.
	execChosen := map[uint64]bool{}

	scanner := bufio.NewScanner(r)
	// A maps pathname can be long; grow the buffer beyond the default 64KiB cap.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			// Anonymous mappings ([heap]/[stack]/anon) have no inode/path, or the
			// line is truncated mid-read: skip, never error.
			continue
		}

		rangeKey := fields[0]
		perms := fields[1]
		inode := parseInode(fields[4])
		if inode == 0 {
			// Anonymous / non-file-backed mapping.
			continue
		}

		// The pathname is everything after the 5th field; it can contain spaces.
		path := strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)")
		if path == "" {
			continue
		}
		if !basenamePattern.MatchString(filepath.Base(path)) {
			continue
		}

		isExec := strings.Contains(perms, "x")
		if existing, seen := byInode[inode]; seen {
			// Already have this inode. Upgrade to the r-xp VMA's rangeKey if the
			// stored one was not executable and this VMA is.
			if isExec && !execChosen[inode] {
				existing.rangeKey = rangeKey
				byInode[inode] = existing
				execChosen[inode] = true
			}
			continue
		}

		byInode[inode] = mappedLib{rangeKey: rangeKey, inode: inode, path: path}
		execChosen[inode] = isExec
		order = append(order, inode)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning maps: %w", err)
	}

	libs := make([]mappedLib, 0, len(order))
	for _, inode := range order {
		libs = append(libs, byInode[inode])
	}
	return libs, nil
}

// parseInode parses the maps inode field. A malformed value is treated as 0
// (non-file-backed) so a single bad line is skipped rather than failing the walk.
func parseInode(field string) uint64 {
	var inode uint64
	if _, err := fmt.Sscanf(field, "%d", &inode); err != nil {
		return 0
	}
	return inode
}

// openMapFile opens /proc/<containerPid>/map_files/<rangeKey> O_RDONLY (NOT
// O_PATH: the downstream inode read needs a real fd), verifies it is a regular
// file, and re-validates that the fd still belongs to the tracked container
// before returning. This is the new open primitive that secureopen.OpenInContainer
// cannot provide because it refuses procfs magic links.
//
// expectedMntns is the mount-namespace inode recorded for the container at
// discovery time (see readProcMntns). After opening, openMapFile re-reads
// /proc/<containerPid>/ns/mnt and rejects the open if the PID is gone or now
// lives in a different mount namespace: a recycled PID that has been reused by
// another container (or the host) MUST NOT receive a host-wide uprobe.
//
// On the expected, NON-FATAL failure modes (EACCES/EPERM/ENOENT and the
// PID-recycle/teardown races) openMapFile returns an error wrapping
// ErrMapFileUnavailable; callers log-and-skip and never fail the tracer.
func openMapFile(containerPid uint32, rangeKey string, expectedMntns uint64) (*os.File, error) {
	mapFilePath := filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "map_files", rangeKey)

	f, err := os.OpenFile(mapFilePath, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) ||
			errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("opening %q: %w: %w", mapFilePath, ErrMapFileUnavailable, err)
		}
		return nil, fmt.Errorf("opening %q: %w", mapFilePath, err)
	}

	// Verify a regular file immediately on the open fd (mirrors secureopen's
	// S_IFREG gate) before doing anything else with it.
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("fstat %q: %w: %w", mapFilePath, ErrMapFileUnavailable, err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%q: not a regular file (mode %s)", mapFilePath, fi.Mode())
	}

	// Container-escape defense: the PID must still be alive and in the SAME mount
	// namespace recorded at discovery time. A PID recycled into another container
	// or the host between discovery and open would otherwise receive the uprobe.
	currentMntns, err := readProcMntns(containerPid)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("re-reading mntns for pid %d: %w: %w", containerPid, ErrMapFileUnavailable, err)
	}
	if currentMntns != expectedMntns {
		f.Close()
		return nil, fmt.Errorf("pid %d mntns changed (expected %d, got %d): %w",
			containerPid, expectedMntns, currentMntns, ErrMapFileUnavailable)
	}

	return f, nil
}

// readProcMntns returns the mount-namespace inode of containerPid by reading the
// /proc/<pid>/ns/mnt magic link (e.g. "mnt:[4026532abc]"). Used both to record
// the expected mntns at discovery time and to re-validate it in openMapFile.
func readProcMntns(containerPid uint32) (uint64, error) {
	nsPath := filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "ns", "mnt")
	target, err := os.Readlink(nsPath)
	if err != nil {
		return 0, fmt.Errorf("readlink %q: %w", nsPath, err)
	}
	// Format: "mnt:[<inode>]".
	open := strings.IndexByte(target, '[')
	close := strings.IndexByte(target, ']')
	if open < 0 || close < 0 || close <= open+1 {
		return 0, fmt.Errorf("unexpected mntns link %q", target)
	}
	var inode uint64
	if _, err := fmt.Sscanf(target[open+1:close], "%d", &inode); err != nil {
		return 0, fmt.Errorf("parsing mntns inode from %q: %w", target, err)
	}
	return inode, nil
}

// elfMachineMatchesProcess reports whether the ELF e_machine of the already-open
// file matches that of the container process (read from /proc/<containerPid>/exe).
// When several matched inodes exist (e.g. a multi-arch image ships both x86_64
// and aarch_64 .so files), the caller uses this to attach only the .so whose
// architecture matches the running process. The host architecture is never
// assumed.
//
// The passed file's read offset is restored before returning so the caller can
// reuse the same fd.
func elfMachineMatchesProcess(file *os.File, containerPid uint32) (bool, error) {
	fileMachine, err := elfMachineFromReaderAt(file)
	if err != nil {
		return false, fmt.Errorf("reading ELF machine from mapped file: %w", err)
	}

	exePath := filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "exe")
	exe, err := os.Open(exePath)
	if err != nil {
		return false, fmt.Errorf("opening %q: %w", exePath, err)
	}
	defer exe.Close()

	procMachine, err := elfMachineFromReaderAt(exe)
	if err != nil {
		return false, fmt.Errorf("reading ELF machine from %q: %w", exePath, err)
	}

	return fileMachine == procMachine, nil
}

// elfMachineFromReaderAt reads only the ELF header e_machine from r without
// consuming the file's read offset (elf.NewFile uses ReaderAt).
func elfMachineFromReaderAt(r io.ReaderAt) (elf.Machine, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return 0, err
	}
	defer ef.Close()
	return ef.Machine, nil
}
