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

import (
	"regexp"
	"strings"
	"testing"
)

// tcnativeRe mirrors the node-agent-side matcher shape; the basename pattern is
// caller-supplied, so it is defined here in the test rather than baked into the
// parser. It is deliberately broad (suffix omitted) to also catch the
// " (deleted)" stripping behaviour.
var tcnativeRe = regexp.MustCompile(`^libnetty_tcnative_linux_.*\.so`)

func TestParseMappedLibraries(t *testing.T) {
	tests := []struct {
		name    string
		maps    string
		pattern *regexp.Regexp
		// want maps an expected inode -> expected rangeKey. The number of
		// entries also asserts dedup/count.
		want map[uint64]string
	}{
		{
			name: "tcnative present with deleted suffix, single r-xp VMA",
			// Modeled on the spike's actual maps line.
			maps: strings.Join([]string{
				"7e87145dc000-7e87145ff000 r--p 00000000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
				"7e87145ff000-7e871477f000 r-xp 00023000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
			}, "\n"),
			pattern: tcnativeRe,
			want:    map[uint64]string{1057930: "7e87145ff000-7e871477f000"},
		},
		{
			name: "tcnative absent",
			maps: strings.Join([]string{
				"55a000000000-55a000021000 r-xp 00000000 fd:00 131073    /usr/lib/jvm/java-21/bin/java",
				"7f0000000000-7f0000123000 r-xp 00001000 fd:00 262145    /usr/lib/x86_64-linux-gnu/libc.so.6",
			}, "\n"),
			pattern: tcnativeRe,
			want:    map[uint64]string{},
		},
		{
			name: "same inode mapped as multiple VMAs dedups to one r-xp entry",
			maps: strings.Join([]string{
				"7e8714000000-7e8714023000 r--p 00000000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
				"7e8714023000-7e87141a3000 r-xp 00023000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
				"7e87141a3000-7e87141b3000 rw-p 001a3000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
			}, "\n"),
			pattern: tcnativeRe,
			want:    map[uint64]string{1057930: "7e8714023000-7e87141a3000"},
		},
		{
			name: "multi-arch: two distinct matched inodes both returned",
			maps: strings.Join([]string{
				"7e8714000000-7e8714180000 r-xp 00023000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
				"7e8715000000-7e8715180000 r-xp 00023000 00:2e 2222222   /tmp/libnetty_tcnative_linux_aarch_645151.so (deleted)",
			}, "\n"),
			pattern: tcnativeRe,
			want: map[uint64]string{
				1057930: "7e8714000000-7e8714180000",
				2222222: "7e8715000000-7e8715180000",
			},
		},
		{
			name: "non-ELF anon, heap, stack and malformed lines ignored",
			maps: strings.Join([]string{
				"7e8714000000-7e8714180000 r-xp 00023000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
				"5500000000-5500021000 rw-p 00000000 00:00 0 ",                 // anonymous, inode 0
				"5600000000-5600021000 rw-p 00000000 00:00 0          [heap]",  // heap, inode 0
				"7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0      [stack]", // stack, inode 0
				"this is not a maps line",        // malformed
				"7e8716000000-7e8716001000 r--p", // truncated mid-read
				"7e8717000000-7e8717123000 r-xp 00000000 fd:00 999    /usr/lib/x86_64-linux-gnu/libssl.so.3", // file-backed but no match
			}, "\n"),
			pattern: tcnativeRe,
			want:    map[uint64]string{1057930: "7e8714000000-7e8714180000"},
		},
		{
			name: "first VMA is r-xp, later non-exec VMAs do not downgrade rangeKey",
			maps: strings.Join([]string{
				"7e8714023000-7e87141a3000 r-xp 00023000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
				"7e8714000000-7e8714023000 r--p 00000000 00:2e 1057930   /tmp/libnetty_tcnative_linux_x86_644242.so (deleted)",
			}, "\n"),
			pattern: tcnativeRe,
			want:    map[uint64]string{1057930: "7e8714023000-7e87141a3000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			libs, err := parseMappedLibraries(strings.NewReader(tt.maps), tt.pattern)
			if err != nil {
				t.Fatalf("parseMappedLibraries returned error: %v", err)
			}
			if len(libs) != len(tt.want) {
				t.Fatalf("got %d libs, want %d: %+v", len(libs), len(tt.want), libs)
			}
			for _, lib := range libs {
				wantRange, ok := tt.want[lib.inode]
				if !ok {
					t.Errorf("unexpected inode %d (rangeKey %q, path %q)", lib.inode, lib.rangeKey, lib.path)
					continue
				}
				if lib.rangeKey != wantRange {
					t.Errorf("inode %d: got rangeKey %q, want %q", lib.inode, lib.rangeKey, wantRange)
				}
				if strings.Contains(lib.path, "(deleted)") {
					t.Errorf("inode %d: path %q still contains the deleted suffix", lib.inode, lib.path)
				}
			}
		})
	}
}

func TestMapFilesParseInode(t *testing.T) {
	tests := []struct {
		field string
		want  uint64
	}{
		{"1057930", 1057930},
		{"0", 0},
		{"notanumber", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := parseInode(tt.field); got != tt.want {
			t.Errorf("parseInode(%q) = %d, want %d", tt.field, got, tt.want)
		}
	}
}
