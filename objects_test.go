/*
Copyright 2023 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nftables

import (
	"testing"
)

func TestParsePriority(t *testing.T) {
	for _, tc := range []struct {
		name     string
		family   Family
		priority string
		err      bool
		out      int
	}{
		{
			name:     "basic",
			family:   IPv4Family,
			priority: "dstnat",
			out:      -100,
		},
		{
			name:     "bridge family",
			family:   BridgeFamily,
			priority: "dstnat",
			out:      -300,
		},
		{
			name:     "numeric",
			family:   IPv4Family,
			priority: "35",
			out:      35,
		},
		{
			name:     "numeric, negative",
			family:   IPv4Family,
			priority: "-35",
			out:      -35,
		},
		{
			name:     "addition",
			family:   IPv4Family,
			priority: "srcnat+1",
			out:      101,
		},
		{
			name:     "subtraction",
			family:   IPv4Family,
			priority: "srcnat-1",
			out:      99,
		},
		{
			name:     "unknown",
			family:   IPv4Family,
			priority: "blah",
			err:      true,
		},
		{
			name:     "unknown with math",
			family:   IPv4Family,
			priority: "blah+1",
			err:      true,
		},
		{
			name:     "bad math",
			family:   IPv4Family,
			priority: "dstnat+one",
			err:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			val, err := ParsePriority(tc.family, tc.priority)
			if tc.err {
				if err == nil {
					t.Errorf("expected error, got %d", val)
				}
			} else {
				if err != nil {
					t.Errorf("expected %d, got error %v", tc.out, err)
				} else if val != tc.out {
					t.Errorf("expected %d, got %d", tc.out, val)
				}
			}
		})
	}
}
