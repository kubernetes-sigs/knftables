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
	"strings"
	"testing"
)

func Test_validate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		verb   verb
		object Object
		err    string
	}{
		// Tables
		{
			name:   "add table",
			verb:   addVerb,
			object: &Table{},
		},
		{
			name:   "add table with comment",
			verb:   addVerb,
			object: &Table{Comment: Optional("foo")},
		},
		{
			name:   "flush table",
			verb:   flushVerb,
			object: &Table{},
		},
		{
			name:   "delete table",
			verb:   deleteVerb,
			object: &Table{},
		},
		{
			name:   "delete table by handle",
			verb:   deleteVerb,
			object: &Table{Handle: Optional(5)},
		},
		{
			name:   "invalid add table",
			verb:   addVerb,
			object: &Table{Handle: Optional(5)},
			err:    "cannot specify Handle",
		},

		// Chains
		{
			name:   "add chain",
			verb:   addVerb,
			object: &Chain{Name: "mychain"},
		},
		{
			name:   "add chain with comment",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Comment: Optional("foo")},
		},
		{
			name:   "add base chain",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: Optional(NATType), Hook: Optional(PostroutingHook), Priority: Optional(SNATPriority)},
		},
		{
			name:   "add base chain with comment",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: Optional(NATType), Hook: Optional(PostroutingHook), Priority: Optional(SNATPriority), Comment: Optional("foo")},
		},
		{
			name:   "flush chain",
			verb:   flushVerb,
			object: &Chain{Name: "mychain"},
		},
		{
			name:   "delete chain",
			verb:   deleteVerb,
			object: &Chain{Name: "mychain"},
		},
		{
			name:   "delete chain by handle",
			verb:   deleteVerb,
			object: &Chain{Name: "mychain", Handle: Optional(5)},
		},
		{
			name:   "delete chain by handle (without name)",
			verb:   deleteVerb,
			object: &Chain{Handle: Optional(5)},
		},
		{
			name:   "invalid add chain without name",
			verb:   addVerb,
			object: &Chain{},
			err:    "no name",
		},
		{
			name:   "invalid add chain with handle",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Handle: Optional(5)},
			err:    "cannot specify Handle",
		},
		{
			name:   "invalid add base chain with no Type",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Hook: Optional(PostroutingHook), Priority: Optional(SNATPriority)},
			err:    "must specify Type and Priority",
		},
		{
			name:   "invalid add base chain with no Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: Optional(NATType), Hook: Optional(PostroutingHook)},
			err:    "must specify Type and Priority",
		},
		{
			name:   "invalid add base chain with no Type or Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Hook: Optional(PostroutingHook)},
			err:    "must specify Type and Priority",
		},
		{
			name:   "invalid add non-base chain with Type and Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: Optional(NATType), Priority: Optional(SNATPriority)},
			err:    "must not specify Type or Priority",
		},
		{
			name:   "invalid add non-base chain with Type",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: Optional(NATType)},
			err:    "must not specify Type or Priority",
		},
		{
			name:   "invalid add non-base chain with Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Priority: Optional(SNATPriority)},
			err:    "must not specify Type or Priority",
		},

		// Rules
		{
			name:   "add rule",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
		},
		{
			name:   "add rule with comment",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Comment: Optional("comment")},
		},
		{
			name:   "add rule relative to index",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Index: Optional(2)},
		},
		{
			name:   "add rule relative to handle",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Handle: Optional(2)},
		},
		{
			name:   "insert rule",
			verb:   insertVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
		},
		{
			name:   "insert rule with comment relative to handle",
			verb:   insertVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Comment: Optional("comment"), Handle: Optional(2)},
		},
		{
			name:   "replace rule",
			verb:   replaceVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Handle: Optional(2)},
		},
		{
			name:   "delete rule",
			verb:   deleteVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Handle: Optional(2)},
		},
		{
			name:   "delete rule without Rule",
			verb:   deleteVerb,
			object: &Rule{Chain: "mychain", Handle: Optional(2)},
		},
		{
			name:   "invalid flush rule",
			verb:   flushVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
			err:    "not implemented",
		},
		{
			name:   "invalid add rule with no Chain",
			verb:   addVerb,
			object: &Rule{Rule: "drop"},
			err:    "no chain name",
		},
		{
			name:   "invalid add rule with no Rule",
			verb:   addVerb,
			object: &Rule{Chain: "mychain"},
			err:    "no rule",
		},
		{
			name:   "invalid add rule with both Index and Handle",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Index: Optional(2), Handle: Optional(5)},
			err:    "both Index and Handle",
		},
		{
			name:   "invalid replace rule with no Handle",
			verb:   replaceVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
			err:    "must specify Handle",
		},
		{
			name:   "invalid delete rule with no Handle",
			verb:   deleteVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
			err:    "must specify Handle",
		},

		// Sets
		{
			name:   "add set",
			verb:   addVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr"},
		},
		{
			name:   "add set with TypeOf",
			verb:   addVerb,
			object: &Set{Name: "myset", TypeOf: "ip addr"},
		},
		{
			name:   "flush set",
			verb:   flushVerb,
			object: &Set{Name: "myset"},
		},
		{
			name:   "flush set with extraneous Type",
			verb:   flushVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr"},
		},
		{
			name:   "delete set",
			verb:   deleteVerb,
			object: &Set{Name: "myset"},
		},
		{
			name:   "delete set by handle",
			verb:   deleteVerb,
			object: &Set{Name: "myset", Handle: Optional(5)},
		},
		{
			name:   "delete set by handle without Name",
			verb:   deleteVerb,
			object: &Set{Handle: Optional(5)},
		},
		{
			name:   "invalid add set without Name",
			verb:   addVerb,
			object: &Set{Type: "ipv4_addr"},
			err:    "no name",
		},
		{
			name:   "invalid add set without Type or TypeOf",
			verb:   addVerb,
			object: &Set{Name: "myset"},
			err:    "must specify either Type or TypeOf",
		},
		{
			name:   "invalid add set with both Type and TypeOf",
			verb:   addVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr", TypeOf: "ip addr"},
			err:    "must specify either Type or TypeOf",
		},
		{
			name:   "invalid add set with Handle",
			verb:   addVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr", Handle: Optional(5)},
			err:    "cannot specify Handle",
		},

		// Maps
		{
			name:   "add map",
			verb:   addVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
		},
		{
			name:   "add map with TypeOf",
			verb:   addVerb,
			object: &Map{Name: "mymap", TypeOf: "ip addr : ip addr"},
		},
		{
			name:   "flush map",
			verb:   flushVerb,
			object: &Map{Name: "mymap"},
		},
		{
			name:   "flush map with extraneous Type",
			verb:   flushVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
		},
		{
			name:   "delete map",
			verb:   deleteVerb,
			object: &Map{Name: "mymap"},
		},
		{
			name:   "delete map by Handle",
			verb:   deleteVerb,
			object: &Map{Name: "mymap", Handle: Optional(5)},
		},
		{
			name:   "delete map by Handle without Name",
			verb:   deleteVerb,
			object: &Map{Handle: Optional(5)},
		},
		{
			name:   "invalid add map without Name",
			verb:   addVerb,
			object: &Map{Type: "ipv4_addr : ipv4_addr"},
			err:    "no name",
		},
		{
			name:   "invalid add map without Type of TypeOf",
			verb:   addVerb,
			object: &Map{Name: "mymap"},
			err:    "must specify either Type or TypeOf",
		},
		{
			name:   "invalid add map with both Type and TypeOf",
			verb:   addVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr", TypeOf: "ip addr : ip addr"},
			err:    "must specify either Type or TypeOf",
		},
		{
			name:   "invalid add map with Handle",
			verb:   addVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr", Handle: Optional(5)},
			err:    "cannot specify Handle",
		},

		// Elements
		{
			name:   "add (set) element",
			verb:   addVerb,
			object: &Element{Name: "myset", Key: "10.0.0.1"},
		},
		{
			name:   "add (map) element",
			verb:   addVerb,
			object: &Element{Name: "mymap", Key: "10.0.0.1", Value: "192.168.1.1"},
		},
		{
			name:   "delete (set) element",
			verb:   deleteVerb,
			object: &Element{Name: "myset", Key: "10.0.0.1"},
		},
		{
			name:   "delete (map) element with unnecessary Value",
			verb:   deleteVerb,
			object: &Element{Name: "mymap", Key: "10.0.0.1", Value: "192.168.1.1"},
		},
		{
			name:   "delete (map) element",
			verb:   deleteVerb,
			object: &Element{Name: "mymap", Key: "10.0.0.1"},
		},
		{
			name:   "invalid add element with no Name",
			verb:   addVerb,
			object: &Element{Key: "10.0.0.1"},
			err:    "no set/map name",
		},
		{
			name:   "invalid add element with no Key",
			verb:   addVerb,
			object: &Element{Name: "myset"},
			err:    "no key",
		},
		{
			name:   "invalid add element with Value but no Key",
			verb:   addVerb,
			object: &Element{Name: "mymap", Value: "192.168.1.1"},
			err:    "no key",
		},
		{
			name:   "invalid flush element",
			verb:   flushVerb,
			object: &Element{Name: "myset", Key: "10.0.0.1"},
			err:    "not implemented",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.object.validate(tc.verb)
			if err == nil {
				if tc.err != "" {
					t.Errorf("expected error with %q but got none", tc.err)
				}
			} else if tc.err == "" {
				t.Errorf("expected no error but got %q", err)
			} else if !strings.Contains(err.Error(), tc.err) {
				t.Errorf("expected error with %q but got %q", tc.err, err)
			}
		})
	}
}

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
