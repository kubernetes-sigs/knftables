/*
Copyright 2023 The Kubernetes Authors.

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

package knftables

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func getObjType(object Object) string {
	fullType := fmt.Sprintf("%T", object)
	parts := strings.Split(fullType, ".")
	return parts[len(parts)-1]
}

func TestObjects(t *testing.T) {
	tested := make(map[string]map[verb]struct{})

	for _, tc := range []struct {
		name   string
		verb   verb
		object Object
		err    string
		out    string
	}{
		// Tables
		{
			name:   "add table",
			verb:   addVerb,
			object: &Table{},
			out:    `add table ip mytable`,
		},
		{
			name:   "add table with comment",
			verb:   addVerb,
			object: &Table{Comment: PtrTo("foo")},
			out:    `add table ip mytable { comment "foo" ; }`,
		},
		{
			name:   "create table",
			verb:   createVerb,
			object: &Table{},
			out:    `create table ip mytable`,
		},
		{
			name:   "flush table",
			verb:   flushVerb,
			object: &Table{},
			out:    `flush table ip mytable`,
		},
		{
			name:   "delete table",
			verb:   deleteVerb,
			object: &Table{},
			out:    `delete table ip mytable`,
		},
		{
			name:   "delete table by handle",
			verb:   deleteVerb,
			object: &Table{Handle: PtrTo(5)},
			out:    `delete table ip handle 5`,
		},
		{
			name:   "invalid insert table",
			verb:   insertVerb,
			object: &Table{},
			err:    "not implemented",
		},
		{
			name:   "invalid replace table",
			verb:   replaceVerb,
			object: &Table{},
			err:    "not implemented",
		},
		{
			name:   "invalid add table with Handle",
			verb:   addVerb,
			object: &Table{Handle: PtrTo(5)},
			err:    "cannot specify Handle",
		},

		// Flowtables
		{
			name: "add flowtable",
			verb: addVerb,
			object: &Flowtable{
				Name: "myflowtable",
			},
			out: `add flowtable ip mytable myflowtable { }`,
		},
		{
			name: "create flowtable",
			verb: createVerb,
			object: &Flowtable{
				Name: "myflowtable",
			},
			out: `create flowtable ip mytable myflowtable { }`,
		},
		{
			name: "create flowtable with priority math",
			verb: createVerb,
			object: &Flowtable{
				Name:     "myflowtable",
				Priority: PtrTo(FilterIngressPriority + "+5"),
			},
			out: `create flowtable ip mytable myflowtable { hook ingress priority filter+5 ; }`,
		},
		{
			name: "create flowtable with devices",
			verb: createVerb,
			object: &Flowtable{
				Name:    "myflowtable",
				Devices: []string{"eth0", "eth1"},
			},
			out: `create flowtable ip mytable myflowtable { devices = { eth0, eth1 } ; }`,
		},
		{
			name: "create flowtable with devices and default priority",
			verb: createVerb,
			object: &Flowtable{
				Name:     "myflowtable",
				Priority: PtrTo(FilterIngressPriority),
				Devices:  []string{"eth0", "eth1"},
			},
			out: `create flowtable ip mytable myflowtable { hook ingress priority filter ; devices = { eth0, eth1 } ; }`,
		},
		{
			name: "flush flowtable",
			verb: flushVerb,
			object: &Flowtable{
				Name: "myflowtable",
			},
			err: "not implemented",
		},
		{
			name: "delete flowtable",
			verb: deleteVerb,
			object: &Flowtable{
				Name: "myflowtable",
			},
			out: `delete flowtable ip mytable myflowtable`,
		},
		{
			name: "delete flowtable by handle",
			verb: deleteVerb,
			object: &Flowtable{
				Name:   "myflowtable",
				Handle: PtrTo(5),
			},
			out: `delete flowtable ip mytable handle 5`,
		},
		{
			name: "invalid insert flowtable",
			verb: insertVerb,
			object: &Flowtable{
				Name: "myflowtable",
			}, err: "not implemented",
		},
		{
			name: "invalid replace flowtable",
			verb: replaceVerb,
			object: &Flowtable{
				Name: "myflowtable",
			},
			err: "not implemented",
		},
		{
			name: "invalid add flowtable with Handle",
			verb: addVerb,
			object: &Flowtable{
				Name:   "myflowtable",
				Handle: PtrTo(5),
			},
			err: "cannot specify Handle",
		},

		// Chains
		{
			name:   "add chain",
			verb:   addVerb,
			object: &Chain{Name: "mychain"},
			out:    `add chain ip mytable mychain`,
		},
		{
			name:   "add chain with comment",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Comment: PtrTo("foo")},
			out:    `add chain ip mytable mychain { comment "foo" ; }`,
		},
		{
			name:   "add base chain",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Hook: PtrTo(PostroutingHook), Priority: PtrTo(SNATPriority)},
			out:    `add chain ip mytable mychain { type nat hook postrouting priority 100 ; }`,
		},
		{
			name:   "add base chain with priority math",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Hook: PtrTo(PostroutingHook), Priority: PtrTo(SNATPriority + "+5")},
			out:    `add chain ip mytable mychain { type nat hook postrouting priority 105 ; }`,
		},
		{
			name:   "add base chain with unrecognized priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Hook: PtrTo(PostroutingHook), Priority: PtrTo(BaseChainPriority("futurevalue"))},
			out:    `add chain ip mytable mychain { type nat hook postrouting priority futurevalue ; }`,
		},
		{
			name:   "add base chain with comment",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Hook: PtrTo(PostroutingHook), Priority: PtrTo(SNATPriority), Comment: PtrTo("foo")},
			out:    `add chain ip mytable mychain { type nat hook postrouting priority 100 ; comment "foo" ; }`,
		},
		{
			name:   "add base chain with device",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Hook: PtrTo(IngressHook), Device: PtrTo("eth0"), Priority: PtrTo(SNATPriority)},
			out:    `add chain ip mytable mychain { type nat hook ingress device "eth0" priority 100 ; }`,
		},
		{
			name:   "create chain",
			verb:   createVerb,
			object: &Chain{Name: "mychain"},
			out:    `create chain ip mytable mychain`,
		},
		{
			name:   "flush chain",
			verb:   flushVerb,
			object: &Chain{Name: "mychain"},
			out:    `flush chain ip mytable mychain`,
		},
		{
			name:   "delete chain",
			verb:   deleteVerb,
			object: &Chain{Name: "mychain"},
			out:    `delete chain ip mytable mychain`,
		},
		{
			name:   "delete chain by handle",
			verb:   deleteVerb,
			object: &Chain{Name: "mychain", Handle: PtrTo(5)},
			out:    `delete chain ip mytable handle 5`,
		},
		{
			name:   "delete chain by handle (without name)",
			verb:   deleteVerb,
			object: &Chain{Handle: PtrTo(5)},
			out:    `delete chain ip mytable handle 5`,
		},
		{
			name:   "invalid insert chain",
			verb:   insertVerb,
			object: &Chain{Name: "mychain"},
			err:    "not implemented",
		},
		{
			name:   "invalid replace chain",
			verb:   replaceVerb,
			object: &Chain{Name: "mychain"},
			err:    "not implemented",
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
			object: &Chain{Name: "mychain", Handle: PtrTo(5)},
			err:    "cannot specify Handle",
		},
		{
			name:   "invalid add base chain with no Type",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Hook: PtrTo(PostroutingHook), Priority: PtrTo(SNATPriority)},
			err:    "must specify Type and Priority",
		},
		{
			name:   "invalid add base chain with no Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Hook: PtrTo(PostroutingHook)},
			err:    "must specify Type and Priority",
		},
		{
			name:   "invalid add base chain with no Type or Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Hook: PtrTo(PostroutingHook)},
			err:    "must specify Type and Priority",
		},
		{
			name:   "invalid add non-base chain with Type and Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Priority: PtrTo(SNATPriority)},
			err:    "must not specify Type or Priority",
		},
		{
			name:   "invalid add non-base chain with Type",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Type: PtrTo(NATType)},
			err:    "must not specify Type or Priority",
		},
		{
			name:   "invalid add non-base chain with Priority",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Priority: PtrTo(SNATPriority)},
			err:    "must not specify Type or Priority",
		},
		{
			name:   "invalid add non-base chain with device",
			verb:   addVerb,
			object: &Chain{Name: "mychain", Device: PtrTo("eth0")},
			err:    "must not specify Device",
		},

		// Rules
		{
			name:   "add rule",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
			out:    `add rule ip mytable mychain drop`,
		},
		{
			name:   "add rule with comment",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Comment: PtrTo("comment")},
			out:    `add rule ip mytable mychain drop comment "comment"`,
		},
		{
			name:   "add rule relative to index",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Index: PtrTo(2)},
			out:    `add rule ip mytable mychain index 2 drop`,
		},
		{
			name:   "add rule relative to handle",
			verb:   addVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Handle: PtrTo(2)},
			out:    `add rule ip mytable mychain handle 2 drop`,
		},
		{
			name:   "insert rule",
			verb:   insertVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
			out:    `insert rule ip mytable mychain drop`,
		},
		{
			name:   "insert rule with comment relative to handle",
			verb:   insertVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Comment: PtrTo("comment"), Handle: PtrTo(2)},
			out:    `insert rule ip mytable mychain handle 2 drop comment "comment"`,
		},
		{
			name:   "replace rule",
			verb:   replaceVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Handle: PtrTo(2)},
			out:    `replace rule ip mytable mychain handle 2 drop`,
		},
		{
			name:   "delete rule",
			verb:   deleteVerb,
			object: &Rule{Chain: "mychain", Rule: "drop", Handle: PtrTo(2)},
			out:    `delete rule ip mytable mychain handle 2`,
		},
		{
			name:   "delete rule without Rule",
			verb:   deleteVerb,
			object: &Rule{Chain: "mychain", Handle: PtrTo(2)},
			out:    `delete rule ip mytable mychain handle 2`,
		},
		{
			name:   "invalid create rule",
			verb:   createVerb,
			object: &Rule{Chain: "mychain", Rule: "drop"},
			err:    "not implemented",
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
			object: &Rule{Chain: "mychain", Rule: "drop", Index: PtrTo(2), Handle: PtrTo(5)},
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
			out:    `add set ip mytable myset { type ipv4_addr ; }`,
		},
		{
			name:   "add set with TypeOf",
			verb:   addVerb,
			object: &Set{Name: "myset", TypeOf: "ip saddr"},
			out:    `add set ip mytable myset { typeof ip saddr ; }`,
		},
		{
			name: "add set with all properties",
			verb: addVerb,
			object: &Set{
				Name:       "myset",
				Type:       "ipv4_addr",
				Flags:      []SetFlag{DynamicFlag, IntervalFlag},
				Timeout:    PtrTo(3 * time.Minute),
				GCInterval: PtrTo(time.Hour),
				Size:       PtrTo[uint64](1000),
				Policy:     PtrTo(PerformancePolicy),
				AutoMerge:  PtrTo(true),
				Comment:    PtrTo("that's a lot of options"),
			},
			out: `add set ip mytable myset { type ipv4_addr ; flags dynamic,interval ; timeout 180s ; gc-interval 3600s ; size 1000 ; policy performance ; auto-merge ; comment "that's a lot of options" ; }`,
		},
		{
			name:   "create set",
			verb:   createVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr"},
			out:    `create set ip mytable myset { type ipv4_addr ; }`,
		},
		{
			name:   "flush set",
			verb:   flushVerb,
			object: &Set{Name: "myset"},
			out:    `flush set ip mytable myset`,
		},
		{
			name:   "flush set with extraneous Type",
			verb:   flushVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr"},
			out:    `flush set ip mytable myset`,
		},
		{
			name:   "delete set",
			verb:   deleteVerb,
			object: &Set{Name: "myset"},
			out:    `delete set ip mytable myset`,
		},
		{
			name:   "delete set by handle",
			verb:   deleteVerb,
			object: &Set{Name: "myset", Handle: PtrTo(5)},
			out:    `delete set ip mytable handle 5`,
		},
		{
			name:   "delete set by handle without Name",
			verb:   deleteVerb,
			object: &Set{Handle: PtrTo(5)},
			out:    `delete set ip mytable handle 5`,
		},
		{
			name:   "invalid insert set",
			verb:   insertVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr"},
			err:    "not implemented",
		},
		{
			name:   "invalid replace set",
			verb:   replaceVerb,
			object: &Set{Name: "myset", Type: "ipv4_addr"},
			err:    "not implemented",
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
			object: &Set{Name: "myset", Type: "ipv4_addr", Handle: PtrTo(5)},
			err:    "cannot specify Handle",
		},

		// Maps
		{
			name:   "add map",
			verb:   addVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
			out:    `add map ip mytable mymap { type ipv4_addr : ipv4_addr ; }`,
		},
		{
			name:   "add map with TypeOf",
			verb:   addVerb,
			object: &Map{Name: "mymap", TypeOf: "ip saddr : ip saddr"},
			out:    `add map ip mytable mymap { typeof ip saddr : ip saddr ; }`,
		},
		{
			name: "add map with all properties",
			verb: addVerb,
			object: &Map{
				Name:       "mymap",
				Type:       "ipv4_addr : ipv4_addr",
				Flags:      []SetFlag{DynamicFlag, IntervalFlag},
				Timeout:    PtrTo(3 * time.Minute),
				GCInterval: PtrTo(time.Hour),
				Size:       PtrTo[uint64](1000),
				Policy:     PtrTo(PerformancePolicy),
				Comment:    PtrTo("that's a lot of options"),
			},
			out: `add map ip mytable mymap { type ipv4_addr : ipv4_addr ; flags dynamic,interval ; timeout 180s ; gc-interval 3600s ; size 1000 ; policy performance ; comment "that's a lot of options" ; }`,
		},
		{
			name:   "create map",
			verb:   createVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
			out:    `create map ip mytable mymap { type ipv4_addr : ipv4_addr ; }`,
		},
		{
			name:   "flush map",
			verb:   flushVerb,
			object: &Map{Name: "mymap"},
			out:    `flush map ip mytable mymap`,
		},
		{
			name:   "flush map with extraneous Type",
			verb:   flushVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
			out:    `flush map ip mytable mymap`,
		},
		{
			name:   "delete map",
			verb:   deleteVerb,
			object: &Map{Name: "mymap"},
			out:    `delete map ip mytable mymap`,
		},
		{
			name:   "delete map by Handle",
			verb:   deleteVerb,
			object: &Map{Name: "mymap", Handle: PtrTo(5)},
			out:    `delete map ip mytable handle 5`,
		},
		{
			name:   "delete map by Handle without Name",
			verb:   deleteVerb,
			object: &Map{Handle: PtrTo(5)},
			out:    `delete map ip mytable handle 5`,
		},
		{
			name:   "invalid insert map",
			verb:   insertVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
			err:    "not implemented",
		},
		{
			name:   "invalid replace map",
			verb:   replaceVerb,
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
			err:    "not implemented",
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
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr", Handle: PtrTo(5)},
			err:    "cannot specify Handle",
		},

		// Elements
		{
			name:   "add (set) element",
			verb:   addVerb,
			object: &Element{Set: "myset", Key: []string{"10.0.0.1"}},
			out:    `add element ip mytable myset { 10.0.0.1 }`,
		},
		{
			name:   "add (map) element",
			verb:   addVerb,
			object: &Element{Map: "mymap", Key: []string{"10.0.0.1"}, Value: []string{"192.168.1.1"}},
			out:    `add element ip mytable mymap { 10.0.0.1 : 192.168.1.1 }`,
		},
		{
			name:   "create (set) element with comment",
			verb:   createVerb,
			object: &Element{Set: "myset", Key: []string{"10.0.0.1"}, Comment: PtrTo("comment")},
			out:    `create element ip mytable myset { 10.0.0.1 comment "comment" }`,
		},
		{
			name:   "create (map) element with comment",
			verb:   addVerb,
			object: &Element{Map: "mymap", Key: []string{"10.0.0.1"}, Value: []string{"192.168.1.1"}, Comment: PtrTo("comment")},
			out:    `add element ip mytable mymap { 10.0.0.1 comment "comment" : 192.168.1.1 }`,
		},
		{
			name:   "delete (set) element",
			verb:   deleteVerb,
			object: &Element{Set: "myset", Key: []string{"10.0.0.1"}},
			out:    `delete element ip mytable myset { 10.0.0.1 }`,
		},
		{
			name:   "delete (map) element with unnecessary Value",
			verb:   deleteVerb,
			object: &Element{Map: "mymap", Key: []string{"10.0.0.1"}, Value: []string{"192.168.1.1"}},
			out:    `delete element ip mytable mymap { 10.0.0.1 }`,
		},
		{
			name:   "delete (map) element",
			verb:   deleteVerb,
			object: &Element{Map: "mymap", Key: []string{"10.0.0.1"}},
			out:    `delete element ip mytable mymap { 10.0.0.1 }`,
		},
		{
			name:   "invalid add element with no Set",
			verb:   addVerb,
			object: &Element{Key: []string{"10.0.0.1"}},
			err:    "no set/map name",
		},
		{
			name:   "invalid add element with no Map",
			verb:   addVerb,
			object: &Element{Key: []string{"10.0.0.1"}, Value: []string{"80"}},
			err:    "no set/map name",
		},
		{
			name:   "invalid add element with both Set and Map",
			verb:   addVerb,
			object: &Element{Set: "myset", Map: "mymap", Key: []string{"10.0.0.1"}},
			err:    "both",
		},
		{
			name:   "invalid add element with no Key",
			verb:   addVerb,
			object: &Element{Set: "myset"},
			err:    "no key",
		},
		{
			name:   "invalid add element with Value but no Key",
			verb:   addVerb,
			object: &Element{Map: "mymap", Value: []string{"192.168.1.1"}},
			err:    "no key",
		},
		{
			name:   "invalid flush element",
			verb:   flushVerb,
			object: &Element{Set: "myset", Key: []string{"10.0.0.1"}},
			err:    "not implemented",
		},
		{
			name:   "invalid insert element",
			verb:   insertVerb,
			object: &Element{Set: "myset", Key: []string{"10.0.0.1"}},
			err:    "not implemented",
		},
		{
			name:   "invalid replace element",
			verb:   replaceVerb,
			object: &Element{Set: "myset", Key: []string{"10.0.0.1"}},
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

			objType := getObjType(tc.object)
			if tested[objType] == nil {
				tested[objType] = make(map[verb]struct{})
			}
			tested[objType][tc.verb] = struct{}{}

			if err == nil && tc.err == "" {
				b := &strings.Builder{}
				ctx := &nftContext{family: IPv4Family, table: "mytable"}
				tc.object.writeOperation(tc.verb, ctx, b)
				out := strings.TrimSuffix(b.String(), "\n")
				if out != tc.out {
					t.Errorf("expected %q but got %q", tc.out, out)
				}
			}
		})
	}

	// add, create, flush, insert, replace, delete
	numVerbs := 6
	for objType, verbs := range tested {
		if len(verbs) != numVerbs {
			t.Errorf("expected to test %d verbs for %s, got %d (%v)", numVerbs, objType, len(verbs), verbs)
		}
	}
}

func TestNoObjectComments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object Object
		out    string
	}{
		{
			name:   "add table with comment",
			object: &Table{Comment: PtrTo("foo")},
			out:    `add table ip mytable`,
		},
		{
			name:   "add chain with comment",
			object: &Chain{Name: "mychain", Comment: PtrTo("foo")},
			out:    `add chain ip mytable mychain`,
		},
		{
			name:   "add base chain with comment",
			object: &Chain{Name: "mychain", Type: PtrTo(NATType), Hook: PtrTo(PostroutingHook), Priority: PtrTo(SNATPriority), Comment: PtrTo("foo")},
			out:    `add chain ip mytable mychain { type nat hook postrouting priority 100 ; }`,
		},
		{
			name:   "add rule with comment",
			object: &Rule{Chain: "mychain", Rule: "drop", Comment: PtrTo("comment")},
			out:    `add rule ip mytable mychain drop comment "comment"`,
		},
		{
			name:   "add set with comment",
			object: &Set{Name: "myset", Type: "ipv4_addr", Comment: PtrTo("comment")},
			out:    `add set ip mytable myset { type ipv4_addr ; }`,
		},
		{
			name:   "add map with comment",
			object: &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr", Comment: PtrTo("comment")},
			out:    `add map ip mytable mymap { type ipv4_addr : ipv4_addr ; }`,
		},
		{
			name:   "add (set) element with comment",
			object: &Element{Set: "myset", Key: []string{"10.0.0.1"}, Comment: PtrTo("comment")},
			out:    `add element ip mytable myset { 10.0.0.1 comment "comment" }`,
		},
		{
			name:   "add (map) element with comment",
			object: &Element{Map: "mymap", Key: []string{"10.0.0.1"}, Value: []string{"192.168.1.1"}, Comment: PtrTo("comment")},
			out:    `add element ip mytable mymap { 10.0.0.1 comment "comment" : 192.168.1.1 }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &strings.Builder{}
			ctx := &nftContext{family: IPv4Family, table: "mytable", noObjectComments: true}
			tc.object.writeOperation(addVerb, ctx, b)
			out := strings.TrimSuffix(b.String(), "\n")
			if out != tc.out {
				t.Errorf("expected %q but got %q", tc.out, out)
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
