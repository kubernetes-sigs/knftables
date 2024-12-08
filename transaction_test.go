/*
Copyright 2024 The Kubernetes Authors.

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
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Test Destroy semantics, and in particular, that we get the same errors whether or not
// we have `nft destroy` support.
func TestDestroy(t *testing.T) {
	initialState := `
		add table ip mytable
		add chain ip mytable mychain
		add chain ip mytable mybasechain { type nat hook postrouting priority 100 ; }
		add set ip mytable myset { type ipv4_addr ; }
		add map ip mytable mymap { type ipv4_addr : ipv4_addr ; }
		add element ip mytable myset { 10.0.0.1 }
		add element ip mytable mymap { 10.0.0.1 : 192.168.1.1 }
	`

	for _, tc := range []struct {
		name         string
		object       Object
		destroyOut   string
		noDestroyOut string
		err          string
	}{
		{
			name:         "destroy table",
			object:       &Table{},
			destroyOut:   "destroy table ip mytable",
			noDestroyOut: "add table ip mytable\ndelete table ip mytable",
		},
		{
			name:         "destroy chain",
			object:       &Chain{Name: "mychain"},
			destroyOut:   "destroy chain ip mytable mychain",
			noDestroyOut: "add chain ip mytable mychain\ndelete chain ip mytable mychain",
		},
		{
			name:   "invalid destroy chain by Handle",
			object: &Chain{Handle: PtrTo(5)},
			err:    "no name specified",
		},
		{
			name:         "destroy base chain",
			object:       &Chain{Name: "mybasechain", Type: PtrTo(NATType), Hook: PtrTo(PostroutingHook), Priority: PtrTo(SNATPriority)},
			destroyOut:   "destroy chain ip mytable mybasechain",
			noDestroyOut: "add chain ip mytable mybasechain { type nat hook postrouting priority 100 ; }\ndelete chain ip mytable mybasechain",
		},
		{
			name:   "invalid destroy base chain with invalid Add data",
			object: &Chain{Name: "mybasechain", Hook: PtrTo(PostroutingHook)},
			err:    "must specify Type and Priority",
		},
		{
			name:         "destroy set",
			object:       &Set{Name: "myset", Type: "ipv4_addr"},
			destroyOut:   "destroy set ip mytable myset",
			noDestroyOut: "add set ip mytable myset { type ipv4_addr ; }\ndelete set ip mytable myset",
		},
		{
			name:   "invalid destroy set by handle",
			object: &Set{Handle: PtrTo(5)},
			err:    "no name specified for set",
		},
		{
			name:   "invalid destroy set with no Type",
			object: &Set{Name: "myset"},
			err:    "must specify either Type or TypeOf",
		},
		{
			name:         "destroy map",
			object:       &Map{Name: "mymap", Type: "ipv4_addr : ipv4_addr"},
			destroyOut:   "destroy map ip mytable mymap",
			noDestroyOut: "add map ip mytable mymap { type ipv4_addr : ipv4_addr ; }\ndelete map ip mytable mymap",
		},
		{
			name:   "invalid destroy map by handle",
			object: &Map{Handle: PtrTo(5)},
			err:    "no name specified for map",
		},
		{
			name:   "invalid destroy map with no Type",
			object: &Map{Name: "mymap"},
			err:    "must specify either Type or TypeOf",
		},
		{
			name:         "destroy set element",
			object:       &Element{Set: "myset", Key: []string{"10.0.0.1"}},
			destroyOut:   "destroy element ip mytable myset { 10.0.0.1 }",
			noDestroyOut: "add element ip mytable myset { 10.0.0.1 }\ndelete element ip mytable myset { 10.0.0.1 }",
		},
		{
			name:         "destroy map element",
			object:       &Element{Map: "mymap", Key: []string{"10.0.0.1"}, Value: []string{"192.168.1.1"}},
			destroyOut:   "destroy element ip mytable mymap { 10.0.0.1 }",
			noDestroyOut: "add element ip mytable mymap { 10.0.0.1 : 192.168.1.1 }\ndelete element ip mytable mymap { 10.0.0.1 }",
		},
		{
			name:   "invalid destroy map element with no Value",
			object: &Element{Map: "mymap", Key: []string{"10.0.0.1"}},
			err:    "no map value specified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := NewFake(IPv4Family, "mytable")
			fake.emulateDestroy = true
			fake.hasDestroy = true
			err := fake.ParseDump(initialState)
			if err != nil {
				t.Fatalf("unexpected error parsing initial state: %v", err)
			}

			tx := fake.NewTransaction()
			tx.Destroy(tc.object)
			err = fake.Run(context.Background(), tx)
			if tc.err != "" {
				if err == nil {
					t.Errorf("with destroy, expected error containing %q, got none", tc.err)
				} else if !strings.Contains(err.Error(), tc.err) {
					t.Errorf("with destroy, expected error containing %q, got %v", tc.err, err)
				}
			} else if err != nil {
				t.Errorf("with destroy, expected no error, got %v", err)
			} else {
				out := strings.TrimSuffix(tx.String(), "\n")
				if out != tc.destroyOut {
					t.Errorf("with destroy, expected commands %q, got %q", tc.destroyOut, out)
				}
			}
			destroyDump := fake.Dump()

			fake = NewFake(IPv4Family, "mytable")
			fake.emulateDestroy = true
			fake.hasDestroy = false
			err = fake.ParseDump(initialState)
			if err != nil {
				t.Fatalf("unexpected error parsing initial state: %v", err)
			}

			tx = fake.NewTransaction()
			tx.Destroy(tc.object)
			err = fake.Run(context.Background(), tx)
			if tc.err != "" {
				if err == nil {
					t.Errorf("emulating destroy, expected error containing %q, got none", tc.err)
				} else if !strings.Contains(err.Error(), tc.err) {
					t.Errorf("emulating destroy, expected error containing %q, got %v", tc.err, err)
				}
			} else if err != nil {
				t.Errorf("emulating destroy, expected no error, got %v", err)
			} else {
				out := strings.TrimSuffix(tx.String(), "\n")
				if out != tc.noDestroyOut {
					t.Errorf("emulating destroy, expected commands %q, got %q", tc.noDestroyOut, out)
				}
			}
			noDestroyDump := fake.Dump()

			if tc.err == "" {
				if diff := cmp.Diff(destroyDump, noDestroyDump); diff != "" {
					t.Errorf("unexpected difference between final state with destroy and final state without destroy:\n%s", diff)
				}
			}
		})
	}
}
