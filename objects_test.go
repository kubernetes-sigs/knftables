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
	makeChain := func(family Family, prio string) *Chain {
		return &Chain{
			Table: &TableName{
				Family: family,
				Name:   "test",
			},
			Name: "test",

			Type:     Optional(FilterType),
			Hook:     Optional(OutputHook),
			Priority: Optional(BaseChainPriority(prio)),
		}
	}

	for _, tc := range []struct {
		name     string
		chain    *Chain
		err      bool
		priority int
	}{
		{
			name:     "basic",
			chain:    makeChain(IPv4Family, "dstnat"),
			priority: -100,
		},
		{
			name:     "bridge family",
			chain:    makeChain(BridgeFamily, "dstnat"),
			priority: -300,
		},
		{
			name:     "numeric",
			chain:    makeChain(IPv4Family, "35"),
			priority: 35,
		},
		{
			name:     "numeric, negative",
			chain:    makeChain(IPv4Family, "-35"),
			priority: -35,
		},
		{
			name:     "addition",
			chain:    makeChain(IPv4Family, "srcnat+1"),
			priority: 101,
		},
		{
			name:     "subtraction",
			chain:    makeChain(IPv4Family, "srcnat-1"),
			priority: 99,
		},
		{
			name:  "unknown",
			chain: makeChain(IPv4Family, "blah"),
			err:   true,
		},
		{
			name:  "unknown with math",
			chain: makeChain(IPv4Family, "blah+1"),
			err:   true,
		},
		{
			name:  "bad math",
			chain: makeChain(IPv4Family, "dstnat+one"),
			err:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			val, err := tc.chain.ParsePriority()
			if tc.err {
				if err == nil {
					t.Errorf("expected error, got %d", val)
				}
			} else {
				if err != nil {
					t.Errorf("expected %d, got error %v", tc.priority, err)
				} else if val != tc.priority {
					t.Errorf("expected %d, got %d", tc.priority, val)
				}
			}
		})
	}
}
