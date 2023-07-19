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
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/lithammer/dedent"
)

func TestFakeRun(t *testing.T) {
	fake := NewFake(IPv4Family, "kube-proxy")
	tx := NewTransaction()

	tx.Define("IP", "ip")

	tx.Add(&Table{})
	tx.Add(&Chain{
		Name:    "chain",
		Comment: Optional("foo"),
	})
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "$IP daddr 10.0.0.0/8 drop",
	})

	tx.Add(&Chain{
		Name: "anotherchain",
	})
	tx.Add(&Rule{
		Chain:   "anotherchain",
		Rule:    "$IP saddr 1.2.3.4 drop",
		Comment: Optional("drop rule"),
	})
	tx.Add(&Rule{
		Chain:   "anotherchain",
		Rule:    "$IP daddr 5.6.7.8 reject",
		Comment: Optional("reject rule"),
	})

	tx.Add(&Map{
		Name: "map1",
		Type: "ipv4_addr . inet_proto . inet_service : verdict",
	})
	tx.Add(&Element{
		Name:  "map1",
		Key:   "192.168.0.1 . tcp . 80",
		Value: "goto chain",
	})
	tx.Add(&Element{
		Name:  "map1",
		Key:   Join("192.168.0.2", "tcp", "443"),
		Value: "goto anotherchain",
	})
	// Duplicate element
	tx.Add(&Element{
		Name:  "map1",
		Key:   Join("192.168.0.1", "tcp", "80"),
		Value: "drop",
	})

	err := fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	table := fake.Table
	if table == nil {
		t.Fatalf("fake.Table is nil")
	}

	chain := table.Chains["chain"]
	if chain == nil || len(table.Chains) != 2 {
		t.Fatalf("unexpected contents of table.Chains: %+v", table.Chains)
	}

	if len(chain.Rules) != 1 {
		t.Fatalf("unexpected chain.Rules length: expected 1, got %d", len(chain.Rules))
	}
	expectedRule := "ip daddr 10.0.0.0/8 drop"
	if chain.Rules[0].Rule != expectedRule {
		t.Fatalf("unexpected chain.Rules content: expected %q, got %q", expectedRule, chain.Rules[0].Rule)
	}

	m := table.Maps["map1"]
	if m == nil || len(table.Maps) != 1 {
		t.Fatalf("unexpected contents of table.Maps: %+v", table.Maps)
	}

	elem := m.FindElement("192.168.0.2 . tcp . 443")
	if elem == nil || elem.Value != "goto anotherchain" {
		t.Fatalf("missing map element for key \"192.168.0.2 . tcp . 443\"")
	} else if elem.Value != "goto anotherchain" {
		t.Fatalf("unexpected map element for key \"192.168.0.2 . tcp . 443\": %+v", elem)
	}

	elem = m.FindElement("192.168.0.1", "tcp", "80")
	if elem == nil {
		t.Fatalf("missing map element for key \"192.168.0.1 . tcp . 80\"")
	} else if elem.Value == "goto chain" {
		t.Fatalf("map element for key \"192.168.0.1 . tcp . 80\" did not get overwritten")
	} else if elem.Value != "drop" {
		t.Fatalf("unexpected map element for key \"192.168.0.1 . tcp . 80\": %+v", elem)
	}

	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy anotherchain
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add map ip kube-proxy map1 { type ipv4_addr . inet_proto . inet_service : verdict ; }
		add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : drop }
		add element ip kube-proxy map1 { 192.168.0.2 . tcp . 443 : goto anotherchain }
		`), "\n")
	dump := fake.Dump()
	if dump != expected {
		t.Errorf("unexpected Dump content:\nexpected\n%s\n\ngot\n%s", expected, dump)
	}

	chains, err := fake.List(context.Background(), "chains")
	if err != nil {
		t.Errorf("unexpected error listing chains: %v", err)
	}

	sort.Strings(chains)
	expectedChains := []string{"chain", "anotherchain"}
	sort.Strings(expectedChains)
	if !reflect.DeepEqual(chains, expectedChains) {
		t.Errorf("unexpected result from List(chains): %v", chains)
	}
}
