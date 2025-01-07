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
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lithammer/dedent"
)

func TestFakeRun(t *testing.T) {
	fake := NewFake(IPv4Family, "kube-proxy")

	_, err := fake.List(context.Background(), "chains")
	if err == nil || !IsNotFound(err) {
		t.Errorf("expected table not found error but got: %v", err)
	}

	tx := fake.NewTransaction()

	tx.Add(&Table{})
	tx.Add(&Chain{
		Name:    "chain",
		Comment: PtrTo("foo"),
	})
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "ip daddr 10.0.0.0/8 drop",
	})
	tx.Add(&Rule{
		Chain:   "chain",
		Rule:    "masquerade",
		Comment: PtrTo("comment"),
	})

	tx.Add(&Chain{
		Name: "anotherchain",
	})
	tx.Add(&Rule{
		Chain:   "anotherchain",
		Rule:    "ip saddr 1.2.3.4 drop",
		Comment: PtrTo("drop rule"),
	})
	tx.Add(&Rule{
		Chain:   "anotherchain",
		Rule:    "ip daddr 5.6.7.8 reject",
		Comment: PtrTo("reject rule"),
	})

	tx.Add(&Map{
		Name: "map1",
		Type: "ipv4_addr . inet_proto . inet_service : verdict",
	})
	tx.Add(&Element{
		Map:   "map1",
		Key:   []string{"192.168.0.1", "tcp", "80"},
		Value: []string{"goto chain"},
	})
	tx.Add(&Element{
		Map:     "map1",
		Key:     []string{"192.168.0.2", "tcp", "443"},
		Value:   []string{"goto anotherchain"},
		Comment: PtrTo("with a comment"),
	})
	// Duplicate element
	tx.Add(&Element{
		Map:   "map1",
		Key:   []string{"192.168.0.1", "tcp", "80"},
		Value: []string{"drop"},
	})
	tx.Add(&Flowtable{
		Name:    "myflowtable",
		Devices: []string{"eth0", "eth1"},
	})
	tx.Add(&Counter{
		Name:    "test-counter",
		Comment: PtrTo("test counter comment"),
		Packets: PtrTo[uint64](300),
		Bytes:   PtrTo[uint64](5000),
	})
	// The transaction should contain exactly those commands, in order
	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add rule ip kube-proxy chain masquerade comment "comment"
		add chain ip kube-proxy anotherchain
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
		add map ip kube-proxy map1 { type ipv4_addr . inet_proto . inet_service : verdict ; }
		add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : goto chain }
		add element ip kube-proxy map1 { 192.168.0.2 . tcp . 443 comment "with a comment" : goto anotherchain }
		add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : drop }
		add flowtable ip kube-proxy myflowtable { devices = { eth0, eth1 } ; }
		add counter ip kube-proxy test-counter { packets 300 bytes 5000 ; comment "test counter comment" ; }
		`), "\n")
	diff := cmp.Diff(expected, tx.String())
	if diff != "" {
		t.Errorf("unexpected transaction content:\n%s", diff)
	}

	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	if fake.Table == nil {
		t.Fatalf("fake.Table is nil")
	}

	chain := fake.Table.Chains["chain"]
	if chain == nil || len(fake.Table.Chains) != 2 {
		t.Fatalf("unexpected contents of table.Chains: %+v", fake.Table.Chains)
	}

	if len(chain.Rules) != 2 {
		t.Fatalf("unexpected chain.Rules length: expected 2, got %d", len(chain.Rules))
	}
	expectedRule := "ip daddr 10.0.0.0/8 drop"
	if chain.Rules[0].Rule != expectedRule {
		t.Fatalf("unexpected chain.Rules content: expected %q, got %q", expectedRule, chain.Rules[0].Rule)
	}
	expectedRule = "masquerade"
	if chain.Rules[1].Rule != expectedRule {
		t.Fatalf("unexpected chain.Rules content: expected %q, got %q", expectedRule, chain.Rules[1].Rule)
	}
	expectedComment := "comment"
	if chain.Rules[1].Comment == nil {
		t.Fatalf("unexpected chain.Rules content: expected comment %q, got nil", expectedComment)
	} else if *chain.Rules[1].Comment != expectedComment {
		t.Fatalf("unexpected chain.Rules content: expected comment %q, got %q", expectedComment, *chain.Rules[1].Comment)
	}
	// Save this Rule object for later
	ruleToDelete := chain.Rules[1]

	m := fake.Table.Maps["map1"]
	if m == nil || len(fake.Table.Maps) != 1 {
		t.Fatalf("unexpected contents of table.Maps: %+v", fake.Table.Maps)
	}

	elem := m.FindElement("192.168.0.2", "tcp", "443")
	if elem == nil {
		t.Fatalf("missing map element for key \"192.168.0.2 . tcp . 443\"")
	} else if len(elem.Value) != 1 || elem.Value[0] != "goto anotherchain" {
		t.Fatalf("unexpected map element for key \"192.168.0.2 . tcp . 443\": %+v", elem)
	}

	elem = m.FindElement("192.168.0.1", "tcp", "80")
	if elem == nil {
		t.Fatalf("missing map element for key \"192.168.0.1 . tcp . 80\"")
	} else if len(elem.Value) == 1 && elem.Value[0] == "goto chain" {
		t.Fatalf("map element for key \"192.168.0.1 . tcp . 80\" did not get overwritten")
	} else if len(elem.Value) != 1 || elem.Value[0] != "drop" {
		t.Fatalf("unexpected map element for key \"192.168.0.1 . tcp . 80\": %+v", elem)
	}

	// The expected Dump() result is different from the expected Transaction content
	// above; it will be sorted, and the map element that was later overwritten won't
	// be seen.
	expected = strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add flowtable ip kube-proxy myflowtable { devices = { eth0, eth1 } ; }
		add chain ip kube-proxy anotherchain
		add chain ip kube-proxy chain { comment "foo" ; }
		add map ip kube-proxy map1 { type ipv4_addr . inet_proto . inet_service : verdict ; }
		add counter ip kube-proxy test-counter { packets 300 bytes 5000 ; comment "test counter comment" ; }
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add rule ip kube-proxy chain masquerade comment "comment"
		add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : drop }
		add element ip kube-proxy map1 { 192.168.0.2 . tcp . 443 comment "with a comment" : goto anotherchain }
		`), "\n")
	diff = cmp.Diff(expected, fake.Dump())
	if diff != "" {
		t.Errorf("unexpected Dump content:\n%s", diff)
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

	tx = fake.NewTransaction()
	tx.Delete(ruleToDelete)
	tx.Reset(&Counter{Name: "test-counter"})
	expected = fmt.Sprintf("delete rule ip kube-proxy chain handle %d\nreset counter ip kube-proxy test-counter\n", *ruleToDelete.Handle)
	diff = cmp.Diff(expected, tx.String())
	if diff != "" {
		t.Errorf("unexpected transaction content:\n%s", diff)
	}
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}
	expected = strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add flowtable ip kube-proxy myflowtable { devices = { eth0, eth1 } ; }
		add chain ip kube-proxy anotherchain
		add chain ip kube-proxy chain { comment "foo" ; }
		add map ip kube-proxy map1 { type ipv4_addr . inet_proto . inet_service : verdict ; }
		add counter ip kube-proxy test-counter { packets 0 bytes 0 ; comment "test counter comment" ; }
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : drop }
		add element ip kube-proxy map1 { 192.168.0.2 . tcp . 443 comment "with a comment" : goto anotherchain }
		`), "\n")
	diff = cmp.Diff(expected, fake.Dump())
	if diff != "" {
		t.Errorf("unexpected Dump content:\n%s", diff)
	}

	// Now try to re-delete the same element, and ensure that Run() behaves
	// transactionally.
	tx = fake.NewTransaction()
	tx.Add(&Element{
		Map:   "map1",
		Key:   []string{"192.168.0.3", "tcp", "80"},
		Value: []string{"accept"},
	})
	tx.Delete(ruleToDelete)
	tx.Add(&Element{
		Map:   "map1",
		Key:   []string{"192.168.0.4", "tcp", "80"},
		Value: []string{"accept"},
	})
	err = fake.Run(context.Background(), tx)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	// Neither element should have been added
	m = fake.Table.Maps["map1"]
	if m == nil || len(fake.Table.Maps) != 1 {
		t.Fatalf("unexpected contents of table.Maps: %+v", fake.Table.Maps)
	}

	elem = m.FindElement("192.168.0.3", "tcp", "80")
	if elem != nil {
		t.Errorf("element should not have been added: %+v", elem)
	}
	elem = m.FindElement("192.168.0.4", "tcp", "80")
	if elem != nil {
		t.Errorf("element should not have been added: %+v", elem)
	}
	if len(m.Elements) != 2 {
		t.Errorf("unexpected contents of map1: %+v", m)
	}

	// Check delete element from map works
	tx = fake.NewTransaction()
	tx.Delete(&Element{
		Map: "map1",
		Key: []string{"192.168.0.1", "tcp", "80"},
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}
	m = fake.Table.Maps["map1"]
	if len(m.Elements) != 1 {
		t.Errorf("unexpected contents of map1: %+v", m)
	}
	elem = m.FindElement("192.168.0.1", "tcp", "80")
	if elem != nil {
		t.Errorf("element should have been deleted: %+v", elem)
	}

	// Ensure that we can't add things that refer to non-existing things
	tx = fake.NewTransaction()
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "tcp dport 80 goto missingchain",
	})
	err = fake.Run(context.Background(), tx)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	tx = fake.NewTransaction()
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "tcp dport 80 vmap @missingmap",
	})
	err = fake.Run(context.Background(), tx)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	tx = fake.NewTransaction()
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "tcp dport @missingset drop",
	})
	err = fake.Run(context.Background(), tx)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	tx = fake.NewTransaction()
	tx.Add(&Element{
		Map:   "map1",
		Key:   []string{"192.168.0.5", "tcp", "80"},
		Value: []string{"jump missingchain"},
	})
	err = fake.Run(context.Background(), tx)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("unexpected error from Run: %v", err)
	}
}

func TestFakeCheck(t *testing.T) {
	fake := NewFake(IPv4Family, "kube-proxy")

	tx := fake.NewTransaction()

	if tx.NumOperations() != 0 {
		t.Errorf("empty transaction should have 0 operations, got %d", tx.NumOperations())
	}

	tx.Add(&Table{})
	tx.Add(&Chain{
		Name:    "chain",
		Comment: PtrTo("foo"),
	})
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "ip daddr 10.0.0.0/8 drop",
	})
	tx.Add(&Rule{
		Chain:   "chain",
		Rule:    "masquerade",
		Comment: PtrTo("comment"),
	})

	// The transaction should contain exactly those commands, in order
	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add rule ip kube-proxy chain masquerade comment "comment"
		`), "\n")
	diff := cmp.Diff(expected, tx.String())
	if diff != "" {
		t.Errorf("unexpected transaction content:\n%s", diff)
	}

	if tx.NumOperations() != 4 {
		t.Errorf("unexpected number of operations: expected 4, got %d", tx.NumOperations())
	}

	err := fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	// Checking if we can delete an existing chain should succeed (and not delete the
	// chain)
	tx = fake.NewTransaction()
	tx.Delete(&Chain{
		Name: "chain",
	})
	err = fake.Check(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Check: %v", err)
	}
	chain := fake.Table.Chains["chain"]
	if chain == nil || len(fake.Table.Chains) != 1 {
		t.Fatalf("unexpected contents of table.Chains: %+v", fake.Table.Chains)
	}

	// Checking if we can delete an non-existent chain should fail
	tx = fake.NewTransaction()
	tx.Delete(&Chain{
		Name: "another-chain",
	})
	err = fake.Check(context.Background(), tx)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("unexpected error from Check: %v", err)
	}
}

func assertRules(t *testing.T, fake *Fake, expected ...string) {
	t.Helper()

	actual, err := fake.ListRules(context.Background(), "test")
	if err != nil {
		t.Fatalf("could not ListRules: %v", err)
	}

	if len(actual) != len(expected) {
		t.Errorf("expected %d rules, got %d", len(expected), len(actual))
	}

	for i := range expected {
		if i == len(actual) {
			break
		}
		if actual[i].Rule != expected[i] {
			t.Errorf("expected rule %d to be %q but got %q", i+1, expected[i], actual[i].Rule)
		}
	}

	rulesByHandle := make(map[int][]string)
	for _, r := range actual {
		rulesByHandle[*r.Handle] = append(rulesByHandle[*r.Handle], r.Rule)
	}
	for handle, rules := range rulesByHandle {
		if len(rules) > 1 {
			t.Errorf("multiple rules for handle %d: %v", handle, rules)
		}
	}
}

func TestFakeAddInsertReplace(t *testing.T) {
	fake := NewFake(IPv4Family, "kube-proxy")

	tx := fake.NewTransaction()
	tx.Add(&Table{})
	err := fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	_, err = fake.ListRules(context.Background(), "test")
	if err == nil || !IsNotFound(err) {
		t.Errorf("expected chain not found but got: %v", err)
	}

	tx = fake.NewTransaction()
	tx.Add(&Chain{
		Name: "test",
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake /* no rules */)

	// Test basic Add
	tx = fake.NewTransaction()
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "first",
	})
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "second",
	})
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "third",
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "first", "second", "third")

	// (can't fail: we just did this in assertRules)
	rules, _ := fake.ListRules(context.Background(), "test")
	firstHandle := *rules[0].Handle
	secondHandle := *rules[1].Handle
	thirdHandle := *rules[2].Handle

	// Test Add with Handle or Index
	tx = fake.NewTransaction()
	// Should go after "second"
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "fourth",
		Index: PtrTo(1),
	})
	// Should go after "first"
	tx.Add(&Rule{
		Chain:  "test",
		Rule:   "fifth",
		Handle: PtrTo(firstHandle),
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "first", "fifth", "second", "fourth", "third")

	// Test Insert
	tx = fake.NewTransaction()
	// Should go first
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "sixth",
	})
	// Should go before "second"
	tx.Insert(&Rule{
		Chain:  "test",
		Rule:   "seventh",
		Handle: PtrTo(secondHandle),
	})
	// Should go before "fourth". ("fourth" was rule[3] before this
	// transaction and the previous two operations added two more rules
	// before it, so it should now have index 5.)
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "eighth",
		Index: PtrTo(5),
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "sixth", "first", "fifth", "seventh", "second", "eighth", "fourth", "third")

	// Test Replace. And Delete while we're here... the chain is getting kind of long
	tx = fake.NewTransaction()

	tx.Replace(&Rule{
		Chain:  "test",
		Rule:   "ninth",
		Handle: PtrTo(secondHandle),
	})
	tx.Delete(&Rule{
		Chain:  "test",
		Handle: PtrTo(firstHandle),
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "sixth", "fifth", "seventh", "ninth", "eighth", "fourth", "third")

	// Re-fetch handles; Replace should not have changed the handle for its rule.
	// (can't fail: we just did this in assertRules)
	rules, _ = fake.ListRules(context.Background(), "test")
	if *rules[3].Handle != secondHandle {
		t.Errorf("Replace changed the rule handle: expected %d got %d", secondHandle, *rules[3].Handle)
	}
	if *rules[6].Handle != thirdHandle {
		t.Errorf("Handle for original third rule changed? expected %d got %d", thirdHandle, *rules[6].Handle)
	}

	// Test edge cases
	tx = fake.NewTransaction()
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "tenth",
		Index: PtrTo(len(rules) - 1),
	})
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "eleventh",
		Index: PtrTo(len(rules)),
	})
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "twelfth",
		Index: PtrTo(0),
	})
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "thirteenth",
		Index: PtrTo(0),
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "thirteenth", "sixth", "twelfth", "fifth", "seventh", "ninth", "eighth", "fourth", "third", "eleventh", "tenth")
}

func TestFakeParseDump(t *testing.T) {
	for _, tc := range []struct {
		ipFamily Family
		dump     string
	}{
		{
			ipFamily: IPv4Family,
			dump: `
			add table ip kube-proxy
			add flowtable ip kube-proxy myflowtable { hook ingress priority filter ; devices = { eth0, eth1 } ; }
			add chain ip kube-proxy anotherchain
			add chain ip kube-proxy chain { comment "foo" ; }
			add map ip kube-proxy map1 { type ipv4_addr . inet_proto . inet_service ; }
			add set ip kube-proxy set1 { type ipv4_addr . inet_proto . inet_service ; flags dynamic ; gc-interval 15s ; policy memory ; auto-merge ; }
			add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
			add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
			add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
			add rule ip kube-proxy chain masquerade comment "comment"
			add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : drop }
			add element ip kube-proxy map1 { 192.168.0.2 . tcp . 443 comment "with a comment" : goto anotherchain }
			add counter ip kube-proxy test-counter-1 { comment "test counter 1 comment" ; }
			add counter ip kube-proxy test-counter-2 { packets 100 bytes 1250 ; }
			`,
		},
		{
			ipFamily: IPv4Family,
			dump: `
			add table ip kube-proxy { flags dormant ; }
			add chain ip kube-proxy filter-prerouting { type filter hook prerouting priority -100 ; policy drop ; }
			`,
		},
		{
			ipFamily: IPv4Family,
			dump: `
			add table ip kube-proxy { comment "rules for kube-proxy" ; }
			add chain ip kube-proxy mark-for-masquerade
			add chain ip kube-proxy masquerading
			add chain ip kube-proxy services
			add chain ip kube-proxy firewall-check
			add chain ip kube-proxy endpoints-check
			add chain ip kube-proxy filter-prerouting { type filter hook prerouting priority -110 ; }
			add chain ip kube-proxy filter-forward { type filter hook forward priority -110 ; }
			add chain ip kube-proxy filter-input { type filter hook input priority -110 ; }
			add chain ip kube-proxy filter-output { type filter hook output priority -110 ; }
			add chain ip kube-proxy nat-output { type nat hook output priority -100 ; }
			add chain ip kube-proxy nat-postrouting { type nat hook postrouting priority 100 ; }
			add chain ip kube-proxy nat-prerouting { type nat hook prerouting priority -100 ; }
			add chain ip kube-proxy reject-chain { comment "helper for @no-endpoint-services / @no-endpoint-nodeports" ; }
			add chain ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
			add chain ip kube-proxy endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80
			add chain ip kube-proxy service-42NFTM6N-ns2/svc2/tcp/p80
			add chain ip kube-proxy endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80
			add chain ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80
			add chain ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80
			add chain ip kube-proxy endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80
			add chain ip kube-proxy external-4AT6LBPK-ns3/svc3/tcp/p80
			add chain ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80
			add chain ip kube-proxy endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80
			add chain ip kube-proxy endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80
			add chain ip kube-proxy external-LAUZTJTB-ns4/svc4/tcp/p80
			add chain ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80
			add chain ip kube-proxy external-HVFWP5L3-ns5/svc5/tcp/p80
			add chain ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80
			add chain ip kube-proxy firewall-HVFWP5L3-ns5/svc5/tcp/p80

			add rule ip kube-proxy mark-for-masquerade mark set mark or 0x4000
			add rule ip kube-proxy masquerading mark and 0x4000 == 0 return
			add rule ip kube-proxy masquerading mark set mark xor 0x4000
			add rule ip kube-proxy masquerading masquerade fully-random
			add rule ip kube-proxy filter-prerouting ct state new jump firewall-check
			add rule ip kube-proxy filter-forward ct state new jump endpoints-check
			add rule ip kube-proxy filter-input ct state new jump endpoints-check
			add rule ip kube-proxy filter-output ct state new jump endpoints-check
			add rule ip kube-proxy filter-output ct state new jump firewall-check
			add rule ip kube-proxy nat-output jump services
			add rule ip kube-proxy nat-postrouting jump masquerading
			add rule ip kube-proxy nat-prerouting jump services

			add map ip kube-proxy firewall-ips { type ipv4_addr . inet_proto . inet_service : verdict ; comment "destinations that are subject to LoadBalancerSourceRanges" ; }
			add rule ip kube-proxy firewall-check ip daddr . meta l4proto . th dport vmap @firewall-ips

			add rule ip kube-proxy reject-chain reject

			add map ip kube-proxy no-endpoint-services { type ipv4_addr . inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to services with no endpoints" ; }
			add map ip kube-proxy no-endpoint-nodeports { type inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to service nodeports with no endpoints" ; }

			add rule ip kube-proxy endpoints-check ip daddr . meta l4proto . th dport vmap @no-endpoint-services
			add rule ip kube-proxy endpoints-check fib daddr type local ip daddr != 127.0.0.0/8 meta l4proto . th dport vmap @no-endpoint-nodeports

			add map ip kube-proxy service-ips { type ipv4_addr . inet_proto . inet_service : verdict ; comment "ClusterIP, ExternalIP and LoadBalancer IP traffic" ; }
			add map ip kube-proxy service-nodeports { type inet_proto . inet_service : verdict ; comment "NodePort traffic" ; }
			add rule ip kube-proxy services ip daddr . meta l4proto . th dport vmap @service-ips
			add rule ip kube-proxy services fib daddr type local ip daddr != 127.0.0.0/8 meta l4proto . th dport vmap @service-nodeports

			# svc1
			add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip daddr 172.30.0.41 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
			add rule ip kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80 }

			add rule ip kube-proxy endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80 ip saddr 10.180.0.1 jump mark-for-masquerade
			add rule ip kube-proxy endpoint-5OJB2KTY-ns1/svc1/tcp/p80__10.180.0.1/80 meta l4proto tcp dnat to 10.180.0.1:80

			add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }

			# svc2
			add rule ip kube-proxy service-42NFTM6N-ns2/svc2/tcp/p80 ip daddr 172.30.0.42 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
			add rule ip kube-proxy service-42NFTM6N-ns2/svc2/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80 }
			add rule ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80 ip saddr 10.0.0.0/8 goto service-42NFTM6N-ns2/svc2/tcp/p80 comment "short-circuit pod traffic"
			add rule ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80 fib saddr type local jump mark-for-masquerade comment "masquerade local traffic"
			add rule ip kube-proxy external-42NFTM6N-ns2/svc2/tcp/p80 fib saddr type local goto service-42NFTM6N-ns2/svc2/tcp/p80 comment "short-circuit local traffic"
			add rule ip kube-proxy endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80 ip saddr 10.180.0.2 jump mark-for-masquerade
			add rule ip kube-proxy endpoint-SGOXE6O3-ns2/svc2/tcp/p80__10.180.0.2/80 meta l4proto tcp dnat to 10.180.0.2:80

			add element ip kube-proxy service-ips { 172.30.0.42 . tcp . 80 : goto service-42NFTM6N-ns2/svc2/tcp/p80 }
			add element ip kube-proxy service-ips { 192.168.99.22 . tcp . 80 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }
			add element ip kube-proxy service-ips { 1.2.3.4 . tcp . 80 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }
			add element ip kube-proxy service-nodeports { tcp . 3001 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }

			add element ip kube-proxy no-endpoint-nodeports { tcp . 3001 comment "ns2/svc2:p80" : drop }
			add element ip kube-proxy no-endpoint-services { 1.2.3.4 . tcp . 80 comment "ns2/svc2:p80" : drop }
			add element ip kube-proxy no-endpoint-services { 192.168.99.22 . tcp . 80 comment "ns2/svc2:p80" : drop }

			# svc3
			add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 ip daddr 172.30.0.43 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
			add rule ip kube-proxy service-4AT6LBPK-ns3/svc3/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80 }
			add rule ip kube-proxy external-4AT6LBPK-ns3/svc3/tcp/p80 jump mark-for-masquerade
			add rule ip kube-proxy external-4AT6LBPK-ns3/svc3/tcp/p80 goto service-4AT6LBPK-ns3/svc3/tcp/p80
			add rule ip kube-proxy endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80 ip saddr 10.180.0.3 jump mark-for-masquerade
			add rule ip kube-proxy endpoint-UEIP74TE-ns3/svc3/tcp/p80__10.180.0.3/80 meta l4proto tcp dnat to 10.180.0.3:80

			add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }
			add element ip kube-proxy service-nodeports { tcp . 3003 : goto external-4AT6LBPK-ns3/svc3/tcp/p80 }

			# svc4
			add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 ip daddr 172.30.0.44 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
			add rule ip kube-proxy service-LAUZTJTB-ns4/svc4/tcp/p80 numgen random mod 2 vmap { 0 : goto endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80 , 1 : goto endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80 }
			add rule ip kube-proxy external-LAUZTJTB-ns4/svc4/tcp/p80 jump mark-for-masquerade
			add rule ip kube-proxy external-LAUZTJTB-ns4/svc4/tcp/p80 goto service-LAUZTJTB-ns4/svc4/tcp/p80
			add rule ip kube-proxy endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80 ip saddr 10.180.0.5 jump mark-for-masquerade
			add rule ip kube-proxy endpoint-5RFCDDV7-ns4/svc4/tcp/p80__10.180.0.5/80 meta l4proto tcp dnat to 10.180.0.5:80
			add rule ip kube-proxy endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80 ip saddr 10.180.0.4 jump mark-for-masquerade
			add rule ip kube-proxy endpoint-UNZV3OEC-ns4/svc4/tcp/p80__10.180.0.4/80 meta l4proto tcp dnat to 10.180.0.4:80

			add element ip kube-proxy service-ips { 172.30.0.44 . tcp . 80 : goto service-LAUZTJTB-ns4/svc4/tcp/p80 }
			add element ip kube-proxy service-ips { 192.168.99.33 . tcp . 80 : goto external-LAUZTJTB-ns4/svc4/tcp/p80 }

			# svc5
			add set ip kube-proxy affinity-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 { type ipv4_addr ; flags dynamic,timeout ; timeout 10800s ; }
			add rule ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80 ip daddr 172.30.0.45 tcp dport 80 ip saddr != 10.0.0.0/8 jump mark-for-masquerade
			add rule ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80 ip saddr @affinity-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 goto endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80
			add rule ip kube-proxy service-HVFWP5L3-ns5/svc5/tcp/p80 numgen random mod 1 vmap { 0 : goto endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 }
			add rule ip kube-proxy external-HVFWP5L3-ns5/svc5/tcp/p80 jump mark-for-masquerade
			add rule ip kube-proxy external-HVFWP5L3-ns5/svc5/tcp/p80 goto service-HVFWP5L3-ns5/svc5/tcp/p80

			add rule ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 ip saddr 10.180.0.3 jump mark-for-masquerade
			add rule ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 update @affinity-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 { ip saddr }
			add rule ip kube-proxy endpoint-GTK6MW7G-ns5/svc5/tcp/p80__10.180.0.3/80 meta l4proto tcp dnat to 10.180.0.3:80

			add rule ip kube-proxy firewall-HVFWP5L3-ns5/svc5/tcp/p80 ip saddr != { 203.0.113.0/25 } drop

			add element ip kube-proxy service-ips { 172.30.0.45 . tcp . 80 : goto service-HVFWP5L3-ns5/svc5/tcp/p80 }
			add element ip kube-proxy service-ips { 5.6.7.8 . tcp . 80 : goto external-HVFWP5L3-ns5/svc5/tcp/p80 }
			add element ip kube-proxy service-nodeports { tcp . 3002 : goto external-HVFWP5L3-ns5/svc5/tcp/p80 }
			add element ip kube-proxy firewall-ips { 5.6.7.8 . tcp . 80 comment "ns5/svc5:p80" : goto firewall-HVFWP5L3-ns5/svc5/tcp/p80 }

			# svc6
			add element ip kube-proxy no-endpoint-services { 172.30.0.46 . tcp . 80 comment "ns6/svc6:p80" : goto reject-chain }
			`,
		},
		{
			ipFamily: IPv6Family,
			dump: `
			add table ip6 kube-proxy { comment "rules for kube-proxy" ; }
			add chain ip6 kube-proxy cluster-ips-check
			add chain ip6 kube-proxy endpoint-2CRNCTTE-ns1/svc1/tcp/p80__fd00.10.180..2.1/80
			add chain ip6 kube-proxy endpoint-ZVRFLKHO-ns1/svc1/tcp/p80__fd00.10.180..1/80
			add chain ip6 kube-proxy external-ULMVA6XW-ns1/svc1/tcp/p80
			add chain ip6 kube-proxy filter-forward { type filter hook forward priority -110 ; }
			add chain ip6 kube-proxy filter-input { type filter hook input priority -110 ; }
			add chain ip6 kube-proxy filter-output { type filter hook output priority -110 ; }
			add chain ip6 kube-proxy filter-output-post-dnat { type filter hook output priority -90 ; }
			add chain ip6 kube-proxy filter-prerouting { type filter hook prerouting priority -110 ; }
			add chain ip6 kube-proxy firewall-check
			add chain ip6 kube-proxy mark-for-masquerade
			add chain ip6 kube-proxy masquerading
			add chain ip6 kube-proxy nat-output { type nat hook output priority -100 ; }
			add chain ip6 kube-proxy nat-postrouting { type nat hook postrouting priority 100 ; }
			add chain ip6 kube-proxy nat-prerouting { type nat hook prerouting priority -100 ; }
			add chain ip6 kube-proxy nodeport-endpoints-check
			add chain ip6 kube-proxy reject-chain { comment "helper for @no-endpoint-services / @no-endpoint-nodeports" ; }
			add chain ip6 kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80
			add chain ip6 kube-proxy service-endpoints-check
			add chain ip6 kube-proxy services
			add set ip6 kube-proxy cluster-ips { type ipv6_addr ; comment "Active ClusterIPs" ; }
			add set ip6 kube-proxy nodeport-ips { type ipv6_addr ; comment "IPs that accept NodePort traffic" ; }
			add map ip6 kube-proxy firewall-ips { type ipv6_addr . inet_proto . inet_service : verdict ; comment "destinations that are subject to LoadBalancerSourceRanges" ; }
			add map ip6 kube-proxy no-endpoint-nodeports { type inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to service nodeports with no endpoints" ; }
			add map ip6 kube-proxy no-endpoint-services { type ipv6_addr . inet_proto . inet_service : verdict ; comment "vmap to drop or reject packets to services with no endpoints" ; }
			add map ip6 kube-proxy service-ips { type ipv6_addr . inet_proto . inet_service : verdict ; comment "ClusterIP, ExternalIP and LoadBalancer IP traffic" ; }
			add map ip6 kube-proxy service-nodeports { type inet_proto . inet_service : verdict ; comment "NodePort traffic" ; }
			add rule ip6 kube-proxy cluster-ips-check ip6 daddr @cluster-ips reject comment "Reject traffic to invalid ports of ClusterIPs"
			add rule ip6 kube-proxy cluster-ips-check ip6 daddr { fd00:10:96::/112 } drop comment "Drop traffic to unallocated ClusterIPs"
			add rule ip6 kube-proxy endpoint-2CRNCTTE-ns1/svc1/tcp/p80__fd00.10.180..2.1/80 ip6 saddr fd00:10:180::2:1 jump mark-for-masquerade
			add rule ip6 kube-proxy endpoint-2CRNCTTE-ns1/svc1/tcp/p80__fd00.10.180..2.1/80 meta l4proto tcp dnat to [fd00:10:180::2:1]:80
			add rule ip6 kube-proxy endpoint-ZVRFLKHO-ns1/svc1/tcp/p80__fd00.10.180..1/80 ip6 saddr fd00:10:180::1 jump mark-for-masquerade
			add rule ip6 kube-proxy endpoint-ZVRFLKHO-ns1/svc1/tcp/p80__fd00.10.180..1/80 meta l4proto tcp dnat to [fd00:10:180::1]:80
			add rule ip6 kube-proxy external-ULMVA6XW-ns1/svc1/tcp/p80 jump mark-for-masquerade
			add rule ip6 kube-proxy external-ULMVA6XW-ns1/svc1/tcp/p80 goto service-ULMVA6XW-ns1/svc1/tcp/p80
			add rule ip6 kube-proxy filter-forward ct state new jump service-endpoints-check
			add rule ip6 kube-proxy filter-forward ct state new jump cluster-ips-check
			add rule ip6 kube-proxy filter-input ct state new jump nodeport-endpoints-check
			add rule ip6 kube-proxy filter-input ct state new jump service-endpoints-check
			add rule ip6 kube-proxy filter-output ct state new jump service-endpoints-check
			add rule ip6 kube-proxy filter-output ct state new jump firewall-check
			add rule ip6 kube-proxy filter-output-post-dnat ct state new jump cluster-ips-check
			add rule ip6 kube-proxy filter-prerouting ct state new jump firewall-check
			add rule ip6 kube-proxy firewall-check ip6 daddr . meta l4proto . th dport vmap @firewall-ips
			add rule ip6 kube-proxy mark-for-masquerade mark set mark or 0x4000
			add rule ip6 kube-proxy masquerading mark and 0x4000 == 0 return
			add rule ip6 kube-proxy masquerading mark set mark xor 0x4000
			add rule ip6 kube-proxy masquerading masquerade fully-random
			add rule ip6 kube-proxy nat-output jump services
			add rule ip6 kube-proxy nat-postrouting jump masquerading
			add rule ip6 kube-proxy nat-prerouting jump services
			add rule ip6 kube-proxy nodeport-endpoints-check ip6 daddr @nodeport-ips meta l4proto . th dport vmap @no-endpoint-nodeports
			add rule ip6 kube-proxy reject-chain reject
			add rule ip6 kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 ip6 daddr fd00:172:30::41 tcp dport 80 ip6 saddr != fd00:10::/64 jump mark-for-masquerade
			add rule ip6 kube-proxy service-ULMVA6XW-ns1/svc1/tcp/p80 numgen random mod 2 vmap { 0 : goto endpoint-ZVRFLKHO-ns1/svc1/tcp/p80__fd00.10.180..1/80 , 1 : goto endpoint-2CRNCTTE-ns1/svc1/tcp/p80__fd00.10.180..2.1/80 }
			add rule ip6 kube-proxy service-endpoints-check ip6 daddr . meta l4proto . th dport vmap @no-endpoint-services
			add rule ip6 kube-proxy services ip6 daddr . meta l4proto . th dport vmap @service-ips
			add rule ip6 kube-proxy services ip6 daddr @nodeport-ips meta l4proto . th dport vmap @service-nodeports
			add element ip6 kube-proxy cluster-ips { fd00:172:30::41 }
			add element ip6 kube-proxy nodeport-ips { 2001:db8::1 comment "test comment" }
			add element ip6 kube-proxy nodeport-ips { 2001:db8:1::2 }
			add element ip6 kube-proxy service-ips { fd00:172:30::41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
			add element ip6 kube-proxy service-nodeports { tcp . 3001 comment "test comment" : goto external-ULMVA6XW-ns1/svc1/tcp/p80 }
			`,
		},
	} {
		rules := dedent.Dedent(tc.dump)
		fake := NewFake(tc.ipFamily, "kube-proxy")
		err := fake.ParseDump(rules)
		if err != nil {
			t.Fatalf("unexpected error from ParseDump: %v", err)
		}

		// Dump() will add 1 empty line, so add to rulesSlice to match
		rulesSlice := []string{""}
		for _, rule := range strings.Split(rules, "\n") {
			if rule == "" || strings.HasPrefix(rule, "#") {
				continue
			}
			rulesSlice = append(rulesSlice, rule)
		}
		sort.Strings(rulesSlice)
		dumpSlice := strings.Split(fake.Dump(), "\n")
		sort.Strings(dumpSlice)

		diff := cmp.Diff(rulesSlice, dumpSlice)
		if diff != "" {
			t.Errorf("Dump doesn't match given rules:\n%s", diff)
		}
	}
}
