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

	_, err := fake.List(context.Background(), "chains")
	if err == nil || !IsNotFound(err) {
		t.Errorf("expected table not found error but got: %v", err)
	}

	tx := NewTransaction()

	tx.Add(&Table{})
	tx.Add(&Chain{
		Name:    "chain",
		Comment: Optional("foo"),
	})
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "$IP daddr 10.0.0.0/8 drop",
	})
	tx.Add(&Rule{
		Chain:   "chain",
		Rule:    "masquerade",
		Comment: Optional("comment"),
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
		Map:   "map1",
		Key:   []string{"192.168.0.1", "tcp", "80"},
		Value: []string{"goto chain"},
	})
	tx.Add(&Element{
		Map:     "map1",
		Key:     []string{"192.168.0.2", "tcp", "443"},
		Value:   []string{"goto anotherchain"},
		Comment: Optional("with a comment"),
	})
	// Duplicate element
	tx.Add(&Element{
		Map:   "map1",
		Key:   []string{"192.168.0.1", "tcp", "80"},
		Value: []string{"drop"},
	})

	err = fake.Run(context.Background(), tx)
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

	m := table.Maps["map1"]
	if m == nil || len(table.Maps) != 1 {
		t.Fatalf("unexpected contents of table.Maps: %+v", table.Maps)
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

	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy anotherchain
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add rule ip kube-proxy chain masquerade comment "comment"
		add map ip kube-proxy map1 { type ipv4_addr . inet_proto . inet_service : verdict ; }
		add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : drop }
		add element ip kube-proxy map1 { 192.168.0.2 . tcp . 443 comment "with a comment" : goto anotherchain }
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

	tx = NewTransaction()
	tx.Delete(ruleToDelete)
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}
	expected = strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy anotherchain
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add map ip kube-proxy map1 { type ipv4_addr . inet_proto . inet_service : verdict ; }
		add element ip kube-proxy map1 { 192.168.0.1 . tcp . 80 : drop }
		add element ip kube-proxy map1 { 192.168.0.2 . tcp . 443 comment "with a comment" : goto anotherchain }
		`), "\n")
	dump = fake.Dump()
	if dump != expected {
		t.Errorf("unexpected Dump content after delete:\nexpected\n%s\n\ngot\n%s", expected, dump)
	}

	tx = NewTransaction()
	tx.Delete(ruleToDelete)
	err = fake.Run(context.Background(), tx)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("unexpected error from Run: %v", err)
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

	tx := NewTransaction()
	tx.Add(&Table{})
	err := fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	_, err = fake.ListRules(context.Background(), "test")
	if err == nil || !IsNotFound(err) {
		t.Errorf("expected chain not found but got: %v", err)
	}

	tx = NewTransaction()
	tx.Add(&Chain{
		Name: "test",
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake /* no rules */)

	// Test basic Add
	tx = NewTransaction()
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
	tx = NewTransaction()
	// Should go after "second"
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "fourth",
		Index: Optional(1),
	})
	// Should go after "first"
	tx.Add(&Rule{
		Chain:  "test",
		Rule:   "fifth",
		Handle: Optional(firstHandle),
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "first", "fifth", "second", "fourth", "third")

	// Test Insert
	tx = NewTransaction()
	// Should go first
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "sixth",
	})
	// Should go before "second"
	tx.Insert(&Rule{
		Chain:  "test",
		Rule:   "seventh",
		Handle: Optional(secondHandle),
	})
	// Should go before "fourth". ("fourth" was rule[3] before this
	// transaction and the previous two operations added two more rules
	// before it, so it should now have index 5.)
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "eighth",
		Index: Optional(5),
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "sixth", "first", "fifth", "seventh", "second", "eighth", "fourth", "third")

	// Test Replace. And Delete while we're here... the chain is getting kind of long
	tx = NewTransaction()

	tx.Replace(&Rule{
		Chain:  "test",
		Rule:   "ninth",
		Handle: Optional(secondHandle),
	})
	tx.Delete(&Rule{
		Chain:  "test",
		Handle: Optional(firstHandle),
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
	tx = NewTransaction()
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "tenth",
		Index: Optional(len(rules) - 1),
	})
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "eleventh",
		Index: Optional(len(rules)),
	})
	tx.Add(&Rule{
		Chain: "test",
		Rule:  "twelfth",
		Index: Optional(0),
	})
	tx.Insert(&Rule{
		Chain: "test",
		Rule:  "thirteenth",
		Index: Optional(0),
	})
	err = fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	assertRules(t, fake, "thirteenth", "sixth", "twelfth", "fifth", "seventh", "ninth", "eighth", "fourth", "third", "eleventh", "tenth")
}
