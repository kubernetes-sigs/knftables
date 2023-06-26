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
	fake := NewFake()
	tx := NewTransaction(IPv4Family, "kube-proxy")

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

	err := fake.Run(context.Background(), tx)
	if err != nil {
		t.Fatalf("unexpected error from Run: %v", err)
	}

	tables := fake.Tables[IPv4Family]
	if tables == nil || len(fake.Tables) != 1 {
		t.Fatalf("unexpected contents of fake.Tables: %+v", fake.Tables)
	}

	table := tables["kube-proxy"]
	if table == nil || len(tables) != 1 {
		t.Fatalf("unexpected contents of fake.Tables[`ip`]: %+v", tables)
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

	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy anotherchain
		add rule ip kube-proxy anotherchain ip saddr 1.2.3.4 drop comment "drop rule"
		add rule ip kube-proxy anotherchain ip daddr 5.6.7.8 reject comment "reject rule"
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		`), "\n")
	dump := fake.Dump()
	if dump != expected {
		t.Errorf("unexpected Dump content:\nexpected\n%s\n\ngot\n%s", expected, dump)
	}

	chains, err := fake.List(context.Background(), IPv4Family, "kube-proxy", "chains")
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
