/*
Copyright The Kubernetes Authors.

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

package knftables_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"sigs.k8s.io/knftables"
)

// TestNetlinkListing verifies that the netlink adapter correctly lists objects.
// It requires root privileges and should be run in an isolated network namespace.
func TestNetlinkListing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping test that requires root")
	}

	ctx := context.Background()
	tableName := "knftables-test"
	family := knftables.IPv4Family

	// 1. Create a knftables user WITHOUT netlink to set up the rules.
	// We rely on the `nft` binary for this part, which is what `knftables` used to default to.
	nft, err := knftables.New(family, tableName, knftables.DisableNetlink)
	if err != nil {
		t.Fatalf("failed to create knftables: %v", err)
	}

	// Clean up any existing table (just in case)
	tx := nft.NewTransaction()
	tx.Delete(&knftables.Table{})
	_ = nft.Run(ctx, tx) // specific errors ignored, just cleanup

	// 2. Setup a scenario: Table, Chain, Rule, Set, Map, Counter
	tx = nft.NewTransaction()
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("table comment"),
	})
	tx.Add(&knftables.Chain{
		Name:    "mychain",
		Comment: knftables.PtrTo("chain comment"),
	})
	tx.Add(&knftables.Rule{
		Chain:   "mychain",
		Rule:    "ip daddr 1.2.3.4 drop",
		Comment: knftables.PtrTo("rule comment"),
	})
	tx.Add(&knftables.Set{
		Name: "myset",
		Type: "ipv4_addr",
	})
	tx.Add(&knftables.Element{
		Set: "myset",
		Key: []string{"192.168.0.1"},
	})
	tx.Add(&knftables.Map{
		Name: "mymap",
		Type: "ipv4_addr : inet_service",
	})
	tx.Add(&knftables.Counter{
		Name: "mycounter",
	})
	tx.Add(&knftables.Flowtable{
		Name:     "myflowtable",
		Priority: knftables.PtrTo(knftables.FilterIngressPriority),
	})

	if err := nft.Run(ctx, tx); err != nil {
		t.Fatalf("failed to setup nftables rules: %v", err)
	}

	// 3. Create a knftables client WITH netlink enabled (default).
	nftNL, err := knftables.New(family, tableName)
	if err != nil {
		t.Fatalf("failed to create knftables with netlink: %v", err)
	}

	// 4. Verify List (Objects)
	t.Run("ListChains", func(t *testing.T) {
		chains, err := nftNL.List(ctx, "chains")
		if err != nil {
			t.Fatalf("List(chains) failed: %v", err)
		}
		if diff := cmp.Diff([]string{"mychain"}, chains, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
			t.Errorf("List(chains) mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ListSets", func(t *testing.T) {
		sets, err := nftNL.List(ctx, "sets")
		if err != nil {
			t.Fatalf("List(sets) failed: %v", err)
		}
		if diff := cmp.Diff([]string{"myset"}, sets); diff != "" {
			t.Errorf("List(sets) mismatch:\n%s", diff)
		}
	})

	t.Run("ListMaps", func(t *testing.T) {
		maps, err := nftNL.List(ctx, "maps")
		if err != nil {
			t.Fatalf("List(maps) failed: %v", err)
		}
		if diff := cmp.Diff([]string{"mymap"}, maps); diff != "" {
			t.Errorf("List(maps) mismatch:\n%s", diff)
		}
	})

	t.Run("ListCounters", func(t *testing.T) {
		counters, err := nftNL.List(ctx, "counters")
		if err != nil {
			t.Fatalf("List(counters) failed: %v", err)
		}
		if diff := cmp.Diff([]string{"mycounter"}, counters); diff != "" {
			t.Errorf("List(counters) mismatch:\n%s", diff)
		}
	})

	t.Run("ListFlowtables", func(t *testing.T) {
		flowtables, err := nftNL.List(ctx, "flowtables")
		if err != nil {
			t.Fatalf("List(flowtables) failed: %v", err)
		}
		if diff := cmp.Diff([]string{"myflowtable"}, flowtables); diff != "" {
			t.Errorf("List(flowtables) mismatch:\n%s", diff)
		}
	})
}

// TestNetlinkParity validates that Netlink-based listing and standard "nft"-based listing
// return the same results for randomly generated resources.
// It requires root privileges.
func TestNetlinkParity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping test that requires root")
	}

	ctx := context.Background()
	// Use a random table name to avoid conflicts
	tableName := fmt.Sprintf("knftables-parity-%d", time.Now().UnixNano())
	family := knftables.IPv4Family

	// 1. Client for setup (Binary)
	// We use binary client for setup to ensure we are testing "Netlink Listing" against "Real Underlying State" created by "Standard Means".
	clientBinary, err := knftables.New(family, tableName, knftables.DisableNetlink)
	if err != nil {
		t.Fatalf("failed to create clientBinary: %v", err)
	}

	// 2. Client for Netlink Listing
	clientNetlink, err := knftables.New(family, tableName)
	if err != nil {
		t.Fatalf("failed to create clientNetlink: %v", err)
	}

	// Prepare cleanup
	cleanup := func() {
		tx := clientBinary.NewTransaction()
		tx.Delete(&knftables.Table{})
		_ = clientBinary.Run(ctx, tx)
	}
	defer cleanup()
	cleanup() // clean start

	// Fuzz loop
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	const iterations = 50
	for i := 0; i < iterations; i++ {
		t.Run(fmt.Sprintf("Iteration-%d", i), func(t *testing.T) {
			// Clear table first to have clean state for each iteration
			// Or we could accumulate. Let's start clean to isolate failures.
			cleanup()

			tx := clientBinary.NewTransaction()
			tx.Add(&knftables.Table{Comment: knftables.PtrTo("parity test table")})

			chainName := fmt.Sprintf("c%d", i)
			tx.Add(&knftables.Chain{Name: chainName})

			// Generate random comment
			comment := randomComment(r)

			// Generate random rule
			// "ip daddr <random_ip> drop"
			ip := fmt.Sprintf("1.2.3.%d", r.Intn(255))
			ruleBody := fmt.Sprintf("ip daddr %s drop", ip)

			tx.Add(&knftables.Rule{
				Chain:   chainName,
				Rule:    ruleBody,
				Comment: knftables.PtrTo(comment),
			})

			// Add a Set
			setName := fmt.Sprintf("s%d", i)
			tx.Add(&knftables.Set{
				Name: setName,
				Type: "ipv4_addr",
			})

			// Add a Map
			mapName := fmt.Sprintf("m%d", i)
			tx.Add(&knftables.Map{
				Name: mapName,
				Type: "ipv4_addr : inet_service",
			})

			// Add a Counter
			counterName := fmt.Sprintf("ctr%d", i)
			tx.Add(&knftables.Counter{
				Name: counterName,
			})

			if err := clientBinary.Run(ctx, tx); err != nil {
				// If randomComment produces characters that nft binary rejects (e.g. unescaped quotes),
				// we might fail here. We log and skip if it's a write failure,
				// but ideally we want to test valid inputs.
				t.Logf("Setup failed (likely invalid comment for nft binary): %v", err)
				return // skip this iteration if we can't write it
			}

			// Verify ListRules
			gotNetlink, err := clientNetlink.ListRules(ctx, chainName)
			if err != nil {
				t.Fatalf("Netlink ListRules failed: %v", err)
			}

			gotBinary, err := clientBinary.ListRules(ctx, chainName)
			if err != nil {
				t.Fatalf("Binary ListRules failed: %v", err)
			}

			// Define comparison options
			if diff := cmp.Diff(gotBinary, gotNetlink); diff != "" {
				t.Errorf("ListRules mismatch (-binary +netlink):\n%s", diff)
			}

			// Also verify ListChains
			chainsNetlink, err := clientNetlink.List(ctx, "chains")
			if err != nil {
				t.Fatalf("Netlink List(chains) failed: %v", err)
			}
			chainsBinary, err := clientBinary.List(ctx, "chains")
			if err != nil {
				t.Fatalf("Binary List(chains) failed: %v", err)
			}
			if diff := cmp.Diff(chainsBinary, chainsNetlink, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("List(chains) mismatch:\n%s", diff)
			}

			// Verify List(sets)
			setsNetlink, err := clientNetlink.List(ctx, "sets")
			if err != nil {
				t.Fatalf("Netlink List(sets) failed: %v", err)
			}
			setsBinary, err := clientBinary.List(ctx, "sets")
			if err != nil {
				t.Fatalf("Binary List(sets) failed: %v", err)
			}
			if diff := cmp.Diff(setsBinary, setsNetlink, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("List(sets) mismatch:\n%s", diff)
			}

			// Verify List(maps)
			mapsNetlink, err := clientNetlink.List(ctx, "maps")
			if err != nil {
				t.Fatalf("Netlink List(maps) failed: %v", err)
			}
			mapsBinary, err := clientBinary.List(ctx, "maps")
			if err != nil {
				t.Fatalf("Binary List(maps) failed: %v", err)
			}
			if diff := cmp.Diff(mapsBinary, mapsNetlink, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("List(maps) mismatch:\n%s", diff)
			}

			// Verify List(counters)
			countersNetlink, err := clientNetlink.List(ctx, "counters")
			if err != nil {
				t.Fatalf("Netlink List(counters) failed: %v", err)
			}
			countersBinary, err := clientBinary.List(ctx, "counters")
			if err != nil {
				t.Fatalf("Binary List(counters) failed: %v", err)
			}
			if diff := cmp.Diff(countersBinary, countersNetlink, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("List(counters) mismatch:\n%s", diff)
			}
		})
	}
}

func randomComment(r *rand.Rand) string {
	// Generate random ASCII strings.
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-!@#%^&*()+=[]{}|;:,.<>?"
	length := r.Intn(50) + 1
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = chars[r.Intn(len(chars))]
	}
	return string(b)
}
