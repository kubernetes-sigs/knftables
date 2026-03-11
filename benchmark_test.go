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
	"os"
	"testing"

	"sigs.k8s.io/knftables"
)

func setupBenchmarkChains(b *testing.B, nft knftables.Interface, tableName string, numChains int) {
	b.Helper()
	ctx := context.Background()

	// Clean up any existing table
	tx := nft.NewTransaction()
	tx.Delete(&knftables.Table{
		Name: tableName,
	})
	_ = nft.Run(ctx, tx)

	// Create table
	tx = nft.NewTransaction()
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("benchmark table"),
	})

	for i := 0; i < numChains; i++ {
		tx.Add(&knftables.Chain{
			Name: fmt.Sprintf("chain-%d", i),
		})
	}

	if err := nft.Run(ctx, tx); err != nil {
		b.Fatalf("failed to setup chains: %v", err)
	}
}

func runBenchmarkListChains(b *testing.B, useNetlink bool, numChains int) {
	if os.Geteuid() != 0 {
		b.Skip("skipping benchmark that requires root")
	}

	tableName := fmt.Sprintf("bench-chains-%d-%v", numChains, useNetlink)
	family := knftables.IPv4Family

	var opts []knftables.Option
	if !useNetlink {
		opts = append(opts, knftables.DisableNetlink)
	}

	nft, err := knftables.New(family, tableName, opts...)
	if err != nil {
		b.Fatalf("failed to create knftables client: %v", err)
	}

	setupBenchmarkChains(b, nft, tableName, numChains)
	defer func() {
		// cleanup
		tx := nft.NewTransaction()
		tx.Delete(&knftables.Table{Name: tableName})
		_ = nft.Run(context.Background(), tx)
	}()

	b.ResetTimer()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		out, err := nft.List(ctx, "chains")
		if err != nil {
			b.Fatalf("List chains failed: %v", err)
		}
		if len(out) != numChains {
			b.Fatalf("List chains failed: expected %d chains, got %d", numChains, len(out))
		}
	}
	b.StopTimer()
}

func BenchmarkListChains_NFT_10(b *testing.B) {
	runBenchmarkListChains(b, false, 10)
}

func BenchmarkListChains_NFT_100(b *testing.B) {
	runBenchmarkListChains(b, false, 100)
}

func BenchmarkListChains_NFT_1000(b *testing.B) {
	runBenchmarkListChains(b, false, 1000)
}

func BenchmarkListChains_NFT_10000(b *testing.B) {
	runBenchmarkListChains(b, false, 10000)
}

func BenchmarkListChains_Netlink_10(b *testing.B) {
	runBenchmarkListChains(b, true, 10)
}

func BenchmarkListChains_Netlink_100(b *testing.B) {
	runBenchmarkListChains(b, true, 100)
}

func BenchmarkListChains_Netlink_1000(b *testing.B) {
	runBenchmarkListChains(b, true, 1000)
}

func BenchmarkListChains_Netlink_10000(b *testing.B) {
	runBenchmarkListChains(b, true, 10000)
}
