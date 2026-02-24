package knftables

import (
	"context"
	"fmt"
	"testing"

	gnftables "github.com/google/nftables"
	nl "github.com/mdlayher/netlink"
)

// DisableNetlink is an exported alias for the internal disableNetlink option,
// specifically for use for the integration tests on knftables_test.
var DisableNetlink = disableNetlink

func TestNetlinkAdapterListErrors(t *testing.T) {
	// Create a gnftables.Conn with a mock dialer that always returns an error.
	c, err := gnftables.New(gnftables.WithTestDial(func(_ []nl.Message) ([]nl.Message, error) {
		return nil, fmt.Errorf("mock netlink error")
	}))
	if err != nil {
		t.Fatalf("Failed to create mock gnftables.Conn: %v", err)
	}

	adapter := &netlinkAdapter{
		conn:   c,
		family: gnftables.TableFamilyIPv4,
		table:  "test-table",
	}

	// Test error propagation for supported objects
	tests := []string{"chains", "sets", "maps", "counters", "flowtables"}
	for _, objectType := range tests {
		t.Run("Error propagation for "+objectType, func(t *testing.T) {
			_, err := adapter.List(context.Background(), objectType)
			if err == nil {
				t.Errorf("List(%q) expected error, got nil", objectType)
			}
		})
	}

	// Test unsupported object types
	t.Run("Unsupported object type", func(t *testing.T) {
		_, err := adapter.List(context.Background(), "invalid")
		if err == nil {
			t.Errorf("List(%q) expected error, got nil", "invalid")
		}
	})

	// Test listSets validation
	t.Run("Invalid listSets objectType", func(t *testing.T) {
		_, err := adapter.listSets("invalid")
		if err == nil {
			t.Errorf("listSets(%q) expected error, got nil", "invalid")
		}
	})
}
