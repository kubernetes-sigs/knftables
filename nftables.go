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
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Interface is an interface for running nftables commands against a given family and table.
type Interface interface {
	// Present determines if nftables is present/usable on the system.
	Present() error

	// Run runs a Transaction and returns the result.
	Run(ctx context.Context, tx *Transaction) error

	// List returns a list of the names of the objects of objectType ("chain", "set",
	// or "map") in the table.
	List(ctx context.Context, objectType string) ([]string, error)

	// ListRules returns a list of the rules in a chain.
	ListRules(ctx context.Context, chain string) ([]*Rule, error)

	// ListElements returns a list of the elements in a set or map. (objectType
	// should be "set" or "map".)
	ListElements(ctx context.Context, objectType, name string) ([]*Element, error)
}

// realNFTables is an implementation of Interface
type realNFTables struct {
	family Family
	table  string

	exec execer
}

func New(family Family, table string) Interface {
	return &realNFTables{
		family: family,
		table:  table,

		exec: realExec{},
	}
}

// Present is part of Interface.
func (nft *realNFTables) Present() error {
	if _, err := nft.exec.LookPath("nft"); err != nil {
		return fmt.Errorf("could not run nftables binary: %v", err)
	}

	cmd := exec.Command("nft", "--check", "add", "table", string(nft.family), nft.table)
	_, err := nft.exec.Run(cmd)
	return err
}

// Run is part of Interface
func (nft *realNFTables) Run(ctx context.Context, tx *Transaction) error {
	if tx.err != nil {
		return tx.err
	}

	buf, err := tx.asCommandBuf(nft.family, nft.table)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = buf
	_, err = nft.exec.Run(cmd)
	return err
}

func jsonVal[T any](json map[string]interface{}, key string) (T, bool) {
	if ifVal, exists := json[key]; exists {
		tVal, ok := ifVal.(T)
		return tVal, ok
	} else {
		var zero T
		return zero, false
	}
}

// List is part of Interface.
func (nft *realNFTables) List(ctx context.Context, objectType string) ([]string, error) {
	// All currently-existing nftables object types have plural forms that are just
	// the singular form plus 's'.
	var typeSingular, typePlural string
	if objectType[len(objectType)-1] == 's' {
		typeSingular = objectType[:len(objectType)-1]
		typePlural = objectType
	} else {
		typeSingular = objectType
		typePlural = objectType + "s"
	}

	cmd := exec.CommandContext(ctx, "nft", "--json", "list", typePlural, string(nft.family))
	out, err := nft.exec.Run(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run nft: %v", err)
	}

	// out contains JSON looking like:
	// {
	//   "nftables": [
	//     {
	//       "metainfo": {
	//         "json_schema_version": 1
	//         ...
	//       }
	//     },
	//     {
	//       "chain": {
	//         "family": "ip",
	//         "table": "kube_proxy",
	//         "name": "KUBE-SERVICES",
	//         "handle": 3,
	//       }
	//     },
	//     ...
	//   ]
	// }

	jsonResult := map[string][]map[string]map[string]interface{}{}
	if err := json.Unmarshal([]byte(out), &jsonResult); err != nil {
		return nil, fmt.Errorf("could not parse nft output: %v", err)
	}

	nftablesResult := jsonResult["nftables"]
	if nftablesResult == nil || len(nftablesResult) == 0 {
		return nil, fmt.Errorf("could not find result in nft output %q", out)
	}
	metainfo := nftablesResult[0]["metainfo"]
	if metainfo == nil {
		return nil, fmt.Errorf("could not find metadata in nft output %q", out)
	}
	if version, ok := jsonVal[float64](metainfo, "json_schema_version"); !ok || version != 1.0 {
		return nil, fmt.Errorf("could not find supported json_schema_version in nft output %q", out)
	}

	var result []string
	for _, objContainer := range nftablesResult {
		obj := objContainer[typeSingular]
		if obj == nil {
			continue
		}
		objTable, _ := jsonVal[string](obj, "table")
		if objTable != nft.table {
			continue
		}

		if name, ok := jsonVal[string](obj, "name"); ok {
			result = append(result, name)
		}
	}

	return result, nil
}

// ListRules is part of Interface
func (nft *realNFTables) ListRules(ctx context.Context, chain string) ([]*Rule, error) {
	// We don't use the JSON API because the syntax for rules is wildly different in
	// JSON and there is no way to convert it to "normal" form.
	cmd := exec.CommandContext(ctx, "nft", "--handle", "list", "chain", string(nft.family), nft.table, chain)
	out, err := nft.exec.Run(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run nft: %v", err)
	}

	// Output looks like:
	//
	// table inet firewalld { # handle 1
	//     chain filter_INPUT { # handle 165
	//         type filter hook input priority filter + 10; policy accept;
	//         ct state { established, related } accept # handle 169
	//         ct status dnat accept # handle 170
	//         iifname "lo" accept # handle 171
	//         ...
	//     }
	// }
	//
	// (Where the "type ..." line only appears for base chains.) If a rule has a
	// comment, it will always be the last part of the rule (before the handle).

	lines := strings.Split(out, "\n")
	rules := make([]*Rule, 0, len(lines))
	sawTable := false
	sawChain := false
	for _, line := range lines {
		line := strings.TrimSpace(line)

		if !sawTable {
			if strings.HasPrefix(line, "table ") {
				sawTable = true
			}
			continue
		} else if !sawChain {
			if strings.HasPrefix(line, "chain "+chain) {
				sawChain = true
			}
			continue
		} else if line == "}" {
			break
		}

		parts := strings.Split(line, " # handle ")
		if len(parts) != 2 {
			continue
		}
		line, handleStr := parts[0], parts[1]
		handle, err := strconv.Atoi(handleStr)
		if err != nil {
			continue
		}

		rule, comment := splitComment(line)
		rules = append(rules, &Rule{
			Chain:   chain,
			Rule:    rule,
			Comment: comment,
			Handle:  &handle,
		})
	}

	return rules, nil
}

// ListElements is part of Interface
func (nft *realNFTables) ListElements(ctx context.Context, objectType, name string) ([]*Element, error) {
	// We don't use the JSON API because the JSON syntax for elements, while not quite
	// as bad as the syntax for rules, is still not easily transformable into "normal"
	// form. (And in particular, for verdict maps, the verdict part is stored as a
	// JSON rule, not as a string.)
	cmd := exec.CommandContext(ctx, "nft", "list", objectType, string(nft.family), nft.table, name)
	out, err := nft.exec.Run(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run nft: %v", err)
	}

	// Output looks like:
	//
	// table ip testing {
	//     map map1 {
	//         type ipv4_addr . inet_proto . inet_service : verdict
	//         elements = { 192.168.0.1 . tcp . 80 : goto chain1,
	//                      192.168.0.2 . tcp . 443 comment "foo" : drop }
	//     }
	// }

	lines := strings.Split(out, "\n")
	elements := make([]*Element, 0, len(lines))
	sawTable := false
	sawObject := false
	sawElements := false
	for _, line := range lines {
		line := strings.TrimSpace(line)

		if !sawTable {
			if strings.HasPrefix(line, "table ") {
				sawTable = true
			}
			continue
		} else if !sawObject {
			if strings.HasPrefix(line, objectType+" "+name) {
				sawObject = true
			}
			continue
		} else if !sawElements {
			if !strings.HasPrefix(line, "elements = { ") {
				continue
			}
			sawElements = true
			line = strings.TrimPrefix(line, "elements = { ")
			// fall through into the main loop body
		} else if line == "}" {
			break
		}

		line = strings.TrimRight(line, ", }")
		var key, value string
		var comment *string

		if objectType == "map" {
			key, comment, value = splitMapValue(line)
		} else {
			key, comment = splitComment(line)
		}
		if key == "" {
			continue
		}

		elements = append(elements, &Element{
			Name:    name,
			Key:     key,
			Value:   value,
			Comment: comment,
		})
	}

	return elements, nil
}

var commentRegexp = regexp.MustCompile(`^(.*) comment "([^"]*)"$`)

// splitComment splits line into a required pre-comment and optional trailing comment
// (which is enclosed in quotes but does not contain any quotes).
func splitComment(line string) (string, *string) {
	// We could perhaps do this more efficiently without using a regexp, but it would
	// be more complicated...
	match := commentRegexp.FindStringSubmatch(line)
	if match != nil {
		return match[1], &match[2]
	}
	return line, nil
}

var mapValueRegexp = regexp.MustCompile(`^(([^"]|"[^"]*")+) : (([^"]|"[^"]*")+)`)

// splitMapValue splits line into key, optional comment, and value, dealing with the
// possibility of strings whose contents look like nftables syntax.
func splitMapValue(line string) (string, *string, string) {
	// We could perhaps do this more efficiently without using a regexp, but it would
	// be more complicated...
	match := mapValueRegexp.FindStringSubmatch(line)
	if match == nil {
		return "", nil, ""
	}

	value := match[3]
	key, comment := splitComment(match[1])
	return key, comment, value
}
