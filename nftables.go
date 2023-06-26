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
	"strings"
)

// Interface is an interface for running nftables commands against a given family and table.
type Interface interface {
	// Present determines if nftables is present/usable on the system
	Present() error

	// List returns a list of the names of the objects of objectType ("chain", "set",
	// or "map") in the indicated table.
	List(ctx context.Context, family Family, tableName, objectType string) ([]string, error)

	// Run runs a Transaction and returns the result
	Run(ctx context.Context, tx *Transaction) error
}

// runner is an implementation of Interface
type runner struct {
	exec execer
}

func New() Interface {
	return &runner{
		exec: realExec{},
	}
}

// Present is part of Interface.
func (runner *runner) Present() error {
	cmd := exec.Command("nft", "--check", "add", "table", "testing")
	_, err := runner.exec.CombinedOutput(cmd)
	return err
}

// Run is part of Interface
func (runner *runner) Run(ctx context.Context, tx *Transaction) error {
	if tx.err != nil {
		return tx.err
	}

	buf, err := tx.asCommandBuf()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = buf
	out, err := runner.exec.CombinedOutput(cmd)

	if err != nil {
		return fmt.Errorf("failed to run nft: %s", string(out))
	}
	return nil
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
func (runner *runner) List(ctx context.Context, family Family, tableName, objectType string) ([]string, error) {
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

	cmd := exec.CommandContext(ctx, "nft", "-j", "list", typePlural, string(family))
	stdout := &strings.Builder{}
	cmd.Stdout = stdout
	stderr := &strings.Builder{}
	cmd.Stderr = stderr

	err := runner.exec.Run(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run nft: %s", stderr.String())
	}

	// stdout contains JSON looking like:
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
	//         ...
	//       }
	//     },
	//     ...
	//   ]
	// }

	jsonResult := map[string][]map[string]map[string]interface{}{}
	if err := json.Unmarshal([]byte(stdout.String()), &jsonResult); err != nil {
		return nil, fmt.Errorf("could not parse nft output: %v", err)
	}

	nftablesResult := jsonResult["nftables"]
	if nftablesResult == nil || len(nftablesResult) == 0 {
		return nil, fmt.Errorf("could not find result in nft output %q", stdout.String())
	}
	metainfo := nftablesResult[0]["metainfo"]
	if metainfo == nil {
		return nil, fmt.Errorf("could not find metadata in nft output %q", stdout.String())
	}
	if version, ok := jsonVal[float64](metainfo, "json_schema_version"); !ok || version != 1.0 {
		return nil, fmt.Errorf("could not find supported json_schema_version in nft output %q", stdout.String())
	}

	var result []string
	for _, objContainer := range nftablesResult {
		obj := objContainer[typeSingular]
		if obj == nil {
			continue
		}
		objTable, _ := jsonVal[string](obj, "table")
		if objTable != tableName {
			continue
		}

		if name, ok := jsonVal[string](obj, "name"); ok {
			result = append(result, name)
		}
	}

	return result, nil
}
