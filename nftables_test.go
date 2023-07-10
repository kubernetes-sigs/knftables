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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/lithammer/dedent"
)

func TestListBad(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nftOutput string
		nftError  string
		listError string
	}{
		{
			name:      "empty",
			nftOutput: ``,
			listError: "could not parse nft output",
		},
		{
			name:      "nft failure",
			nftOutput: ``,
			nftError:  "blah blah blah",
			listError: "failed to run nft: blah blah blah",
		},
		{
			name:      "bad format",
			nftOutput: `{"foo": "bar"}`,
			listError: "could not parse nft output",
		},
		{
			name:      "no result",
			nftOutput: `{"foo": []}`,
			listError: "could not find result",
		},
		{
			name:      "no result (2)",
			nftOutput: `{"nftables":[]}`,
			listError: "could not find result",
		},
		{
			name:      "no metadata",
			nftOutput: `{"nftables":[{"foo":{}}]}`,
			listError: "could not find metadata",
		},
		{
			name:      "no schema info",
			nftOutput: `{"nftables":[{"metainfo":{}}]}`,
			listError: "could not find supported json_schema_version",
		},
		{
			name:      "bad version",
			nftOutput: `{"nftables":[{"metainfo":{"json_schema_version":2}}]}`,
			listError: "could not find supported json_schema_version",
		},
		{
			name:      "bad version (2)",
			nftOutput: `{"nftables":[{"metainfo":{"json_schema_version":"one"}}]}`,
			listError: "could not find supported json_schema_version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var nftErr error
			if tc.nftError != "" {
				nftErr = fmt.Errorf(tc.nftError)
			}

			fexec := newFakeExec(t)
			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"nft", "-j", "list", "chains", "ip"},
					stdout: tc.nftOutput,
					err:    nftErr,
				},
			)
			nft := &realNFTables{fexec}

			result, err := nft.List(context.Background(), IPv4Family, "testing", "chains")
			if result != nil {
				t.Errorf("unexpected non-nil result: %v", result)
			}
			if !strings.Contains(err.Error(), tc.listError) {
				t.Errorf("unexpected error: wanted %q got %q", tc.listError, err.Error())
			}
		})
	}
}

func TestList(t *testing.T) {
	for _, tc := range []struct {
		name       string
		objType    string
		nftOutput  string
		listOutput []string
	}{
		{
			name:       "empty list",
			objType:    "chains",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}]}`,
			listOutput: nil,
		},
		{
			name:       "singular objType",
			objType:    "chain",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "testing", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "output", "handle": 3, "type": "nat", "hook": "output", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "postrouting", "handle": 7, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "KUBE-SERVICES", "handle": 11}}, {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "filter", "name": "FOO", "handle": 3}}]}`,
			listOutput: []string{"prerouting", "output", "postrouting", "KUBE-SERVICES"},
		},
		{
			name:       "plural objType",
			objType:    "chains",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "testing", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "output", "handle": 3, "type": "nat", "hook": "output", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "postrouting", "handle": 7, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "testing", "name": "KUBE-SERVICES", "handle": 11}}, {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "filter", "name": "FOO", "handle": 3}}]}`,
			listOutput: []string{"prerouting", "output", "postrouting", "KUBE-SERVICES"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fexec := newFakeExec(t)
			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"nft", "-j", "list", "chains", "ip"},
					stdout: tc.nftOutput,
				},
			)
			nft := &realNFTables{fexec}

			result, err := nft.List(context.Background(), IPv4Family, "testing", tc.objType)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(result, tc.listOutput) {
				t.Errorf("unexpected result: wanted %v got %v", tc.listOutput, result)
			}
		})
	}
}

func TestRun(t *testing.T) {
	fexec := newFakeExec(t)
	nft := &realNFTables{fexec}

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

	expected := strings.TrimPrefix(dedent.Dedent(`
		define IP = ip
		add table ip kube-proxy
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain $IP daddr 10.0.0.0/8 drop
		`), "\n")
	fexec.expected = append(fexec.expected,
		expectedCmd{
			args:  []string{"nft", "-f", "-"},
			stdin: expected,
		},
	)

	err := nft.Run(context.Background(), tx)
	if err != nil {
		t.Errorf("unexpected error from Run: %v", err)
	}
}
