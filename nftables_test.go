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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lithammer/dedent"
)

func newTestInterface(t *testing.T, family Family, tableName string) (Interface, *fakeExec, error) {
	fexec := newFakeExec(t)
	fexec.expected = append(fexec.expected,
		expectedCmd{
			args:   []string{"/nft", "--version"},
			stdout: "nftables v1.0.7 (Old Doc Yak)\n",
		},
		expectedCmd{
			args:  []string{"/nft", "--check", "-f", "-"},
			stdin: fmt.Sprintf("add table %s %s { comment \"test\" ; }\n", family, tableName),
		},
	)
	nft, err := newInternal(family, tableName, fexec)
	return nft, fexec, err
}

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

			nft, fexec, _ := newTestInterface(t, IPv6Family, "testing")

			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"/nft", "--json", "list", "chains", "ip6"},
					stdout: tc.nftOutput,
					err:    nftErr,
				},
			)
			result, err := nft.List(context.Background(), "chains")
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
			nft, fexec, _ := newTestInterface(t, IPv4Family, "testing")

			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"/nft", "--json", "list", "chains", "ip"},
					stdout: tc.nftOutput,
				},
			)
			result, err := nft.List(context.Background(), tc.objType)
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
	nft, fexec, _ := newTestInterface(t, IPv4Family, "kube-proxy")

	tx := nft.NewTransaction()

	tx.Add(&Table{})
	tx.Add(&Chain{
		Name:    "chain",
		Comment: PtrTo("foo"),
	})
	tx.Add(&Rule{
		Chain: "chain",
		Rule:  "ip daddr 10.0.0.0/8 drop",
	})
	tx.Add(&Flowtable{
		Name:     "flowtable",
		Priority: PtrTo(FilterIngressPriority),
		Devices:  []string{"eth0", "eth1"},
	})
	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain ip daddr 10.0.0.0/8 drop
		add flowtable ip kube-proxy flowtable { hook ingress priority filter ; devices = { eth0, eth1 } ; }
		`), "\n")
	fexec.expected = append(fexec.expected,
		expectedCmd{
			args:  []string{"/nft", "-f", "-"},
			stdin: expected,
		},
	)

	err := nft.Run(context.Background(), tx)
	if err != nil {
		t.Errorf("unexpected error from Run: %v", err)
	}
}

func TestListRules(t *testing.T) {
	for _, tc := range []struct {
		name       string
		chain      string
		nftOutput  string
		nftError   string
		listOutput []*Rule
	}{
		{
			name:     "no such chain",
			chain:    "testchain",
			nftError: "Error: No such file or directory\nlist chain ip testing testchain\n                      ^^^^^^^^^\n",
		},
		{
			name:       "no rules",
			chain:      "testchain",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "testing", "name": "testchain", "handle": 21}}]}`,
			listOutput: []*Rule{},
		},
		{
			name:      "normal output",
			chain:     "testchain",
			nftOutput: `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "testing", "name": "testchain", "handle": 165}}, {"rule": {"family": "ip", "table": "testing", "chain": "testchain", "handle": 169, "expr": [{"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": {"set": ["established", "related"]}}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "testing", "chain": "testchain", "handle": 170, "comment": "This rule does something", "expr": [{"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "testing", "chain": "testchain", "handle": 171, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}]}}]}`,
			listOutput: []*Rule{
				{
					Chain:  "testchain",
					Handle: PtrTo(169),
				},
				{
					Chain:   "testchain",
					Comment: PtrTo("This rule does something"),
					Handle:  PtrTo(170),
				},
				{
					Chain:  "testchain",
					Handle: PtrTo(171),
				},
			},
		},
		{
			name:      "all rules in table",
			nftOutput: `{"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"table": {"family": "ip", "name": "testing", "handle": 3}}, {"chain": {"family": "ip", "table": "testing", "name": "chain1", "handle": 1}}, {"rule": {"family": "ip", "table": "testing", "chain": "chain1", "handle": 3, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "8.8.8.8"}}, {"counter": {"packets": 0, "bytes": 0}}]}}, {"chain": {"family": "ip", "table": "testing", "name": "chain2", "handle": 2}}, {"rule": {"family": "ip", "table": "testing", "chain": "chain2", "handle": 4, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "1.2.3.4"}}, {"counter": {"packets": 0, "bytes": 0}}]}}]}`,
			listOutput: []*Rule{
				{
					Chain:  "chain1",
					Handle: PtrTo(3),
				},
				{
					Chain:  "chain2",
					Handle: PtrTo(4),
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nft, fexec, _ := newTestInterface(t, IPv4Family, "testing")

			var err error
			if tc.nftError != "" {
				err = fmt.Errorf(tc.nftError)
			}
			if tc.chain == "" {
				fexec.expected = append(fexec.expected,
					expectedCmd{
						args:   []string{"/nft", "--json", "list", "table", "ip", "testing"},
						stdout: strings.TrimSpace(dedent.Dedent(tc.nftOutput)),
						err:    err,
					},
				)
			} else {
				fexec.expected = append(fexec.expected,
					expectedCmd{
						args:   []string{"/nft", "--json", "list", "chain", "ip", "testing", "testchain"},
						stdout: strings.TrimSpace(dedent.Dedent(tc.nftOutput)),
						err:    err,
					},
				)
			}
			result, err := nft.ListRules(context.Background(), tc.chain)
			if err != nil {
				if tc.nftError == "" {
					t.Errorf("unexpected error: %v", err)
				}
				return
			} else if tc.nftError != "" {
				t.Errorf("unexpected non-error")
				return
			}

			diff := cmp.Diff(tc.listOutput, result)
			if diff != "" {
				t.Errorf("unexpected result:\n%s", diff)
			}
		})
	}
}

func TestListElements(t *testing.T) {
	for _, tc := range []struct {
		name       string
		objectType string
		nftOutput  string
		nftError   string
		listOutput []*Element
	}{
		{
			name:       "no such set",
			objectType: "set",
			nftError:   "Error: No such file or directory\nlist set ip testing test\n                    ^^^^\n",
		},
		{
			name:       "no elements",
			objectType: "set",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "test", "table": "testing", "type": "inet_proto", "handle": 16}}]}`,
			listOutput: []*Element{},
		},
		{
			name:       "no elements",
			objectType: "set",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "test", "table": "testing", "type": "inet_proto", "handle": 16, "elem": []}}]}`,
			listOutput: []*Element{},
		},
		{
			name:       "simple type",
			objectType: "set",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "test", "table": "testing", "type": "ipv4_addr", "handle": 12, "elem": ["192.168.1.1", "192.168.1.2", {"elem": {"val": "192.168.1.3", "comment": "with a comment"}}]}}]}`,
			listOutput: []*Element{
				{
					Set: "test",
					Key: []string{"192.168.1.1"},
				},
				{
					Set: "test",
					Key: []string{"192.168.1.2"},
				},
				{
					Set:     "test",
					Key:     []string{"192.168.1.3"},
					Comment: PtrTo("with a comment"),
				},
			},
		},
		{
			name:       "concatenated type",
			objectType: "set",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "test", "table": "testing", "type": ["ipv4_addr", "inet_proto", "inet_service"], "handle": 13, "elem": [{"concat": ["192.168.1.3", "tcp", 80]}, {"concat": ["192.168.1.4", "udp", 80]}, {"elem": {"val": {"concat": ["192.168.1.5", "tcp", 443]}, "comment": "foo"}}]}}]}`,
			listOutput: []*Element{
				{
					Set: "test",
					Key: []string{"192.168.1.3", "tcp", "80"},
				},
				{
					Set: "test",
					Key: []string{"192.168.1.4", "udp", "80"},
				},
				{
					Set:     "test",
					Key:     []string{"192.168.1.5", "tcp", "443"},
					Comment: PtrTo("foo"),
				},
			},
		},
		{
			name:       "prefix type",
			objectType: "set",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "test", "table": "testing", "type": ["ipv4_addr"], "handle": 13, "flags": ["interval"], "elem": [{"prefix": {"addr": "192.168.0.0", "len": 16}}]}}]}`,
			listOutput: []*Element{
				{
					Set: "test",
					Key: []string{"192.168.0.0/16"},
				},
			},
		},
		{
			name:       "prefix type - bad len value",
			objectType: "set",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "test", "table": "testing", "type": ["ipv4_addr"], "handle": 13, "flags": ["interval"], "elem": [{"prefix": {"addr": "192.168.0.0", "len": "16"}}]}}]}`,
			nftError:   `could not parse 'len' value as number: map["addr":"192.168.0.0" "len":"16"]`,
		},
		{
			name:       "prefix type - missing addr",
			objectType: "set",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"set": {"family": "ip", "name": "test", "table": "testing", "type": ["ipv4_addr"], "handle": 13, "flags": ["interval"], "elem": [{"prefix": {"len": "16"}}]}}]}`,
			nftError:   `could not parse 'addr' value as string: map["len":"16"]`,
		},
		{
			name:       "simple map",
			objectType: "map",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"map": {"family": "ip", "name": "test", "table": "testing", "type": "ipv4_addr", "handle": 14, "map": "inet_service", "elem": [["10.0.0.1", 80], [{"elem": {"val": "10.0.0.2", "comment": "a comment"}}, 443]]}}]}`,
			listOutput: []*Element{
				{
					Map:   "test",
					Key:   []string{"10.0.0.1"},
					Value: []string{"80"},
				},
				{
					Map:     "test",
					Key:     []string{"10.0.0.2"},
					Value:   []string{"443"},
					Comment: PtrTo("a comment"),
				},
			},
		},
		{
			name:       "verdict map, concatenated key",
			objectType: "map",
			nftOutput:  `{"nftables": [{"metainfo": {"version": "1.0.1", "release_name": "Fearless Fosdick #3", "json_schema_version": 1}}, {"map": {"family": "ip", "name": "test", "table": "testing", "type": ["ipv4_addr", "inet_proto"], "handle": 15, "map": "verdict", "elem": [[{"concat": ["192.168.1.1", "tcp"]}, {"drop": null}], [{"elem": {"val": {"concat": ["192.168.1.3", "tcp"]}, "comment": "foo"}}, {"return": null}], [{"concat": ["192.168.1.2", "udp"]}, {"goto": {"target": "test"}}]]}}]}`,
			listOutput: []*Element{
				{
					Map:   "test",
					Key:   []string{"192.168.1.1", "tcp"},
					Value: []string{"drop"},
				},
				{
					Map:     "test",
					Key:     []string{"192.168.1.3", "tcp"},
					Value:   []string{"return"},
					Comment: PtrTo("foo"),
				},
				{
					Map:   "test",
					Key:   []string{"192.168.1.2", "udp"},
					Value: []string{"goto test"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nft, fexec, _ := newTestInterface(t, IPv4Family, "testing")

			var err error
			if tc.nftError != "" {
				err = fmt.Errorf(tc.nftError)
			}
			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"/nft", "--json", "list", tc.objectType, "ip", "testing", "test"},
					stdout: strings.TrimSpace(dedent.Dedent(tc.nftOutput)),
					err:    err,
				},
			)

			result, err := nft.ListElements(context.Background(), tc.objectType, "test")
			if err != nil {
				if tc.nftError == "" {
					t.Errorf("unexpected error: %v", err)
				}
				return
			} else if tc.nftError != "" {
				t.Errorf("unexpected non-error")
				return
			}

			diff := cmp.Diff(tc.listOutput, result)
			if diff != "" {
				t.Errorf("unexpected result:\n%s", diff)
			}
		})
	}
}

func TestFeatures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commands []expectedCmd
		result   *nftContext
	}{
		{
			name: "old nftables",
			commands: []expectedCmd{
				{
					args: []string{
						"/nft", "--version",
					},
					stdout: "nftables v0.9.3 (Topsy)\n",
				},
			},
			result: nil,
		},
		{
			name: "all features",
			commands: []expectedCmd{
				{
					args: []string{
						"/nft", "--version",
					},
					stdout: "nftables v1.0.7 (Old Doc Yak)\n",
				},
				{
					args:  []string{"/nft", "--check", "-f", "-"},
					stdin: "add table ip testing { comment \"test\" ; }\n",
				},
			},
			result: &nftContext{
				family: IPv4Family,
				table:  "testing",
			},
		},
		{
			name: "noObjectComments",
			commands: []expectedCmd{
				{
					args: []string{
						"/nft", "--version",
					},
					stdout: "nftables v1.0.7 (Old Doc Yak)\n",
				},
				{
					args:  []string{"/nft", "--check", "-f", "-"},
					stdin: "add table ip testing { comment \"test\" ; }\n",
					err:   fmt.Errorf("Error: syntax error, unexpected comment"),
				},
				{
					args:  []string{"/nft", "--check", "-f", "-"},
					stdin: "add table ip testing\n",
				},
			},
			result: &nftContext{
				family: IPv4Family,
				table:  "testing",

				noObjectComments: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fexec := newFakeExec(t)
			fexec.expected = tc.commands
			nft, err := newInternal(IPv4Family, "testing", fexec)
			if err != nil {
				if tc.result != nil {
					t.Fatalf("Unexpected error creating Interface: %v", err)
				}
			} else {
				result := nft.(*realNFTables).nftContext
				if tc.result != nil {
					if !reflect.DeepEqual(*tc.result, result) {
						t.Errorf("Expected %#v, got %#v", *tc.result, result)
					}
				} else {
					t.Fatalf("Expected failure, got %#v", result)
				}
			}
		})
	}
}

func TestListCounters(t *testing.T) {
	for _, tc := range []struct {
		name             string
		nftOutput        string
		nftError         string
		expectedCounters []*Counter
	}{
		{
			name:             "no counters",
			nftOutput:        `{"nftables": [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}}]}`,
			expectedCounters: []*Counter{},
		},
		{
			name:      "single counter with comment",
			nftOutput: `{"nftables": [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}}, {"counter": {"family": "ip", "name": "test-counter", "table": "testing", "handle": 1, "comment": "test-counter-comment", "packets": 100, "bytes": 5000}}]}`,
			expectedCounters: []*Counter{
				{Name: "test-counter", Comment: PtrTo("test-counter-comment"), Packets: PtrTo[uint64](100), Bytes: PtrTo[uint64](5000), Handle: PtrTo(1)},
			},
		},
		{
			name:      "multiple counters without comments",
			nftOutput: `{"nftables": [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}}, {"counter": {"family": "ip", "name": "test-counter-1", "table": "testing", "handle": 2, "packets": 10, "bytes": 5000}}, {"counter": {"family": "ip", "name": "test-counter-2", "table": "testing", "handle": 3, "packets": 20, "bytes": 10000}}]}`,
			expectedCounters: []*Counter{
				{Name: "test-counter-1", Packets: PtrTo[uint64](10), Bytes: PtrTo[uint64](5000), Handle: PtrTo(2)},
				{Name: "test-counter-2", Packets: PtrTo[uint64](20), Bytes: PtrTo[uint64](10000), Handle: PtrTo(3)},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nft, fexec, _ := newTestInterface(t, IPv4Family, "testing")

			var err error
			if tc.nftError != "" {
				err = fmt.Errorf(tc.nftError)
			}
			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"/nft", "--json", "list", "counters", "table", "ip", "testing"},
					stdout: strings.TrimSpace(dedent.Dedent(tc.nftOutput)),
					err:    err,
				},
			)

			counters, err := nft.ListCounters(context.Background())
			if err != nil {
				if tc.nftError == "" {
					t.Errorf("unexpected error: %v", err)
				}
				return
			} else if tc.nftError != "" {
				t.Errorf("unexpected non-error")
				return
			}

			diff := cmp.Diff(tc.expectedCounters, counters)
			if diff != "" {
				t.Errorf("unexpected result:\n%s", diff)
			}
		})
	}
}
