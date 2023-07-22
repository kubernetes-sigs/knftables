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

	"github.com/google/go-cmp/cmp"
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
					args:   []string{"nft", "--json", "list", "chains", "ip"},
					stdout: tc.nftOutput,
					err:    nftErr,
				},
			)
			nft := newInternal(IPv4Family, "testing", fexec)

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
			fexec := newFakeExec(t)
			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"nft", "--json", "list", "chains", "ip"},
					stdout: tc.nftOutput,
				},
			)
			nft := newInternal(IPv4Family, "testing", fexec)

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
	fexec := newFakeExec(t)
	nft := newInternal(IPv4Family, "kube-proxy", fexec)
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

	expected := strings.TrimPrefix(dedent.Dedent(`
		add table ip kube-proxy
		add chain ip kube-proxy chain { comment "foo" ; }
		add rule ip kube-proxy chain $IP daddr 10.0.0.0/8 drop
		`), "\n")
	fexec.expected = append(fexec.expected,
		expectedCmd{
			args:  []string{"nft", "-D", "IP=ip", "-D", "INET_ADDR=ipv4_addr", "-f", "-"},
			stdin: expected,
		},
	)

	err := nft.Run(context.Background(), tx)
	if err != nil {
		t.Errorf("unexpected error from Run: %v", err)
	}
}

func Test_splitComment(t *testing.T) {
	for _, tc := range []struct {
		name    string
		line    string
		rule    string
		comment *string
	}{
		{
			name:    "empty",
			line:    "",
			rule:    "",
			comment: nil,
		},
		{
			name:    "no comment",
			line:    "ip saddr 1.2.3.4 drop",
			rule:    "ip saddr 1.2.3.4 drop",
			comment: nil,
		},
		{
			name:    "simple comment",
			line:    `ip saddr 1.2.3.4 drop comment "I don't like him"`,
			rule:    "ip saddr 1.2.3.4 drop",
			comment: Optional("I don't like him"),
		},
		{
			name:    "empty comment",
			line:    `ip saddr 1.2.3.4 drop comment ""`,
			rule:    "ip saddr 1.2.3.4 drop",
			comment: Optional(""),
		},
		{
			name:    "tricky comment",
			line:    `ip saddr 1.2.3.4 drop comment "I have no comment "`,
			rule:    "ip saddr 1.2.3.4 drop",
			comment: Optional("I have no comment "),
		},
		{
			name:    "not a comment",
			line:    `iifname "comment " drop`,
			rule:    `iifname "comment " drop`,
			comment: nil,
		},
		{
			name:    "not a comment plus a comment",
			line:    `iifname "comment " drop comment "fooled ya?"`,
			rule:    `iifname "comment " drop`,
			comment: Optional("fooled ya?"),
		},
		{
			name:    "not a comment plus tricky comment",
			line:    `iifname "comment " drop comment "comment "`,
			rule:    `iifname "comment " drop`,
			comment: Optional("comment "),
		},
	} {
		t.Run(tc.name, func (t *testing.T) {
			rule, comment := splitComment(tc.line)
			if rule != tc.rule {
				t.Errorf("bad rule: expected %q got %q", tc.rule, rule)
			}
			if comment == nil {
				if tc.comment != nil {
					t.Errorf("bad comment: expected %q got nil", *tc.comment)
				}
			} else if tc.comment == nil {
				t.Errorf("bad comment: expected nil got %q", *comment)
			} else if *comment != *tc.comment {
				t.Errorf("bad comment: expected %q got %q", *tc.comment, *comment)
			}
		})
	}
}

func Test_splitMapValue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		line    string
		key     string
		comment *string
		value   string
	}{
		{
			name:    "empty (bad)",
			line:    "",
			key:     "",
			comment: nil,
			value:   "",
		},
		{
			name:    "simple",
			line:    "192.168.0.1 . tcp . 80 : drop",
			key:     "192.168.0.1 . tcp . 80",
			comment: nil,
			value:   "drop",
		},
		{
			name:    "with comment",
			line:    `192.168.0.1 . tcp . 80 comment "hello" : drop`,
			key:     "192.168.0.1 . tcp . 80",
			comment: Optional("hello"),
			value:   "drop",
		},
		{
			name:    "tricky comment #1",
			line:    `192.168.0.1 . tcp . 80 comment " : " : drop`,
			key:     "192.168.0.1 . tcp . 80",
			comment: Optional(" : "),
			value:   "drop",
		},
		{
			name:    "tricky comment #2",
			line:    `192.168.0.1 . tcp . 80 comment " no comment " : drop`,
			key:     "192.168.0.1 . tcp . 80",
			comment: Optional(" no comment "),
			value:   "drop",
		},
		{
			name:    "tricky key",
			line:    `192.168.0.1 . " comment " . 80 : drop`,
			key:     `192.168.0.1 . " comment " . 80`,
			comment: nil,
			value:   "drop",
		},
		{
			name:    "tricky key with comment",
			line:    `192.168.0.1 . " comment " . 80 comment "weird" : drop`,
			key:     `192.168.0.1 . " comment " . 80`,
			comment: Optional("weird"),
			value:   "drop",
		},
		{
			name:    "tricky value #1",
			line:    `192.168.0.1 . tcp . 80 : " comment "`,
			key:     `192.168.0.1 . tcp . 80`,
			comment: nil,
			value:   `" comment "`,
		},
		{
			name:    "tricky value #2",
			line:    `192.168.0.1 . tcp . 80 : " : drop "`,
			key:     `192.168.0.1 . tcp . 80`,
			comment: nil,
			value:   `" : drop "`,
		},
	} {
		t.Run(tc.name, func (t *testing.T) {
			key, comment, value := splitMapValue(tc.line)
			if key != tc.key {
				t.Errorf("bad key: expected %q got %q", tc.key, key)
			}
			if value != tc.value {
				t.Errorf("bad value: expected %q got %q", tc.value, value)
			}
			if comment == nil {
				if tc.comment != nil {
					t.Errorf("bad comment: expected %q got nil", *tc.comment)
				}
			} else if tc.comment == nil {
				t.Errorf("bad comment: expected nil got %q", *comment)
			} else if *comment != *tc.comment {
				t.Errorf("bad comment: expected %q got %q", *tc.comment, *comment)
			}
		})
	}
}

func TestListRules(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nftOutput  string
		nftError   string
		listOutput []*Rule
	}{
		{
			name:     "no such chain",
			nftError: "Error: No such file or directory\nlist chain ip testing testchain\n                      ^^^^^^^^^\n",
		},
		{
			name:       "no output",
			nftOutput:  ``,
			listOutput: []*Rule{},
		},
		{
			name:      "no rules",
			nftOutput: `
				table ip testing { # handle 1
					chain testchain { # handle 165
					}
				}`,
			listOutput: []*Rule{},
		},
		{
			name:      "no rules",
			nftOutput: `
				table ip testing { # handle 1
					chain testchain { # handle 165
						# this line is a comment, and the next is not a rule
						type filter hook input priority filter + 10; policy accept;
						# no handle; shouldn't happen, but should be ignored
						ip daddr 10.0.0.1
						# bad handle; shouldn't happen, but should be ignored
						ip daddr 10.0.0.1 # handle bob
					}
				}`,
			listOutput: []*Rule{},
		},
		{
			name:      "normal output",
			nftOutput: `
				table ip testing { # handle 1
				  yeah I don't think nftables ever actually outputs random extra lines like this but maybe?
					chain testchain { # handle 165
						type filter hook input priority filter + 10; policy accept;
						ct state { established, related } accept # handle 169
						ct status dnat accept comment "This rule does something" # handle 170
						iifname "lo" accept # handle 171
					}
				}`,
			listOutput: []*Rule{
				&Rule{
					Chain: "testchain",
					Rule: "ct state { established, related } accept",
					Handle: Optional(169),
				},
				&Rule{
					Chain: "testchain",
					Rule: "ct status dnat accept",
					Comment: Optional("This rule does something"),
					Handle: Optional(170),
				},
				&Rule{
					Chain: "testchain",
					Rule: `iifname "lo" accept`,
					Handle: Optional(171),
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fexec := newFakeExec(t)
			var err error
			if tc.nftError != "" {
				err = fmt.Errorf(tc.nftError)
			}
			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"nft", "--handle", "list", "chain", "ip", "testing", "testchain"},
					stdout: strings.TrimSpace(dedent.Dedent(tc.nftOutput)),
					err:    err,
				},
			)
			nft := newInternal(IPv4Family, "testing", fexec)

			result, err := nft.ListRules(context.Background(), "testchain")
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
			name:       "no output",
			objectType: "set",
			nftOutput:  ``,
			listOutput: []*Element{},
		},
		{
			name:       "no elements",
			objectType: "set",
			nftOutput:  `
				table ip testing {
					set test {
						type ipv4_addr . inet_proto . inet_service
						elements = {}
					}
				}`,
			listOutput: []*Element{},
		},
		{
			name:       "no elements",
			objectType: "set",
			nftOutput:  `
				table ip testing {
					set test {
						type ipv4_addr . inet_proto . inet_service
						elements = {
						}
					}
				}`,
			listOutput: []*Element{},
		},
		{
			name:       "one element",
			objectType: "map",
			nftOutput:  `
				table ip testing {
					map test {
						type ipv4_addr . inet_proto . inet_service : verdict
						elements = { 192.168.0.1 . tcp . 80 : goto chain1 }
					}
				}`,
			listOutput: []*Element{
				&Element{
					Name:  "test",
					Key:   "192.168.0.1 . tcp . 80",
					Value: "goto chain1",
				},
			},
		},
		{
			name:       "two elements",
			objectType: "map",
			nftOutput:  `
				table ip testing {
					map test {
						type ipv4_addr . inet_proto . inet_service : verdict
						elements = { 192.168.0.1 . tcp . 80 : goto chain1,
						             192.168.0.2 . tcp . 443 comment "foo" : drop }
					}
				}`,
			listOutput: []*Element{
				&Element{
					Name:  "test",
					Key:   "192.168.0.1 . tcp . 80",
					Value: "goto chain1",
				},
				&Element{
					Name:    "test",
					Key:     "192.168.0.2 . tcp . 443",
					Comment: Optional("foo"),
					Value:   "drop",
				},
			},
		},
		{
			name:       "three elements",
			objectType: "set",
			nftOutput:  `
				table ip testing {
					set test {
						type ipv4_addr . inet_proto . inet_service
						elements = { 192.168.0.1 . tcp . 80,
						             192.168.0.3 . udp . 80,
						             192.168.0.2 . tcp . 443 comment "foo" }
					}
				}`,
			listOutput: []*Element{
				&Element{
					Name: "test",
					Key:  "192.168.0.1 . tcp . 80",
				},
				&Element{
					Name: "test",
					Key:  "192.168.0.3 . udp . 80",
				},
				&Element{
					Name:    "test",
					Key:     "192.168.0.2 . tcp . 443",
					Comment: Optional("foo"),
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fexec := newFakeExec(t)
			var err error
			if tc.nftError != "" {
				err = fmt.Errorf(tc.nftError)
			}
			fexec.expected = append(fexec.expected,
				expectedCmd{
					args:   []string{"nft", "list", tc.objectType, "ip", "testing", "test"},
					stdout: strings.TrimSpace(dedent.Dedent(tc.nftOutput)),
					err:    err,
				},
			)
			nft := newInternal(IPv4Family, "testing", fexec)

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
